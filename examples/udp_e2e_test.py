"""
SwarmLink v0.3 — 真实 UDP Socket 端到端联调
==================================================
把前面所有模块串起来:
  安全层 (PyNaCl) + 分片/FEC + ARQ 完整链路 + 弱网整形

架构 (一对多, 每条方向独立整形):

    Sky(天空端) ──┬─ down[0] ─→ UDP ─→ Ground#0 ─┬─ up[0] ─┐
                  ├─ down[1] ─→ UDP ─→ Ground#1 ─┼─ up[1] ─┼─→ Sky
                  └─ down[2] ─→ UDP ─→ Ground#2 ─┴─ up[2] ─┘

  · 数据面: 天空端只加密一次 → 广播给 N 个地面端 (组会话密钥)
  · 控制面: 地面端各自发 ARQ_REQ → 天空端按窗口合并 → 只重传一次

数据管线 (顺序不能反):
  发送: 原始帧 → 分片 → RS(10,14) 编码 → 逐片加密(+24B) → UDP
  接收: UDP → 逐片解密(-24B) → RS 解码/重组 → 完整帧

测试场景:
  1. 正常 (0% 丢包)          : 验证全链路正确性
  2. 标准 (15% 丢包)         : 验证 FEC + ARQ 恢复
  3. 地狱 (40% 丢包 + 断连)  : 验证韧性

运行: python3 examples/udp_e2e_test.py
"""

import sys
import os
import time
import json
import random
import struct
import threading
import socket
from typing import Optional, List
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.header import (
    HEADER_SIZE, unpack_header, HeaderError,
)
from protocol.fragment import Fragmenter, Reassembler
from protocol.arq_full import (
    PacketStore, GroundReceiver, SkySender,
)
from protocol.multiplex import (
    StreamMultiplexer, StreamType,
)
from protocol.security_nacl import (
    create_session_manager, get_backend_info, SECURITY_HEADER_SIZE,
)
from tests.weaknet import WeakNetSimulator

# ============================================================
# 配置
# ============================================================
SKY_PORT_BASE = 5000
GND_PORT_BASE = 5010
SESSION_TAG = 0xDEADBEEF
CHUNK_SIZE = 600
FEC_K = 10
FEC_N = 14
N_CLIENTS = 3
N_FRAMES = 30

# 弱网场景 (上下行各自独立实例, 参数相同)
SCENARIOS = [
    {"name": "正常(0%丢包)", "loss_rate": 0.00, "delay_ms": 5,
     "jitter_ms": 2, "blackout_prob": 0.0, "seed": 42},
    {"name": "标准(15%丢包)", "loss_rate": 0.15, "delay_ms": 30,
     "jitter_ms": 10, "blackout_prob": 0.0, "seed": 42},
    {"name": "地狱(40%丢包+断连)", "loss_rate": 0.40, "delay_ms": 50,
     "jitter_ms": 30, "blackout_prob": 0.001, "blackout_ms": 1000, "seed": 7},
]


# ============================================================
# 真实 UDP 链路 (弱网整形在 egress, 真包过 socket)
# ============================================================
class UDPLink:
    """一个 UDP 端点。

    修复要点：旧版 send() 只是把包塞回自己的 WeakNet 队列, recv() 又从
    同一个队列取出来 —— socket 只是 bind 了一下, 从来没真正发过包,
    所谓"真实 UDP 测试"实际是进程内队列自嗨。

    现在:
      send(data) → 每个 peer 各自的 WeakNet 整形(丢包/延迟/抖动/断连)
                 → pump 线程到点后 sendto() 真发出去
      recv()     → 后台线程 recvfrom() 收进 inbox, 应用层从 inbox 取
    """

    def __init__(self, bind_port: int, label: str = ""):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 2**20)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 2**20)
        self._sock.bind(("127.0.0.1", bind_port))
        self._sock.settimeout(0.02)
        self.port = bind_port
        self.label = label

        self._peers: List[tuple] = []      # [(addr, weaknet), ...]
        self._inbox: deque = deque()
        self._inbox_lock = threading.Lock()
        self._running = True
        self.bytes_on_wire = 0
        self.pkts_on_wire = 0

        self._rx = threading.Thread(target=self._recv_loop, daemon=True)
        self._tx = threading.Thread(target=self._pump_loop, daemon=True)
        self._rx.start()
        self._tx.start()

    def add_peer(self, port: int, weaknet: WeakNetSimulator) -> int:
        """注册一个下游 peer, 返回它的索引 (= client_id)"""
        self._peers.append((("127.0.0.1", port), weaknet))
        return len(self._peers) - 1

    def _recv_loop(self):
        while self._running:
            try:
                data, _ = self._sock.recvfrom(65535)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            with self._inbox_lock:
                self._inbox.append(data)

    def _pump_loop(self):
        """把弱网队列里"已到投递时间"的包真正 sendto 出去"""
        while self._running:
            moved = 0
            for addr, wn in list(self._peers):
                while True:
                    pkt = wn.recv(0)
                    if pkt is None:
                        break
                    try:
                        self._sock.sendto(pkt, addr)
                        self.bytes_on_wire += len(pkt)
                        self.pkts_on_wire += 1
                    except OSError:
                        pass
                    moved += 1
            if moved == 0:
                time.sleep(0.0005)

    def send(self, data: bytes, recipients: Optional[list] = None):
        """应用层发送。recipients=None → 广播给所有 peer"""
        for idx, (_addr, wn) in enumerate(self._peers):
            if recipients is None or idx in recipients:
                wn.send(data)

    def recv(self) -> Optional[bytes]:
        with self._inbox_lock:
            return self._inbox.popleft() if self._inbox else None

    def drain(self, max_n: int = 4096) -> list:
        out = []
        with self._inbox_lock:
            while self._inbox and len(out) < max_n:
                out.append(self._inbox.popleft())
        return out

    def close(self):
        self._running = False
        time.sleep(0.03)
        try:
            self._sock.close()
        except OSError:
            pass


def _wn(cfg: dict, seed_offset: int = 0) -> WeakNetSimulator:
    kwargs = {k: v for k, v in cfg.items() if k != "name"}
    kwargs["seed"] = kwargs.get("seed", 42) + seed_offset
    return WeakNetSimulator(**kwargs)


# ============================================================
# 单场景测试
# ============================================================
def run_scenario(cfg: dict, run_idx: int = 0,
                 n_frames: int = N_FRAMES,
                 n_clients: int = N_CLIENTS,
                 encrypted: bool = True,
                 use_multiplex: bool = False,
                 verbose: bool = True) -> dict:
    name = cfg["name"]
    if verbose:
        print(f"\n{'─' * 62}")
        print(f"  场景: {name}   客户端: {n_clients}   加密: "
              f"{'开' if encrypted else '关'}"
              f"   复用: {'开' if use_multiplex else '关'}")
        print(f"  丢包率: {cfg['loss_rate']*100:.0f}%  "
              f"延迟: {cfg['delay_ms']}ms  抖动: {cfg['jitter_ms']}ms", end="")
        if cfg.get("blackout_prob", 0) > 0:
            print(f"  断连: {cfg['blackout_ms']}ms@p={cfg['blackout_prob']}",
                  end="")
        print(f"\n{'─' * 62}")

    # --- 端口分配 (每轮错开, 避免复用冲突) ---
    base = run_idx * 100
    sky_port = SKY_PORT_BASE + base
    gnd_ports = [GND_PORT_BASE + base + i for i in range(n_clients)]

    # --- 链路 ---
    down_wns = [_wn(cfg, seed_offset=i) for i in range(n_clients)]
    up_wns = [_wn(cfg, seed_offset=100 + i) for i in range(n_clients)]

    sky_link = UDPLink(sky_port, "sky")
    for i, p in enumerate(gnd_ports):
        sky_link.add_peer(p, down_wns[i])

    gnd_links = []
    for i, p in enumerate(gnd_ports):
        gl = UDPLink(p, f"gnd{i}")
        gl.add_peer(sky_port, up_wns[i])
        gnd_links.append(gl)

    # --- 会话: DH 一次, 派生组密钥, 分发给所有地面端 ---
    sky_sm = create_session_manager(b"sky-001")
    peer_sm = create_session_manager(b"ground-000")
    sp = sky_sm.initiate_handshake()
    gp = peer_sm.accept_handshake(sp, b"sky-001")
    sky_sm.finalize_handshake(gp, b"ground-000")
    group_key = sky_sm.session_key

    gnd_sms = []
    for i in range(n_clients):
        sm = create_session_manager(f"ground-{i:03d}".encode())
        sm.adopt_session_key(group_key, b"sky-001")
        gnd_sms.append(sm)

    # --- 天空端 ---
    fragger = Fragmenter(SESSION_TAG, chunk_size=CHUNK_SIZE,
                         fec_k=FEC_K, fec_n=FEC_N)
    store = PacketStore(max_frames=120, ttl_sec=6.0)

    mux = None
    ctrl_msgs_sent = []
    if use_multiplex:
        # 统一出口: 复用器调度 (视频 + 控制 + 遥测 一条链路)
        mux = StreamMultiplexer(SESSION_TAG, sky_link.send,
                                chunk_size=CHUNK_SIZE, fec_k=FEC_K, fec_n=FEC_N)

        def sky_send_via_mux(pkt, recipients=None):
            # 广播给所有地面端 (mux 统一调度); 视频流不区分接收者
            mux.submit_packet(StreamType.VIDEO, pkt)

        sky_send = sky_send_via_mux
    else:
        sky_send = sky_link.send

    sender = SkySender(
        session_tag=SESSION_TAG,
        fragmenter=fragger,
        encrypt_func=(sky_sm.encrypt_payload if encrypted else None),
        send_callback=sky_send,
        chunk_size=CHUNK_SIZE, fec_k=FEC_K, fec_n=FEC_N,
        packet_store=store,
        arq_window_ms=20,
    )

    # --- 地面端 x N ---
    send_times: dict = {}
    completed = [dict() for _ in range(n_clients)]
    latencies = [dict() for _ in range(n_clients)]
    ctrl_recv = [dict() for _ in range(n_clients)]  # stream_id=1 控制消息

    def make_cb(cid):
        def cb(client_id, frame_id, data):
            completed[cid][frame_id] = data
            if frame_id in send_times:
                latencies[cid][frame_id] = (time.monotonic()
                                            - send_times[frame_id]) * 1000
        return cb

    # 控制流重组器 (独立于视频流, frame_id 空间隔离)
    ctrl_reasms = [Reassembler(SESSION_TAG, fec_k=FEC_K, fec_n=FEC_N)
                   for _ in range(n_clients)]

    receivers = []
    for i in range(n_clients):
        reasm = Reassembler(SESSION_TAG, fec_k=FEC_K, fec_n=FEC_N)
        receivers.append(GroundReceiver(
            client_id=i,
            session_tag=SESSION_TAG,
            reassembler=reasm,
            decryptor_func=gnd_sms[i].decrypt_payload,
            send_arq_func=gnd_links[i].send,
            on_frame_complete=make_cb(i),
            rto_ms=40, max_retries=6,
            fec_k=FEC_K, fec_n=FEC_N,
        ))

    # --- 原始帧 (一帧 ≈ 一个 FEC 组, 4800~6000B) ---
    rng = random.Random(cfg.get("seed", 42))
    original = {fid: os.urandom(rng.randint(4800, 6000))
                for fid in range(n_frames)}
    original_bytes = sum(len(v) for v in original.values())

    # --- 控制消息 (multiplex 场景: 与控制流同链路) ---
    ctrl_msgs = []
    ctrl_msgs_expected = []
    if use_multiplex:
        ctrl_msgs = [
            b"ARM_MOTORS",
            b"SET_ALTITUDE:50m",
            b"RTL_NOW",
            b"GIMBAL_PITCH:-15",
        ]
        ctrl_msgs_expected = list(ctrl_msgs)

    # --- 发送 (按 30fps 节奏, 别一次灌爆) ---
    t0 = time.monotonic()
    for fid in range(n_frames):
        send_times[fid] = time.monotonic()
        sender.send_frame(original[fid], frame_id=fid,
                          stream_id=0, key_frame=(fid % 10 == 0))
        if mux is not None and ctrl_msgs:
            # 控制消息插在视频流之间 (WFQ 保证优先出队)
            msg = ctrl_msgs.pop(0)
            mux.submit(StreamType.CONTROL, msg)
        time.sleep(0.008)

    # --- 主循环 ---
    max_wait = 12.0
    last_report = 0.0
    while time.monotonic() - t0 < max_wait:
        # 1) 地面端收数据 (multiplex: 按 stream_id 分流)
        for i in range(n_clients):
            for pkt in gnd_links[i].drain():
                if use_multiplex:
                    try:
                        hdr = unpack_header(pkt)
                    except HeaderError:
                        continue
                    if hdr.stream_id == StreamType.CONTROL:
                        # 控制消息 (明文, mux 直发): 独立重组器
                        frame = ctrl_reasms[i].feed(pkt)
                        if frame is not None:
                            ctrl_recv[i][len(ctrl_recv[i])] = frame
                        continue
                receivers[i].feed(pkt)

        # 2) 天空端收 ARQ_REQ (client_id 来自 REQ payload)
        for pkt in sky_link.drain():
            try:
                hdr = unpack_header(pkt)
            except HeaderError:
                continue
            if not hdr.is_arq_req():
                continue
            cid = 0
            if len(pkt) >= HEADER_SIZE + 4:
                cid = struct.unpack("!I", pkt[HEADER_SIZE:HEADER_SIZE + 4])[0]
            sender.handle_arq_request(pkt, client_id=cid)

        # 3) 按合并窗口刷新 ARQ (关键: 不是无条件 flush)
        sender.tick_arq()

        # 4) 地面端丢失检测
        for r in receivers:
            r.tick_loss_check()

        # 5) 完成判定
        if all(len(c) >= n_frames for c in completed):
            break

        elapsed = time.monotonic() - t0
        if verbose and elapsed - last_report > 1.0:
            last_report = elapsed
            done = "/".join(str(len(c)) for c in completed)
            print(f"    [{elapsed:4.1f}s] 各端完成 {done} (共需 {n_frames})")

        time.sleep(0.001)

    sender.flush_arq()
    time.sleep(0.15)
    for i in range(n_clients):
        for pkt in gnd_links[i].drain():
            if use_multiplex:
                try:
                    hdr = unpack_header(pkt)
                except HeaderError:
                    continue
                if hdr.stream_id == StreamType.CONTROL:
                    frame = ctrl_reasms[i].feed(pkt)
                    if frame is not None:
                        ctrl_recv[i][len(ctrl_recv[i])] = frame
                    continue
            receivers[i].feed(pkt)
    elapsed = time.monotonic() - t0

    if mux is not None:
        time.sleep(0.1)
        mux.shutdown()

    # --- 验证 (重组帧尾部含 FEC 补零, 用前缀比对) ---
    verified = [0] * n_clients
    corrupted = [0] * n_clients
    for i in range(n_clients):
        for fid, data in completed[i].items():
            orig = original.get(fid)
            if orig is None:
                continue
            if len(data) >= len(orig) and data[:len(orig)] == orig:
                verified[i] += 1
            else:
                corrupted[i] += 1
                if corrupted[i] == 1 and verbose:
                    print(f"      [dbg] client{i} fid={fid} "
                          f"len={len(data)} orig={len(orig)}")

    sky_stats = sender.stats()
    arq = sky_stats["arq"]

    all_lat = [v for d in latencies for v in d.values()]
    all_lat.sort()

    def pct(p):
        if not all_lat:
            return 0.0
        return round(all_lat[min(len(all_lat) - 1, int(len(all_lat) * p))], 1)

    total_complete = sum(len(c) for c in completed)
    total_verified = sum(verified)
    denom = n_frames * n_clients

    down_in = sum(w.stats()["packets_in"] for w in down_wns)
    down_lost = sum(w.stats()["packets_lost"] for w in down_wns)
    up_in = sum(w.stats()["packets_in"] for w in up_wns)
    up_lost = sum(w.stats()["packets_lost"] for w in up_wns)
    blackouts = sum(w.stats()["blackouts"] for w in down_wns)

    reqs = arq.get("reqs_received", 0)
    merged = arq.get("reqs_merged", 0)
    retx = arq.get("retransmits_sent", 0)

    result = {
        "name": name,
        "clients": n_clients,
        "encrypted": encrypted,
        "time_sec": round(elapsed, 2),
        "frames_per_client": n_frames,
        "completion_rate": round(total_complete / denom * 100, 1),
        "verify_rate": round(total_verified / denom * 100, 1),
        "corrupted": sum(corrupted),
        "per_client_verified": verified,
        "avg_latency_ms": round(sum(all_lat) / len(all_lat), 1) if all_lat else 0,
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "packets_sent": sky_stats["packets_sent"],
        "retransmits": sky_stats["retransmits"],
        "bytes_sent": sky_stats["bytes_sent"],
        "original_bytes": original_bytes,
        "overhead_x": round(sky_stats["bytes_sent"] / original_bytes, 2),
        "down_loss_pct": round(down_lost / max(1, down_in) * 100, 1),
        "up_loss_pct": round(up_lost / max(1, up_in) * 100, 1),
        "blackouts": blackouts,
        "arq_reqs": reqs,
        "arq_retransmits": retx,
        "arq_merged": merged,
        "arq_merge_rate": arq.get("merge_rate_pct", 0),
        "arq_store_miss": arq.get("store_misses", 0),
        "loss_detected": sum(r.stats()["loss"]["loss_detected"]
                             for r in receivers),
        "recovered_by_arq": sum(r.stats()["loss"]["recovered_by_arq"]
                                for r in receivers),
        "decrypt_ok": sum(r.stats()["rx"]["decrypt_ok"] for r in receivers),
        "decrypt_fail": sum(r.stats()["rx"]["decrypt_fail"] for r in receivers),
        "wire_bytes": sky_link.bytes_on_wire,
    }

    # 控制消息统计 (multiplex 场景)
    if use_multiplex:
        ctrl_expected = len(ctrl_msgs_expected) if ctrl_msgs_expected else 0
        result["ctrl_sent"] = ctrl_expected
        result["ctrl_recv"] = sum(len(c) for c in ctrl_recv)
        if verbose:
            print(f"      控制消息: 发送 {ctrl_expected}  "
                  f"各端收到 {[len(c) for c in ctrl_recv]}")

    if verbose:
        print(f"\n    结果 (耗时 {result['time_sec']}s):")
        print(f"      帧完成:     {total_complete}/{denom} "
              f"({result['completion_rate']}%)")
        print(f"      帧验证:     {total_verified}/{denom} "
              f"({result['verify_rate']}%)  坏帧 {result['corrupted']}")
        print(f"      端到端延迟: avg {result['avg_latency_ms']}ms  "
              f"p50 {result['p50_ms']}ms  p95 {result['p95_ms']}ms")
        print(f"      实际丢包:   下行 {result['down_loss_pct']}%  "
              f"上行 {result['up_loss_pct']}%  断连 {blackouts} 次")
        print(f"      发包:       {result['packets_sent']} "
              f"(其中重传 {result['retransmits']})  "
              f"带宽放大 {result['overhead_x']}x")
        print(f"      ARQ:        收到请求 {reqs}  实际重传 {retx}  "
              f"合并省下 {merged} 次 ({result['arq_merge_rate']}%)")
        print(f"      ARQ 救回:   {result['recovered_by_arq']} 个分片"
              f"   PacketStore 未命中 {result['arq_store_miss']}")
        print(f"      解密:       成功 {result['decrypt_ok']}  "
              f"失败/重放 {result['decrypt_fail']}")

    # --- 收尾 ---
    for gl in gnd_links:
        gl.close()
    sky_link.close()
    sky_sm.destroy_session()
    for sm in gnd_sms:
        sm.destroy_session()

    return result


# ============================================================
# 主入口
# ============================================================
def main():
    print("╔" + "═" * 60 + "╗")
    print("║" + "  SwarmLink v0.3 — 真实 UDP 端到端联调".ljust(53) + "║")
    print("║" + "  安全层(PyNaCl) + 分片/FEC + ARQ 聚合重传".ljust(51) + "║")
    print("╚" + "═" * 60 + "╝")

    info = get_backend_info()
    print(f"\n  加密后端: {info['backend']} ({info['speed_class']})  "
          f"每片开销 {SECURITY_HEADER_SIZE}B")
    print(f"  拓扑: 1 天空端 → {N_CLIENTS} 地面端   "
          f"每端 {N_FRAMES} 帧   RS({FEC_K},{FEC_N})  分片 {CHUNK_SIZE}B")

    results = []
    for idx, cfg in enumerate(SCENARIOS):
        results.append(run_scenario(dict(cfg), run_idx=idx))

    # 对照组: 关加密, 验证加密不是瓶颈也不是错误源
    print(f"\n{'═' * 62}")
    print("  对照组: 关闭加密 (排除加密干扰)")
    print(f"{'═' * 62}")
    plain = run_scenario(dict(SCENARIOS[1]), run_idx=10, encrypted=False)

    # 多流复用对照组: 视频 + 控制 + 遥测同链路 (15% 丢包)
    print(f"\n{'═' * 62}")
    print("  对照组: 多流复用 (StreamMultiplexer 统一调度)")
    print(f"{'═' * 62}")
    mux_r = run_scenario(dict(SCENARIOS[1]), run_idx=11,
                         use_multiplex=True)

    # ---- 汇总 ----
    print(f"\n\n{'═' * 78}")
    print("  SwarmLink v0.3 三档弱网对比")
    print(f"{'═' * 78}")
    hdr = (f"  {'场景':<22s}{'完成率':>8s}{'验证率':>8s}{'实测丢包':>9s}"
           f"{'p50':>7s}{'p95':>8s}{'重传':>7s}{'合并率':>8s}{'带宽':>8s}")
    print(hdr)
    print("  " + "─" * 80)
    for r in results:
        print(f"  {r['name']:<22s}"
              f"{r['completion_rate']:>7.1f}%"
              f"{r['verify_rate']:>7.1f}%"
              f"{r['down_loss_pct']:>8.1f}%"
              f"{r['p50_ms']:>6.0f}ms"
              f"{r['p95_ms']:>7.0f}ms"
              f"{r['retransmits']:>7d}"
              f"{r['arq_merge_rate']:>7.1f}%"
              f"{r['overhead_x']:>7.2f}x")
    print(f"  {'标准档(不加密)':<22s}"
          f"{plain['completion_rate']:>7.1f}%"
          f"{plain['verify_rate']:>7.1f}%"
          f"{plain['down_loss_pct']:>8.1f}%"
          f"{plain['p50_ms']:>6.0f}ms"
          f"{plain['p95_ms']:>7.0f}ms"
          f"{plain['retransmits']:>7d}"
          f"{plain['arq_merge_rate']:>7.1f}%"
          f"{plain['overhead_x']:>7.2f}x")
    print(f"  {'标准档(多流复用)':<22s}"
          f"{mux_r['completion_rate']:>7.1f}%"
          f"{mux_r['verify_rate']:>7.1f}%"
          f"{mux_r['down_loss_pct']:>8.1f}%"
          f"{mux_r['p50_ms']:>6.0f}ms"
          f"{mux_r['p95_ms']:>7.0f}ms"
          f"{mux_r['retransmits']:>7d}"
          f"{mux_r['arq_merge_rate']:>7.1f}%"
          f"{mux_r['overhead_x']:>7.2f}x")

    # ---- 判定 ----
    ok_normal = results[0]["verify_rate"] == 100.0
    ok_std = results[1]["verify_rate"] >= 80.0
    ok_hell = results[2]["verify_rate"] >= 30.0
    no_corrupt = all(r["corrupted"] == 0 for r in results)
    mux_ok = (mux_r["verify_rate"] >= 80.0
              and mux_r.get("ctrl_recv", 0) > 0)
    all_pass = ok_normal and ok_std and ok_hell and no_corrupt and mux_ok

    print(f"\n{'═' * 78}")
    for r, thr in zip(results, [100.0, 80.0, 30.0]):
        flag = "✓" if r["verify_rate"] >= thr else "✗"
        print(f"  {flag} {r['name']:<22s} 验证率 {r['verify_rate']:>5.1f}% "
              f"(门槛 {thr}%)  坏帧 {r['corrupted']}")
    if all_pass:
        print("\n  ✅ SwarmLink v0.3 全链路联调通过 — 零坏帧")
    else:
        print("\n  ⚠ 部分场景未达标")
    print(f"{'═' * 78}")

    # ---- 落盘 ----
    out = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "tools", "v03_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"scenarios": results, "plaintext_control": plain,
                   "backend": info, "config": {
                       "clients": N_CLIENTS, "frames": N_FRAMES,
                       "chunk_size": CHUNK_SIZE,
                       "fec": [FEC_K, FEC_N]}},
                  f, ensure_ascii=False, indent=2)
    print(f"\n  数据已写入: {out}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
