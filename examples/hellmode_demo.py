"""
SwarmLink 地狱档 Demo — "当别人崩溃时，我们在自愈"
====================================================
模拟最恶劣场景：40% 丢包 + 2 秒断连，证明协议韧性。

运行：python3 examples/hellmode_demo.py
"""

import os, sys, time, random
import argparse
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.header import (
    pack_header, unpack_header, HeaderError,
    FLAG_ARQ_REQ, FLAG_ARQ_REP, FLAG_KEY_FRAME,
)
from protocol.fragment import Fragmenter, Reassembler
from protocol.arq import ARQAggregator, ARQClient
from tests.weaknet import WeakNetSimulator, MetricsCollector


def make_fake_frame(frame_id: int, size: int) -> bytes:
    """用确定性随机生成帧数据（保证发送端和接收端能对账）"""
    return random.Random(frame_id).randbytes(size)


def frame_size_for(fid: int) -> int:
    return random.Random(fid + 999).randint(3000, 7000)


class ClientSim:
    """一个地面端 / 一副 FPV 眼镜"""
    def __init__(self, cid: int, session: int, net: WeakNetSimulator,
                 arq_agg: ARQAggregator, metrics: MetricsCollector):
        self.cid = cid
        self.session = session
        self.net = net
        self.arq_agg = arq_agg
        self.metrics = metrics
        self.reasm = Reassembler(session)
        self.arq = ARQClient(session, cid)
        self.completed: dict = {}
        self.mismatches = 0
        self.keyframe_misses = 0
        self._lock = threading.Lock()

    def feed(self, packet: bytes, now: float):
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return
        # ARQ 回复处理
        self.arq.on_packet(packet)
        # 喂重组器
        result = self.reasm.feed(packet)
        if result is not None:
            fid = hdr.frame_id
            expected = make_fake_frame(fid, frame_size_for(fid))
            ok = (result[:len(expected)] == expected)
            with self._lock:
                self.completed[fid] = result[:len(expected)]
            self.metrics.mark_complete(fid, now)
            if not ok:
                self.mismatches += 1
                if hdr.is_key_frame():
                    self.keyframe_misses += 1


def sender_thread(frames: int, fragger: Fragmenter, nets: list,
                  packet_store: dict, metrics: MetricsCollector,
                  fps: float = 30.0):
    """天空端发送线程"""
    interval = 1.0 / fps
    for fid in range(frames):
        size = frame_size_for(fid)
        data = make_fake_frame(fid, size)
        is_key = (fid % 5 == 0)
        packets = fragger.fragment(data, stream_id=0, key_frame=is_key)
        now = time.monotonic()
        metrics.mark_send(fid, len(packets), now)
        for pkt in packets:
            try:
                h = unpack_header(pkt)
                packet_store[(h.frame_id, h.frag_id)] = pkt
            except HeaderError:
                pass
            for net in nets:
                net.send(pkt)
        # FPS 节奏
        sleep_to = time.monotonic() + interval
        while time.monotonic() < sleep_to:
            time.sleep(0.001)


def main():
    parser = argparse.ArgumentParser(description="SwarmLink 地狱档 Demo")
    parser.add_argument("--clients", type=int, default=8, help="客户端数")
    parser.add_argument("--frames", type=int, default=60, help="总帧数")
    parser.add_argument("--loss", type=float, default=0.40, help="丢包率")
    parser.add_argument("--delay", type=float, default=50, help="基础延迟(ms)")
    parser.add_argument("--jitter", type=float, default=25, help="抖动(ms)")
    parser.add_argument("--blackout", type=int, default=2000, help="断连时长(ms)")
    parser.add_argument("--blackout-prob", type=float, default=0.008, help="断连概率")
    parser.add_argument("--fps", type=float, default=20, help="帧率（地狱档降帧省带宽）")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    # --- 横幅 ---
    print()
    print("╔════════════════════════════════════════════════════════╗")
    print("║        SwarmLink — HELL MODE DEMO                     ║")
    print("║  \"当别人在丢包里崩溃时，SwarmLink 在自愈\"           ║")
    print("╚════════════════════════════════════════════════════════╝")
    print()
    print(f"  📡 客户端数  : {args.clients} 副 FPV 眼镜")
    print(f"  🎬 总帧数    : {args.frames} 帧 @ {args.fps}fps")
    print(f"  💀 丢包率    : {args.loss*100:.0f}%")
    print(f"  ⏱️  延迟      : {args.delay}ms ± {args.jitter}ms")
    print(f"  🔌 断连      : {args.blackout}ms @ p={args.blackout_prob}")
    print(f"  🌱 随机种子  : {args.seed}")
    print()

    SESSION = 0x5C77A8
    interval = 1.0 / args.fps

    # 每客户端独立弱网
    nets = [
        WeakNetSimulator(
            loss_rate=args.loss, delay_ms=args.delay, jitter_ms=args.jitter,
            blackout_ms=args.blackout, blackout_prob=args.blackout_prob,
            seed=args.seed + c,
        )
        for c in range(args.clients)
    ]
    fragger = Fragmenter(SESSION, chunk_size=800)
    metrics = MetricsCollector(jitter_threshold_ms=150)
    packet_store: dict = {}

    arq_agg = ARQAggregator(SESSION, packet_store, window_ms=20)

    clients = [
        ClientSim(c, SESSION, nets[c], arq_agg, metrics)
        for c in range(args.clients)
    ]

    # 启动发送线程
    t_send = threading.Thread(
        target=sender_thread,
        args=(args.frames, fragger, nets, packet_store, metrics, args.fps),
        daemon=True,
    )
    t_send.start()

    # 主循环：drain + feed
    t_start = time.monotonic()
    timeout_at = t_start + args.frames * interval + 10.0
    last_report = t_start
    blackouts_seen = 0
    last_blackout_count = 0

    while time.monotonic() < timeout_at:
        now = time.monotonic()
        for idx, cli in enumerate(clients):
            drained = nets[idx].drain()
            for pkt in drained:
                cli.feed(pkt, now)

        # 检测断连事件
        cur_bo = sum(n.blackouts_triggered for n in nets)
        if cur_bo > last_blackout_count:
            new_bo = cur_bo - last_blackout_count
            blackouts_seen += new_bo
            elapsed = now - t_start
            print(f"  ⚡ [{elapsed:5.1f}s] 🔴 断连 x{new_bo} (累计 {cur_bo})")
            last_blackout_count = cur_bo

        # 进度
        if now - last_report > 3.0:
            done = sum(len(c.completed) for c in clients)
            total = args.frames * args.clients
            elapsed = now - t_start
            fps_now = done / max(elapsed, 0.1)
            print(f"  [{elapsed:5.1f}s] ✅ 完成 {done}/{total} ({done/max(1,total)*100:.1f}%) | 实时 {fps_now:.1f} fps")
            last_report = now
        time.sleep(0.005)

    t_send.join(timeout=3.0)

    # 最终 drain
    for _ in range(5):
        for idx, cli in enumerate(clients):
            drained = nets[idx].drain()
            for pkt in drained:
                cli.feed(pkt, time.monotonic())
        time.sleep(0.05)

    # ============ 输出报告 ============
    total_completed = sum(len(c.completed) for c in clients)
    total_expected = args.frames * args.clients
    total_mismatch = sum(c.mismatches for c in clients)
    total_kf_miss = sum(c.keyframe_misses for c in clients)

    elapsed_total = time.monotonic() - t_start

    print()
    print("╔════════════════════════════════════════════════════════╗")
    print("║                    📊  PERFORMANCE REPORT               ║")
    print("╚════════════════════════════════════════════════════════╝")
    print()

    # 网络层
    s0 = nets[0].stats()
    print(f"  🌐 网络层（客户端 0 样本）")
    print(f"     包入网    : {s0['packets_in']}")
    print(f"     送达      : {s0['packets_out']}")
    print(f"     丢失      : {s0['packets_lost']} ({s0['loss_pct']:.1f}%)")
    print(f"     断连次数  : {s0['blackouts']}")
    print()

    # ARQ
    print(f"  🔥 ARQ 聚合")
    print(f"     模式      : A 方案（合并同 frag → 1 次广播）")
    print(f"     窗口      : {arq_agg.window_ms}ms")
    theoretical_save = (1 - 1/max(1,args.clients)) * 100
    print(f"     理论带宽省: {theoretical_save:.1f}% (vs 无聚合)")
    print()

    # 完成度
    print(f"  ✅ 完成度")
    for c in range(args.clients):
        n = len(clients[c].completed)
        bar_len = int(n / args.frames * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        pct = n / args.frames * 100
        flag = " ⚠️" if pct < 70 else ""
        print(f"     client[{c}]: {bar} {n}/{args.frames} ({pct:.0f}%){flag}")
    overall = total_completed / max(1, total_expected) * 100
    print(f"     总计      : {total_completed}/{total_expected} ({overall:.1f}%)")
    print(f"     数据校验失败: {total_mismatch}（关键帧失败: {total_kf_miss}）")
    print()

    # 端到端度量
    ms = metrics.summary()
    if "error" not in ms:
        print(f"  ⏱️  端到端延迟")
        print(f"     平均      : {ms['avg_latency_ms']} ms")
        print(f"     P50       : {ms['p50_ms']} ms")
        print(f"     P95       : {ms['p95_ms']} ms")
        print(f"     P99       : {ms['p99_ms']} ms")
        print(f"     卡顿率(>150ms): {ms['jitter_pct']}%")
        print(f"     平均 FPS  : {ms['avg_fps']}")
    print()

    # 震撼总结
    print("╔════════════════════════════════════════════════════════╗")
    if overall >= 80:
        print("║  🟢 RESULT: SURVIVED.                              ║")
        print("║  40% 丢包 + 断连，画面抖一下，继续飞。            ║")
    elif overall >= 50:
        print("║  🟡 RESULT: DEGRADED BUT ALIVE.                     ║")
        print("║  部分帧丢失，但系统未崩溃。                        ║")
    else:
        print("║  🔴 RESULT: TOO HARSH. NEEDS TUNING.               ║")
    print(f"║  总耗时: {elapsed_total:.1f}s | 断连事件: {blackouts_seen} 次      ║")
    print("╚════════════════════════════════════════════════════════╝")
    print()


if __name__ == "__main__":
    main()
