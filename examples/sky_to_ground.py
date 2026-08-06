"""
SwarmLink 端到端 Demo（边发边收模型）
========================================
真实模拟：发送和接收并发进行，不攒包。
- 天空端逐帧发送，每帧间隔 ~33ms（模拟 30fps）
- 弱网在中间注入延迟/丢包/断连
- 每个客户端持续 drain 自己的网络队列
- 完成帧立即校验 + 打点

运行：python3 examples/sky_to_ground.py [参数]
"""

import os
import sys
import time
import random
import argparse
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.header import (
    pack_header, unpack_header, HeaderError,
    FLAG_ARQ_REQ, FLAG_ARQ_REP,
)
from protocol.fragment import Fragmenter, Reassembler
from protocol.arq import ARQAggregator, ARQClient
from tests.weaknet import WeakNetSimulator, MetricsCollector


def make_fake_frame(frame_id: int, size: int) -> bytes:
    return random.Random(frame_id).randbytes(size)


def frame_size_for(fid: int) -> int:
    return random.Random(fid).randint(3000, 7000)


class ClientSim:
    """一个地面端。"""
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
        self._lock = threading.Lock()

    def feed(self, packet: bytes, now: float):
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return
        # ARQ 回复
        rep = self.arq.on_packet(packet)
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
                print(f"  ⚠ cid={self.cid} fid={fid} mismatch")


def sender_thread(frames: int, fragger: Fragmenter, nets: list,
                  packet_store: dict, metrics: MetricsCollector,
                  fps: float = 30.0):
    """天空端发送线程：按 fps 节奏发送。"""
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
        # 按 fps 节奏
        sleep_to = time.monotonic() + interval
        while time.monotonic() < sleep_to:
            time.sleep(0.001)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument("--frames", type=int, default=50)
    parser.add_argument("--loss", type=float, default=0.30)
    parser.add_argument("--delay", type=float, default=50)
    parser.add_argument("--jitter", type=float, default=25)
    parser.add_argument("--blackout", type=int, default=2000)
    parser.add_argument("--blackout-prob", type=float, default=0.005)
    parser.add_argument("--chunk", type=int, default=800)
    parser.add_argument("--fps", type=float, default=30)
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  SwarmLink Demo — 边发边收模型")
    print(f"  clients={args.clients}  frames={args.frames}  fps={args.fps}")
    print(f"  loss={args.loss*100:.0f}%  delay={args.delay}ms  "
          f"jitter={args.jitter}ms")
    print(f"  blackout={args.blackout}ms @ p={args.blackout_prob}")
    print(f"{'='*50}\n")

    SESSION = 0x5C77A8
    fps = args.fps
    interval = 1.0 / fps

    # 每客户端独立弱网实例
    nets = [
        WeakNetSimulator(
            loss_rate=args.loss, delay_ms=args.delay, jitter_ms=args.jitter,
            blackout_ms=args.blackout, blackout_prob=args.blackout_prob,
            seed=100 + c,
        )
        for c in range(args.clients)
    ]
    fragger = Fragmenter(SESSION, chunk_size=args.chunk)
    metrics = MetricsCollector(jitter_threshold_ms=100)
    packet_store: dict = {}

    arq_agg = ARQAggregator(SESSION, packet_store, window_ms=20)

    clients = [
        ClientSim(c, SESSION, nets[c], arq_agg, metrics)
        for c in range(args.clients)
    ]

    # 启动发送线程
    t_send = threading.Thread(
        target=sender_thread,
        args=(args.frames, fragger, nets, packet_store, metrics, fps),
        daemon=True,
    )
    t_send.start()

    # 主线程：持续 drain + feed，直到发送完且所有队列空
    t_start = time.monotonic()
    timeout_at = t_start + args.frames * interval + 5.0
    last_report = t_start

    while time.monotonic() < timeout_at:
        now = time.monotonic()
        for idx, cli in enumerate(clients):
            drained = nets[idx].drain()
            for pkt in drained:
                cli.feed(pkt, now)
        # 进度报告
        if now - last_report > 2.0:
            done = sum(len(c.completed) for c in clients)
            total = args.frames * args.clients
            elapsed = now - t_start
            print(f"  [{elapsed:5.1f}s] completed {done}/{total}")
            last_report = now
        time.sleep(0.005)

    t_send.join(timeout=2.0)

    # 最终 drain
    for _ in range(3):
        for idx, cli in enumerate(clients):
            drained = nets[idx].drain()
            for pkt in drained:
                cli.feed(pkt, time.monotonic())
        time.sleep(0.05)

    # --- 输出 ---
    total_completed = sum(len(c.completed) for c in clients)
    total_expected = args.frames * args.clients
    total_mismatch = sum(c.mismatches for c in clients)

    print(f"\n{'='*50}")
    print(f"  网络层（客户端 0）")
    s0 = nets[0].stats()
    print(f"    包入网: {s0['packets_in']}  送达: {s0['packets_out']}  "
          f"丢失: {s0['packets_lost']} ({s0['loss_pct']:.1f}%)")
    print(f"    断连次数: {s0['blackouts']}")

    print(f"\n  ARQ 聚合")
    print(f"    模式: A 方案（合并同 frag 请求 → 1 次广播）")
    print(f"    聚合窗口: {arq_agg.window_ms}ms")

    print(f"\n  完成度")
    for c in range(args.clients):
        n = len(clients[c].completed)
        print(f"    client[{c}]: {n}/{args.frames} 帧")
    print(f"    总: {total_completed}/{total_expected} "
          f"({total_completed/max(1,total_expected)*100:.1f}%)")
    print(f"    数据校验失败: {total_mismatch}")

    ms = metrics.summary()
    if "error" not in ms:
        print(f"\n  端到端度量（全局）")
        print(f"    完成帧数: {ms['frames']}")
        print(f"    平均延迟: {ms['avg_latency_ms']} ms")
        print(f"    P50: {ms['p50_ms']} ms")
        print(f"    P95: {ms['p95_ms']} ms")
        print(f"    P99: {ms['p99_ms']} ms")
        print(f"    卡顿率(>100ms): {ms['jitter_pct']}%")
        print(f"    平均 FPS: {ms['avg_fps']}")

    print(f"\n{'='*50}")
    print(f"  Done.\n")


if __name__ == "__main__":
    main()
