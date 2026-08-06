"""
SwarmLink 弱网模拟 + 性能度量
================================
WeakNetSimulator: 模拟丢包、延迟、抖动、断连（地狱档）
MetricsCollector: 收集 PSNR/延迟/卡顿率/重传开销，最后出图
"""

import time
import random
import heapq
import threading
from collections import deque
from typing import Optional


# --- 弱网模拟器 ---
class WeakNetSimulator:
    """
    包一个 send/recv 对，中间插入：
    - 丢包（固定概率 + 突发）
    - 延迟（基础 + 抖动）
    - 断连（一段时间完全不通）

    用法：
        net = WeakNetSimulator(loss_rate=0.30, delay_ms=50, jitter_ms=20,
                              blackout_ms=2000, blackout_prob=0.001)
        net.send(packet)              # 发送端调用
        packet = net.recv()           # 接收端轮询
    """
    def __init__(self, loss_rate: float = 0.15, delay_ms: float = 30,
                 jitter_ms: float = 10, blackout_ms: int = 2000,
                 blackout_prob: float = 0.0, seed: int = 42):
        self.loss_rate = loss_rate
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
        self.blackout_ms = blackout_ms
        self.blackout_prob = blackout_prob
        self.rng = random.Random(seed)

        self._queue = []  # 堆：(deliver_time, seq, packet)
        self._seq = 0     # 单调序号，避免 bytes 参与堆比较
        self._blackout_until = 0.0
        self._now = time.monotonic
        # send() 由应用线程调用、recv() 由 UDP 泵线程调用 → 必须加锁
        self._lock = threading.Lock()

        # 统计
        self.packets_in = 0
        self.packets_out = 0
        self.packets_lost = 0
        self.blackouts_triggered = 0

    def send(self, packet: bytes):
        with self._lock:
            self.packets_in += 1
            # 1) 断连期间：全丢
            if self._now() < self._blackout_until:
                self.packets_lost += 1
                return
            # 2) 概率触发断连
            if self.blackout_prob > 0 and self.rng.random() < self.blackout_prob:
                self._blackout_until = self._now() + self.blackout_ms / 1000
                self.blackouts_triggered += 1
                self.packets_lost += 1
                return
            # 3) 普通丢包
            if self.rng.random() < self.loss_rate:
                self.packets_lost += 1
                return
            # 4) 延迟 + 抖动
            d = self.delay_ms + self.rng.uniform(-self.jitter_ms, self.jitter_ms)
            deliver_at = self._now() + max(0, d) / 1000
            self._seq += 1
            heapq.heappush(self._queue, (deliver_at, self._seq, packet))

    def recv(self, timeout_ms: int = 0) -> Optional[bytes]:
        """取出一个已到时间的包。timeout_ms=0 表示非阻塞。"""
        now = self._now()
        deadline = now + timeout_ms / 1000
        while True:
            with self._lock:
                if not self._queue:
                    break
                deliver_at = self._queue[0][0]
                if deliver_at <= now:
                    _, _, packet = heapq.heappop(self._queue)
                    self.packets_out += 1
                    return packet
            if timeout_ms <= 0 or deliver_at > deadline:
                break
            # 还没到时间
            time.sleep(min(0.001, max(0.0, (deliver_at - now) / 2)))
            now = self._now()
        return None

    def drain(self) -> list:
        """取出所有已到时间的包。"""
        out = []
        while True:
            p = self.recv()
            if p is None:
                break
            out.append(p)
        return out

    def stats(self) -> dict:
        with self._lock:
            return {
                "packets_in": self.packets_in,
                "packets_out": self.packets_out,
                "packets_lost": self.packets_lost,
                "loss_pct": (self.packets_lost / max(1, self.packets_in)) * 100,
                "queued": len(self._queue),
                "blackouts": self.blackouts_triggered,
            }


# --- 性能度量 ---
class MetricsCollector:
    """
    收集端到端指标：
    - 帧延迟（从发送到收齐）
    - 卡顿率（延迟 > 阈值的比例）
    - 重传开销（重传包数 / 总包数）
    - PSNR（需要原始帧 vs 接收帧，可选）
    """
    def __init__(self, jitter_threshold_ms: float = 100):
        self.jitter_threshold = jitter_threshold_ms
        self._frame_send_time: dict = {}
        self._frame_complete_time: dict = {}
        self._frame_sizes: dict = {}
        self._retransmits = 0
        self._total_packets = 0
        self._fps_samples = deque(maxlen=300)

    def mark_send(self, frame_id: int, packet_count: int, timestamp: float = None):
        self._frame_send_time[frame_id] = timestamp or time.monotonic()
        self._total_packets += packet_count

    def mark_complete(self, frame_id: int, timestamp: float = None):
        t = timestamp or time.monotonic()
        if frame_id in self._frame_send_time:
            self._frame_complete_time[frame_id] = t
            # FPS 采样
            if len(self._frame_complete_time) >= 2:
                prev_id = frame_id - 1
                if prev_id in self._frame_complete_time:
                    dt = (self._frame_complete_time[frame_id]
                          - self._frame_complete_time[prev_id])
                    if dt > 0:
                        self._fps_samples.append(1.0 / dt)

    def mark_retransmit(self, count: int = 1):
        self._retransmits += count

    def frame_latency_ms(self, frame_id) -> Optional[float]:
        if frame_id in self._frame_complete_time and frame_id in self._frame_send_time:
            return (self._frame_complete_time[frame_id]
                    - self._frame_send_time[frame_id]) * 1000
        return None

    def summary(self) -> dict:
        latencies = [
            (self._frame_complete_time[f] - self._frame_send_time[f]) * 1000
            for f in self._frame_complete_time if f in self._frame_send_time
        ]
        if not latencies:
            return {"error": "no completed frames"}
        latencies.sort()
        n = len(latencies)
        avg = sum(latencies) / n
        p50 = latencies[n // 2]
        p95 = latencies[int(n * 0.95)]
        p99 = latencies[int(n * 0.99)]
        jittered = sum(1 for l in latencies if l > self.jitter_threshold)
        fps = (sum(self._fps_samples) / len(self._fps_samples)
               if self._fps_samples else 0)
        return {
            "frames": n,
            "avg_latency_ms": round(avg, 1),
            "p50_ms": round(p50, 1),
            "p95_ms": round(p95, 1),
            "p99_ms": round(p99, 1),
            "jitter_pct": round(jittered / n * 100, 1),
            "retransmit_pct": round(self._retransmits / max(1, self._total_packets) * 100, 1),
            "avg_fps": round(fps, 1),
        }


# --- tc netem 脚本生成 ---
TC_SCRIPT = """#!/bin/bash
# SwarmLink 弱网模拟脚本（需 root）
# 用法: sudo ./tc_qdisc_setup.sh [loss] [delay_ms] [jitter_ms]
LOSS=${1:-30%}
DELAY=${2:-50ms}
JITTER=${3:-20ms}
IFACE=${4:-lo}

echo "Setting netem on $IFACE: loss=$LOSS delay=$DELAY ±$JITTER"
tc qdisc del dev $IFACE root 2>/dev/null
tc qdisc add dev $IFACE root netem loss $LOSS $JITTER delay $DELAY $JITTER
tc qdisc show dev $IFACE
"""

if __name__ == "__main__":
    # 自测：地狱档跑 1000 个包
    net = WeakNetSimulator(loss_rate=0.35, delay_ms=50, jitter_ms=25,
                          blackout_ms=2000, blackout_prob=0.005, seed=7)
    for i in range(1000):
        net.send(f"packet-{i}".encode())
    time.sleep(0.5)
    drained = net.drain()
    s = net.stats()
    print(f"drained={len(drained)} stats={s}")
