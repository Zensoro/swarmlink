"""
SwarmLink v0.5 — 三级拓扑中继演示
==================================
Sky ──▶ Relay ──▶ Gnd0
              └──▶ Gnd1

演示:
  1. 天空端经中继广播分片给 2 个地面端
  2. 中继缓存最近帧 (stale-while-revalidate 数据源)
  3. 下游断连重连 → 中继立即从缓存补发旧帧
  4. 地面端缺片 REQ → 中继 → 天空端 (每跳独立 ARQ)

运行: python3 examples/relay_demo.py
"""

import sys
import os
import time
import threading
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.routing import RelayNode, ConsistentHash
from protocol.cache import StaleWhileRevalidate
from protocol.header import (
    pack_header, unpack_header, HEADER_SIZE,
)


SESSION = 0x0A05
N_FRAMES = 20


class Wire:
    """进程内链路: relay→gnd 方向, 可拔线模拟断连。"""
    def __init__(self, name):
        self.name = name
        self.queue = deque()
        self.connected = True

    def send(self, pkt):
        if self.connected:
            self.queue.append(pkt)

    def drain(self):
        out = []
        while self.queue:
            out.append(self.queue.popleft())
        return out


def main():
    print("═" * 62)
    print("  SwarmLink v0.5 — 三级拓扑中继演示")
    print("  Sky ──▶ Relay ──▶ Gnd0 / Gnd1")
    print("═" * 62)

    # --- 一致性哈希: 多中继场景演示路由 ---
    print("\n[1] 一致性哈希路由 (2 中继, 100 帧按 key 分布)")
    ring = ConsistentHash(virtual_nodes=80)
    ring.add_node("relay-1")
    ring.add_node("relay-2")
    dist = ring.key_distribution([f"frame-{i}" for i in range(100)])
    for node, cnt in sorted(dist.items()):
        print(f"    {node}: {cnt} 帧")
    # 扩容: 加第 3 个中继, 只迁移部分
    before = dict(dist)
    ring.add_node("relay-3")
    after = ring.key_distribution([f"frame-{i}" for i in range(100)])
    migrated = sum(before[n] - after.get(n, 0) for n in before
                   if after.get(n, 0) < before[n])
    print(f"    扩容后: relay-3 接管 {after['relay-3']} 帧, "
          f"原节点共迁移 {migrated} 帧 (平滑扩容)")

    # --- 三级拓扑: 转发 + 缓存 + 断连恢复 ---
    print("\n[2] 三级拓扑: 天空端 → 中继 → 2 地面端")
    relay = RelayNode("relay-1", max_hop=2)

    wire_g0 = Wire("gnd0")
    wire_g1 = Wire("gnd1")
    relay.add_downstream("gnd0", wire_g0.send)
    relay.add_downstream("gnd1", wire_g1.send)

    # 天空端直发到中继 (模拟)
    sky_packets = []
    for fid in range(N_FRAMES):
        pkt = pack_header(SESSION, fid, 0, 1, 0, 0) + \
            f"frame-{fid}-data-".encode() * 4
        sky_packets.append(pkt)

    # 地面端重组 (单分片帧, 直接收)
    g0_recv = {}
    g1_recv = {}
    for pkt in sky_packets:
        relay.forward_down(pkt)      # 天空端 → 中继 → 广播
        for p in wire_g0.drain():
            g0_recv[unpack_header(p).frame_id] = p[HEADER_SIZE:]
        for p in wire_g1.drain():
            g1_recv[unpack_header(p).frame_id] = p[HEADER_SIZE:]

    print(f"    Gnd0 收到 {len(g0_recv)}/{N_FRAMES} 帧  "
          f"Gnd1 收到 {len(g1_recv)}/{N_FRAMES} 帧")
    print(f"    中继缓存 {relay.stats()['buffer_frames']} 帧 "
          f"(供断连恢复)")

    # --- 断连恢复: stale-while-revalidate ---
    print("\n[3] Gnd1 断连 → 重连 → 中继缓存立即补发旧帧")
    # 模拟 Gnd1 断连期间, 新帧只到 Gnd0
    wire_g1.connected = False
    for fid in range(N_FRAMES, N_FRAMES + 5):
        pkt = pack_header(SESSION, fid, 0, 1, 0, 0) + b"new-data-" * 4
        relay.forward_down(pkt)
    wire_g0.drain()

    # 重连: 从缓存补发最近帧
    wire_g1.connected = True
    recovered = 0
    for fid in range(N_FRAMES + 4, N_FRAMES - 1, -1):
        if relay.serve_stale("gnd1", fid) is not None:
            recovered += 1
    for p in wire_g1.drain():
        g1_recv[unpack_header(p).frame_id] = p[HEADER_SIZE:]
    print(f"    缓存补发 {recovered} 帧, "
          f"Gnd1 总帧数 {len(g1_recv)} "
          f"(断连期间漏的 5 帧由缓存补回 {recovered} 帧)")

    # --- 每跳 ARQ: 下游 REQ 经中继到上游 ---
    print("\n[4] Gnd0 缺片 → REQ 经中继 → 天空端")
    upstream = []
    relay.connect_upstream(upstream.append)
    req = pack_header(SESSION, 3, 0, 1, 0x10, 0) + b"req-client0"
    relay.forward_up(req)
    print(f"    REQ 到达天空端: {len(upstream)} 条 (帧 3 缺片请求)")

    # --- 防环 ---
    print("\n[5] 防环: hop 超限的包被中继丢弃")
    loop_pkt = pack_header(SESSION, 99, 0, 1, 0, 0x20) + b"loop"
    relay.forward_down(loop_pkt)
    print(f"    丢弃环包: {relay.stats()['dropped_loop']} 个")

    print("\n" + "═" * 62)
    print("  ✅ v0.5 路由层演示完成")
    print("═" * 62)


if __name__ == "__main__":
    main()
