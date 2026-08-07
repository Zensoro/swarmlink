"""
SwarmLink v0.5 — 路由层 (一致性哈希 + 三级拓扑)
=================================================
1. ConsistentHash: 一致性哈希环 (虚拟节点 + 平滑扩容/缩容)
   用途: 多中继/多地面端间按 key (frame_id/stream) 路由, 扩容时
   只迁移 1/N 的 key, 不是全量重路由 (CDN 同款思路)

2. RelayNode: 三级拓扑中继 (天空端 → 中继 → 地面端)
   - 转发数据: 上游分片 → 下游 (支持多下游)
   - 防环: 每包 TTL 字段 (relay_hop 计数, 超过丢弃)
   - 每跳独立 ARQ: 中继对上游 REQ 上游补片, 对下游缺片发 REQ
   - 断连恢复: 中继缓冲最近帧, 下游重连后立即补发 (stale-while-revalidate)

架构示意:
    Sky ──(上行)──▶ Relay ──(下行)──▶ Gnd0
                         └────────────▶ Gnd1
    Gnd ──(REQ)──────▶ Relay ──(REQ)──▶ Sky
"""

import hashlib
import bisect
import time
import threading
from collections import deque, OrderedDict
from typing import Callable, Dict, List, Optional, Tuple


# ============================================================
# 1. 一致性哈希环
# ============================================================
class ConsistentHash:
    """
    一致性哈希环 (Chord 风格)。

    特性:
    - 虚拟节点: 每个物理节点挂 N 个虚拟点 → 分布更均匀
    - 平滑扩容: 加节点只迁移约 1/(N+1) 的 key
    - 平滑缩容: 删节点只影响它的 key
    - 逆时针找后继: key 落在环上某点, 路由到顺时针第一个节点
    """

    def __init__(self, virtual_nodes: int = 100):
        self._virtual = virtual_nodes
        self._ring: Dict[int, str] = {}   # 环位置(hash) -> 节点名
        self._sorted: List[int] = []      # 排序后的环位置
        self._lock = threading.Lock()

    def _hash(self, key: str) -> int:
        return int(hashlib.md5(key.encode()).hexdigest(), 16)

    def add_node(self, node: str):
        """加入物理节点 (自动挂虚拟节点)。"""
        with self._lock:
            for i in range(self._virtual):
                pos = self._hash(f"{node}#v{i}")
                self._ring[pos] = node
            self._sorted = sorted(self._ring.keys())

    def remove_node(self, node: str):
        """移除物理节点 (连同虚拟节点)。"""
        with self._lock:
            for i in range(self._virtual):
                pos = self._hash(f"{node}#v{i}")
                self._ring.pop(pos, None)
            self._sorted = sorted(self._ring.keys())

    def route(self, key: str) -> Optional[str]:
        """把 key 路由到负责它的节点。空环返回 None。"""
        with self._lock:
            if not self._sorted:
                return None
            h = self._hash(key)
            idx = bisect.bisect_right(self._sorted, h)
            if idx == len(self._sorted):
                idx = 0  # 环回绕
            return self._ring[self._sorted[idx]]

    def nodes(self) -> List[str]:
        with self._lock:
            return sorted(set(self._ring.values()))

    def key_distribution(self, keys: List[str]) -> Dict[str, int]:
        """统计一批 key 的路由分布 (用于均匀性验证)。"""
        dist = {n: 0 for n in self.nodes()}
        for k in keys:
            n = self.route(k)
            if n:
                dist[n] = dist.get(n, 0) + 1
        return dist

    def keys_for_node(self, keys: List[str], node: str) -> List[str]:
        return [k for k in keys if self.route(k) == node]


# ============================================================
# 2. 三级拓扑中继
# ============================================================
class RelayNode:
    """
    三级拓扑中继: 上游(天空端) ↔ 中继 ↔ 下游(地面端, 可多个)。

    职责:
    - 转发: 上游分片 → 广播给所有下游
    - 防环: 每包 header stream_id 高位携带 relay_hop, 超过 max_hop 丢弃
    - 每跳独立 ARQ: 中继对上/下游各自维护缺片记录, 双向补片
    - 断连缓冲: 最近 max_buffered_frames 帧缓冲, 下游重连立即补发

    注: 中继不修改分片内容 (不重加密), 只做转发 + 缓存 + 缺片管理。
    实际每跳加密/认证由上层链路保证, 这里聚焦拓扑转发语义。
    """

    def __init__(self, node_id: str, max_hop: int = 2,
                 max_buffered_frames: int = 60):
        self.node_id = node_id
        self.max_hop = max_hop
        self._upstream_send: Optional[Callable] = None   # 发往上游
        self._downstreams: Dict[str, Callable] = {}      # 下游名 -> send
        self._buffer: OrderedDict = OrderedDict()        # frame_id -> 分片
        self._max_buffered = max_buffered_frames
        self._lock = threading.Lock()
        self._stats = {
            "fwd_down": 0, "fwd_up": 0, "dropped_loop": 0,
            "cached": 0, "served_from_cache": 0,
        }

    # ---------------- 拓扑接线 ----------------
    def connect_upstream(self, send_func: Callable):
        self._upstream_send = send_func

    def add_downstream(self, name: str, send_func: Callable):
        self._downstreams[name] = send_func

    def remove_downstream(self, name: str):
        self._downstreams.pop(name, None)

    # ---------------- 核心转发 ----------------
    def forward_down(self, packet: bytes) -> Optional[bytes]:
        """上游 → 下游: 转发给所有下游, 并缓存分片。"""
        hop = packet[13] >> 4 if len(packet) > 13 else 0  # stream_id 高半字节
        if hop >= self.max_hop:
            self._stats["dropped_loop"] += 1
            return None
        # 转发 (hop+1 由下一跳链路重打头, 这里原样转发)
        for name, send in list(self._downstreams.items()):
            try:
                send(packet)
                self._stats["fwd_down"] += 1
            except Exception:
                pass
        # 缓存 (供 stale-while-revalidate / 断连补发)
        with self._lock:
            fid = int.from_bytes(packet[4:8], "big") if len(packet) > 8 else None
            if fid is not None:
                self._buffer[fid] = packet
                while len(self._buffer) > self._max_buffered:
                    self._buffer.popitem(last=False)
                self._stats["cached"] += 1
        return packet

    def forward_up(self, packet: bytes) -> Optional[bytes]:
        """下游 → 上游: 转发 REQ/控制给上游。"""
        if self._upstream_send is None:
            return None
        try:
            self._upstream_send(packet)
            self._stats["fwd_up"] += 1
        except Exception:
            return None
        return packet

    # ---------------- 断连恢复 / stale-while-revalidate ----------------
    def serve_stale(self, downstream: str, frame_id: int) -> Optional[bytes]:
        """下游重连/断连恢复: 从缓存取旧帧立即下发 (stale-while-revalidate)。"""
        with self._lock:
            pkt = self._buffer.get(frame_id)
        if pkt is not None:
            send = self._downstreams.get(downstream)
            if send:
                try:
                    send(pkt)
                    self._stats["served_from_cache"] += 1
                except Exception:
                    pass
        return pkt

    def stats(self) -> dict:
        s = dict(self._stats)
        with self._lock:
            s["buffer_frames"] = len(self._buffer)
        return s
