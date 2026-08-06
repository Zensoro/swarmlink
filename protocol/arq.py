"""
SwarmLink ARQ 聚合器
=====================
A 方案（当前默认）：
  多个客户端请求同一 frag → 合并成 1 次重传，广播给所有等待者
B 方案（预留接口）：
  用 client_bitmap 记录谁缺啥，只发给真正缺的客户端

架构角色：
- SkyEnd (天空端)    : 持有 ARQAggregator，收到 REQ 后合并，发 REP
- GroundEnd (地面端) : 持有 ARQClient，监听丢包，发 REQ

协议交互：
  Ground --(ARQ_REQ, frame_id, frag_id)--> Sky
  Sky 合并同 frag 的多个 REQ → 只重传 1 次 → 广播 REP
  Ground 收到 REP → 喂入 Reassembler

亮点：
- 即使 100 个眼镜同时缺第 7 片，天空端也只发 1 次
- 这就是抄 MTProto "server 聚合多 client" 的核心价值
"""

import time
import struct
from collections import defaultdict
from typing import Optional

# 兼容 `python -m pytest` 和直接 `python script.py` 两种运行方式
try:
    from .header import (
        HEADER_STRUCT, HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_ARQ_REQ, FLAG_ARQ_REP, FLAG_LAST_FRAG,
        flags_for,
    )
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from protocol.header import (
        HEADER_STRUCT, HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_ARQ_REQ, FLAG_ARQ_REP, FLAG_LAST_FRAG,
        flags_for,
    )


# --- 天空端：ARQ 聚合器 ---
class ARQAggregator:
    """
    运行在天空端（或中转站）。
    收集来自 N 个客户端的 ARQ_REQ，按 (frame_id, frag_id) 合并，
    触发一次重传（广播 REP），所有等待者共享。
    """
    def __init__(self, session_tag: int, packet_store: dict,
                 retransmit_callback=None, window_ms: int = 20):
        """
        packet_store: dict[(frame_id, frag_id)] = 原始数据包 bytes（含头）
                      由发送端在发包时填充，供重传时查表
        retransmit_callback(packet_bytes): 真正发出去的函数（由链路层注入）
        window_ms: 合并窗口，REQ 在这段时间内的同 frag 合并为一次
        """
        self.session_tag = session_tag
        self.packet_store = packet_store
        self._retransmit = retransmit_callback
        self.window_ms = window_ms

        # (frame_id, frag_id) -> [client_id, ...]
        self._pending: dict = defaultdict(list)
        self._last_flush = time.monotonic()

    def receive_request(self, packet: bytes, client_id: int):
        """天空端收到一个 ARQ_REQ 包时调用。"""
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return
        if not hdr.is_arq_req():
            return
        key = (hdr.frame_id, hdr.frag_id)
        if client_id not in self._pending[key]:
            self._pending[key].append(client_id)

        # 到达窗口就 flush
        now = time.monotonic()
        if (now - self._last_flush) * 1000 >= self.window_ms:
            self.flush()

    def flush(self):
        """把当前 pending 合并后重传，清空。"""
        if not self._pending:
            self._last_flush = time.monotonic()
            return
        for (frame_id, frag_id), clients in list(self._pending.items()):
            pkt = self.packet_store.get((frame_id, frag_id))
            if pkt is None:
                # 自己也没这片（极罕见，说明当时就丢了）→ 跳过
                continue
            # 标记为 ARQ_REP，保留原 frag 信息
            rep_header = self._make_rep_header(frame_id, frag_id, len(clients))
            rep_packet = rep_header + pkt[HEADER_SIZE:]
            if self._retransmit:
                self._retransmit(rep_packet)
        self._pending.clear()
        self._last_flush = time.monotonic()

    def _make_rep_header(self, frame_id: int, frag_id: int,
                         waiter_count: int) -> bytes:
        # 复用 pack_header，flags 置 ARQ_REP，stream_id=0
        return pack_header(
            session_tag=self.session_tag,
            frame_id=frame_id,
            frag_id=frag_id,
            total_frags=waiter_count,  # 借用 total_frags 字段捎带"等待者数"
            flags=FLAG_ARQ_REP | FLAG_LAST_FRAG,
            stream_id=0,
        )

    def stats(self) -> dict:
        """返回合并效率统计。"""
        return {
            "pending_keys": len(self._pending),
            "window_ms": self.window_ms,
        }


# --- 地面端：ARQ 客户端 ---
class ARQClient:
    """
    运行在每个眼镜/地面端。
    监听 Reassembler 的缺失，发 ARQ_REQ 给天空端。
    """
    def __init__(self, session_tag: int, client_id: int,
                 send_callback=None):
        self.session_tag = session_tag
        self.client_id = client_id
        self._send = send_callback
        # 已请求过但尚未收到回复的，避免重复请求
        self._inflight: set = set()

    def request(self, frame_id: int, frag_id: int):
        """请求重传某个分片。"""
        key = (frame_id, frag_id)
        if key in self._inflight:
            return  # 已请求过，等回复
        self._inflight.add(key)
        hdr = pack_header(
            session_tag=self.session_tag,
            frame_id=frame_id,
            frag_id=frag_id,
            total_frags=1,
            flags=FLAG_ARQ_REQ,
            stream_id=0,
        )
        # payload 携带 client_id（让天空端知道谁在要）
        payload = struct.pack("!I", self.client_id)
        if self._send:
            self._send(hdr + payload)

    def ack_received(self, frame_id: int, frag_id: int):
        """收到 REP 后调用，清除 inflight。"""
        self._inflight.discard((frame_id, frag_id))

    def on_packet(self, packet: bytes) -> Optional[bytes]:
        """收到任意包时调用，若是 REP 则提取数据返回。"""
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return None
        if hdr.is_arq_rep():
            self.ack_received(hdr.frame_id, hdr.frag_id)
            return packet[HEADER_SIZE:]
        return None


# --- B 方案预留：Client Bitmap ---
class ClientBitmap:
    """
    为 B 方案预留的位图管理。
    每个 (frame_id, frag_id) 对应一个 bit 位图，标记哪些 client 缺这片。
    天空端据此"只发给缺的人"，而不是无脑广播。
    PoC 阶段不启用，接口先留好。
    """
    def __init__(self, max_clients: int = 64):
        self.max_clients = max_clients
        self._bitmaps: dict = defaultdict(int)  # key -> int 位图

    def mark_missing(self, frame_id: int, frag_id: int, client_id: int):
        if 0 <= client_id < self.max_clients:
            self._bitmaps[(frame_id, frag_id)] |= (1 << client_id)

    def clear(self, frame_id: int, frag_id: int, client_id: int):
        self._bitmaps[(frame_id, frag_id)] &= ~(1 << client_id)

    def get_bitmap(self, frame_id: int, frag_id: int) -> int:
        return self._bitmaps.get((frame_id, frag_id), 0)

    def recipients(self, frame_id: int, frag_id: int) -> list:
        b = self.get_bitmap(frame_id, frag_id)
        return [i for i in range(self.max_clients) if (b >> i) & 1]
