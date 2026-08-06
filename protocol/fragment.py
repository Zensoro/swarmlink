"""
SwarmLink 分片器 / 重组器 / FEC 引擎
=====================================
- Fragmenter : 把一帧视频切成 N 个 MTU 友好的分片，附 16B 头
- Reassembler: 收齐分片后拼回完整帧；FEC 缺失时先用冗余包修复
- FEC        : Reed-Solomon(10,14) — 10 数据 + 4 冗余，丢 4 片以内可恢复
               实现见 rs_codec.py（GF(256) 矩阵求逆，任意 erasure 模式可用）

设计要点：
- 分片大小固定（默认 800B 载荷 + 16B 头 = 816B，留 Ethernet 余量）
- 关键帧（I帧）自动标记 KEY_FRAME flag，ARQ 优先级更高
- FEC 冗余包单独发送，带 FLAG_FEC_PARITY
"""

import os
import struct
from collections import deque
from typing import List, Optional

try:
    from .header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_KEY_FRAME, FLAG_FEC_PARITY, FLAG_LAST_FRAG,
        flags_for,
    )
    from .rs_codec import ReedSolomon
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from protocol.header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_KEY_FRAME, FLAG_FEC_PARITY, FLAG_LAST_FRAG,
        flags_for,
    )
    from protocol.rs_codec import ReedSolomon


# --- 分片器 ---
class Fragmenter:
    """把一帧数据切成 (data_chunks + fec_parity_chunks)，每个带 16B 头。"""
    def __init__(self, session_tag: int, chunk_size: int = 800,
                 fec_k: int = 10, fec_n: int = 14):
        self.session_tag = session_tag
        self.chunk_size = chunk_size
        self.fec_k = fec_k
        self.fec_n = fec_n
        self._rs = ReedSolomon()
        self._next_frame_id = 0

    def fragment(self, frame_data: bytes, stream_id: int = 0,
                 key_frame: bool = False) -> List[bytes]:
        """输入一帧完整数据 → 返回打好头的包列表（数据片 + FEC 冗余片）。"""
        frame_id = self._next_frame_id
        self._next_frame_id = (self._next_frame_id + 1) & 0xFFFFFFFF

        cs = self.chunk_size

        # 1) 切成等长 K 片（超过 K 截断，PoC 单帧 ≤ K*cs）
        raw = []
        for i in range(0, len(frame_data), cs):
            raw.append(frame_data[i:i + cs])
        if len(raw) > self.fec_k:
            raw = raw[:self.fec_k]

        # 2) 统一补零到 cs 字节
        data_group = []
        for c in raw:
            if len(c) < cs:
                c = c + b'\x00' * (cs - len(c))
            data_group.append(c)
        while len(data_group) < self.fec_k:
            data_group.append(b'\x00' * cs)

        # 3) RS 编码 → N 片
        encoded = self._rs.encode(data_group)
        total_frags = len(encoded)

        # 4) 打 20B 头（frame_len 携带原始帧真实长度，重组端裁剪补零）
        packets = []
        base_flags = flags_for(stream_id, key_frame=key_frame)
        for idx, payload in enumerate(encoded):
            flags = base_flags
            if idx >= self.fec_k:
                flags |= FLAG_FEC_PARITY
            if idx == total_frags - 1:
                flags |= FLAG_LAST_FRAG
            hdr = pack_header(self.session_tag, frame_id, idx,
                              total_frags, flags, stream_id,
                              frame_len=len(frame_data))
            packets.append(hdr + payload)
        return packets


# --- 重组器 ---
class Reassembler:
    """接收分片，FEC 修复缺失，拼回完整帧。"""
    def __init__(self, session_tag: int, fec_k: int = 10, fec_n: int = 14):
        self.session_tag = session_tag
        self.fec_k = fec_k
        self.fec_n = fec_n
        self._rs = ReedSolomon()
        # frame_id -> {frag_id: payload_bytes}
        self._buffers: dict = {}
        self._completed: dict = {}
        # frame_id -> 原始帧真实长度（用于裁剪分片补零）
        self._frame_lens: dict = {}
        # 已经交付过的 frame_id（防止重传分片让同一帧二次完成 + buffer 泄漏）
        self._done: set = set()
        self._done_order: deque = deque()
        self._done_max = 512

    def feed(self, packet: bytes) -> Optional[bytes]:
        """喂入一个包。返回完整帧 bytes（刚收齐时），否则 None。

        注意：ARQ_REP 携带的是真实分片数据，必须允许进入重组器。
        只有 ARQ_REQ（纯控制包，payload 是 client_id）才丢弃。
        """
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return None
        if hdr.session_tag != self.session_tag:
            return None
        if hdr.is_arq_req():
            return None

        frame_id = hdr.frame_id
        if frame_id in self._done:
            return None  # 已交付，迟到的重传片直接丢弃

        buf = self._buffers.setdefault(frame_id, {})
        payload = packet[HEADER_SIZE:]
        buf[hdr.frag_id] = payload
        # 记录原始帧长（任一非零分片即可，重传片同理）
        if hdr.frame_len > 0:
            self._frame_lens[frame_id] = hdr.frame_len

        # 计数数据片（frag_id < fec_k）
        data_count = sum(1 for k in buf if isinstance(k, int) and k < self.fec_k)
        total_count = sum(1 for k in buf if isinstance(k, int))

        # 情况 A：所有"数据分片"都到齐 → 直接拼
        # 判断"应有多少数据片": 看 LAST_FRAG 标记或 total_frags
        expected_data = self._expected_data_count(frame_id, hdr)
        if expected_data > 0 and data_count >= expected_data:
            return self._finalize(frame_id)

        # 情况 B：总片数够 FEC 修复
        if total_count >= self.fec_k:
            try:
                return self._finalize_with_fec(frame_id)
            except Exception:
                pass
        return None

    def _expected_data_count(self, frame_id, hint_hdr) -> int:
        """推断本帧应有几个数据分片。
        优先用 hint_hdr.total_frags (非 FEC 包数),
        否则用当前 buffer 中非 FEC 分片数 + 缺失数。
        """
        # 用 header 的 total_frags: 如果 fec_n > fec_k, total_frags 可能 = fec_n
        # 简单策略: 数据片 = total_frags 中 frag_id < fec_k 的个数
        # 这里用 hint: 如果已知 total_frags <= fec_k → 就是 total_frags
        tf = hint_hdr.total_frags
        if tf <= self.fec_k:
            return tf
        # total_frags > fec_k (含 FEC), 数据片数 = fec_k
        return self.fec_k

    def _finalize(self, frame_id) -> bytes:
        buf = self._buffers[frame_id]
        ordered = []
        for i in range(self.fec_k):
            if i in buf:
                ordered.append(buf[i])
            else:
                # 数据片齐了理论上不会到这里，保险补零
                ordered.append(b'\x00' * 16)
        frame = b''.join(ordered)
        frame = self._trim(frame_id, frame)
        self._cleanup(frame_id)
        self._completed[frame_id] = frame
        return frame

    def _finalize_with_fec(self, frame_id) -> bytes:
        buf = self._buffers[frame_id]
        chunks: List[Optional[bytes]] = []
        for i in range(self.fec_n):
            chunks.append(buf.get(i))  # None if missing
        erasures = [i for i, c in enumerate(chunks) if c is None]
        recovered = self._rs.decode(chunks, erasures)
        frame = b''.join(recovered[:self.fec_k])
        frame = self._trim(frame_id, frame)
        self._cleanup(frame_id)
        self._completed[frame_id] = frame
        return frame

    def _trim(self, frame_id: int, frame: bytes) -> bytes:
        """按头部携带的真实帧长裁剪分片补零。未知(0)时保持原样。"""
        fl = self._frame_lens.get(frame_id, 0)
        if fl > 0 and len(frame) > fl:
            return frame[:fl]
        return frame

    def _cleanup(self, frame_id):
        self._buffers.pop(frame_id, None)
        self._frame_lens.pop(frame_id, None)
        if frame_id not in self._done:
            self._done.add(frame_id)
            self._done_order.append(frame_id)
            while len(self._done_order) > self._done_max:
                self._done.discard(self._done_order.popleft())

    def drop_frame(self, frame_id):
        """上层放弃该帧（超时/重试耗尽）时调用，释放 buffer。"""
        self._buffers.pop(frame_id, None)
        self._frame_lens.pop(frame_id, None)

    def pending_frames(self) -> dict:
        """返回 {frame_id: 已收分片数}，供丢失检测/调试。"""
        return {fid: len(b) for fid, b in self._buffers.items()}

    def has_frame(self, frame_id) -> bool:
        return frame_id in self._completed

    def get_frame(self, frame_id) -> Optional[bytes]:
        return self._completed.pop(frame_id, None)
