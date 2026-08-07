"""
SwarmLink v0.4 — SFU 选择性转发 (完整版)
==========================================
多副眼镜各看各的码率 (Simulcast 风格)。

核心能力:
  1. 天空端为每帧发布多个质量层 (LOW/HIGH), 各自独立分片/FEC/加密
  2. 地面端订阅某个质量层 (subscribe/unsubscribe)
  3. 天空端按订阅只发对应层 → 带宽按订阅分配 (不是无脑广播最高码率)
  4. 订阅可动态切换 (弱网时降档, 网络好时升档)

架构:
    Sky:  publish(frame_id, {LOW: data_low, HIGH: data_high})
          → 每层 Fragmenter 分片 → 加密 → 按订阅者定向 send
    Gnd:  subscribe(client_id, quality) → 只收该层的片 → 独立 Reassembler

对比现有多播 ARQ:
  - 现有: 一帧一份, 所有人收同一码率, 重传按 bitmap 选择性补片
  - SFU: 每帧多份 (按码率), 首次就按订阅定向, 重传同样按订阅
  两者可叠加: SFU 定码率 + bitmap 定补片
"""

import os
import time
import struct
from typing import Callable, Dict, Optional, List
from enum import IntEnum

try:
    from .header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_KEY_FRAME, FLAG_FEC_PARITY, FLAG_ENCRYPTED,
        FLAG_LAST_FRAG, flags_for,
    )
    from .fragment import Reassembler
    from .rs_codec import ReedSolomon
except ImportError:
    import sys, os as _os
    sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from protocol.header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_KEY_FRAME, FLAG_FEC_PARITY, FLAG_ENCRYPTED,
        FLAG_LAST_FRAG, flags_for,
    )
    from protocol.fragment import Reassembler
    from protocol.rs_codec import ReedSolomon


class Quality(IntEnum):
    """质量层。LOW=低码率(省带宽), HIGH=高码率(清晰)。"""
    LOW = 0
    HIGH = 1


# 质量层默认参数 (帧长由调用方决定, 这里只定义分片/FEC)
QUALITY_CONFIG = {
    Quality.LOW: {
        "description": "低码率 - 省带宽, 适合弱网/远距离",
    },
    Quality.HIGH: {
        "description": "高码率 - 清晰, 适合强网/近距",
    },
}


class _LayerEncoder:
    """单个质量层的分片+加密+存储 (发送侧)。"""

    def __init__(self, session_tag: int, quality: Quality,
                 chunk_size: int = 800, fec_k: int = 10, fec_n: int = 14,
                 encrypt_func: Optional[Callable] = None):
        self.session_tag = session_tag
        self.quality = quality
        self.chunk_size = chunk_size
        self.fec_k = fec_k
        self.fec_n = fec_n
        self._encrypt = encrypt_func
        self._rs = ReedSolomon()
        self._next_frame_id = 0

    def encode_frame(self, data: bytes,
                     key_frame: bool = False) -> List[bytes]:
        """分片 + (加密) → 线上包列表。每层独立 frame_id 空间。

        省带宽关键: 只发实际数据片, 不补零。
        短帧 (如 LOW 层) 只发少量片; 满 fec_k 片才加 FEC 冗余。
        """
        frame_id = self._next_frame_id
        self._next_frame_id = (self._next_frame_id + 1) & 0xFFFFFFFF

        cs = self.chunk_size
        raw = []
        for i in range(0, len(data), cs):
            c = data[i:i + cs]
            if len(c) < cs:
                c = c + b'\x00' * (cs - len(c))
            raw.append(c)
        # 超过 fec_k 片截断 (PoC 限制, 与 fragment.py 一致)
        if len(raw) > self.fec_k:
            raw = raw[:self.fec_k]

        k = len(raw)
        base_flags = FLAG_KEY_FRAME if key_frame else 0

        # FEC: 满 fec_k 片才编码 (k < fec_k 时靠 ARQ 兜底, 不补零)
        if k >= self.fec_k:
            data_group = list(raw)
            while len(data_group) < self.fec_k:
                data_group.append(b'\x00' * cs)
            encoded = self._rs.encode(data_group)  # fec_n 片
            payloads = list(encoded)
            total = len(encoded)
        else:
            payloads = list(raw)
            total = k

        packets = []
        for idx, payload in enumerate(payloads):
            f = base_flags
            if idx >= k:
                f |= FLAG_FEC_PARITY
            if idx == total - 1:
                f |= FLAG_LAST_FRAG
            if self._encrypt is not None:
                payload = self._encrypt(payload)
                f |= FLAG_ENCRYPTED
            stream_id = (int(self.quality) << 4) | 0
            hdr = pack_header(
                self.session_tag, frame_id, idx, total,
                f, stream_id, frame_len=len(data),
            )
            packets.append(hdr + payload)
        return packets


# ============================================================
# SFU 转发器 (发送侧: 天空端)
# ============================================================
class SFUForwarder:
    """
    天空端 SFU 转发器: 按订阅定向发送质量层。

    用法:
      fwd = SFUForwarder(SESSION, send_func, encrypt_func=sky_sm.encrypt_payload)
      fwd.subscribe(client_id=0, Quality.HIGH)
      fwd.subscribe(client_id=1, Quality.LOW)
      for fid in range(N):
          fwd.publish_frame(fid, {
              Quality.LOW: low_data,        # 低码率帧
              Quality.HIGH: high_data,      # 高码率帧
          })
      fwd.change_subscription(client_id=1, Quality.HIGH)  # 动态切换
    """

    def __init__(self, session_tag: int,
                 send_func: Callable,  # send_func(pkt, client_id)
                 encrypt_func: Optional[Callable] = None,
                 chunk_size: int = 800, fec_k: int = 10, fec_n: int = 14,
                 max_clients: int = 16):
        self.session_tag = session_tag
        self._send = send_func
        self._encrypt = encrypt_func
        self._chunk_size = chunk_size
        self._fec_k = fec_k
        self._fec_n = fec_n
        self._max_clients = max_clients

        self._encoders: Dict[Quality, _LayerEncoder] = {
            q: _LayerEncoder(session_tag, q, chunk_size, fec_k, fec_n,
                             encrypt_func)
            for q in Quality
        }
        # client_id -> quality
        self._subscriptions: Dict[int, Quality] = {}
        self._stats = {
            "subscribed": 0,
            "frames_published": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
            "bytes_per_quality": {int(q): 0 for q in Quality},
        }

    # ---------------- 订阅管理 ----------------
    def subscribe(self, client_id: int, quality: Quality):
        self._subscriptions[client_id] = Quality(quality)
        self._stats["subscribed"] = len(self._subscriptions)

    def unsubscribe(self, client_id: int):
        self._subscriptions.pop(client_id, None)
        self._stats["subscribed"] = len(self._subscriptions)

    def change_subscription(self, client_id: int, quality: Quality):
        """动态切换 (弱网降档 / 网络恢复升档)"""
        self.subscribe(client_id, quality)

    def subscription_of(self, client_id: int) -> Optional[Quality]:
        return self._subscriptions.get(client_id)

    # ---------------- 发布 ----------------
    def publish_frame(self, frame_id: int,
                      layers: Dict[Quality, bytes],
                      key_frame: bool = False) -> int:
        """发布一帧: 每层编码 → 按订阅定向发送。
        返回: 发送的包总数。没订阅任何层的层不发送。
        """
        packets_by_quality: Dict[int, List[bytes]] = {}
        for q, data in layers.items():
            q = Quality(q)
            packets_by_quality[int(q)] = self._encoders[q].encode_frame(
                data, key_frame=key_frame)

        # 按订阅者定向: 每个 client 收它订阅的层
        clients_by_quality: Dict[int, List[int]] = {int(q): [] for q in Quality}
        for cid, q in self._subscriptions.items():
            clients_by_quality[int(q)].append(cid)

        sent = 0
        for q_int, packets in packets_by_quality.items():
            targets = clients_by_quality.get(q_int, [])
            if not targets:
                continue  # 没订阅者 → 这层不占带宽
            for pkt in packets:
                for cid in targets:
                    self._send(pkt, cid)
                    self._stats["packets_sent"] += 1
                    self._stats["bytes_sent"] += len(pkt)
                    self._stats["bytes_per_quality"][q_int] += len(pkt)
                    sent += 1

        self._stats["frames_published"] += 1
        return sent

    # ---------------- 统计 ----------------
    def stats(self) -> dict:
        s = dict(self._stats)
        # 带宽分配占比
        total = max(1, self._stats["bytes_sent"])
        s["bandwidth_low_pct"] = round(
            self._stats["bytes_per_quality"][int(Quality.LOW)] / total * 100, 1)
        s["bandwidth_high_pct"] = round(
            self._stats["bytes_per_quality"][int(Quality.HIGH)] / total * 100, 1)
        s["subscriptions"] = {
            f"client{cid}": int(q)
            for cid, q in self._subscriptions.items()
        }
        return s


# ============================================================
# 地面端: 订阅 + 独立重组
# ============================================================
class SFUReceiver:
    """地面端: 订阅一个质量层, 用独立 Reassembler 重组该层帧。"""

    def __init__(self, session_tag: int, client_id: int,
                 quality: Quality,
                 decryptor_func: Optional[Callable] = None,
                 on_frame: Optional[Callable] = None,
                 fec_k: int = 10, fec_n: int = 14):
        self.session_tag = session_tag
        self.client_id = client_id
        self.quality = Quality(quality)
        self._decrypt = decryptor_func
        self._on_frame = on_frame
        self._reasm = Reassembler(session_tag, fec_k=fec_k, fec_n=fec_n)
        self.completed: Dict[int, bytes] = {}
        self._stats = {"pkts_in": 0, "frames_complete": 0, "bad": 0}

    def feed(self, packet: bytes) -> Optional[bytes]:
        """喂包。只处理本订阅层的片。返回完整帧或 None。"""
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return None
        if hdr.session_tag != self.session_tag:
            return None
        layer_q = (hdr.stream_id >> 4) & 0x0F
        if layer_q != int(self.quality):
            return None  # 不是本订阅层

        # 解密
        payload = packet[HEADER_SIZE:]
        if hdr.is_encrypted() and self._decrypt is not None:
            plain = self._decrypt(payload)
            if plain is None:
                self._stats["bad"] += 1
                return None
            payload = plain
        else:
            # 去掉 ENCRYPTED 位, 让重组器当普通分片
            pass

        # 重建干净头 (去掉 ENCRYPTED)
        clean_flags = hdr.flags & ~FLAG_ENCRYPTED
        clean = pack_header(
            self.session_tag, hdr.frame_id, hdr.frag_id, hdr.total_frags,
            clean_flags, hdr.stream_id, frame_len=hdr.frame_len,
        )
        pkt = clean + payload
        self._stats["pkts_in"] += 1

        result = self._reasm.feed(pkt)
        if result is not None:
            self._stats["frames_complete"] += 1
            self.completed[hdr.frame_id] = result
            if self._on_frame:
                self._on_frame(self.client_id, hdr.frame_id, result)
            return result
        return None

    def stats(self) -> dict:
        return dict(self._stats)
