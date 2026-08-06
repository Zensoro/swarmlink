"""
SwarmLink Packet Header — 20 字节紧凑版
==========================================
对齐方式：大端（network byte order），缓存友好

字段排布（按字节）：
+0        +4        +8        +12       +16       +20
| session_tag | frame_id | frag_id | total_frags | flags | stream_id | frame_len | crc |
    4B          4B         2B         2B         1B       1B        4B        2B

字段说明：
- session_tag (4B) : 会话标识，DH 建邻后派生，区分不同"飞行任务"
- frame_id    (4B) : 视频帧编号，单调递增，32bit 够飞 136 年不回绕@60fps
- frag_id     (2B) : 本帧内分片序号，0~65535
- total_frags (2B) : 本帧总分片数
- flags       (1B) : 位域，见下方 FLAG_*
- stream_id   (1B) : 0=图传 1=控制 2=遥测 3=中继（预留）
- frame_len   (4B) : 原始帧真实长度（重组时裁剪分片补零），0=未知/不裁剪
- crc         (2B) : 头校验（CRC16-CCITT），快速丢弃坏包

FLAG 位域（从高位到低位）：
  bit7 : KEY_FRAME   — 关键帧（I帧），丢失则整帧不可解码，ARQ 优先
  bit6 : FEC_PARITY  — 此包是 FEC 冗余包（非数据分片）
  bit5 : LAST_FRAG   — 本帧最后一个分片（接收端可提前触发重组）
  bit4 : ARQ_REQ     — 此包是 ARQ 重传请求（不是数据）
  bit3 : ARQ_REP     — 此包是 ARQ 重传回复
  bit2 : ENCRYPTED   — 载荷已加密（P1 启用）
  bit1 : RELIABLE    — 必须可靠到达（控制流置位，图传流清零）
  bit0 : RESERVED    — 预留扩展

设计取舍：
- 不选 24B 版 → 省 8B/包，@1000 包/秒 = 省 8KB/s 带宽，解析更快
- 预留位 + flags 位域 → 后期加 relay_hop/group_id 不破协议（塞 reserved 或扩展头）
- crc 只盖头不盖载荷 → 快速失败，载荷完整性交给 FEC/加密层
"""

import struct
import zlib

# --- 常量 ---
HEADER_SIZE = 20
MAX_FRAG_ID = 0xFFFF        # 65535
MAX_FRAME_ID = 0xFFFFFFFF   # 约 42 亿
SUPPORTED_STREAMS = {
    0: "video",
    1: "control",
    2: "telemetry",
    3: "relay",
}

# --- FLAG 位 ---
FLAG_KEY_FRAME  = 0x80
FLAG_FEC_PARITY = 0x40
FLAG_LAST_FRAG  = 0x20
FLAG_ARQ_REQ    = 0x10
FLAG_ARQ_REP    = 0x08
FLAG_ENCRYPTED  = 0x04
FLAG_RELIABLE   = 0x02
FLAG_RESERVED   = 0x01

# --- 打包/解包 ---
HEADER_STRUCT = struct.Struct("!I I H H B B I")  # 18 字节（不含尾部 2B crc）


def pack_header(session_tag: int, frame_id: int, frag_id: int,
                total_frags: int, flags: int, stream_id: int,
                frame_len: int = 0) -> bytes:
    """构造 20 字节头。crc 自动从前面 18 字节算出。
    frame_len = 原始帧真实长度；默认 0（未知/不裁剪），保持向后兼容。
    """
    assert 0 <= session_tag < (1 << 32)
    assert 0 <= frame_id    < (1 << 32)
    assert 0 <= frag_id     < (1 << 16)
    assert 0 <= total_frags < (1 << 16)
    assert 0 <= flags       < (1 << 8)
    assert 0 <= stream_id   < (1 << 8)
    assert 0 <= frame_len   < (1 << 32)

    pre = HEADER_STRUCT.pack(session_tag, frame_id, frag_id,
                             total_frags, flags, stream_id, frame_len)
    crc = zlib.crc32(pre) & 0xFFFF
    return pre + struct.pack("!H", crc)


def unpack_header(data: bytes):
    """解包。crc 校验失败抛 HeaderError。返回命名元组。"""
    if len(data) < HEADER_SIZE:
        raise HeaderError(f"packet too short: {len(data)} < {HEADER_SIZE}")
    pre = data[:18]
    crc_recv = struct.unpack("!H", data[18:20])[0]
    crc_calc = zlib.crc32(pre) & 0xFFFF
    if crc_recv != crc_calc:
        raise HeaderError(f"header crc mismatch: recv={crc_recv:#x} calc={crc_calc:#x}")
    session_tag, frame_id, frag_id, total_frags, flags, stream_id, frame_len = \
        HEADER_STRUCT.unpack(pre)
    return Header(session_tag, frame_id, frag_id, total_frags,
                  flags, stream_id, frame_len, data[:HEADER_SIZE])


class Header:
    """解包后的头对象，附带若干便利方法。"""
    __slots__ = ("session_tag", "frame_id", "frag_id", "total_frags",
                 "flags", "stream_id", "frame_len", "raw")

    def __init__(self, session_tag, frame_id, frag_id, total_frags,
                 flags, stream_id, frame_len, raw: bytes):
        self.session_tag = session_tag
        self.frame_id = frame_id
        self.frag_id = frag_id
        self.total_frags = total_frags
        self.flags = flags
        self.stream_id = stream_id
        self.frame_len = frame_len
        self.raw = raw

    # --- flag 检查 ---
    def is_key_frame(self):  return bool(self.flags & FLAG_KEY_FRAME)
    def is_fec_parity(self):return bool(self.flags & FLAG_FEC_PARITY)
    def is_last_frag(self): return bool(self.flags & FLAG_LAST_FRAG)
    def is_arq_req(self):   return bool(self.flags & FLAG_ARQ_REQ)
    def is_arq_rep(self):   return bool(self.flags & FLAG_ARQ_REP)
    def is_encrypted(self): return bool(self.flags & FLAG_ENCRYPTED)
    def is_reliable(self):  return bool(self.flags & FLAG_RELIABLE)

    def stream_name(self) -> str:
        return SUPPORTED_STREAMS.get(self.stream_id, f"unknown({self.stream_id})")

    def __repr__(self):
        return (f"Hdr[sess={self.session_tag:#x} frame={self.frame_id} "
                f"frag={self.frag_id}/{self.total_frags} "
                f"stream={self.stream_name()} flags={self.flags:#x}]")


class HeaderError(Exception):
    pass


# --- 工具：构造常见 flag 组合 ---
def flags_for(stream_id: int, key_frame: bool = False,
              reliable: bool = False, encrypted: bool = False) -> int:
    f = 0
    if key_frame: f |= FLAG_KEY_FRAME
    if reliable:  f |= FLAG_RELIABLE
    if encrypted:  f |= FLAG_ENCRYPTED
    return f
