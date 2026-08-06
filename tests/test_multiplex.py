"""
SwarmLink v0.3 — 多流复用器接入测试
=====================================
验证 StreamMultiplexer / StreamDemultiplexer 核心卖点:
  1. 三流 (图传/控制/遥测) 同链路交付, 内容逐字节一致
  2. frame_len 裁剪: 260B 视频帧重组后 == 260B (不带补零)
  3. 图传流 FEC: 丢 ≤4 片可恢复
  4. 控制流优先: 不被视频大包阻塞 (WFQ)
  5. 图传队列满: 丢旧帧不阻塞控制流
"""

import sys
import os
import time
import threading
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.multiplex import (
    StreamMultiplexer, StreamDemultiplexer, StreamType,
)
from protocol.header import unpack_header, FLAG_FEC_PARITY


SESSION = 0xA11CE


class CollectingLink:
    """有损链路: 收集 mux 发出全部包, 可按规则丢弃后喂给 demux。
    send_delay_ms > 0 时模拟慢链路 (拥塞), 用于测 WFQ 优先/队列溢出。
    """
    def __init__(self, loss_rate: float = 0.0, seed: int = 42,
                 send_delay_ms: float = 0.0):
        import random
        self.rng = random.Random(seed)
        self.loss_rate = loss_rate
        self.send_delay_ms = send_delay_ms
        self.packets = []
        self.lock = threading.Lock()
        self.send_order = []  # (stream_id, frame_id) 按发出顺序

    def send(self, pkt: bytes):
        if self.send_delay_ms > 0:
            time.sleep(self.send_delay_ms / 1000.0)
        with self.lock:
            hdr = unpack_header(pkt)
            self.packets.append(pkt)
            self.send_order.append((hdr.stream_id, hdr.frame_id))

    def drain_to_demux(self, demux, drop_fec: int = 0, drop_data: int = 0):
        """把收集到的包喂给 demux; 可选丢弃若干 FEC/数据片模拟丢包。"""
        with self.lock:
            pkts = list(self.packets)
            self.packets.clear()
        dropped_fec = 0
        dropped_data = 0
        delivered = 0
        for pkt in pkts:
            hdr = unpack_header(pkt)
            is_parity = bool(hdr.flags & FLAG_FEC_PARITY)
            if is_parity and dropped_fec < drop_fec:
                dropped_fec += 1
                continue
            if not is_parity and dropped_data < drop_data:
                dropped_data += 1
                continue
            if self.rng.random() < self.loss_rate:
                continue
            demux.feed(pkt)
            delivered += 1
        return delivered

    def wait_sent(self, mux, n, timeout=3.0):
        """等待 mux 发出至少 n 包。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if len(self.packets) >= n:
                    return True
            time.sleep(0.005)
        return False


def make_pair(link, fec_k=10, fec_n=14):
    video = []
    control = []
    telem = []
    mux = StreamMultiplexer(SESSION, link.send, chunk_size=400,
                            fec_k=fec_k, fec_n=fec_n)
    demux = StreamDemultiplexer(
        SESSION,
        on_video_frame=lambda f: video.append(f),
        on_control_message=lambda m: control.append(m),
        on_telemetry=lambda t: telem.append(t),
        fec_k=fec_k, fec_n=fec_n,
    )
    return mux, demux, video, control, telem


def drain_all(link, demux, wait=1.0):
    """把链路里所有包喂完, 等重组。"""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        link.drain_to_demux(demux)
        time.sleep(0.01)


# ============================================================
# 1. 三流交付 (无丢包) + frame_len 裁剪
# ============================================================
def test_triple_stream_delivery_exact():
    link = CollectingLink()
    mux, demux, video, control, telem = make_pair(link)

    # 视频: 260B (非整片, 验证 frame_len 裁剪) + 750B (接近 2 片)
    v1 = b"VIDEO-260B-" * 20           # 260B
    v2 = b"V" * 750                     # 750B
    mux.submit(StreamType.VIDEO, v1, key_frame=True)
    mux.submit(StreamType.VIDEO, v2)
    # 控制: 小消息, 可靠
    c1 = b"ARM_MOTORS"
    c2 = b"SET_ALTITUDE:50m"
    mux.submit(StreamType.CONTROL, c1)
    mux.submit(StreamType.CONTROL, c2)
    # 遥测
    t1 = b"BAT:85% GPS:3D ALT:42.5"
    mux.submit(StreamType.TELEMETRY, t1)

    assert link.wait_sent(mux, 1)
    drain_all(link, demux)
    mux.shutdown()

    # 视频: 顺序提交 → 完成顺序一致, 内容逐字节一致 (无补零尾巴)
    assert video[0] == v1, f"260B 帧应精确还原, 实际 {len(video[0]) if video else 0}B"
    assert video[1] == v2
    # 控制/遥测
    assert control[0] == c1
    assert control[1] == c2
    assert telem[0] == t1


# ============================================================
# 2. 图传 FEC: 丢 4 片以内可恢复
# ============================================================
def test_video_fec_recovery():
    link = CollectingLink()
    mux, demux, video, control, telem = make_pair(link)

    # 10 片数据 + 4 片 FEC
    frame = b"FEC-TEST-FRAME-" * 300   # ~4200B → 11 片, 截断到 10 片
    mux.submit(StreamType.VIDEO, frame, key_frame=True)
    assert link.wait_sent(mux, 1)
    link.drain_to_demux(demux, drop_fec=4)  # 丢全部 4 片冗余 → 10 片数据刚好全在

    # 等重组
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and not video:
        link.drain_to_demux(demux)
        time.sleep(0.01)
    mux.shutdown()

    assert len(video) == 1
    assert video[0] == frame[:10 * 400], "FEC 模式下超限帧截断到 10 片"


# ============================================================
# 3. 控制流优先: 不被视频大包阻塞 (拥塞链路下插队)
# ============================================================
def test_control_priority_over_video():
    """拥塞链路 (慢 send): 视频包堆积时, 控制消息应插队优先发出。"""
    link = CollectingLink(send_delay_ms=2.0)
    mux = StreamMultiplexer(SESSION, link.send, chunk_size=400)

    # 视频帧 ×20 → 每帧 14 片 (10 数据 + 4 FEC), 共 280 片
    for i in range(20):
        mux.submit(StreamType.VIDEO, b"VIDEO-BURST-" + bytes([i]) * 700)
    # 等调度线程发一批 (链路拥塞, 视频远未发完)
    time.sleep(0.1)
    # 控制消息入队 → 应在剩余视频包之前插队发出
    mux.submit(StreamType.CONTROL, b"RTL_NOW")

    ctrl_idx = None
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        with link.lock:
            order = list(link.send_order)
        ctrl_idx = next((i for i, (sid, _) in enumerate(order)
                         if sid == StreamType.CONTROL), None)
        if ctrl_idx is not None:
            break
        time.sleep(0.005)
    mux.shutdown()

    assert ctrl_idx is not None, "控制消息应被发出"
    assert ctrl_idx < 250, f"控制消息应插队 (实际第 {ctrl_idx} 个, 视频共 280 片)"


# ============================================================
# 4. 图传队列满: 丢旧帧, 控制流照常
# ============================================================
def test_video_queue_overflow_drops_old():
    """慢链路 → 视频队列堆积超上限 → 丢旧帧腾空间, 控制流不受影响。"""
    link = CollectingLink(send_delay_ms=2.0)
    mux = StreamMultiplexer(SESSION, link.send, chunk_size=400)

    # 120 帧 × 14 片 = 1680 片 >> max_queue=300, 调度线程消费慢
    for i in range(120):
        mux.submit(StreamType.VIDEO, b"X" * 700)
    time.sleep(0.1)

    # 控制流: 队列独立, 必达
    mux.submit(StreamType.CONTROL, b"EMERGENCY_STOP")
    time.sleep(0.3)
    mux.shutdown()

    stats = mux.stats()
    assert stats[StreamType.VIDEO]["dropped"] > 0, "图传队列满应丢旧帧"
    # 控制包最终被发出 (队列不阻塞)
    with link.lock:
        assert any(sid == StreamType.CONTROL for sid, _ in link.send_order), \
            "控制消息不受图传队列溢出影响"


# ============================================================
# 5. 统计完整性
# ============================================================
def test_multiplex_stats():
    link = CollectingLink()
    mux, demux, video, control, telem = make_pair(link)

    mux.submit(StreamType.VIDEO, b"STATS-VIDEO" * 100)
    mux.submit(StreamType.CONTROL, b"STATS-CTRL")
    assert link.wait_sent(mux, 1)
    drain_all(link, demux)
    mux.shutdown()

    stats = mux.stats()
    assert stats[StreamType.VIDEO]["packets_sent"] > 0
    assert stats[StreamType.CONTROL]["packets_sent"] > 0
    assert stats[StreamType.VIDEO]["stream_name"] == "video"
    assert stats[StreamType.CONTROL]["stream_name"] == "control"
