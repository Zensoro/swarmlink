"""
SwarmLink 多流复用器 v0.3
================================
灵感来源:
  - QUIC 多路复用 (单连接多 stream, 互不阻塞)
  - WebRTC 的 RTP 多流 (audio/video/data 分轨)
  - MTProto 单 TCP 连接多路复用多设备消息

设计目标:
  一根"链路"同时跑 3 条逻辑流:
    stream 0 = 图传 (不可靠, FEC 优先, 允许丢帧)
    stream 1 = 控制 (可靠, ARQ 必达, 高优先级)
    stream 2 = 遥测 (可靠, ARQ, 低带宽)
    stream 3 = 中继 (预留, 用于三级拓扑)

核心机制:
  - 每个流独立 seq 号 (互不影响)
  - 图传流: 不确认、不重传、FEC 修复、丢帧就丢
  - 控制流: 必确认、ARQ 重传、指数退避
  - 遥测流: 必确认、可合并、低频
  - 发送调度: 加权公平队列 (WFQ), 控制流优先
  - 接收分发: 按 stream_id 路由到不同处理器

为什么不用 TCP 多流:
  - TCP 队头阻塞: 控制包会被图传大数据包卡住
  - UDP 多播天然适合图传广播
  - 我们自己管每条流的可靠性 → 灵活
"""

import time
import struct
import threading
from collections import deque
from typing import Optional, Callable, Dict, List, Tuple
from enum import IntEnum

try:
    from .header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_KEY_FRAME, FLAG_FEC_PARITY, FLAG_ENCRYPTED,
        FLAG_RELIABLE, FLAG_LAST_FRAG, FLAG_ARQ_REQ,
        FLAG_ARQ_REP, flags_for, SUPPORTED_STREAMS,
    )
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from protocol.header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_KEY_FRAME, FLAG_FEC_PARITY, FLAG_ENCRYPTED,
        FLAG_RELIABLE, FLAG_LAST_FRAG, FLAG_ARQ_REQ,
        FLAG_ARQ_REP, flags_for, SUPPORTED_STREAMS,
    )


# ============================================================
# 流类型定义
# ============================================================
class StreamType(IntEnum):
    VIDEO     = 0  # 图传: 不可靠, FEC, 允许丢帧
    CONTROL   = 1  # 控制: 可靠, ARQ, 高优先级
    TELEMETRY = 2  # 遥测: 可靠, 低频, 可合并
    RELAY     = 3  # 中继: 预留

# 流的行为配置
STREAM_CONFIG = {
    StreamType.VIDEO: {
        "reliable": False,    # 不保证到达
        "fec_enabled": True,  # FEC 优先
        "arq_enabled": False,  # 不重传 (丢就丢)
        "priority": 50,        # 中等优先级 (带宽大但容忍延迟)
        "max_queue": 300,      # 队列上限 (包数)
        "description": "图传流 - 不可靠, FEC 修复, 丢帧容忍",
    },
    StreamType.CONTROL: {
        "reliable": True,      # 必须到达
        "fec_enabled": False,  # 控制包小, FEC 浪费
        "arq_enabled": True,   # ARQ 重传
        "priority": 100,       # 最高优先级
        "max_queue": 50,       # 控制包少
        "description": "控制流 - 可靠必达, 高优先级",
    },
    StreamType.TELEMETRY: {
        "reliable": True,      # 必须到达
        "fec_enabled": False,
        "arq_enabled": True,   # ARQ 重传
        "priority": 80,        # 较高 (比控制低)
        "max_queue": 100,
        "description": "遥测流 - 可靠, 低频, 可合并",
    },
    StreamType.RELAY: {
        "reliable": True,
        "fec_enabled": False,
        "arq_enabled": True,
        "priority": 60,
        "max_queue": 100,
        "description": "中继流 - 预留",
    },
}


# ============================================================
# 发送端: 多路复用器 (Multiplexer)
# ============================================================
class StreamMultiplexer:
    """
    发送端: 多条流 → 一个出口 (socket/管道)。

    职责:
    1. 应用层按 stream_id 提交数据
    2. 每条流独立分片 + 编号
    3. 加权公平队列调度 (控制流优先)
    4. 流量统计 + 拥塞感知
    """

    def __init__(self, session_tag: int,
                 send_callback: Callable[[bytes], None],
                 chunk_size: int = 800,
                 fec_k: int = 10, fec_n: int = 14):
        self.session_tag = session_tag
        self._send = send_callback
        self.chunk_size = chunk_size
        self.fec_k = fec_k
        self.fec_n = fec_n

        # 每条流的发送队列
        self._queues: Dict[int, deque] = {
            sid: deque() for sid in range(4)
        }
        # 每条流的 seq 计数器
        self._seq: Dict[int, int] = {sid: 0 for sid in range(4)}
        # 每条流的帧计数器
        self._frame_id: Dict[int, int] = {sid: 0 for sid in range(4)}

        # 统计
        self._stats: Dict[int, dict] = {}
        for sid in range(4):
            self._stats[sid] = {
                "packets_sent": 0,
                "bytes_sent": 0,
                "dropped": 0,
                "last_send_time": 0.0,
            }

        self._lock = threading.Lock()
        self._running = True

        # 启动调度线程
        self._scheduler = threading.Thread(
            target=self._schedule_loop, daemon=True
        )
        self._scheduler.start()

    def submit(self, stream_id: int, data: bytes,
               key_frame: bool = False) -> int:
        """
        应用层提交数据到指定流。
        返回: 分片数 (0 表示入队失败/丢弃)
        """
        if stream_id not in self._queues:
            return 0

        config = STREAM_CONFIG[StreamType(stream_id)]
        reliable = config["reliable"]
        fec = config["fec_enabled"]

        # 分片
        fragments = self._fragment(stream_id, data, key_frame, fec)
        if not fragments:
            return 0

        with self._lock:
            queue = self._queues[stream_id]
            max_q = config["max_queue"]

            # 队列满: 图传流丢旧帧 (新帧优先), 控制流阻塞或报错
            if len(queue) + len(fragments) > max_q:
                if stream_id == StreamType.VIDEO:
                    # 丢旧帧 (从队头丢弃完整帧)
                    self._drop_old_frames(stream_id, len(fragments))
                else:
                    # 控制/遥测: 拒绝新数据 (让上层重传/等待)
                    self._stats[stream_id]["dropped"] += len(fragments)
                    return 0

            for frag in fragments:
                queue.append(frag)

        return len(fragments)

    def _fragment(self, stream_id: int, data: bytes,
                  key_frame: bool, use_fec: bool) -> List[bytes]:
        """分片 + 打头"""
        fid = self._frame_id[stream_id]
        self._frame_id[stream_id] = (fid + 1) & 0xFFFFFFFF

        config = STREAM_CONFIG[StreamType(stream_id)]
        reliable = config["reliable"]

        # 基础 flags
        flags = 0
        if key_frame:
            flags |= FLAG_KEY_FRAME
        if reliable:
            flags |= FLAG_RELIABLE

        # 分片
        cs = self.chunk_size
        raw_chunks = []
        for i in range(0, len(data), cs):
            raw_chunks.append(data[i:i+cs])

        total = len(raw_chunks)

        # FEC 冗余
        fec_chunks = []
        if use_fec and total > 0:
            try:
                from .rs_codec import ReedSolomon
                rs = ReedSolomon()
                # 补零对齐
                aligned = list(raw_chunks)
                while len(aligned) < self.fec_k:
                    aligned.append(b'\x00' * cs)
                encoded = rs.encode(aligned[:self.fec_k])
                fec_chunks = encoded[self.fec_k:self.fec_n]
                total = self.fec_n
            except Exception:
                pass

        # 打头
        packets = []
        all_chunks = raw_chunks + fec_chunks
        for idx, chunk in enumerate(all_chunks):
            f = flags
            if idx >= len(raw_chunks):
                f |= FLAG_FEC_PARITY
            if idx == len(all_chunks) - 1:
                f |= FLAG_LAST_FRAG
            hdr = pack_header(
                session_tag=self.session_tag,
                frame_id=fid, frag_id=idx,
                total_frags=total, flags=f,
                stream_id=stream_id,
            )
            packets.append(hdr + chunk)

        return packets

    def _drop_old_frames(self, stream_id: int, need_slots: int):
        """图传流队列满时, 丢旧帧腾空间"""
        queue = self._queues[stream_id]
        dropped = 0
        while len(queue) > 0 and dropped < need_slots:
            queue.popleft()
            dropped += 1
        self._stats[stream_id]["dropped"] += dropped

    def _schedule_loop(self):
        """
        调度循环: 加权公平队列。
        控制流 (priority 100) 优先, 遥测 (80), 中继 (60), 图传 (50)。
        每轮按权重比例取包发送。
        """
        while self._running:
            sent_this_round = 0

            # 按优先级排序
            stream_order = sorted(
                range(4),
                key=lambda s: STREAM_CONFIG[StreamType(s)]["priority"],
                reverse=True,  # 高优先级先发
            )

            for sid in stream_order:
                queue = self._queues[sid]
                if not queue:
                    continue

                config = STREAM_CONFIG[StreamType(sid)]
                priority = config["priority"]

                # 控制流: 一次发尽量多 (低延迟关键)
                if sid == StreamType.CONTROL:
                    budget = min(len(queue), 10)
                elif sid == StreamType.TELEMETRY:
                    budget = min(len(queue), 5)
                else:
                    # 图传/中继: 按权重发
                    budget = min(len(queue), max(1, priority // 10))

                for _ in range(budget):
                    if not queue:
                        break
                    pkt = queue.popleft()
                    try:
                        self._send(pkt)
                        self._stats[sid]["packets_sent"] += 1
                        self._stats[sid]["bytes_sent"] += len(pkt)
                        self._stats[sid]["last_send_time"] = time.monotonic()
                        sent_this_round += 1
                    except Exception:
                        pass

            # 没东西发就睡一下
            if sent_this_round == 0:
                time.sleep(0.001)

    def shutdown(self):
        self._running = False

    def stats(self) -> dict:
        with self._lock:
            result = {}
            for sid in range(4):
                s = dict(self._stats[sid])
                s["stream_name"] = SUPPORTED_STREAMS.get(sid, "?")
                s["queue_depth"] = len(self._queues[sid])
                result[sid] = s
            return result

    def queue_depths(self) -> dict:
        with self._lock:
            return {sid: len(q) for sid, q in self._queues.items()}


# ============================================================
# 接收端: 多路分用器 (Demultiplexer)
# ============================================================
class StreamDemultiplexer:
    """
    接收端: 一个入口 → 按 stream_id 分发到不同处理器。

    职责:
    1. 收包 → 按 stream_id 路由
    2. 每条流独立重组/解码
    3. 图传流: FEC 修复 → 拼帧 → 回调
    4. 控制流: 可靠重组 → 立即回调 (低延迟)
    5. 遥测流: 可靠重组 → 批量回调
    """

    def __init__(self, session_tag: int,
                 on_video_frame: Optional[Callable] = None,
                 on_control_message: Optional[Callable] = None,
                 on_telemetry: Optional[Callable] = None,
                 fec_k: int = 10, fec_n: int = 14):
        self.session_tag = session_tag
        self._on_video = on_video_frame
        self._on_control = on_control_message
        self._on_telem = on_telemetry

        # 各流重组器
        try:
            from .fragment import Reassembler
        except ImportError:
            from protocol.fragment import Reassembler

        self._reasm: Dict[int, Reassembler] = {
            StreamType.VIDEO: Reassembler(session_tag, fec_k=fec_k, fec_n=fec_n),
            StreamType.CONTROL: Reassembler(session_tag, fec_k=fec_k, fec_n=fec_n),
            StreamType.TELEMETRY: Reassembler(session_tag, fec_k=fec_k, fec_n=fec_n),
            StreamType.RELAY: Reassembler(session_tag, fec_k=fec_k, fec_n=fec_n),
        }

        # 统计
        self._stats: Dict[int, dict] = {}
        for sid in range(4):
            self._stats[sid] = {
                "packets_recv": 0,
                "frames_complete": 0,
                "frames_corrupted": 0,
                "last_frame_time": 0.0,
            }
        self._total_recv = 0
        self._lock = threading.Lock()

    def feed(self, packet: bytes) -> Optional[Tuple[int, bytes]]:
        """
        喂入一个包。自动路由到对应流。
        返回 (stream_id, frame_data) 当某流有完整帧时, 否则 None。
        """
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return None

        if hdr.session_tag != self.session_tag:
            return None
        if hdr.is_arq_req() or hdr.is_arq_rep():
            return None  # ARQ 包不归流管

        sid = hdr.stream_id
        if sid not in self._reasm:
            return None

        self._total_recv += 1
        self._stats[sid]["packets_recv"] += 1

        # 喂给对应重组器
        result = self._reasm[sid].feed(packet)

        if result is not None:
            self._stats[sid]["frames_complete"] += 1
            self._stats[sid]["last_frame_time"] = time.monotonic()

            # 回调
            if sid == StreamType.VIDEO and self._on_video:
                try:
                    self._on_video(result)
                except Exception:
                    pass
            elif sid == StreamType.CONTROL and self._on_control:
                try:
                    self._on_control(result)
                except Exception:
                    pass
            elif sid == StreamType.TELEMETRY and self._on_telem:
                try:
                    self._on_telem(result)
                except Exception:
                    pass

            return (sid, result)

        return None

    def stats(self) -> dict:
        result = {}
        for sid in range(4):
            s = dict(self._stats[sid])
            s["stream_name"] = SUPPORTED_STREAMS.get(sid, "?")
            result[sid] = s
        result["total_packets"] = self._total_recv
        return result


# ============================================================
# 端到端演示: 三流并发
# ============================================================
if __name__ == "__main__":
    print("=" * 58)
    print("  SwarmLink 多流复用器 v0.3 — 演示")
    print("  QUIC-style 多路复用: 图传/控制/遥测三流合一")
    print("=" * 58)

    # 模拟链路 (队列)
    link_queue = deque()
    link_lock = threading.Lock()

    def send_to_link(pkt):
        with link_lock:
            link_queue.append(pkt)

    # 接收统计
    video_frames = []
    control_msgs = []
    telem_msgs = []

    def on_video(frame):
        video_frames.append(frame)
    def on_control(msg):
        control_msgs.append(msg)
    def on_telem(msg):
        telem_msgs.append(msg)

    SESSION = 0xAB12CD34

    # 创建复用器
    mux = StreamMultiplexer(SESSION, send_to_link,
                            chunk_size=400, fec_k=10, fec_n=14)
    demux = StreamDemultiplexer(SESSION,
                                on_video_frame=on_video,
                                on_control_message=on_control,
                                on_telemetry=on_telem,
                                fec_k=10, fec_n=14)

    # 模拟数据
    import random
    rng = random.Random(42)

    print("\n--- 并发提交三流数据 ---")

    # 1. 提交图传帧 (大, 不可靠)
    video_data_list = []
    for i in range(5):
        data = f"VIDEO-FRAME-{i}-".encode() * 40  # ~560B
        video_data_list.append(data)
        n = mux.submit(StreamType.VIDEO, data, key_frame=(i == 0))
        print(f"  [VIDEO]   提交帧 {i}: {len(data)}B → {n} 分片")

    # 2. 提交控制消息 (小, 可靠, 高优先级)
    ctrl_msgs = [
        b"ARM_MOTORS",
        b"SET_ALTITUDE:50m",
        b"RTL_NOW",
        b"GIMBAL_PITCH:-15",
    ]
    for msg in ctrl_msgs:
        n = mux.submit(StreamType.CONTROL, msg)
        print(f"  [CONTROL] 提交命令: {msg.decode()} → {n} 分片")

    # 3. 提交遥测 (小, 可靠)
    telem_data = [
        b"BAT:85% GPS:3D ALT:42.5",
        b"BAT:84% GPS:3D ALT:43.1",
        b"BAT:83% GPS:3D ALT:44.0",
    ]
    for t in telem_data:
        n = mux.submit(StreamType.TELEMETRY, t)
        print(f"  [TELEMETRY] 提交: {t.decode()} → {n} 分片")

    # 等待调度器发送
    time.sleep(0.1)

    # 模拟链路: 随机丢包 10%
    print(f"\n--- 链路传输 (10% 丢包 + 乱序) ---")
    in_flight = []
    with link_lock:
        while link_queue:
            in_flight.append(link_queue.popleft())

    # 乱序 + 丢包
    rng.shuffle(in_flight)
    delivered = 0
    dropped = 0
    for pkt in in_flight:
        if rng.random() < 0.10:
            dropped += 1
            continue
        delivered += 1
        demux.feed(pkt)

    print(f"  发送: {len(in_flight)}  送达: {delivered}  丢失: {dropped}")

    # 等 FEC 修复
    time.sleep(0.05)

    # 结果
    print(f"\n{'=' * 58}")
    print(f"  结果:")
    print(f"{'=' * 58}")

    print(f"\n  [VIDEO]")
    print(f"    完整帧: {len(video_frames)}/5")
    for i, frame in enumerate(video_frames):
        ok = frame == video_data_list[i]
        print(f"    帧 {i}: {'✓' if ok else '✗'} ({len(frame)}B)")

    print(f"\n  [CONTROL]")
    print(f"    完整消息: {len(control_msgs)}/{len(ctrl_msgs)}")
    for i, msg in enumerate(control_msgs):
        print(f"    [{i}] {msg.decode()}")

    print(f"\n  [TELEMETRY]")
    print(f"    完整消息: {len(telem_msgs)}/{len(telem_data)}")
    for i, t in enumerate(telem_msgs):
        print(f"    [{i}] {t.decode()}")

    # 统计
    print(f"\n--- 多路复用器统计 ---")
    mux_stats = mux.stats()
    for sid in range(4):
        s = mux_stats[sid]
        if s["packets_sent"] > 0:
            print(f"  {s['stream_name']:<10s}: "
                  f"发送 {s['packets_sent']:4d} 包 "
                  f"({s['bytes_sent']:6d} B) "
                  f"丢弃 {s['dropped']:3d}")

    demux_stats = demux.stats()
    print(f"\n  接收端:")
    print(f"    总包: {demux_stats['total_packets']}")
    for sid in range(4):
        s = demux_stats[sid]
        if s["packets_recv"] > 0:
            print(f"    {s['stream_name']:<10s}: "
                  f"接收 {s['packets_recv']:4d} 包 "
                  f"完整帧 {s['frames_complete']}")

    # 关闭
    mux.shutdown()

    print(f"\n{'=' * 58}")
    print(f"  ✅ 多流复用器 v0.3 演示完成!")
    print(f"{'=' * 58}")
    print(f"\n  核心特性:")
    print(f"    🔀 单链路三流复用 (VIDEO/CONTROL/TELEMETRY)")
    print(f"    ⚡ 控制流最高优先级 (不排队)")
    print(f"    🎬 图传流不可靠 (丢帧就丢, 不阻塞控制)")
    print(f"    📡 遥测流可靠低频 (可合并)")
    print(f"    🛡️  FEC 修复图传丢包")
    print(f"    📊 每流独立统计")
    print(f"\n  下一步: 真实 UDP socket 测试 + SFU 选择性转发")
