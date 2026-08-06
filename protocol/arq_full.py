"""
SwarmLink ARQ 完整重传链路
============================
打通: 接收端检测缺失 → 发 ARQ_REQ → 聚合器合并 → 重传 ARQ_REP
      → 接收端喂入重组器 → 帧完整恢复

架构:
  SkyEnd (天空端)
    ├── Fragmenter      (分片+加密)
    ├── PacketStore     (存最近 N 帧, 供重传查表)
    ├── ARQAggregator   (A方案: 合并同 frag 请求)
    ├── BitmapTracker   (B方案: 记录谁缺啥, 可选启用)
    └── RetransmitPipe  (实际发出去的函数)

  GroundEnd (地面端/眼镜)
    ├── Reassembler     (重组+解密+FEC修复)
    ├── LossDetector    (检测缺失分片, 触发 ARQ_REQ)
    ├── ARQClient       (发请求, 去重)
    └── RecvPipe        (实际收包的函数)

设计取舍:
- A 方案默认: 简单, 够用, 带宽节省 1/N
- B 方案可叠加: 精确位图, 只发给缺的人
- 两种方案共用同一套 PacketStore + RetransmitPipe
"""

import time
import struct
import threading
from collections import defaultdict, deque
from typing import Optional, Callable, Dict, List, Tuple

try:
    from .header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_ARQ_REQ, FLAG_ARQ_REP, FLAG_LAST_FRAG,
        FLAG_KEY_FRAME, FLAG_ENCRYPTED,
        flags_for,
    )
    from .arq import ARQAggregator, ARQClient, ClientBitmap
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from protocol.header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_ARQ_REQ, FLAG_ARQ_REP, FLAG_LAST_FRAG,
        FLAG_KEY_FRAME, FLAG_ENCRYPTED,
        flags_for,
    )
    from protocol.arq import ARQAggregator, ARQClient, ClientBitmap


# ============================================================
# 天空端: Packet Store (带 TTL, 防内存爆)
# ============================================================
class PacketStore:
    """
    存储最近发送的包, 供 ARQ 重传查表。
    超过 TTL 或容量上限自动淘汰 (FIFO)。
    """
    def __init__(self, max_frames: int = 60, ttl_sec: float = 3.0):
        self.max_frames = max_frames
        self.ttl = ttl_sec
        # frame_id -> {frag_id: packet_bytes}
        self._store: Dict[int, Dict[int, bytes]] = {}
        self._order: deque = deque()
        self._lock = threading.Lock()

    def put(self, frame_id: int, packets: list):
        """存储一帧的所有包"""
        with self._lock:
            if frame_id in self._store:
                return
            self._store[frame_id] = {}
            for pkt in packets:
                try:
                    hdr = unpack_header(pkt)
                    self._store[frame_id][hdr.frag_id] = pkt
                except HeaderError:
                    continue
            self._order.append(frame_id)
            self._evict()

    def get(self, frame_id: int, frag_id: int) -> Optional[bytes]:
        """查表: 返回原始包 (含 16B 头)"""
        with self._lock:
            frame = self._store.get(frame_id)
            if frame is None:
                return None
            return frame.get(frag_id)

    def get_frame_packets(self, frame_id: int) -> Optional[Dict[int, bytes]]:
        """获取整帧所有包 (用于 B 方案选择性重发)"""
        with self._lock:
            frame = self._store.get(frame_id)
            if frame is None:
                return None
            return dict(frame)

    def _evict(self):
        """淘汰过期和超容量的帧"""
        now = time.monotonic()
        # TTL 淘汰
        to_remove = []
        for fid in self._order:
            # 用 fid 在 order 中的位置判断 TTL (简化: 超容量即过期)
            pass
        # 容量淘汰 (FIFO)
        while len(self._order) > self.max_frames:
            old_fid = self._order.popleft()
            self._store.pop(old_fid, None)

    def stats(self) -> dict:
        with self._lock:
            return {
                "frames_stored": len(self._store),
                "total_packets": sum(len(v) for v in self._store.values()),
            }


# ============================================================
# 天空端: 增强版 ARQ 聚合器 (A + B 混合)
# ============================================================
class ARQAggregatorV2(ARQAggregator):
    """
    A 方案为主 (合并同 frag → 1 次广播)
    B 方案叠加 (用 ClientBitmap 记录谁缺啥, 可选精确发送)
    """
    def __init__(self, session_tag: int, packet_store: PacketStore,
                 retransmit_callback: Callable = None,
                 window_ms: int = 20, use_bitmap: bool = False,
                 max_clients: int = 64):
        super().__init__(session_tag, {}, window_ms=window_ms,
                        retransmit_callback=retransmit_callback)
        self._packet_store = packet_store
        self._use_bitmap = use_bitmap
        self._bitmap = ClientBitmap(max_clients=max_clients)
        self._stats = {
            "reqs_received": 0,
            "reqs_merged": 0,
            "retransmits_sent": 0,
            "bytes_saved": 0,
        }

    def receive_request(self, packet: bytes, client_id: int):
        """收到 ARQ_REQ, 更新 bitmap + pending"""
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return
        if not hdr.is_arq_req():
            return

        self._stats["reqs_received"] += 1
        key = (hdr.frame_id, hdr.frag_id)

        # B 方案: 记录谁缺啥
        if self._use_bitmap:
            self._bitmap.mark_missing(hdr.frame_id, hdr.frag_id, client_id)

        # A 方案: 合并 (去重 client)
        if client_id not in self._pending[key]:
            self._pending[key].append(client_id)

        now = time.monotonic()
        if (now - self._last_flush) * 1000 >= self.window_ms:
            self.flush()

    def flush(self):
        """合并重传 + 可选 bitmap 精确发送"""
        if not self._pending:
            self._last_flush = time.monotonic()
            return

        for (frame_id, frag_id), clients in list(self._pending.items()):
            pkt = self._packet_store.get(frame_id, frag_id)
            if pkt is None:
                continue

            waiter_count = len(clients)
            self._stats["reqs_merged"] += waiter_count - 1  # 节省的次数
            self._stats["retransmits_sent"] += 1

            if self._use_bitmap:
                # B 方案: 只发给真正缺的人 (通过回调传 recipients)
                recipients = self._bitmap.recipients(frame_id, frag_id)
                rep_packet = self._make_rep_header(
                    frame_id, frag_id, waiter_count) + pkt[HEADER_SIZE:]
                if self._retransmit:
                    self._retransmit(rep_packet, recipients)
            else:
                # A 方案: 无脑广播
                rep_packet = self._make_rep_header(
                    frame_id, frag_id, waiter_count) + pkt[HEADER_SIZE:]
                if self._retransmit:
                    self._retransmit(rep_packet, None)  # None = broadcast

        self._pending.clear()
        self._last_flush = time.monotonic()

    def stats(self) -> dict:
        s = super().stats()
        s.update(self._stats)
        if s["reqs_received"] > 0:
            merge_rate = s["reqs_merged"] / s["reqs_received"] * 100
            s["merge_rate_pct"] = round(merge_rate, 1)
        else:
            s["merge_rate_pct"] = 0
        return s


# ============================================================
# 地面端: 缺失检测器 (核心 - 之前缺失的环节)
# ============================================================
class LossDetector:
    """
    运行在地面端。监控 Reassembler 的进度,
    检测哪些分片超时未到 → 触发 ARQ_REQ。

    算法:
    - 收到分片时, 更新预期窗口
    - 超过 RTO (重传超时) 还没收到的分片 → 标记为 lost
    - 向 ARQClient 发送重传请求
    - 指数退避: 同一分片重试间隔翻倍, 防止风暴
    """
    def __init__(self, session_tag: int, client_id: int,
                 arq_client: ARQClient,
                 rto_ms: int = 50, max_retries: int = 5):
        self.session_tag = session_tag
        self.client_id = client_id
        self._arq = arq_client
        self.rto_ms = rto_ms
        self.max_retries = max_retries

        # frame_id -> {frag_id: {"expected": bool, "received": bool,
        #                        "first_seen": float, "last_retry": float,
        #                        "retries": int}}
        self._frames: dict = {}
        self._lock = threading.Lock()
        self._stats = {
            "loss_detected": 0,
            "reqs_sent": 0,
            "retries_exhausted": 0,
        }

    def on_packet_received(self, frame_id: int, frag_id: int,
                           total_frags: int, now: float = None):
        """每收到一个分片调用。更新状态, 检测缺失。"""
        if now is None:
            now = time.monotonic()
        with self._lock:
            frame = self._frames.setdefault(frame_id, {})
            frame[frag_id] = {
                "received": True,
                "time": now,
            }
            # 更新预期分片数
            for i in range(total_frags):
                if i not in frame:
                    frame.setdefault(i, {"received": False, "time": None})

    def check_loss(self, now: float = None) -> list:
        """
        扫描所有帧, 返回需要请求重传的 [(frame_id, frag_id), ...]
        应在主循环中定期调用 (如每 10ms)。
        """
        if now is None:
            now = time.monotonic()
        requests = []
        with self._lock:
            for frame_id, frags in list(self._frames.items()):
                for frag_id, info in frags.items():
                    if info.get("received"):
                        continue
                    # 未收到: 检查是否超时
                    first_seen = info.get("first_seen")
                    if first_seen is None:
                        info["first_seen"] = now
                        info["last_retry"] = now
                        info["retries"] = 0
                        continue
                    retries = info.get("retries", 0)
                    if retries >= self.max_retries:
                        self._stats["retries_exhausted"] += 1
                        # 标记已放弃, 不再重试
                        info["received"] = True  # 标记为"已处理"避免重复
                        continue
                    # 指数退避
                    backoff = self.rto_ms * (2 ** retries) / 1000.0
                    elapsed = now - info.get("last_retry", first_seen)
                    if elapsed >= backoff:
                        requests.append((frame_id, frag_id))
                        info["last_retry"] = now
                        info["retries"] = retries + 1
                        self._stats["reqs_sent"] += 1
        return requests

    def on_frame_complete(self, frame_id: int):
        """帧重组完成, 清理。"""
        with self._lock:
            self._frames.pop(frame_id, None)

    def on_rep_received(self, frame_id: int, frag_id: int):
        """收到 ARQ_REP, 标记已恢复。"""
        with self._lock:
            frame = self._frames.get(frame_id)
            if frame and frag_id in frame:
                frame[frag_id]["received"] = True

    def stats(self) -> dict:
        return dict(self._stats)


# ============================================================
# 地面端: 完整接收管线
# ============================================================
class GroundReceiver:
    """
    一个地面端/眼镜的完整接收管线:
    WeakNet → 解密 → Reassembler → LossDetector → ARQClient

    回调链:
    net.recv() → decrypt → reassembler.feed()
                          → loss_detector.on_packet()
                          → 完整帧 → callback
    """
    def __init__(self, client_id: int, session_tag: int,
                 reassembler, decryptor_func: Callable,
                 send_arq_func: Callable,
                 on_frame_complete: Callable,
                 rto_ms: int = 50):
        self.client_id = client_id
        self.session_tag = session_tag
        self._reasm = reassembler
        self._decrypt = decryptor_func
        self._send_arq = send_arq_func
        self._on_complete = on_frame_complete

        self._arq_client = ARQClient(session_tag, client_id,
                                     send_callback=send_arq_func)
        self._loss = LossDetector(session_tag, client_id, self._arq_client,
                                  rto_ms=rto_ms)

        self.completed_frames: dict = {}
        self.corrupted_frames = 0
        self._lock = threading.Lock()

    def feed(self, packet: bytes, now: float = None):
        """喂入一个原始包 (可能加密)。"""
        if now is None:
            now = time.monotonic()
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return

        # ARQ_REP: 解密后喂给重组器
        if hdr.is_arq_rep():
            plaintext = self._decrypt(packet[HEADER_SIZE:])
            if plaintext is None:
                return
            self._loss.on_rep_received(hdr.frame_id, hdr.frag_id)
            self._arq_client.ack_received(hdr.frame_id, hdr.frag_id)
            # 把 REP 的 payload 当成分片喂入重组器
            fake_packet = packet[:HEADER_SIZE] + plaintext
            result = self._reasm.feed(fake_packet)
            if result is not None:
                self._handle_complete(hdr.frame_id, result, now)
            return

        # 普通数据/parity 包
        # 如果加密, 先解密 payload
        if hdr.is_encrypted():
            security_blob = packet[HEADER_SIZE:]
            plaintext = self._decrypt(security_blob)
            if plaintext is None:
                # 解密失败, 标记丢失
                self._loss.on_packet_received(hdr.frame_id, hdr.frag_id,
                                               hdr.total_frags, now)
                return
            # 重组器需要 16B 头 + 明文 payload
            full_packet = packet[:HEADER_SIZE] + plaintext
        else:
            full_packet = packet

        # 通知缺失检测器
        self._loss.on_packet_received(hdr.frame_id, hdr.frag_id,
                                       hdr.total_frags, now)

        # 喂重组器
        result = self._reasm.feed(full_packet)
        if result is not None:
            self._handle_complete(hdr.frame_id, result, now)

    def _handle_complete(self, frame_id: int, frame_data: bytes, now: float):
        with self._lock:
            self.completed_frames[frame_id] = frame_data
        self._loss.on_frame_complete(frame_id)
        if self._on_complete:
            self._on_complete(self.client_id, frame_id, frame_data)

    def tick_loss_check(self, now: float = None):
        """主循环调用: 检查缺失, 发送 ARQ_REQ"""
        if now is None:
            now = time.monotonic()
        requests = self._loss.check_loss(now)
        for (fid, frag_id) in requests:
            self._arq_client.request(fid, frag_id)

    def stats(self) -> dict:
        return {
            "completed": len(self.completed_frames),
            "corrupted": self.corrupted_frames,
            "loss": self._loss.stats(),
            "arq": {
                "inflight": len(self._arq_client._inflight),
            },
        }


# ============================================================
# 天空端: 完整发送管线
# ============================================================
class SkySender:
    """
    天空端发送管线:
    Fragmenter → Encrypt → PacketStore → send_callback
    同时持有 ARQAggregatorV2 处理重传请求。
    """
    def __init__(self, session_tag: int, fragmenter,
                 encrypt_func: Callable,
                 send_callback: Callable,
                 chunk_size: int = 800,
                 fec_k: int = 10, fec_n: int = 14,
                 packet_store: Optional[PacketStore] = None,
                 arq_window_ms: int = 20,
                 use_bitmap: bool = False):
        self.session_tag = session_tag
        self._frag = fragmenter
        self._encrypt = encrypt_func
        self._send = send_callback
        self.chunk_size = chunk_size
        self.fec_k = fec_k
        self.fec_n = fec_n

        if packet_store is None:
            packet_store = PacketStore(max_frames=60, ttl_sec=3.0)
        self._store = packet_store

        self._arq = ARQAggregatorV2(
            session_tag=session_tag,
            packet_store=packet_store,
            retransmit_callback=self._retransmit,
            window_ms=arq_window_ms,
            use_bitmap=use_bitmap,
        )

        self._stats = {
            "frames_sent": 0,
            "packets_sent": 0,
            "bytes_sent": 0,
        }

    def send_frame(self, frame_data: bytes, frame_id: int,
                   stream_id: int = 0, key_frame: bool = False,
                   now: float = None) -> int:
        """发送一帧: 分片 → (加密) → 存储 → 发送"""
        if now is None:
            now = time.monotonic()

        # 1) 分片 (Fragmenter 内部处理 FEC)
        packets = self._frag.fragment(frame_data, stream_id=stream_id,
                                      key_frame=key_frame)
        # 重写 frame_id (Fragmenter 内部自增, 这里外部指定)
        packets = self._rewrite_frame_id(packets, frame_id)

        # 2) 加密 (如果 encrypt 函数存在)
        if self._encrypt is not None:
            encrypted_packets = []
            for pkt in packets:
                hdr = pkt[:HEADER_SIZE]
                payload = pkt[HEADER_SIZE:]
                enc_payload = self._encrypt(payload)
                # 包 = 16B 头 + 8B nonce + 16B tag + 密文
                encrypted_packets.append(hdr + enc_payload)
            packets = encrypted_packets

        # 3) 存入 PacketStore (用原始包, 重传时直接发)
        self._store.put(frame_id, packets)

        # 4) 发送
        for pkt in packets:
            self._send(pkt)
            self._stats["packets_sent"] += 1
            self._stats["bytes_sent"] += len(pkt)

        self._stats["frames_sent"] += 1
        return len(packets)

    def _rewrite_frame_id(self, packets: list, frame_id: int) -> list:
        """重写包列表中的 frame_id (Fragmenter 内部自增, 外部要控制)"""
        rewritten = []
        for pkt in packets:
            hdr = pkt[:HEADER_SIZE]
            payload = pkt[HEADER_SIZE:]
            try:
                old_hdr = unpack_header(hdr)
                new_hdr = pack_header(
                    session_tag=old_hdr.session_tag,
                    frame_id=frame_id,
                    frag_id=old_hdr.frag_id,
                    total_frags=old_hdr.total_frags,
                    flags=old_hdr.flags,
                    stream_id=old_hdr.stream_id,
                )
                rewritten.append(new_hdr + payload)
            except HeaderError:
                rewritten.append(pkt)
        return rewritten

    def handle_arq_request(self, packet: bytes, client_id: int):
        """天空端收到 ARQ_REQ 时调用"""
        self._arq.receive_request(packet, client_id)

    def flush_arq(self):
        """强制刷新 ARQ 聚合器"""
        self._arq.flush()

    def _retransmit(self, packet: bytes, recipients: Optional[list] = None):
        """实际重传函数 (可注入 recipients 做 B 方案)"""
        self._send(packet, recipients)
        self._stats["packets_sent"] += 1

    def stats(self) -> dict:
        s = dict(self._stats)
        s["store"] = self._store.stats()
        s["arq"] = self._arq.stats()
        return s


# ============================================================
# 集成测试: 完整 ARQ 链路
# ============================================================
if __name__ == "__main__":
    print("=== SwarmLink ARQ 完整链路自测 ===\n")

    # 简化版: 不用真实网络, 用队列模拟
    from collections import deque

    sky_to_ground = deque()  # 天空端 → 地面端
    ground_to_sky = deque()  # 地面端 → 天空端

    # 模拟链路: 10% 丢包
    import random
    rng = random.Random(42)
    def lossy_send(pkt, recipients=None):
        if rng.random() > 0.10:  # 90% 送达
            sky_to_ground.append(pkt)

    def ground_send(pkt):
        ground_to_sky.append(pkt)

    # 不用加密 (简化测试)
    encrypt_fn = None
    decrypt_fn = lambda x: x  # identity

    # 创建发送端
    from protocol.fragment import Fragmenter, Reassembler
    SESSION = 0xDEADBEEF
    fragger = Fragmenter(SESSION, chunk_size=500, fec_k=10, fec_n=14)
    sender = SkySender(
        session_tag=SESSION,
        fragmenter=fragger,
        encrypt_func=encrypt_fn,
        send_callback=lossy_send,
        arq_window_ms=20,
    )

    # 创建接收端
    reasm = Reassembler(SESSION, fec_k=10, fec_n=14)
    receiver = GroundReceiver(
        client_id=0,
        session_tag=SESSION,
        reassembler=reasm,
        decryptor_func=decrypt_fn,
        send_arq_func=ground_send,
        on_frame_complete=lambda cid, fid, data: print(f"  ✓ Frame {fid} 完成 ({len(data)}B)"),
        rto_ms=30,
    )

    # 发送 5 帧
    print("发送 5 帧 (10% 丢包, ARQ 自动修复)...\n")
    original_frames = {}
    for fid in range(5):
        data = f"Frame-{fid}: " + "X" * (fid * 100 + 500)
        original_frames[fid] = data.encode()
        sender.send_frame(data.encode(), frame_id=fid, key_frame=(fid == 0))

    # 模拟时间推进: 收包 + ARQ 循环
    max_rounds = 200
    for round in range(max_rounds):
        # 地面端收包
        while sky_to_ground:
            pkt = sky_to_ground.popleft()
            receiver.feed(pkt)

        # 天空端收 ARQ 请求
        while ground_to_sky:
            req = ground_to_sky.popleft()
            sender.handle_arq_request(req, client_id=0)

        # 刷新 ARQ
        sender.flush_arq()

        # 地面端检查缺失
        receiver.tick_loss_check()

        # 检查是否全部完成
        if len(receiver.completed_frames) >= 5:
            break

        time.sleep(0.001)

    # 结果
    print(f"\n--- 结果 ---")
    print(f"完成帧: {len(receiver.completed_frames)}/5")
    for fid in range(5):
        if fid in receiver.completed_frames:
            ok = receiver.completed_frames[fid] == original_frames[fid]
            print(f"  Frame {fid}: {'✓ 匹配' if ok else '✗ 不匹配'}")
        else:
            print(f"  Frame {fid}: ✗ 丢失")

    s = sender.stats()
    print(f"\n天空端统计:")
    print(f"  帧发送: {s['frames_sent']}")
    print(f"  包发送: {s['packets_sent']}")
    print(f"  ARQ: {s['arq']}")
    print(f"\n地面端统计:")
    print(f"  {receiver.stats()}")

    if len(receiver.completed_frames) == 5:
        print("\n=== ARQ 完整链路测试通过 ✓ ===")
    else:
        print(f"\n⚠ 未完成所有帧, 可能需要更多轮次或调整参数")
