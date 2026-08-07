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
        self._times: Dict[int, float] = {}
        self._order: deque = deque()
        self._lock = threading.Lock()
        self._stats = {"hits": 0, "misses": 0, "evicted_ttl": 0,
                       "evicted_cap": 0}

    def put(self, frame_id: int, packets: list, now: float = None):
        """存储一帧的所有包"""
        if now is None:
            now = time.monotonic()
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
            self._times[frame_id] = now
            self._order.append(frame_id)
            self._evict(now)

    def get(self, frame_id: int, frag_id: int) -> Optional[bytes]:
        """查表: 返回原始包 (含 16B 头)"""
        with self._lock:
            frame = self._store.get(frame_id)
            pkt = frame.get(frag_id) if frame else None
            if pkt is None:
                self._stats["misses"] += 1
            else:
                self._stats["hits"] += 1
            return pkt

    def get_frame_packets(self, frame_id: int) -> Optional[Dict[int, bytes]]:
        """获取整帧所有包 (用于 B 方案选择性重发)"""
        with self._lock:
            frame = self._store.get(frame_id)
            if frame is None:
                return None
            return dict(frame)

    def _evict(self, now: float):
        """淘汰过期和超容量的帧 (FIFO + TTL, order 天然按时间递增)"""
        # TTL 淘汰: 队头最老, 一旦不过期就可以停
        while self._order:
            fid = self._order[0]
            born = self._times.get(fid)
            if born is not None and (now - born) <= self.ttl:
                break
            self._order.popleft()
            self._store.pop(fid, None)
            self._times.pop(fid, None)
            self._stats["evicted_ttl"] += 1
        # 容量淘汰 (FIFO)
        while len(self._order) > self.max_frames:
            old_fid = self._order.popleft()
            self._store.pop(old_fid, None)
            self._times.pop(old_fid, None)
            self._stats["evicted_cap"] += 1

    def stats(self) -> dict:
        with self._lock:
            s = dict(self._stats)
            s["frames_stored"] = len(self._store)
            s["total_packets"] = sum(len(v) for v in self._store.values())
            return s


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
            "store_misses": 0,
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

    def maybe_flush(self, now: float = None):
        """按合并窗口节流刷新。

        主循环应该调用这个而不是 flush()：无条件 flush 会让每个
        REQ 一到就立刻重传, 20ms 合并窗口形同虚设, 多客户端合并率恒为 0。
        """
        if now is None:
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
                # 已过 TTL 或当时就没存下 → 无法重传
                self._stats["store_misses"] += 1
                continue

            waiter_count = len(clients)
            self._stats["reqs_merged"] += waiter_count - 1  # 节省的次数
            self._stats["retransmits_sent"] += 1
            self._stats["bytes_saved"] += (waiter_count - 1) * len(pkt)

            rep_packet = self._make_rep_packet(pkt)
            if rep_packet is None:
                continue

            if self._use_bitmap:
                # B 方案: 只发给真正缺的人 (通过回调传 recipients)
                recipients = self._bitmap.recipients(frame_id, frag_id)
                if self._retransmit:
                    self._retransmit(rep_packet, recipients)
                for cid in clients:
                    self._bitmap.clear(frame_id, frag_id, cid)
            else:
                # A 方案: 无脑广播
                if self._retransmit:
                    self._retransmit(rep_packet, None)  # None = broadcast

        self._pending.clear()
        self._last_flush = time.monotonic()

    def _make_rep_packet(self, orig_packet: bytes) -> Optional[bytes]:
        """基于原始包重建 ARQ_REP。

        关键修复：不能用基类的 _make_rep_header —— 它把 total_frags 挪用成
        "等待者数"，并且丢掉了 stream_id / FEC_PARITY / ENCRYPTED 标志位。
        接收端拿到这种头，重组器会算错应有分片数、也不知道 payload 是密文。
        这里改为：完整保留原头字段，只额外 OR 上 ARQ_REP 位。
        """
        try:
            h = unpack_header(orig_packet)
        except HeaderError:
            return None
        rep_header = pack_header(
            session_tag=h.session_tag,
            frame_id=h.frame_id,
            frag_id=h.frag_id,
            total_frags=h.total_frags,      # 保真，不再挪用
            flags=h.flags | FLAG_ARQ_REP,   # 保留 ENCRYPTED / FEC_PARITY
            stream_id=h.stream_id,
            frame_len=h.frame_len,          # 保留原始帧长
        )
        return rep_header + orig_packet[HEADER_SIZE:]

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

    算法 (FEC 感知版):
    - 一帧 RS(k,n) 只要收到任意 k 片即可解出, 不需要凑齐特定分片
    - 所以只请求 "亏空数" deficit = k - 已收片数, 而不是所有缺失片
    - 优先请求数据片 (frag_id < k), 冗余片不值得重传
    - 给 FEC 和在途包留一个 grace 窗口, 避免刚丢就狂发 REQ
    - 指数退避: 同一分片重试间隔翻倍, 防止 ARQ 风暴
    """
    def __init__(self, session_tag: int, client_id: int,
                 arq_client: ARQClient,
                 rto_ms: int = 50, max_retries: int = 5,
                 fec_k: int = 10, fec_n: int = 14):
        self.session_tag = session_tag
        self.client_id = client_id
        self._arq = arq_client
        self.rto_ms = rto_ms
        self.max_retries = max_retries
        self.fec_k = fec_k
        self.fec_n = fec_n

        # frame_id -> {"total": int, "recv": set(frag_id),
        #              "first": float, "retry": {frag_id: (n, last_time)},
        #              "gaveup": bool}
        self._frames: dict = {}
        self._completed_frames: set = set()  # 已交付帧, 后续分片不再重建状态
        self._lock = threading.Lock()
        self._stats = {
            "loss_detected": 0,
            "reqs_sent": 0,
            "retries_exhausted": 0,
            "frames_gaveup": 0,
            "recovered_by_arq": 0,
        }

    def on_packet_received(self, frame_id: int, frag_id: int,
                           total_frags: int, now: float = None):
        """每收到一个分片调用。更新状态。"""
        if now is None:
            now = time.monotonic()
        with self._lock:
            if frame_id in self._completed_frames:
                return  # 帧已交付, 迟到的分片不重建状态
            f = self._frames.get(frame_id)
            if f is None:
                f = {"total": total_frags, "recv": set(), "first": now,
                     "retry": {}, "gaveup": False}
                self._frames[frame_id] = f
            if total_frags > f["total"]:
                f["total"] = total_frags
            f["recv"].add(frag_id)

    def check_loss(self, now: float = None) -> list:
        """
        扫描所有帧, 返回需要请求重传的 [(frame_id, frag_id), ...]
        应在主循环中定期调用 (如每 10ms)。
        """
        if now is None:
            now = time.monotonic()
        requests = []
        with self._lock:
            for frame_id, f in list(self._frames.items()):
                if f["gaveup"]:
                    continue
                # grace: 第一个分片到达后 rto 内不发 REQ, 等 FEC / 在途包
                if (now - f["first"]) * 1000 < self.rto_ms:
                    continue

                need = self.fec_k - len(f["recv"])
                if need <= 0:
                    continue  # 片数够 FEC 解码, 交给重组器

                # 只挑数据片, 按 frag_id 升序, 取 need 个
                missing = [i for i in range(self.fec_k)
                           if i not in f["recv"]]
                if not missing:
                    # 数据片都在但总数不足 → 补请求冗余片
                    missing = [i for i in range(self.fec_k, f["total"])
                               if i not in f["recv"]]
                targets = missing[:need]

                exhausted = 0
                for frag_id in targets:
                    n, last = f["retry"].get(frag_id, (0, f["first"]))
                    if n >= self.max_retries:
                        exhausted += 1
                        self._stats["retries_exhausted"] += 1
                        continue
                    backoff = self.rto_ms * (2 ** n) / 1000.0
                    if (now - last) >= backoff:
                        requests.append((frame_id, frag_id))
                        f["retry"][frag_id] = (n + 1, now)
                        self._stats["reqs_sent"] += 1
                        if n == 0:
                            self._stats["loss_detected"] += 1

                # 所有候选片都重试耗尽 → 放弃整帧
                if targets and exhausted == len(targets):
                    f["gaveup"] = True
                    self._stats["frames_gaveup"] += 1
        return requests

    def on_frame_complete(self, frame_id: int):
        """帧重组完成, 清理。"""
        with self._lock:
            self._frames.pop(frame_id, None)
            self._completed_frames.add(frame_id)
            # 防止 completed 集合无界增长 (保留最近 1024 帧)
            if len(self._completed_frames) > 1024:
                self._completed_frames = set(
                    list(self._completed_frames)[-512:])

    def on_rep_received(self, frame_id: int, frag_id: int):
        """收到 ARQ_REP, 标记已恢复。"""
        with self._lock:
            if frame_id in self._completed_frames:
                return  # 帧已交付, 迟到的 REP 无意义
            f = self._frames.get(frame_id)
            if f is not None and frag_id not in f["recv"]:
                f["recv"].add(frag_id)
                self._stats["recovered_by_arq"] += 1

    def gaveup_frames(self) -> list:
        with self._lock:
            return [fid for fid, f in self._frames.items() if f["gaveup"]]

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
                 rto_ms: int = 50, max_retries: int = 5,
                 fec_k: int = 10, fec_n: int = 14,
                 stream_id: int = 0):
        self.client_id = client_id
        self.session_tag = session_tag
        self.stream_id = stream_id
        self._reasm = reassembler
        self._decrypt = decryptor_func
        self._send_arq = send_arq_func
        self._on_complete = on_frame_complete

        self._arq_client = ARQClient(session_tag, client_id,
                                     send_callback=send_arq_func,
                                     stream_id=stream_id)
        self._loss = LossDetector(session_tag, client_id, self._arq_client,
                                  rto_ms=rto_ms, max_retries=max_retries,
                                  fec_k=fec_k, fec_n=fec_n)

        self.completed_frames: dict = {}
        self.corrupted_frames = 0
        self._lock = threading.Lock()
        self._stats = {
            "pkts_in": 0,
            "decrypt_ok": 0,
            "decrypt_fail": 0,
            "rep_in": 0,
            "rep_used": 0,
        }

    # --- 核心: 逐分片解密, 解密完成之后才交给重组器 ---
    def _open(self, packet: bytes, hdr) -> Optional[bytes]:
        """把一个线上包还原成 [16B 明文头 + 明文分片]。

        这是本次修复的核心：加密是 **按分片粒度** 做的, 每片多 24B
        (8B nonce + 16B Poly1305 tag)。所以必须先逐片解密剥掉这 24B,
        再把等长明文分片交给 Reassembler 拼帧。
        以前 SkySender 加密后忘了置 FLAG_ENCRYPTED, 接收端据此判断
        "没加密" → 直接把密文当明文拼 → 10×624=6240B, 帧校验必然失败。
        """
        payload = packet[HEADER_SIZE:]
        if hdr.is_encrypted():
            # REP 与原包同 nonce → 豁免防重放 (KNOWN_LIMITATIONS #12)
            is_rep = hdr.is_arq_rep()
            try:
                plain = self._decrypt(payload, is_rep=is_rep)
            except TypeError:
                # 兼容旧式 decryptor_func(packet) 单参签名
                plain = self._decrypt(payload)
            if plain is None:
                self._stats["decrypt_fail"] += 1
                return None
            self._stats["decrypt_ok"] += 1
        else:
            plain = payload

        # 重建头: 去掉 ENCRYPTED / ARQ_REP 位, 让重组器看到"一个普通分片"
        clean_flags = hdr.flags & ~(FLAG_ENCRYPTED | FLAG_ARQ_REP)
        clean_hdr = pack_header(
            session_tag=hdr.session_tag,
            frame_id=hdr.frame_id,
            frag_id=hdr.frag_id,
            total_frags=hdr.total_frags,
            flags=clean_flags,
            stream_id=hdr.stream_id,
            frame_len=hdr.frame_len,
        )
        return clean_hdr + plain

    def feed(self, packet: bytes, now: float = None):
        """喂入一个原始包 (可能加密)。"""
        if now is None:
            now = time.monotonic()
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return
        if hdr.session_tag != self.session_tag:
            return
        if hdr.stream_id != self.stream_id:
            return  # 只处理本流的包 (视频/控制/遥测各自独立)
        if hdr.is_arq_req():
            return  # 地面端不处理别人的重传请求

        self._stats["pkts_in"] += 1
        is_rep = hdr.is_arq_rep()
        if is_rep:
            self._stats["rep_in"] += 1

        # 1) 逐片解密 (先解密, 后重组 —— 顺序不能反)
        full_packet = self._open(packet, hdr)
        if full_packet is None:
            # 解密失败 (篡改 / 重放 / 重复重传) → 当作没收到, 留给 FEC/ARQ
            return

        # 2) 更新缺失检测器
        if is_rep:
            self._loss.on_rep_received(hdr.frame_id, hdr.frag_id)
            self._arq_client.ack_received(hdr.frame_id, hdr.frag_id)
            self._stats["rep_used"] += 1
        else:
            self._loss.on_packet_received(hdr.frame_id, hdr.frag_id,
                                          hdr.total_frags, now)

        # 3) 交给重组器拼帧
        result = self._reasm.feed(full_packet)
        if result is not None:
            self._handle_complete(hdr.frame_id, result, now)

    def _handle_complete(self, frame_id: int, frame_data: bytes, now: float):
        with self._lock:
            self.completed_frames[frame_id] = frame_data
        self._loss.on_frame_complete(frame_id)
        self._arq_client.clear_frame(frame_id)
        if self._on_complete:
            self._on_complete(self.client_id, frame_id, frame_data)

    def tick_loss_check(self, now: float = None):
        """主循环调用: 检查缺失, 发送 ARQ_REQ"""
        if now is None:
            now = time.monotonic()
        requests = self._loss.check_loss(now)
        for (fid, frag_id) in requests:
            # allow_resend: LossDetector 自带指数退避, 不能被 inflight 卡死
            self._arq_client.request(fid, frag_id, allow_resend=True)
        # 放弃的帧: 释放重组器 buffer
        for fid in self._loss.gaveup_frames():
            self._reasm.drop_frame(fid)
            self._arq_client.clear_frame(fid)

    def stats(self) -> dict:
        s = dict(self._stats)
        return {
            "completed": len(self.completed_frames),
            "corrupted": self.corrupted_frames,
            "loss": self._loss.stats(),
            "rx": s,
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
            "packets_encrypted": 0,
            "retransmits": 0,
        }

    def send_frame(self, frame_data: bytes, frame_id: int,
                   stream_id: int = 0, key_frame: bool = False,
                   now: float = None) -> int:
        """发送一帧: 分片 → (加密) → 存储 → 发送"""
        if now is None:
            now = time.monotonic()

        # 1) 分片 (Fragmenter 内部处理 FEC, 对明文做 RS 编码)
        packets = self._frag.fragment(frame_data, stream_id=stream_id,
                                      key_frame=key_frame)

        # 2) 重写 frame_id + 逐分片加密 + 置 ENCRYPTED 标志 (一趟完成)
        #    顺序: 明文分片 → RS 编码 → 逐片加密
        #    对应接收端: 逐片解密 → RS 解码 → 拼帧
        packets = self._seal(packets, frame_id)

        # 3) 存入 PacketStore (存的是最终线上包, 重传时原样发)
        self._store.put(frame_id, packets, now=now)

        # 4) 发送
        for pkt in packets:
            self._send(pkt)
            self._stats["packets_sent"] += 1
            self._stats["bytes_sent"] += len(pkt)

        self._stats["frames_sent"] += 1
        return len(packets)

    def _seal(self, packets: list, frame_id: int) -> list:
        """重写 frame_id, 并按分片粒度加密。

        修复点：加密后必须在头里置 FLAG_ENCRYPTED。
        以前漏了这一位, 接收端 hdr.is_encrypted() 恒为 False,
        于是把 "8B nonce + 16B tag + 密文" 整块当作明文分片拼接,
        重组出 10×(600+24)=6240B 的垃圾帧。
        """
        out = []
        for pkt in packets:
            payload = pkt[HEADER_SIZE:]
            try:
                old = unpack_header(pkt)
            except HeaderError:
                out.append(pkt)
                continue

            flags = old.flags
            if self._encrypt is not None:
                payload = self._encrypt(payload)   # +24B (nonce+tag)
                flags |= FLAG_ENCRYPTED            # ← 关键的一位
                self._stats["packets_encrypted"] += 1

            new_hdr = pack_header(
                session_tag=old.session_tag,
                frame_id=frame_id,                 # 外部指定, 覆盖内部自增
                frag_id=old.frag_id,
                total_frags=old.total_frags,
                flags=flags,
                stream_id=old.stream_id,
                frame_len=old.frame_len,           # 保留原始帧长
            )
            out.append(new_hdr + payload)
        return out

    def handle_arq_request(self, packet: bytes, client_id: int):
        """天空端收到 ARQ_REQ 时调用"""
        self._arq.receive_request(packet, client_id)

    def tick_arq(self, now: float = None):
        """主循环调用: 按合并窗口节流刷新 (保住聚合效果)"""
        self._arq.maybe_flush(now)

    def flush_arq(self):
        """强制刷新 ARQ 聚合器 (收尾/测试用)"""
        self._arq.flush()

    def _retransmit(self, packet: bytes, recipients: Optional[list] = None):
        """实际重传函数 (可注入 recipients 做 B 方案)"""
        self._send(packet, recipients)
        self._stats["packets_sent"] += 1
        self._stats["retransmits"] += 1
        self._stats["bytes_sent"] += len(packet)

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
