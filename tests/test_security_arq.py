"""
SwarmLink v0.2 集成测试
========================
测试覆盖:
1. 安全层: DH 握手 → session_key → 加解密 → 防重放 → 篡改检测
2. ARQ 完整链路: 发送 → 丢包 → 检测 → 请求 → 重传 → 恢复
3. 安全 + ARQ 集成: 加密包经过 ARQ 重传后正确解密
4. 性能度量: 不同丢包率下的完成度 + ARQ 合并效率
"""

import os
import sys
import time
import random
import threading
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.header import (
    pack_header, unpack_header, HeaderError,
    FLAG_ARQ_REQ, FLAG_ARQ_REP, FLAG_ENCRYPTED,
    FLAG_KEY_FRAME, flags_for, HEADER_SIZE,
)
from protocol.fragment import Fragmenter, Reassembler
from protocol.arq import ARQAggregator, ARQClient, ClientBitmap
from protocol.arq_full import (
    PacketStore, ARQAggregatorV2, LossDetector,
    GroundReceiver, SkySender,
)
from protocol.security import (
    KeyPair, Encryptor, Decryptor, SessionManager,
    SecurePacketBuilder, derive_sub_key,
    SECURITY_HEADER_SIZE, NONCE_SIZE, TAG_SIZE,
    benchmark_throughput,
)


# ============================================================
# 1. 安全层测试
# ============================================================
class TestSecurity:
    def setup_method(self):
        # 两个设备各生成 key pair
        self.alice_sm = SessionManager(b"alice")
        self.bob_sm = SessionManager(b"bob")
        self.alice_pub = self.alice_sm.initiate_handshake()
        self.bob_pub = self.bob_sm.accept_handshake(
            self.alice_pub, b"alice")
        self.alice_sm.finalize_handshake(self.bob_pub, b"bob")
        assert self.alice_sm.is_established
        assert self.bob_sm.is_established
        assert self.alice_sm.session_key == self.bob_sm.session_key

    def test_encrypt_decrypt_roundtrip(self):
        alice_b = SecurePacketBuilder(self.alice_sm, 0x1234)
        bob_b = SecurePacketBuilder(self.bob_sm, 0x1234)

        for i in range(20):
            data = f"secret-frame-{i}".encode() * 10
            pkt = alice_b.build_secure_packet(
                frame_id=i, frag_id=0, total_frags=1,
                stream_id=0, payload=data, key_frame=(i == 0),
            )
            result = bob_b.open_secure_packet(pkt)
            assert result is not None, f"解密失败 fid={i}"
            hdr, plaintext = result
            assert plaintext == data, f"明文不匹配 fid={i}"
            assert hdr.is_encrypted()
            if i == 0:
                assert hdr.is_key_frame()

    def test_replay_protection(self):
        alice_b = SecurePacketBuilder(self.alice_sm, 0xAAAA)
        bob_b = SecurePacketBuilder(self.bob_sm, 0xAAAA)

        data = b"replay-test"
        pkt = alice_b.build_secure_packet(1, 0, 1, 0, data)

        # 第一次: 成功
        r1 = bob_b.open_secure_packet(pkt)
        assert r1 is not None

        # 重放: 应被拒绝
        r2 = bob_b.open_secure_packet(pkt)
        assert r2 is None, "重放包应该被拒绝!"

    def test_tamper_detection(self):
        alice_b = SecurePacketBuilder(self.alice_sm, 0xBBBB)
        bob_b = SecurePacketBuilder(self.bob_sm, 0xBBBB)

        pkt = alice_b.build_secure_packet(1, 0, 1, 0, b"tamper-me")
        # 篡改密文
        tampered = bytearray(pkt)
        tampered[HEADER_SIZE + NONCE_SIZE + TAG_SIZE] ^= 0xFF
        result = bob_b.open_secure_packet(bytes(tampered))
        assert result is None, "篡改的包应该被拒绝!"

    def test_forward_secrecy(self):
        """每次新会话, key 不同"""
        sm1 = SessionManager(b"dev1")
        sm2 = SessionManager(b"dev2")
        pub1 = sm1.initiate_handshake()
        pub2 = sm2.accept_handshake(pub1, b"dev1")
        sm1.finalize_handshake(pub2, b"dev2")
        key1 = sm1.session_key

        # 新会话
        sm3 = SessionManager(b"dev1")
        sm4 = SessionManager(b"dev2")
        pub3 = sm3.initiate_handshake()
        pub4 = sm4.accept_handshake(pub3, b"dev1")
        sm3.finalize_handshake(pub4, b"dev2")
        key2 = sm3.session_key

        assert key1 != key2, "不同会话应有不同 key"

    def test_session_isolation(self):
        """设备 A-B 和 A-C 的 session_key 应不同"""
        sm_ab_alice = SessionManager(b"alice")
        sm_ab_bob = SessionManager(b"bob")
        pub_a = sm_ab_alice.initiate_handshake()
        pub_b = sm_ab_bob.accept_handshake(pub_a, b"alice")
        sm_ab_alice.finalize_handshake(pub_b, b"bob")
        key_ab = sm_ab_alice.session_key

        sm_ac_alice = SessionManager(b"alice")
        sm_ac_charlie = SessionManager(b"charlie")
        pub_c = sm_ac_alice.initiate_handshake()
        pub_d = sm_ac_charlie.accept_handshake(pub_c, b"alice")
        sm_ac_alice.finalize_handshake(pub_d, b"charlie")
        key_ac = sm_ac_alice.session_key

        assert key_ab != key_ac, "不同对端应有不同 session key"


# ============================================================
# 2. ARQ 完整链路测试
# ============================================================
class TestARQFull:
    def test_loss_detection_and_recovery(self):
        """模拟丢包 → 检测 → ARQ → 重传 → 恢复"""
        SESSION = 0xCAFE
        rng = random.Random(123)

        # 链路: 控制丢包
        sky_queue = deque()
        ground_queue = deque()
        lost_packets = []

        def sky_send(pkt, recipients=None):
            if rng.random() > 0.20:  # 80% 送达
                sky_queue.append(pkt)
            else:
                lost_packets.append(pkt)

        def ground_send(pkt):
            ground_queue.append(pkt)

        # 组件
        fragger = Fragmenter(SESSION, chunk_size=400, fec_k=10, fec_n=14)
        store = PacketStore(max_frames=60)
        sender = SkySender(
            session_tag=SESSION,
            fragmenter=fragger,
            encrypt_func=None,
            send_callback=sky_send,
            packet_store=store,
            arq_window_ms=10,
        )

        reasm = Reassembler(SESSION, fec_k=10, fec_n=14)
        receiver = GroundReceiver(
            client_id=0,
            session_tag=SESSION,
            reassembler=reasm,
            decryptor_func=lambda x: x,
            send_arq_func=ground_send,
            on_frame_complete=None,
            rto_ms=20,
        )

        # 发送 3 帧
        original = {}
        for fid in range(3):
            data = f"frame-{fid}-data".encode() * 30
            original[fid] = data
            sender.send_frame(data, frame_id=fid, key_frame=(fid == 0))

        # 模拟循环: 收包 + ARQ + 重传 (最多 50 轮)
        completed = {}
        for round in range(50):
            # 地面端收包
            while sky_queue:
                pkt = sky_queue.popleft()
                old_len = len(completed)
                receiver.feed(pkt)
                # 检查新完成
                for fid in list(receiver.completed_frames.keys()):
                    if fid not in completed:
                        completed[fid] = receiver.completed_frames[fid]

            # 天空端收 ARQ
            while ground_queue:
                req = ground_queue.popleft()
                sender.handle_arq_request(req, client_id=0)

            sender.flush_arq()
            receiver.tick_loss_check()

            if len(completed) >= 3:
                break
            time.sleep(0.001)

        # 验证
        assert len(completed) == 3, f"只完成 {len(completed)}/3 帧"
        for fid in range(3):
            assert completed[fid] == original[fid], f"Frame {fid} 不匹配"
        print(f"\n  ✓ ARQ 完整链路: 3/3 帧恢复, "
              f"丢失 {len(lost_packets)} 包经重传修复")

    def test_arq_aggregation_efficiency(self):
        """多客户端请求同片 → 合并为 1 次重传"""
        SESSION = 0x5555
        store = PacketStore(max_frames=10)

        # 预填包
        for fid in range(2):
            for frid in range(14):
                pkt = pack_header(SESSION, fid, frid, 14, 0, 0) + b"x" * 100
                store.put(fid, [pkt])

        retransmits = []
        agg = ARQAggregatorV2(
            session_tag=SESSION,
            packet_store=store,
            retransmit_callback=lambda p, r=None: retransmits.append(p),
            window_ms=10,
        )

        # 8 个客户端都请求 (0, 5)
        for cid in range(8):
            req = pack_header(SESSION, 0, 5, 1, FLAG_ARQ_REQ, 0)
            agg.receive_request(req, cid)

        agg.flush()

        assert len(retransmits) == 1, f"应该只重传 1 次, 实际 {len(retransmits)}"
        s = agg.stats()
        assert s["merge_rate_pct"] == 87.5, f"合并率应为 87.5%, 实际 {s['merge_rate_pct']}"
        print(f"\n  ✓ ARQ 聚合: 8 客户端请求 → 1 次重传 "
              f"(节省 87.5% 带宽)")

    def test_bitmap_selective_send(self):
        """B 方案: 只发给真正缺的人"""
        SESSION = 0x7777
        store = PacketStore(max_frames=10)

        pkt_0_5 = pack_header(SESSION, 0, 5, 14, 0, 0) + b"data"
        store.put(0, [pkt_0_5])

        sent_to = []
        def retransmit(pkt, recipients=None):
            sent_to.append(recipients)

        agg = ARQAggregatorV2(
            session_tag=SESSION,
            packet_store=store,
            retransmit_callback=retransmit,
            window_ms=10,
            use_bitmap=True,
            max_clients=8,
        )

        # Client 0, 3, 7 缺 (0, 5)
        for cid in [0, 3, 7]:
            req = pack_header(SESSION, 0, 5, 1, FLAG_ARQ_REQ, 0)
            agg.receive_request(req, cid)
        agg.flush()

        assert len(sent_to) == 1
        assert sent_to[0] == [0, 3, 7], f"应发给 [0,3,7], 实际 {sent_to[0]}"
        print(f"\n  ✓ B 方案位图: 精确发给缺片者 {sent_to[0]}")


# ============================================================
# 3. 安全 + ARQ 集成测试
# ============================================================
class TestSecureARQ:
    def test_encrypted_arq_recovery(self):
        """加密帧经丢包 + ARQ 重传后正确解密还原"""
        SESSION = 0x5EC0DE  # 合法十六进制 (替换无效的 0x5ECURE)

        # DH 握手
        sky_sm = SessionManager(b"sky")
        ground_sm = SessionManager(b"ground")
        sky_pub = sky_sm.initiate_handshake()
        ground_pub = ground_sm.accept_handshake(sky_pub, b"sky")
        sky_sm.finalize_handshake(ground_pub, b"ground")

        rng = random.Random(777)
        sky_queue = deque()
        ground_queue = deque()

        def sky_send(pkt, recipients=None):
            if rng.random() > 0.25:  # 75% 送达
                sky_queue.append(pkt)

        def ground_send(pkt):
            ground_queue.append(pkt)

        # 加密发送
        fragger = Fragmenter(SESSION, chunk_size=300, fec_k=10, fec_n=14)
        store = PacketStore(max_frames=60)
        sky_builder = SecurePacketBuilder(sky_sm, SESSION)

        # 包装: 加密每个包
        original_frames = {}
        sent_packets = {}

        for fid in range(3):
            data = f"secret-{fid}-".encode() * 40
            original_frames[fid] = data

            # 先分片
            raw_packets = fragger.fragment(data, stream_id=0, key_frame=(fid == 0))

            # 加密每个包
            encrypted_packets = []
            for pkt in raw_packets:
                hdr = pkt[:HEADER_SIZE]
                payload = pkt[HEADER_SIZE:]
                enc = sky_sm.encrypt_payload(payload)
                encrypted_packets.append(hdr + enc)

            sent_packets[fid] = encrypted_packets
            store.put(fid, encrypted_packets)
            for pkt in encrypted_packets:
                sky_send(pkt)

        # 地面端
        ground_builder = SecurePacketBuilder(ground_sm, SESSION)
        reasm = Reassembler(SESSION, fec_k=10, fec_n=14)

        completed = {}
        arq = ARQClient(SESSION, 0, send_callback=ground_send)

        def feed_ground(pkt):
            try:
                hdr = unpack_header(pkt)
            except HeaderError:
                return
            if hdr.is_arq_rep():
                # 解密 REP payload 后喂重组器
                security = pkt[HEADER_SIZE:]
                plain = ground_sm.decrypt_payload(security)
                if plain is not None:
                    fake = pkt[:HEADER_SIZE] + plain
                    r = reasm.feed(fake)
                    if r is not None:
                        completed[hdr.frame_id] = r
                return
            # 数据/parity 包
            security = pkt[HEADER_SIZE:]
            plain = ground_sm.decrypt_payload(security)
            if plain is not None:
                fake = pkt[:HEADER_SIZE] + plain
                r = reasm.feed(fake)
                if r is not None:
                    completed[hdr.frame_id] = r

        # 模拟循环
        for round in range(100):
            # 收包
            while sky_queue:
                feed_ground(sky_queue.popleft())

            # 检查缺失 → 发 ARQ
            # (简化: 每轮检查重组器状态)
            for fid in range(3):
                if fid in completed:
                    continue
                buf = reasm._buffers.get(fid, {})
                expected = range(10)
                missing = [i for i in expected if i not in buf]
                for mid in missing[:2]:  # 每轮最多请求 2 个
                    arq.request(fid, mid)

            # 处理 ARQ
            while ground_queue:
                req = ground_queue.popleft()
                # 天空端处理
                try:
                    hdr = unpack_header(req)
                except HeaderError:
                    continue
                if hdr.is_arq_req():
                    # 查找并重传
                    for fid in range(3):
                        pkts = sent_packets.get(fid, [])
                        for pkt in pkts:
                            try:
                                ph = unpack_header(pkt)
                                if ph.frag_id == hdr.frag_id:
                                    sky_send(pkt)
                                    break
                            except HeaderError:
                                continue

            if len(completed) >= 3:
                break
            time.sleep(0.001)

        # 验证
        assert len(completed) == 3, f"只完成 {len(completed)}/3"
        for fid in range(3):
            assert completed[fid] == original_frames[fid], \
                f"Frame {fid} 解密后不匹配"
        print(f"\n  ✓ 安全+ARQ 集成: 3/3 加密帧经丢包+重传后完整恢复")


# ============================================================
# 4. 性能度量测试
# ============================================================
class TestPerformance:
    def test_completion_vs_loss_rate(self):
        """不同丢包率下的完成度 (不加密, 纯 ARQ+FEC)"""
        SESSION = 0x7EAF  # 0xPERF 含非法字符, 改用 0x7EAF
        rng = random.Random(42)

        results = []
        for loss_rate in [0.05, 0.15, 0.25, 0.35]:
            completed_count = 0
            total_frames = 10
            rto = 20

            for fid in range(total_frames):
                # 每帧生成包
                packets = []
                for i in range(14):
                    p = pack_header(SESSION, fid, i, 14, 0, 0) + b"x" * 200
                    packets.append(p)

                # 模拟丢包
                received = [p for p in packets if rng.random() > loss_rate]

                # 检查能否恢复 (FEC: 10 数据 + 4 冗余)
                data_count = sum(1 for p in received
                               if unpack_header(p).frag_id < 10)
                total_count = len(received)
                if data_count >= 10:
                    completed_count += 1
                elif total_count >= 10:
                    completed_count += 1  # FEC 可修复

            pct = completed_count / total_frames * 100
            results.append((loss_rate, pct))
            print(f"  loss={loss_rate*100:4.0f}% → 完成度 {pct:5.1f}%")

        # 验证趋势: 丢包率越高, 完成度越低
        assert results[0][1] > results[-1][1], "趋势错误"
        print(f"  ✓ 性能度量: 完成度随丢包率递增而递减 (符合预期)")


# ============================================================
# 主入口
# ============================================================
if __name__ == "__main__":
    print("=" * 55)
    print("  SwarmLink v0.2 集成测试")
    print("  安全层 + ARQ 完整链路 + 性能度量")
    print("=" * 55)

    # 1. 安全层
    print("\n--- 1. 安全层测试 ---")
    ts = TestSecurity()
    ts.setup_method()
    ts.test_encrypt_decrypt_roundtrip()
    print("  ✓ 加解密往返 20 包全部成功")
    ts.test_replay_protection()
    print("  ✓ 防重放: 重放包被拒绝")
    ts.test_tamper_detection()
    print("  ✓ 篡改检测: MAC 验证失败")
    ts.test_forward_secrecy()
    print("  ✓ 前向安全: 不同会话 key 不同")
    ts.test_session_isolation()
    print("  ✓ 会话隔离: 不同对端 key 不同")

    # 2. ARQ 完整链路
    print("\n--- 2. ARQ 完整链路测试 ---")
    ta = TestARQFull()
    ta.test_loss_detection_and_recovery()
    ta.test_arq_aggregation_efficiency()
    ta.test_bitmap_selective_send()

    # 3. 安全 + ARQ 集成
    print("\n--- 3. 安全 + ARQ 集成测试 ---")
    tsarq = TestSecureARQ()
    tsarq.test_encrypted_arq_recovery()

    # 4. 性能
    print("\n--- 4. 性能度量 ---")
    tp = TestPerformance()
    tp.test_completion_vs_loss_rate()

    # 5. 基准
    print("\n--- 5. 加密性能基准 ---")
    benchmark_throughput(800, 200)

    print("\n" + "=" * 55)
    print("  ✅ 全部测试通过!")
    print("=" * 55)
