"""
SwarmLink v0.2 — 完整集成测试套件
=====================================
测试项:
  1. 安全层: DH握手 / 加解密 / 防重放 / 篡改检测 / 前向安全 / 会话隔离
  2. ARQ 完整链路: 发送→丢包→检测→ARQ→重传→恢复 (无加密)
  3. 安全 + ARQ 集成: 加密帧经丢包+重传后正确还原
  4. ARQ 聚合效率: 多客户端合并重传
  5. B 方案位图: 精确发送给缺片者
  6. 性能基准

运行: python3 tests/test_full_suite.py
"""

import os
import sys
import time
import random
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.header import (
    pack_header, unpack_header, HeaderError,
    FLAG_ARQ_REQ, FLAG_ARQ_REP, FLAG_LAST_FRAG,
    FLAG_KEY_FRAME, FLAG_ENCRYPTED,
    flags_for, HEADER_SIZE,
)
from protocol.fragment import Fragmenter, Reassembler
from protocol.rs_codec import ReedSolomon
from protocol.arq import ARQClient, ClientBitmap
from protocol.arq_full import (
    PacketStore, ARQAggregatorV2, LossDetector,
    GroundReceiver, SkySender,
)
from protocol.security import (
    KeyPair, Encryptor, Decryptor, SessionManager,
    SecurePacketBuilder, benchmark_throughput,
)


# ============================================================
# 工具: 有损链路
# ============================================================
class Link:
    def __init__(self, loss_rate=0.20, seed=42, ab_loss=None, ba_loss=None):
        self.rng = random.Random(seed)
        self.ab_loss = ab_loss if ab_loss else loss_rate
        self.ba_loss = ba_loss if ba_loss else loss_rate * 0.3
        self.ab_queue = []
        self.ba_queue = []
        self.stats = {"sent": 0, "lost_ab": 0, "lost_ba": 0}

    def send_ab(self, pkt, recipients=None):
        self.stats["sent"] += 1
        if self.rng.random() < self.ab_loss:
            self.stats["lost_ab"] += 1
        else:
            self.ab_queue.append(pkt)

    def send_ba(self, pkt, recipients=None):
        if self.rng.random() < self.ba_loss:
            self.stats["lost_ba"] += 1
        else:
            self.ba_queue.append(pkt)

    def drain_ab(self):
        q = list(self.ab_queue)
        self.ab_queue.clear()
        return q

    def drain_ba(self):
        q = list(self.ba_queue)
        self.ba_queue.clear()
        return q


# ============================================================
# Test 1: 安全层
# ============================================================
def test_security_layer():
    print("\n" + "─" * 55)
    print("  Test 1: 安全层")
    print("─" * 55)

    # 1a: DH 握手 + 加解密往返
    alice = SessionManager(b"alice")
    bob = SessionManager(b"bob")
    alice_pub = alice.initiate_handshake()
    bob_pub = bob.accept_handshake(alice_pub, b"alice")
    alice.finalize_handshake(bob_pub, b"bob")

    assert alice.is_established and bob.is_established
    assert alice.session_key == bob.session_key
    print(f"  ✓ DH 握手 + HKDF 派生 session_key 成功")
    print(f"    key = {alice.session_key.hex()[:32]}...")

    builder_a = SecurePacketBuilder(alice, 0x1000)
    builder_b = SecurePacketBuilder(bob, 0x1000)

    for i in range(20):
        data = f"secret-payload-{i}".encode() * 15
        pkt = builder_a.build_secure_packet(
            frame_id=i, frag_id=0, total_frags=1,
            stream_id=0, payload=data, key_frame=(i == 0))
        result = builder_b.open_secure_packet(pkt)
        assert result is not None, f"解密失败 i={i}"
        hdr, plain = result
        assert plain == data, f"明文不匹配 i={i}"
    print(f"  ✓ 加解密往返 20/20 成功")

    # 1b: 防重放
    pkt = builder_a.build_secure_packet(99, 0, 1, 0, b"replay")
    r1 = builder_b.open_secure_packet(pkt)
    assert r1 is not None
    r2 = builder_b.open_secure_packet(pkt)
    assert r2 is None, "重放应被拒绝!"
    print(f"  ✓ 防重放: 同包二次提交 → nonce 窗口拒绝")

    # 1c: 篡改检测
    pkt2 = builder_a.build_secure_packet(100, 0, 1, 0, b"tamper")
    tampered = bytearray(pkt2)
    tampered[HEADER_SIZE + 10] ^= 0xFF
    r3 = builder_b.open_secure_packet(bytes(tampered))
    assert r3 is None
    print(f"  ✓ 篡改检测: 密文 1 bit 翻转 → MAC 失败")

    # 1d: 前向安全
    sm_a = SessionManager(b"A")
    sm_b = SessionManager(b"B")
    p1 = sm_a.initiate_handshake()
    p2 = sm_b.accept_handshake(p1, b"A")
    sm_a.finalize_handshake(p2, b"B")
    key1 = sm_a.session_key

    sm_c = SessionManager(b"A")
    sm_d = SessionManager(b"B")
    p3 = sm_c.initiate_handshake()
    p4 = sm_d.accept_handshake(p3, b"A")
    sm_c.finalize_handshake(p4, b"B")
    key2 = sm_c.session_key
    assert key1 != key2
    print(f"  ✓ 前向安全: 每会话新 ephemeral key, key 不同")

    # 1e: 会话隔离
    sm_e = SessionManager(b"alice")
    sm_f = SessionManager(b"bob")
    pe = sm_e.initiate_handshake()
    pf = sm_f.accept_handshake(pe, b"alice")
    sm_e.finalize_handshake(pf, b"bob")
    key_ab = sm_e.session_key

    sm_g = SessionManager(b"alice")
    sm_h = SessionManager(b"charlie")
    pg = sm_g.initiate_handshake()
    ph = sm_h.accept_handshake(pg, b"alice")
    sm_g.finalize_handshake(ph, b"charlie")
    key_ac = sm_g.session_key
    assert key_ab != key_ac
    print(f"  ✓ 会话隔离: Alice-Bob ≠ Alice-Charlie")


# ============================================================
# Test 2: ARQ 完整链路 (无加密)
# ============================================================
def test_arq_full_chain():
    print("\n" + "─" * 55)
    print("  Test 2: ARQ 完整链路 (无加密, 20% 丢包)")
    print("─" * 55)

    SESSION = 0xAAAA
    rng = random.Random(123)
    link = Link(loss_rate=0.20, seed=123)

    fragger = Fragmenter(SESSION, chunk_size=400, fec_k=10, fec_n=14)
    store = PacketStore(max_frames=60)
    sender = SkySender(
        session_tag=SESSION, fragmenter=fragger,
        encrypt_func=None, send_callback=link.send_ab,
        packet_store=store, arq_window_ms=5,
    )

    reasm = Reassembler(SESSION, fec_k=10, fec_n=14)
    completed = {}
    arq_client = None

    def on_complete(cid, fid, data):
        completed[fid] = data

    receiver = GroundReceiver(
        client_id=0, session_tag=SESSION,
        reassembler=reasm,
        decryptor_func=lambda x: x,
        send_arq_func=link.send_ba,
        on_frame_complete=on_complete,
        rto_ms=10,
    )

    # 发送 5 帧
    original = {}
    for fid in range(5):
        data = f"frame-{fid}-data-".encode() * (20 + fid * 5)
        original[fid] = data
        sender.send_frame(data, frame_id=fid, key_frame=(fid == 0))

    print(f"  发送 5 帧, 链路丢包率 20%")

    # 模拟循环
    for it in range(2000):
        # B→A: ARQ 请求
        for req in link.drain_ba():
            try:
                hdr = unpack_header(req)
                if hdr.is_arq_req():
                    sender.handle_arq_request(req, client_id=0)
            except: pass
        sender.flush_arq()

        # A→B: 数据包
        for pkt in link.drain_ab():
            receiver.feed(pkt)

        if len(completed) >= 5:
            print(f"  ✓ 5/5 帧在 {it+1} 轮后全部恢复")
            break

        receiver.tick_loss_check()
        time.sleep(0.0001)

    assert len(completed) == 5, f"只完成 {len(completed)}/5"
    for fid in range(5):
        assert completed[fid] == original[fid], f"Frame {fid} 不匹配"
    print(f"  ✓ 全部 5 帧数据校验通过")
    s = sender.stats()
    print(f"  ✓ ARQ 合并: 接收 {s['arq']['reqs_received']} 请求, "
          f"节省 {s['arq']['reqs_merged']} 次重传 "
          f"({s['arq']['merge_rate_pct']}%)")
    print(f"  ✓ 链路: 发送 {link.stats['sent']}, "
          f"丢失 {link.stats['lost_ab']}")


# ============================================================
# Test 3: 安全 + ARQ 集成
# ============================================================
def test_secure_arq():
    print("\n" + "─" * 55)
    print("  Test 3: 安全 + ARQ 集成 (25% 丢包)")
    print("─" * 55)

    SESSION = 0x5EC0DE

    # DH 握手
    sky_sm = SessionManager(b"sky")
    grd_sm = SessionManager(b"ground")
    sp = sky_sm.initiate_handshake()
    gp = grd_sm.accept_handshake(sp, b"sky")
    sky_sm.finalize_handshake(gp, b"ground")
    print(f"  ✓ DH 握手完成")

    rng = random.Random(777)
    link = Link(loss_rate=0.25, seed=777)

    # 天空端: 分片 + 加密
    fragger = Fragmenter(SESSION, chunk_size=300, fec_k=10, fec_n=14)
    store = PacketStore(max_frames=60)

    def sky_encrypt(payload):
        return sky_sm.encrypt_payload(payload)

    sender = SkySender(
        session_tag=SESSION, fragmenter=fragger,
        encrypt_func=sky_encrypt,
        send_callback=link.send_ab,
        packet_store=store, arq_window_ms=5,
    )

    # 地面端: 解密 + 重组
    reasm = Reassembler(SESSION, fec_k=10, fec_n=14)
    completed = {}

    class SecureRecv:
        def __init__(self):
            self.loss = None
            self.arq = ARQClient(SESSION, 0, send_callback=link.send_ba)

        def feed(self, pkt):
            try:
                hdr = unpack_header(pkt)
            except: return
            if hdr.is_arq_rep():
                sec = pkt[HEADER_SIZE:]
                plain = grd_sm.decrypt_payload(sec)
                if plain is not None:
                    fake = pkt[:HEADER_SIZE] + plain
                    r = reasm.feed(fake)
                    if r is not None:
                        completed[hdr.frame_id] = r
                return
            sec = pkt[HEADER_SIZE:]
            plain = grd_sm.decrypt_payload(sec)
            if plain is None: return
            fake = pkt[:HEADER_SIZE] + plain
            r = reasm.feed(fake)
            if r is not None:
                completed[hdr.frame_id] = r

        def tick(self):
            # 简化: 扫描 buffer 找缺失
            requests = []
            for fid, buf in list(reasm._buffers.items()):
                if fid in completed: continue
                for i in range(10):
                    if i not in buf:
                        requests.append((fid, i))
                        if len(requests) >= 3: break
                if len(requests) >= 3: break
            for (fid, frid) in requests:
                self.arq.request(fid, frid)
            return requests

    recv = SecureRecv()

    # 发送 3 帧加密数据
    original = {}
    for fid in range(3):
        data = f"encrypted-frame-{fid}-".encode() * 25
        original[fid] = data
        sender.send_frame(data, frame_id=fid, key_frame=(fid == 0))

    print(f"  发送 3 帧加密数据, 25% 丢包")

    # 模拟循环
    for it in range(3000):
        # ARQ 请求
        for req in link.drain_ba():
            try:
                hdr = unpack_header(req)
                if hdr.is_arq_req():
                    sender.handle_arq_request(req, 0)
            except: pass
        sender.flush_arq()

        # 数据包
        for pkt in link.drain_ab():
            recv.feed(pkt)

        if len(completed) >= 3:
            print(f"  ✓ 3/3 加密帧在 {it+1} 轮后解密还原")
            break

        recv.tick()
        time.sleep(0.0001)

    assert len(completed) == 3
    for fid in range(3):
        assert completed[fid] == original[fid], f"Frame {fid} 不匹配"
    print(f"  ✓ 全部 3 帧解密后数据完整匹配")
    print(f"  ✓ 链路: 发送 {link.stats['sent']}, "
          f"丢失 {link.stats['lost_ab']}")


# ============================================================
# Test 4: ARQ 聚合效率
# ============================================================
def test_arq_aggregation():
    print("\n" + "─" * 55)
    print("  Test 4: ARQ 聚合效率")
    print("─" * 55)

    SESSION = 0x5555
    store = PacketStore(max_frames=10)

    # 预填 14 个包
    fid = 3
    packets = []
    for i in range(14):
        p = pack_header(SESSION, fid, i, 14, 0, 0) + f"data-{i}".encode() * 10
        packets.append(p)
    store.put(fid, packets)

    for n_clients in [2, 4, 8, 16, 32]:
        retransmits = []
        agg = ARQAggregatorV2(
            session_tag=SESSION, packet_store=store,
            retransmit_callback=lambda p, r=None: retransmits.append(p),
            window_ms=5,
        )
        for cid in range(n_clients):
            req = pack_header(SESSION, fid, 5, 1, FLAG_ARQ_REQ, 0)
            agg.receive_request(req, cid)
        agg.flush()

        assert len(retransmits) == 1, f"{n_clients}客户端: {len(retransmits)}次重传"
        bw_save = (1 - 1 / n_clients) * 100
        print(f"    {n_clients:3d} 客户端 → 1 次重传, "
              f"节省带宽 {bw_save:5.1f}%")


# ============================================================
# Test 5: B 方案位图精确发送
# ============================================================
def test_bitmap_selective():
    print("\n" + "─" * 55)
    print("  Test 5: B 方案位图精确发送")
    print("─" * 55)

    SESSION = 0x7777
    store = PacketStore(max_frames=10)
    fid = 0
    packets = []
    for i in range(14):
        p = pack_header(SESSION, fid, i, 14, 0, 0) + b"x" * 50
        packets.append(p)
    store.put(fid, packets)

    sent_list = []
    agg = ARQAggregatorV2(
        session_tag=SESSION, packet_store=store,
        retransmit_callback=lambda p, r=None: sent_list.append(r),
        window_ms=5, use_bitmap=True, max_clients=8,
    )

    # Client 0, 3, 7 缺 (0, 5)
    for cid in [0, 3, 7]:
        req = pack_header(SESSION, fid, 5, 1, FLAG_ARQ_REQ, 0)
        agg.receive_request(req, cid)
    agg.flush()

    assert len(sent_list) == 1
    assert sent_list[0] == [0, 3, 7]
    print(f"  ✓ 精确发送给缺片者: {sent_list[0]}")

    # 验证 bitmap 状态
    bm = agg._bitmap
    assert bm.recipients(fid, 5) == [0, 3, 7]
    bm.clear(fid, 5, 3)
    assert bm.recipients(fid, 5) == [0, 7]
    print(f"  ✓ 位图动态更新: 移除 client 3 → {bm.recipients(fid, 5)}")


# ============================================================
# Test 6: 性能基准
# ============================================================
def test_performance():
    print("\n" + "─" * 55)
    print("  Test 6: 性能基准")
    print("─" * 55)

    benchmark_throughput(800, 300)
    benchmark_throughput(1400, 300)

    # 不同丢包率下的 FEC 恢复率
    print(f"\n  不同丢包率下的 FEC(10,14) 恢复率:")
    print(f"  {'丢包率':>8s}  {'送达率':>8s}  {'可恢复':>8s}  {'恢复率':>8s}")
    rng = random.Random(42)
    for loss in [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]:
        recovered = 0
        total = 100
        for _ in range(total):
            # 14 个包, 每个独立丢包
            received = [i for i in range(14) if rng.random() > loss]
            data_cnt = sum(1 for i in received if i < 10)
            total_cnt = len(received)
            if data_cnt >= 10 or total_cnt >= 10:
                recovered += 1
        recv_rate = (1 - loss) * 100
        pct = recovered / total * 100
        print(f"  {loss*100:7.0f}%  {recv_rate:7.1f}%  "
              f"{recovered:8d}  {pct:7.1f}%")


# ============================================================
# 主入口
# ============================================================
if __name__ == "__main__":
    print("=" * 58)
    print("  SwarmLink v0.2 — 完整集成测试套件")
    print("  安全层 + ARQ 链路 + 聚合 + 性能基准")
    print("=" * 58)

    t0 = time.monotonic()

    test_security_layer()
    test_arq_full_chain()
    test_secure_arq()
    test_arq_aggregation()
    test_bitmap_selective()
    test_performance()

    elapsed = (time.monotonic() - t0) * 1000
    print(f"\n{'=' * 58}")
    print(f"  ✅ 全部 6 项测试通过!  总耗时 {elapsed:.0f}ms")
    print(f"{'=' * 58}")
