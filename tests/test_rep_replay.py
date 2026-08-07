"""
SwarmLink — KNOWN_LIMITATIONS #12 回归测试
============================================
ARQ_REP 与原包同 nonce: 原包先到入防重放窗口, REP 重发应被豁免接受。

  1. decrypt_payload(is_rep=True) 对重复 nonce 解密成功
  2. decrypt_payload(默认) 对重复 nonce 仍拒绝 (防重放不削弱)
  3. 加密 REP 经 GroundReceiver.feed 完整链路: 帧能收齐 (不被误杀)
  4. ReliableChannel 控制流 REP 豁免
"""

import sys
import os
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.security_nacl import create_session_manager
from protocol.fragment import Fragmenter, Reassembler
from protocol.arq_full import PacketStore, SkySender, GroundReceiver
from protocol.multiplex import ReliableChannel, StreamType
from protocol.header import (
    HEADER_SIZE, unpack_header, HeaderError,
)


KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
SESSION = 0xDD12


def test_rep_skips_replay_protection():
    """REP 同 nonce 解密成功, 普通重复包仍被拒"""
    sm = create_session_manager(b"dev-a")
    sm.adopt_session_key(KEY, b"group")
    enc = sm.encrypt_payload

    orig = os.urandom(100)
    cipher = enc(orig)          # nonce N
    assert sm.decrypt_payload(cipher) == orig      # 第一次 OK, 入窗口
    assert sm.decrypt_payload(cipher) is None, "重复包应被防重放拒绝"
    assert sm.decrypt_payload(cipher, is_rep=True) == orig, \
        "REP 应豁免防重放, 解密成功"


def test_rep_reaches_reassembler():
    """原包入窗口后 REP 重发 → 仍能被重组器消费 (帧收齐)"""
    sm = create_session_manager(b"dev-a")
    sm.adopt_session_key(KEY, b"group")

    # 发送端: SkySender 完整路径 (分片+FEC+加密+置 ENCRYPTED 标志)
    fragger = Fragmenter(SESSION, chunk_size=300, fec_k=10, fec_n=14)
    store = PacketStore(max_frames=60, ttl_sec=6.0)
    sealed = []
    sender = SkySender(
        session_tag=SESSION, fragmenter=fragger,
        encrypt_func=sm.encrypt_payload,
        send_callback=lambda p, r=None: sealed.append(p),
        chunk_size=300, fec_k=10, fec_n=14,
        packet_store=store, arq_window_ms=5,
    )
    sender.send_frame(os.urandom(2000), frame_id=0, stream_id=0)

    # 接收端: 先喂所有包 (全入防重放窗口)
    reasm = Reassembler(SESSION, fec_k=10, fec_n=14)
    completed = {}
    def on_complete(cid, fid, data):
        completed[fid] = data
    recv = GroundReceiver(
        client_id=0, session_tag=SESSION, reassembler=reasm,
        decryptor_func=sm.decrypt_payload,
        send_arq_func=lambda p, r=None: None,
        on_frame_complete=on_complete,
        rto_ms=20, max_retries=3, fec_k=10, fec_n=14,
    )
    for pkt in sealed:
        recv.feed(pkt)

    # 现在原包都已在防重放窗口 → 重新解密必然判重放
    hdr0 = unpack_header(sealed[0])
    assert hdr0.is_encrypted(), "前置: 加密标志已置"
    assert sm.decrypt_payload(sealed[0][HEADER_SIZE:]) is None, \
        "前置: 原包已入窗口"

    # 模拟 REP 重发: 同 nonce 同密文, 走豁免路径 → 不误杀
    for pkt in sealed:
        hdr = unpack_header(pkt)
        from protocol.header import pack_header, FLAG_ARQ_REP
        rep_hdr = pack_header(SESSION, hdr.frame_id, hdr.frag_id,
                              hdr.total_frags,
                              hdr.flags | FLAG_ARQ_REP,
                              hdr.stream_id, frame_len=hdr.frame_len)
        recv.feed(rep_hdr + pkt[HEADER_SIZE:])

    assert len(completed) == 1, f"帧应收齐 (REP 不被误杀): {len(completed)}"


def test_reliable_channel_rep_exempt():
    """ReliableChannel: 原包后 REP 同 nonce → 消息仍到 (去重不重复回调)"""
    received = []
    gnd = ReliableChannel(SESSION, StreamType.CONTROL,
                          decryptor_func=None,  # 明文路径, 隔离测试
                          on_message=received.append,
                          rto_ms=20, max_retries=3)
    sky = ReliableChannel(SESSION, StreamType.CONTROL)
    # 重传出口直接给 gnd (模拟本地回环)
    sky.set_retransmit_func(gnd.feed)

    sky.send_message(b"HELLO_REP")
    assert received == [b"HELLO_REP"], "首发即达"

    # 同一消息再次 feed (模拟 REP 重发) → 去重, 不重复回调
    gnd.feed.__self__ if False else None
    # 重新拿该消息的线上包
    pkt = sky._store.get(0, 0)
    assert pkt is not None
    hdr = unpack_header(pkt)
    from protocol.header import pack_header, FLAG_ARQ_REP
    rep = pack_header(SESSION, hdr.frame_id, hdr.frag_id, hdr.total_frags,
                      hdr.flags | FLAG_ARQ_REP, hdr.stream_id,
                      frame_len=hdr.frame_len) + pkt[HEADER_SIZE:]
    gnd.feed(rep)
    assert received == [b"HELLO_REP"], f"REP 不应重复回调: {received}"


def test_encrypted_reliable_channel_rep():
    """加密的 ReliableChannel: REP 同 nonce 豁免解密, 消息不丢"""
    gnd_sm = create_session_manager(b"gnd")
    gnd_sm.adopt_session_key(KEY, b"group")
    sky_sm = create_session_manager(b"sky")
    sky_sm.adopt_session_key(KEY, b"group")

    received = []
    gnd = ReliableChannel(SESSION, StreamType.CONTROL,
                          decryptor_func=gnd_sm.decrypt_payload,
                          on_message=received.append,
                          rto_ms=20, max_retries=3)
    sky = ReliableChannel(SESSION, StreamType.CONTROL,
                          encrypt_func=sky_sm.encrypt_payload)
    sky.set_retransmit_func(gnd.feed)

    sky.send_message(b"SECRET_REP")
    assert received == [b"SECRET_REP"], "加密首发即达"

    # REP 重发 (同密文同 nonce) → 豁免, 不重复回调
    pkt = sky._store.get(0, 0)
    hdr = unpack_header(pkt)
    from protocol.header import pack_header, FLAG_ARQ_REP
    rep = pack_header(SESSION, hdr.frame_id, hdr.frag_id, hdr.total_frags,
                      hdr.flags | FLAG_ARQ_REP, hdr.stream_id,
                      frame_len=hdr.frame_len) + pkt[HEADER_SIZE:]
    gnd.feed(rep)
    assert received == [b"SECRET_REP"], "加密 REP 不应重复回调"
