"""
SwarmLink v0.4 — SFU 选择性转发测试
=====================================
验证 SFU 核心能力: 不同地面端缺不同分片 → 天空端重传只发给缺的人。

  1. bitmap 语义: mark_missing/clear/recipients 精确寻址
  2. 聚合器 B 方案: 重传 recipients = 恰好缺这片的人
  3. 带宽节省: N 客户端各缺 1 片 → 广播 N 份 vs 精确 1 份/人
  4. 动态更新: 接收端确认后清除 bitmap, 后续重传不再发给已补上的人
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.arq import ClientBitmap
from protocol.arq_full import PacketStore, ARQAggregatorV2
from protocol.header import (
    pack_header, unpack_header, FLAG_ARQ_REQ,
)


# ============================================================
# 1. bitmap 原语
# ============================================================
def test_bitmap_precision():
    """不同客户端缺不同分片 → recipients 精确到人"""
    bm = ClientBitmap(max_clients=8)
    # client 0 缺片 2,5; client 1 缺片 5; client 2 缺片 5,7
    for cid, frags in [(0, [2, 5]), (1, [5]), (2, [5, 7])]:
        for f in frags:
            bm.mark_missing(10, f, cid)

    assert bm.recipients(10, 5) == [0, 1, 2], "片5 三个人都缺"
    assert bm.recipients(10, 2) == [0], "片2 只有 client0 缺"
    assert bm.recipients(10, 7) == [2], "片7 只有 client2 缺"
    assert bm.recipients(10, 9) == [], "没人缺的片 → 空"


def test_bitmap_clear():
    """接收端确认补上后清除 → 不再发给他"""
    bm = ClientBitmap(max_clients=8)
    bm.mark_missing(10, 5, 0)
    bm.mark_missing(10, 5, 1)
    bm.mark_missing(10, 5, 2)
    bm.clear(10, 5, 1)
    assert bm.recipients(10, 5) == [0, 2], "clear 后只剩仍缺的人"
    bm.clear(10, 5, 0)
    bm.clear(10, 5, 2)
    assert bm.recipients(10, 5) == [], "全清空 → 无人缺"


# ============================================================
# 2. 聚合器 B 方案: 重传精确寻址
# ============================================================
def test_aggregator_bitmap_recipients():
    """多个客户端请求同片 → 合并成 1 次重传, 但 recipients 精确"""
    SESSION = 0x5555
    store = PacketStore(max_frames=10)
    fid = 0
    pkts = [pack_header(SESSION, fid, i, 14, 0, 0) + b"x" * 50
            for i in range(14)]
    store.put(fid, pkts)

    sent = []
    agg = ARQAggregatorV2(
        session_tag=SESSION, packet_store=store,
        retransmit_callback=lambda p, r=None: sent.append((p, r)),
        window_ms=5, use_bitmap=True, max_clients=8,
    )

    # 0, 3, 7 缺片 5
    for cid in [0, 3, 7]:
        req = pack_header(SESSION, fid, 5, 1, FLAG_ARQ_REQ, 0)
        agg.receive_request(req, cid)
    agg.flush()

    assert len(sent) == 1, "合并 → 只重传 1 次"
    _, recipients = sent[0]
    assert recipients == [0, 3, 7], f"应发给三个缺片者: {recipients}"

    # REP 里的头应保留原流信息
    rep_pkt, _ = sent[0]
    hdr = unpack_header(rep_pkt)
    assert hdr.frame_id == fid and hdr.frag_id == 5
    assert hdr.total_frags == 14, "total_frags 不被挪用"
    from protocol.header import HEADER_SIZE
    assert rep_pkt[HEADER_SIZE:HEADER_SIZE + 50] == b"x" * 50, "载荷原样保留"


# ============================================================
# 3. 带宽节省对比
# ============================================================
def test_bandwidth_saving_vs_broadcast():
    """N 个客户端各缺 1 片: 广播 N 份 vs 精确转发收敛"""
    SESSION = 0x7777
    store = PacketStore(max_frames=10)
    fid = 0
    pkts = [pack_header(SESSION, fid, i, 14, 0, 0) + b"x" * 100
            for i in range(14)]
    store.put(fid, pkts)

    PKT_SIZE = len(pkts[0])
    N = 8

    # A 方案 (广播): 每个客户端 REQ → 聚合后仍广播给所有人
    broadcast_copies = [0]
    agg_a = ARQAggregatorV2(
        session_tag=SESSION, packet_store=store,
        retransmit_callback=lambda p, r=None: broadcast_copies.__setitem__(
            0, broadcast_copies[0] + N),
        window_ms=5, use_bitmap=False,
    )
    for cid in range(N):
        req = pack_header(SESSION, fid, 5, 1, FLAG_ARQ_REQ, 0)
        agg_a.receive_request(req, cid)
    agg_a.flush()
    broadcast_bytes = broadcast_copies[0] * PKT_SIZE

    # B 方案 (精确): recipients 只含真正缺的人
    recipients_seen = []
    agg_b2 = ARQAggregatorV2(
        session_tag=SESSION, packet_store=store,
        retransmit_callback=lambda p, r=None: recipients_seen.append(r),
        window_ms=5, use_bitmap=True, max_clients=N,
    )
    for cid in range(N):
        req = pack_header(SESSION, fid, 5, 1, FLAG_ARQ_REQ, 0)
        agg_b2.receive_request(req, cid)
    agg_b2.flush()

    exact_copies = sum(len(r) for r in recipients_seen)
    assert len(recipients_seen) == 1
    assert recipients_seen[0] == list(range(N)), "8 人都缺 → 全发"
    # 单 REQ 场景两者相同; 真正的节省在"不同人缺不同片"时体现
    # 见 test_bandwidth_saving_diverse_missing


def test_bandwidth_saving_diverse_missing():
    """不同人缺不同片: 精确转发显著节省带宽"""
    SESSION = 0x8888
    store = PacketStore(max_frames=10)
    fid = 0
    pkts = [pack_header(SESSION, fid, i, 14, 0, 0) + b"x" * 100
            for i in range(14)]
    store.put(fid, pkts)

    PKT_SIZE = len(pkts[0])
    N = 8
    # 每个客户端缺不同的片 (1..8)
    missing_per_client = {cid: cid + 1 for cid in range(N)}

    # 广播: 每次 REQ 都发给所有人
    broadcast_bytes = 0
    for cid in range(N):
        agg = ARQAggregatorV2(
            session_tag=SESSION, packet_store=store,
            retransmit_callback=lambda p, r=None: None,
            window_ms=5, use_bitmap=False,
        )
        # 直接模拟广播: 每片发给 N 个客户端
        broadcast_bytes += N * PKT_SIZE

    # 精确: 每片只发给缺它的人
    exact_bytes = 0
    bm = ClientBitmap(max_clients=N)
    for cid, frag in missing_per_client.items():
        bm.mark_missing(fid, frag, cid)
    for frag in range(1, N + 1):
        exact_bytes += len(bm.recipients(fid, frag)) * PKT_SIZE

    # 8 人各缺 1 片不同片: 广播 8 片 × 8 人 = 64 份; 精确 = 8 份
    assert exact_bytes == N * PKT_SIZE, f"精确转发应每片只发 1 份: {exact_bytes}"
    saving = 1 - exact_bytes / broadcast_bytes
    assert saving >= 0.8, f"8 人各缺不同片, 节省应 ≥80%: {saving:.0%}"
