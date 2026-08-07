"""
SwarmLink v0.5 — 路由层测试 (一致性哈希 / 三级中继 / stale-while-revalidate)
=============================================================================
验证 protocol/routing.py 和 protocol/cache.py:
  1. ConsistentHash: 分布均匀 / 加节点只迁移 1/N / 删节点只影响自身 / 平滑扩容
  2. RelayNode: 上游→多下游转发 / 防环 TTL / 断连缓存补发 / 中继 REQ 转发
  3. StaleWhileRevalidate: 新鲜直出 / stale 先旧后新 / 无缓存触发刷新 /
     同帧不重复刷新 / 完全过期视为 miss
"""

import sys
import os
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.routing import ConsistentHash, RelayNode
from protocol.cache import StaleWhileRevalidate
from protocol.header import pack_header


SESSION = 0x0A05


def mk_packet(frame_id: int, payload: bytes = b"x" * 50) -> bytes:
    return pack_header(SESSION, frame_id, 0, 1, 0, 0) + payload


# ============================================================
# 1. ConsistentHash
# ============================================================
def test_ring_distribution_uniform():
    """分布均匀性: 1000 个 key, 3 节点负载偏差 < 20%"""
    ring = ConsistentHash(virtual_nodes=100)
    for n in ["node-a", "node-b", "node-c"]:
        ring.add_node(n)

    keys = [f"key-{i}" for i in range(1000)]
    dist = ring.key_distribution(keys)

    assert set(dist.keys()) == {"node-a", "node-b", "node-c"}
    avg = 1000 / 3
    for node, cnt in dist.items():
        assert abs(cnt - avg) / avg < 0.20, \
            f"负载偏差过大: {node}={cnt} (均值 {avg:.0f})"


def test_add_node_only_migrates_small_fraction():
    """平滑扩容: 加 1 节点, 原节点最多失去 ~1/(N+1) 的 key"""
    ring = ConsistentHash(virtual_nodes=100)
    for n in ["a", "b", "c"]:
        ring.add_node(n)
    keys = [f"key-{i}" for i in range(2000)]

    before = ring.key_distribution(keys)
    ring.add_node("d")
    after = ring.key_distribution(keys)

    # 每个原节点迁移的 key 比例应 ≤ ~50% (1/(3+1)=25% 期望, 留余量)
    for node in ["a", "b", "c"]:
        migrated = before[node] - after[node]
        assert migrated / max(1, before[node]) < 0.5, \
            f"{node} 迁移 {migrated}/{before[node]} 过多"


def test_remove_node_only_affects_itself():
    """平滑缩容: 删节点后其 key 均匀迁移给幸存者, key 总数守恒"""
    ring = ConsistentHash(virtual_nodes=100)
    for n in ["a", "b", "c", "d"]:
        ring.add_node(n)
    keys = [f"key-{i}" for i in range(2000)]
    before = ring.key_distribution(keys)

    ring.remove_node("d")
    after = ring.key_distribution(keys)

    # d 的 key 全部迁移, 幸存者各得 ~1/3 (增量 < 被删节点总量)
    d_keys = before["d"]
    total_after = sum(after.values())
    assert total_after == 2000, f"key 总数应守恒: {total_after}"
    assert "d" not in after, "d 已移除"
    # 每个幸存者增加的 key ≈ d 的 1/3 (偏差 < 50% 余量)
    avg_gain = d_keys / 3
    for node in ["a", "b", "c"]:
        gain = after[node] - before[node]
        assert abs(gain - avg_gain) / avg_gain < 0.5, \
            f"{node} 获得 {gain} 个 key (期望 ~{avg_gain:.0f})"


def test_route_consistency():
    """同一 key 路由结果稳定; 空环返回 None"""
    ring = ConsistentHash()
    assert ring.route("anything") is None
    ring.add_node("a")
    ring.add_node("b")
    r1 = ring.route("frame-42")
    r2 = ring.route("frame-42")
    assert r1 == r2 and r1 in ("a", "b")


# ============================================================
# 2. RelayNode (三级拓扑)
# ============================================================
def test_forward_down_broadcast():
    """上游 → 中继 → 多下游广播"""
    relay = RelayNode("relay-1")
    gnd0, gnd1 = [], []
    relay.add_downstream("gnd0", gnd0.append)
    relay.add_downstream("gnd1", gnd1.append)

    pkt = mk_packet(0)
    relay.forward_down(pkt)
    assert gnd0 == [pkt] and gnd1 == [pkt], "应广播给所有下游"
    assert relay.stats()["fwd_down"] == 2


def test_forward_down_loop_protection():
    """防环: hop 达到上限丢弃"""
    relay = RelayNode("relay-loop", max_hop=1)
    got = []
    relay.add_downstream("gnd", got.append)

    # hop=1 (stream_id 高半字节) ≥ max_hop=1 → 丢弃
    pkt_hop1 = pack_header(SESSION, 0, 0, 1, 0, 0x10) + b"x" * 50
    relay.forward_down(pkt_hop1)
    assert got == [], "达到 hop 上限应丢弃"
    assert relay.stats()["dropped_loop"] == 1

    # hop=0 → 正常转发
    pkt_hop0 = pack_header(SESSION, 0, 0, 1, 0, 0x00) + b"x" * 50
    relay.forward_down(pkt_hop0)
    assert len(got) == 1


def test_relay_cache_and_stale_serve():
    """断连恢复: 中继缓存旧帧, 下游重连后立即补发"""
    relay = RelayNode("relay-cache")
    gnd = []
    relay.add_downstream("gnd", gnd.append)

    # 上游发 3 帧 → 缓存
    for fid in range(3):
        relay.forward_down(mk_packet(fid, b"data" + bytes([fid])))

    # 模拟下游断连重连: 清空接收, 用 serve_stale 补发旧帧
    gnd.clear()
    pkt = relay.serve_stale("gnd", 2)
    assert pkt is not None, "缓存应有帧 2"
    assert len(gnd) == 1 and gnd[0] == pkt
    assert relay.stats()["served_from_cache"] == 1
    assert relay.stats()["buffer_frames"] == 3


def test_forward_up_req():
    """下游 REQ → 中继 → 上游"""
    relay = RelayNode("relay-up")
    upstream = []
    relay.connect_upstream(upstream.append)

    req = mk_packet(5)
    relay.forward_up(req)
    assert upstream == [req]
    assert relay.stats()["fwd_up"] == 1

    # 无上游时不转发
    relay2 = RelayNode("relay-noup")
    assert relay2.forward_up(req) is None


# ============================================================
# 3. StaleWhileRevalidate
# ============================================================
def test_fresh_hit():
    """新鲜帧直出, 不触发刷新"""
    revalidated = []
    cache = StaleWhileRevalidate(fresh_ttl=10, stale_ttl=60,
                                 revalidate_cb=lambda fid: revalidated.append(fid))
    cache.put(0, b"fresh-frame")
    data, stale = cache.get(0)
    assert data == b"fresh-frame" and stale is False
    assert revalidated == [], "新鲜帧不应触发刷新"


def test_stale_returns_old_and_revalidates():
    """过期帧: 先回旧帧 + 触发后台刷新"""
    revalidated = []
    cache = StaleWhileRevalidate(fresh_ttl=0.05, stale_ttl=60,
                                 revalidate_cb=lambda fid: revalidated.append(fid))
    cache.put(0, b"old-frame")
    time.sleep(0.08)  # 超过 fresh_ttl
    data, stale = cache.get(0)
    assert data == b"old-frame" and stale is True, "应返回旧帧并标记 stale"
    assert revalidated == [0], "应触发刷新"


def test_miss_triggers_revalidate():
    """无缓存 → miss + 触发刷新"""
    revalidated = []
    cache = StaleWhileRevalidate(revalidate_cb=lambda fid: revalidated.append(fid))
    data, stale = cache.get(99)
    assert data is None and stale is False
    assert revalidated == [99]


def test_no_duplicate_revalidate():
    """同帧只触发一次刷新 (防风暴)"""
    revalidated = []
    cache = StaleWhileRevalidate(fresh_ttl=0.01, stale_ttl=60,
                                 revalidate_cb=lambda fid: revalidated.append(fid))
    cache.put(0, b"x")
    time.sleep(0.02)
    cache.get(0)  # stale → 触发
    cache.get(0)  # 仍在 inflight → 不重复
    cache.get(0)
    assert revalidated == [0], f"应只触发一次: {revalidated}"


def test_fully_expired_is_miss():
    """超过 stale_ttl → 视为 miss"""
    revalidated = []
    cache = StaleWhileRevalidate(fresh_ttl=0.01, stale_ttl=0.05,
                                 revalidate_cb=lambda fid: revalidated.append(fid))
    cache.put(0, b"x")
    time.sleep(0.08)  # 超过 stale_ttl
    data, stale = cache.get(0)
    assert data is None, "完全过期应视为 miss"
    assert cache.has(0) is False


def test_update_resets_freshness():
    """新帧写入 → 重新计时为新鲜"""
    cache = StaleWhileRevalidate(fresh_ttl=0.05, stale_ttl=60)
    cache.put(0, b"v1")
    time.sleep(0.08)
    data, stale = cache.get(0)
    assert stale is True, "v1 已过期"

    cache.put(0, b"v2")  # revalidate 拿到新帧
    data, stale = cache.get(0)
    assert data == b"v2" and stale is False, "v2 应新鲜"
