"""
SwarmLink v0.6 — Gilbert-Elliott 模型 + RLNC 可插拔 FEC 测试
===============================================================
  GE: 突发性 (burst > 1) / 统计对齐理论值 / WeakNetSimulator 集成
  RLNC: 编解码闭环 / 丢包恢复 / 线性相关容忍 / 与 RS 对比
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.ge_model import GilbertElliott
from protocol.rlnc import RandomLinearCode
from protocol.rs_codec import ReedSolomon


# ============================================================
# 1. Gilbert-Elliott 模型
# ============================================================
def test_ge_produces_bursts():
    """突发性: 最大连续丢包应明显 > 1 (与均匀丢包区分)"""
    ge = GilbertElliott(p_gb=0.02, p_bg=0.3, p_g=0.0, p_b=0.6, seed=7)
    for _ in range(20000):
        ge.is_lost()
    s = ge.stats()
    assert s["max_burst"] >= 3, f"应有突发 (max_burst={s['max_burst']})"
    assert s["bursts"] > 0, "应发生状态切换"


def test_ge_loss_rate_matches_theory():
    """实测丢包率对齐理论稳态值 (±30%)"""
    p_gb, p_bg, p_g, p_b = 0.02, 0.3, 0.0, 0.6
    ge = GilbertElliott(p_gb, p_bg, p_g, p_b, seed=11)
    for _ in range(50000):
        ge.is_lost()
    s = ge.stats()
    theory = ge.average_loss_rate
    actual = s["loss_rate_actual"]
    # 理论: p_bad = 0.02/0.32 = 0.0625, loss = 0.0625*0.6 = 3.75%
    assert abs(actual - theory) / max(1e-6, theory) < 0.3, \
        f"实测 {actual:.4f} vs 理论 {theory:.4f}"


def test_ge_burst_len_matches_theory():
    """平均突发长度对齐理论 (1/p_bg)"""
    ge = GilbertElliott(p_gb=0.02, p_bg=0.2, p_g=0.0, p_b=1.0, seed=3)
    # p_b=1.0 → 坏态期间全丢, 突发长度 = 坏态持续包数
    # 理论平均突发 = 1/p_bg = 5
    for _ in range(100000):
        ge.is_lost()
    s = ge.stats()
    # 用平均突发 = total_bad_losses / bursts 近似 (坏态全丢时)
    avg = s["bursts"] and (s["lost"] / s["bursts"])
    theory = 1 / 0.2
    if avg is not None:
        assert abs(avg - theory) / theory < 0.3, \
            f"平均突发 {avg:.1f} vs 理论 {theory:.1f}"


def test_ge_uniform_mode_unchanged():
    """GE 模式开启不影响 Uniform 模式 (默认行为不变)"""
    from tests.weaknet import WeakNetSimulator
    net = WeakNetSimulator(loss_rate=0.3, seed=5)
    lost = 0
    for _ in range(10000):
        net.send(b"x")
    lost = net.packets_lost
    assert abs(lost / 10000 - 0.3) < 0.03, f"均匀模式丢包 {lost/10000:.3f}"


def test_weaknet_ge_mode():
    """WeakNetSimulator 接入 GE 模式"""
    from tests.weaknet import WeakNetSimulator
    net = WeakNetSimulator(loss_model="ge",
                           ge_p_gb=0.02, ge_p_bg=0.3, ge_p_b=0.6, seed=9)
    for _ in range(20000):
        net.send(b"x")
    assert net.packets_lost > 0
    # GE 的突发性应让 max 连续丢包 > 均匀模式
    ge = net._ge
    assert ge.stats()["max_burst"] >= 3


# ============================================================
# 2. RLNC 编解码
# ============================================================
def make_chunks(k=10, cs=600, seed=1):
    rng = __import__("random").Random(seed)
    return [os.urandom(cs) for _ in range(k)]


def test_rlnc_roundtrip():
    """无丢包: 编解码完全还原"""
    data = make_chunks(10, 600)
    rlnc = RandomLinearCode(seed=1, extra_packets=4)
    packets = rlnc.encode(data)
    assert len(packets) == 14, "10 数据 + 4 冗余"

    recovered = rlnc.decode(packets)
    assert recovered == data, "应逐字节还原"


def test_rlnc_recovers_loss():
    """丢 4 包 (任意位置): 剩余 10 包应解码"""
    data = make_chunks(10, 600)
    rlnc = RandomLinearCode(seed=2, extra_packets=4)
    packets = rlnc.encode(data)

    # 丢任意 4 个
    survived = packets[:4] + packets[8:]
    assert len(survived) == 10
    recovered = rlnc.decode(survived)
    assert recovered == data, "10 个线性无关包应能恢复"


def test_rlnc_needs_rank_k():
    """少于 K 个包 → 解码失败"""
    data = make_chunks(10, 600)
    rlnc = RandomLinearCode(seed=3, extra_packets=4)
    packets = rlnc.encode(data)
    try:
        rlnc.decode(packets[:9])
        assert False, "9 包应无法解码"
    except ValueError:
        pass


def test_rlnc_flexible_k():
    """K 灵活: 小数据 (K=2) 也能编码 (RS 固定 K=10 做不到)"""
    data = make_chunks(2, 600)
    rlnc = RandomLinearCode(seed=4, extra_packets=1)
    packets = rlnc.encode(data)
    assert len(packets) == 3, "2 数据 + 1 冗余"
    recovered = rlnc.decode(packets[:2])
    assert recovered == data


def test_rlnc_vs_rs_loss_recovery():
    """对比: 同样 10 数据 + 4 冗余, 丢 4 包, RLNC 与 RS 都能恢复"""
    data = make_chunks(10, 600)

    # RS
    rs = ReedSolomon()
    rs_pkts = rs.encode(data)
    rs_survived = [None] * 14
    keep = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10]  # 丢 4, 11, 12, 13
    for idx in keep:
        rs_survived[idx] = rs_pkts[idx]
    erasures = [4, 11, 12, 13]
    rs_rec = rs.decode(rs_survived, erasures)
    assert rs_rec == data, "RS 应恢复"

    # RLNC
    rlnc = RandomLinearCode(seed=5, extra_packets=4)
    rl_pkts = rlnc.encode(data)
    rl_survived = [rl_pkts[i] for i in range(14) if i not in (4, 11, 12, 13)]
    rl_rec = rlnc.decode(rl_survived)
    assert rl_rec == data, "RLNC 应恢复"


def test_rlnc_progressive_decoding():
    """渐进解码: 收到第 K 个有用包即可解码 (不需要等待特定包)"""
    data = make_chunks(10, 600)
    rlnc = RandomLinearCode(seed=6, extra_packets=4)
    packets = rlnc.encode(data)

    # 只取前 10 个 (任何 10 个都行, 随机系数)
    recovered = rlnc.decode(packets[:10])
    assert recovered == data, "前 10 个包应线性无关可解码"
