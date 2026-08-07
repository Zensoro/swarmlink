"""
SwarmLink v0.4 — SFU 完整版 (订阅式多码率转发) 测试
====================================================
验证 protocol/sfu.py:
  1. 订阅正确性: 每端只收自己订阅层的帧
  2. 带宽差异: LOW 订阅端收到的字节显著少于 HIGH
  3. 动态切换: 弱网降档 / 恢复升档后收到新层
  4. 未订阅层不发送: 没人订的层零带宽
  5. 加解密闭环: 加密后接收端正确还原 (两层互不串)
"""

import sys
import os
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.sfu import SFUForwarder, SFUReceiver, Quality
from protocol.security_nacl import create_session_manager


SESSION = 0x5F00


class CollectLink:
    """收集 (pkt, client_id), 按 client 分发到对应接收端。"""
    def __init__(self):
        self.packets = defaultdict(list)

    def send(self, pkt, client_id):
        self.packets[client_id].append(pkt)


def make_encrypted_pair():
    """一对加解密 session (同组密钥)"""
    KEY = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    sky_sm = create_session_manager(b"sky-sfu")
    sky_sm.adopt_session_key(KEY, b"group")
    gnd_sm = create_session_manager(b"gnd-sfu")
    gnd_sm.adopt_session_key(KEY, b"group")
    return sky_sm, gnd_sm


def make_small_high_data(fid):
    return os.urandom(5000)  # HIGH: 完整帧 ~5000B


def make_low_data(fid, high):
    # LOW: 同内容但更小 (模拟低分辨率采样, 取前 1/4)
    return high[:1250]


def test_subscription_routing():
    """订阅正确性: HIGH 端收 HIGH 帧, LOW 端收 LOW 帧, 互不串"""
    link = CollectLink()
    sky_sm, gnd_sm = make_encrypted_pair()
    fwd = SFUForwarder(SESSION, link.send,
                       encrypt_func=sky_sm.encrypt_payload)

    fwd.subscribe(0, Quality.HIGH)
    fwd.subscribe(1, Quality.LOW)

    rcv_high = SFUReceiver(SESSION, 0, Quality.HIGH,
                           decryptor_func=gnd_sm.decrypt_payload)
    rcv_low = SFUReceiver(SESSION, 1, Quality.LOW,
                          decryptor_func=gnd_sm.decrypt_payload)

    # 生成真实数据 (只一次, 复用)
    high_data = {fid: make_small_high_data(fid) for fid in range(5)}
    low_data = {fid: make_low_data(fid, high_data[fid]) for fid in range(5)}

    # 发布 5 帧
    for fid in range(5):
        fwd.publish_frame(fid, {Quality.LOW: low_data[fid],
                                Quality.HIGH: high_data[fid]})

    # 分发
    for cid, pkts in link.packets.items():
        rcv = rcv_high if cid == 0 else rcv_low
        for pkt in pkts:
            rcv.feed(pkt)

    # HIGH 端: 收到完整高码率帧
    assert len(rcv_high.completed) == 5
    for fid in range(5):
        assert rcv_high.completed[fid] == high_data[fid], \
            f"HIGH 端帧 {fid} 应逐字节一致"

    # LOW 端: 收到低码率帧
    assert len(rcv_low.completed) == 5
    for fid in range(5):
        assert rcv_low.completed[fid] == low_data[fid], \
            f"LOW 端帧 {fid} 应逐字节一致"

    # 互不串: HIGH 端没收到 LOW 帧数据
    high_frames = [len(rcv_high.completed[f]) for f in range(5)]
    assert all(f == 5000 for f in high_frames), f"HIGH 帧应全尺寸: {high_frames}"


def test_bandwidth_difference():
    """带宽差异: LOW 订阅端收包显著少于 HIGH"""
    link = CollectLink()
    fwd = SFUForwarder(SESSION, link.send)  # 不加密, 隔离测试

    fwd.subscribe(0, Quality.HIGH)
    fwd.subscribe(1, Quality.LOW)

    for fid in range(20):
        high = os.urandom(5000)
        low = high[:1250]
        fwd.publish_frame(fid, {Quality.LOW: low, Quality.HIGH: high})

    bytes_high = sum(len(p) for p in link.packets[0])
    bytes_low = sum(len(p) for p in link.packets[1])

    assert bytes_high > bytes_low, \
        f"HIGH 应比 LOW 带宽大: {bytes_high} vs {bytes_low}"
    # LOW 是 HIGH 的 1/4 内容, 分片开销也成比例 → 至少 2 倍差距
    assert bytes_high / max(1, bytes_low) >= 2.0, \
        f"HIGH/LOW 带宽比应 ≥2: {bytes_high / max(1, bytes_low):.1f}x"

    # 统计中的带宽分配
    st = fwd.stats()
    assert st["bandwidth_high_pct"] > st["bandwidth_low_pct"]


def test_dynamic_switch():
    """动态切换: LOW 端切到 HIGH 后, 下一帧收到高码率"""
    link = CollectLink()
    fwd = SFUForwarder(SESSION, link.send)

    fwd.subscribe(0, Quality.LOW)   # 先低码率
    rcv = SFUReceiver(SESSION, 0, Quality.LOW)

    # 前 3 帧 LOW
    for fid in range(3):
        high = os.urandom(5000)
        low = high[:1250]
        fwd.publish_frame(fid, {Quality.LOW: low, Quality.HIGH: high})
    for pkt in link.packets[0]:
        rcv.feed(pkt)
    assert len(rcv.completed) == 3
    assert all(len(rcv.completed[f]) == 1250 for f in range(3))

    # 网络恢复 → 升档 HIGH
    fwd.change_subscription(0, Quality.HIGH)
    rcv2 = SFUReceiver(SESSION, 0, Quality.HIGH)
    link.packets.clear()

    for fid in range(3, 6):
        high = os.urandom(5000)
        low = high[:1250]
        fwd.publish_frame(fid, {Quality.LOW: low, Quality.HIGH: high})
    for pkt in link.packets[0]:
        rcv2.feed(pkt)
    assert len(rcv2.completed) == 3, "切换后应收到 HIGH 帧"
    assert all(len(rcv2.completed[f]) == 5000 for f in range(3, 6)), \
        "切换后帧应为全尺寸"


def test_unsubscribed_layer_not_sent():
    """没人订阅的层不发送 (零带宽)"""
    link = CollectLink()
    fwd = SFUForwarder(SESSION, link.send)

    # 只有 HIGH 订阅者, 不发布 LOW (或发布但无人订)
    fwd.subscribe(0, Quality.HIGH)
    for fid in range(5):
        fwd.publish_frame(fid, {
            Quality.HIGH: os.urandom(5000),
            Quality.LOW: os.urandom(1000),
        })

    assert len(link.packets[0]) > 0
    st = fwd.stats()
    # 只有 HIGH 有字节
    assert st["bytes_per_quality"][int(Quality.HIGH)] > 0
    assert st["bytes_per_quality"][int(Quality.LOW)] == 0, \
        "无人订 LOW → LOW 层零带宽"


def test_no_subscriber_sends_nothing():
    """没有订阅者 → 一包都不发"""
    link = CollectLink()
    fwd = SFUForwarder(SESSION, link.send)
    for fid in range(3):
        fwd.publish_frame(fid, {
            Quality.HIGH: os.urandom(5000),
            Quality.LOW: os.urandom(1000),
        })
    assert fwd.stats()["packets_sent"] == 0


def test_multiple_clients_same_quality():
    """多个客户端订同层 → 各收到完整帧"""
    link = CollectLink()
    fwd = SFUForwarder(SESSION, link.send)
    for cid in range(3):
        fwd.subscribe(cid, Quality.HIGH)
    for fid in range(5):
        fwd.publish_frame(fid, {Quality.HIGH: os.urandom(5000)})

    assert len(link.packets) == 3, "3 客户端各应收到包"
    for cid in range(3):
        assert len(link.packets[cid]) > 0
