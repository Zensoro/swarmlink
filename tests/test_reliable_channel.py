"""
SwarmLink v0.3 — 可靠流通道 (ReliableChannel) 测试
====================================================
验证控制/遥测流"可靠必达"的真实实现:
  1. 无丢包: 消息全部到达, 内容逐字节一致
  2. 下行丢包: LossDetector 发 REQ → ARQ 重传 → 全部到达
  3. 双向丢包 (下行 + REQ 上行都丢): 多轮重传后仍必达
  4. 去重: REP 与首发包都到达时只回调一次
"""

import sys
import os
import time
import random
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.multiplex import ReliableChannel, StreamType


SESSION = 0xC0FFEE


class LossyLink:
    """单向有损链路: send 入队, drain 取走 (按概率丢)。"""
    def __init__(self, loss_rate: float, seed: int = 7):
        self.rng = random.Random(seed)
        self.loss_rate = loss_rate
        self.queue = deque()
        self.sent = 0
        self.dropped = 0

    def send(self, pkt: bytes):
        self.sent += 1
        self.queue.append(pkt)

    def drain(self) -> list:
        out = []
        while self.queue:
            pkt = self.queue.popleft()
            if self.rng.random() < self.loss_rate:
                self.dropped += 1
                continue
            out.append(pkt)
        return out


def make_link(sky_chan, gnd_chan, down, up):
    """组环: sky → down → gnd; gnd REQ → up → sky"""
    sky_chan.set_retransmit_func(down.send)
    gnd_chan._send_arq = up.send
    gnd_chan._arq_client._send = up.send


def pump_until(sky_chan, gnd_chan, down, up, n_msgs, timeout=5.0):
    """主循环: 转发下行 + REQ 上行 + tick, 直到 on_message 收到 n_msgs 条。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for pkt in down.drain():
            gnd_chan.feed(pkt)
        for pkt in up.drain():
            try:
                from protocol.header import unpack_header
                unpack_header(pkt)
                sky_chan.handle_arq_request(pkt, 0)
            except Exception:
                pass
        gnd_chan.tick_loss_check()
        sky_chan.tick_arq()
        # 通过外部收集 (on_message) 检查
        collected = getattr(gnd_chan, "_on_message_collector", None)
        if collected is not None and len(collected) >= n_msgs:
            return list(collected)
        time.sleep(0.002)
    collected = getattr(gnd_chan, "_on_message_collector", None)
    return list(collected) if collected is not None else []


def with_collector(chan):
    """给 channel 挂一个外部消息收集器 (on_message 已有回调时叠加)。"""
    outer = chan._on_message
    buf = []
    def collect(msg):
        buf.append(msg)
        if outer:
            outer(msg)
    chan._on_message_collector = buf
    chan._on_message = collect
    return chan


def test_no_loss_delivery():
    msgs = [b"ARM_MOTORS", b"SET_ALTITUDE:50m", b"RTL_NOW"]
    received = []
    gnd_chan = ReliableChannel(SESSION, StreamType.CONTROL,
                               on_message=received.append)
    gnd_chan = with_collector(gnd_chan)
    sky_chan = ReliableChannel(SESSION, StreamType.CONTROL)
    down = LossyLink(0.0)
    up = LossyLink(0.0)
    make_link(sky_chan, gnd_chan, down, up)

    for m in msgs:
        sky_chan.send_message(m)
    got = pump_until(sky_chan, gnd_chan, down, up, len(msgs))

    assert got == msgs, f"应逐字节一致: {got} != {msgs}"


def test_downlink_loss_recovery():
    """30% 下行丢包 → ARQ 重传补回"""
    msgs = [f"CMD-{i}".encode() for i in range(10)]
    received = []
    gnd_chan = ReliableChannel(SESSION, StreamType.CONTROL,
                               on_message=received.append)
    gnd_chan = with_collector(gnd_chan)
    sky_chan = ReliableChannel(SESSION, StreamType.CONTROL)
    down = LossyLink(0.30, seed=11)
    up = LossyLink(0.0)
    make_link(sky_chan, gnd_chan, down, up)

    for m in msgs:
        sky_chan.send_message(m)
    got = pump_until(sky_chan, gnd_chan, down, up, len(msgs))

    assert got == msgs, f"30% 下行丢包应全恢复: {len(got)}/{len(msgs)}"
    s = sky_chan.stats()
    assert s["retransmits"] > 0, "应有重传发生"


def test_bidirectional_loss_recovery():
    """下行 30% + REQ 上行 30% 都丢 → 多轮 ARQ 后仍必达"""
    msgs = [f"TELE-{i}".encode() for i in range(8)]
    received = []
    gnd_chan = ReliableChannel(SESSION, StreamType.TELEMETRY,
                               on_message=received.append)
    gnd_chan = with_collector(gnd_chan)
    sky_chan = ReliableChannel(SESSION, StreamType.TELEMETRY)
    down = LossyLink(0.30, seed=21)
    up = LossyLink(0.30, seed=22)
    make_link(sky_chan, gnd_chan, down, up)

    for m in msgs:
        sky_chan.send_message(m)
    got = pump_until(sky_chan, gnd_chan, down, up, len(msgs))

    assert got == msgs, f"双向丢包应多轮重传必达: {len(got)}/{len(msgs)}"
    s = sky_chan.stats()
    assert s["retransmits"] > 0


def test_dedup_rep_and_original():
    """REP 与首发包都到达 → 只回调一次"""
    received = []
    gnd_chan = ReliableChannel(SESSION, StreamType.CONTROL,
                               on_message=received.append)
    sky_chan = ReliableChannel(SESSION, StreamType.CONTROL)
    down = LossyLink(0.0)
    up = LossyLink(0.0)
    make_link(sky_chan, gnd_chan, down, up)

    sky_chan.send_message(b"ONCE_ONLY")

    # 手动模拟: 原包 + REP 副本都送到
    pkts = list(down.queue)
    down.queue.clear()
    for p in pkts:
        gnd_chan.feed(p)
        gnd_chan.feed(p)  # 重复投递
    assert received == [b"ONCE_ONLY"], f"重复包应去重: {received}"


def test_stats_reported():
    received = []
    gnd_chan = ReliableChannel(SESSION, StreamType.CONTROL,
                               on_message=received.append)
    gnd_chan = with_collector(gnd_chan)
    sky_chan = ReliableChannel(SESSION, StreamType.CONTROL)
    down = LossyLink(0.0)
    up = LossyLink(0.0)
    make_link(sky_chan, gnd_chan, down, up)

    sky_chan.send_message(b"A")
    sky_chan.send_message(b"B")
    got = pump_until(sky_chan, gnd_chan, down, up, 2)

    assert len(got) == 2
    assert sky_chan.stats()["sent"] == 2
    assert gnd_chan.stats()["recv"] == 2
