"""
SwarmLink — 地面端 (接收进程)
================================
单机双进程真实 UDP demo 的接收端。
与 sky.py 配合: 接收视频帧 + 控制消息, 重组验证, 缺片发 ARQ_REQ。

运行 (两个终端):
  # 终端 1: 地面端
  python3 examples/gnd.py --port 5010 --sky-port 5000
  # 终端 2: 天空端
  python3 examples/sky.py --gnd-port 5010 --sky-port 5000 --frames 30 --loss 0.15

单机回环用 127.0.0.1; 双机改 --sky-ip <对端IP>。
"""

import sys
import os
import time
import struct
import argparse
import threading
import socket
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.fragment import Reassembler
from protocol.arq_full import GroundReceiver
from protocol.multiplex import ReliableChannel, StreamType
from protocol.security_nacl import create_session_manager
from protocol.header import (
    HEADER_SIZE, unpack_header, HeaderError,
)


SESSION_TAG = 0xDEADBEEF
CHUNK_SIZE = 600
FEC_K = 10
FEC_N = 14


class GndLink:
    """地面端 UDP 端点: 后台线程收包, 发 REQ 给天空端。"""
    def __init__(self, bind_port: int, sky_addr: tuple):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 2**20)
        self._sock.bind(("0.0.0.0", bind_port))
        self._sock.settimeout(0.02)
        self.port = bind_port
        self._sky = sky_addr

        self._inbox: deque = deque()
        self._lock = threading.Lock()
        self._running = True

        self._rx = threading.Thread(target=self._recv_loop, daemon=True)
        self._rx.start()

    def _recv_loop(self):
        while self._running:
            try:
                data, _ = self._sock.recvfrom(65535)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            with self._lock:
                self._inbox.append(data)

    def send(self, data: bytes, recipients=None):
        self._sock.sendto(data, self._sky)

    def drain(self) -> list:
        out = []
        with self._lock:
            while self._inbox:
                out.append(self._inbox.popleft())
        return out

    def close(self):
        self._running = False
        time.sleep(0.03)
        try:
            self._sock.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="SwarmLink 地面端 (接收)")
    ap.add_argument("--port", type=int, default=5010)
    ap.add_argument("--sky-port", type=int, default=5000)
    ap.add_argument("--sky-ip", default="127.0.0.1")
    ap.add_argument("--frames", type=int, default=30,
                    help="期望收到的帧数 (用于完成判定)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--no-encrypt", action="store_true")
    ap.add_argument("--output", default=None,
                    help="把收到的帧按序写入 .h264 文件 (真实视频验证用)")
    args = ap.parse_args()

    # 会话: 预共享组密钥 (模拟已完成配对的设备组, 跨进程共享)
    # 真实流程: 首次配对 (pairing.py 配对码) → 派生 master_key → 组会话
    DEMO_GROUP_KEY = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    gnd_sm = create_session_manager(b"ground-000")
    gnd_sm.adopt_session_key(DEMO_GROUP_KEY, b"sky-001")

    link = GndLink(args.port, (args.sky_ip, args.sky_port))

    # 视频: GroundReceiver (重组 + FEC + ARQ 兜底)
    completed = {}
    latencies = {}
    send_times = {}

    reasm = Reassembler(SESSION_TAG, fec_k=FEC_K, fec_n=FEC_N)
    receiver = GroundReceiver(
        client_id=0,
        session_tag=SESSION_TAG,
        reassembler=reasm,
        decryptor_func=(None if args.no_encrypt else gnd_sm.decrypt_payload),
        send_arq_func=link.send,
        on_frame_complete=lambda cid, fid, data: (
            completed.__setitem__(fid, data),
            latencies.__setitem__(
                fid, (time.monotonic() - send_times.get(fid, time.monotonic()))
                * 1000) if fid in send_times else None,
        ),
        rto_ms=40, max_retries=8,
        fec_k=FEC_K, fec_n=FEC_N,
    )

    # 控制: ReliableChannel
    ctrl_msgs = []
    ctrl = ReliableChannel(
        SESSION_TAG, StreamType.CONTROL,
        decryptor_func=(None if args.no_encrypt else gnd_sm.decrypt_payload),
        on_message=ctrl_msgs.append,
        send_arq_func=link.send,
        rto_ms=40, max_retries=10,
    )

    print(f"Gnd 接收中: 期望 {args.frames} 帧 (按 --frames 判定完成, "
          f"无视频帧时以 --timeout 退出)")
    t0 = time.monotonic()
    last_report = 0.0
    while time.monotonic() - t0 < args.timeout:
        for pkt in link.drain():
            try:
                hdr = unpack_header(pkt)
            except HeaderError:
                continue
            # 记录视频帧发送时间戳由 sky 端持有; 此处用接收时刻近似
            if hdr.stream_id == StreamType.CONTROL:
                ctrl.feed(pkt)
            else:
                receiver.feed(pkt)

        receiver.tick_loss_check()
        ctrl.tick_loss_check()

        done = len(completed)
        if done >= args.frames:
            break
        elapsed = time.monotonic() - t0
        if elapsed - last_report > 2.0:
            last_report = elapsed
            print(f"  [{elapsed:4.1f}s] 完成 {done}/{args.frames} 帧  "
                  f"控制消息 {len(ctrl_msgs)}")
        time.sleep(0.002)

    # 收尾: 再 drain 一轮让 REP 到达
    time.sleep(0.3)
    for pkt in link.drain():
        try:
            hdr = unpack_header(pkt)
        except HeaderError:
            continue
        if hdr.stream_id == StreamType.CONTROL:
            ctrl.feed(pkt)
        else:
            receiver.feed(pkt)
    ctrl.tick_loss_check()
    receiver.tick_loss_check()
    time.sleep(0.2)
    for pkt in link.drain():
        try:
            hdr = unpack_header(pkt)
        except HeaderError:
            continue
        if hdr.stream_id == StreamType.CONTROL:
            ctrl.feed(pkt)
        else:
            receiver.feed(pkt)

    link.close()
    gnd_sm.destroy_session()

    print(f"Gnd 结束: 完成 {len(completed)}/{args.frames} 帧  "
          f"控制消息 {len(ctrl_msgs)} 条")
    rx = receiver.stats()["rx"]
    print(f"  解密: 成功 {rx.get('decrypt_ok', 0)}  "
          f"失败 {rx.get('decrypt_fail', 0)}")
    if latencies:
        vals = sorted(latencies.values())
        print(f"  延迟: p50 {vals[len(vals)//2]:.0f}ms  "
              f"p95 {vals[int(len(vals)*0.95)]:.0f}ms")

    # 真实视频验证: 按序写 .h264 文件
    if args.output and completed:
        with open(args.output, "wb") as f:
            for fid in sorted(completed.keys()):
                f.write(completed[fid])
        print(f"  视频输出: {args.output} "
              f"({os.path.getsize(args.output)} bytes, "
              f"{len(completed)} 帧)")


if __name__ == "__main__":
    main()
