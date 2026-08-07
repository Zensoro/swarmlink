"""
SwarmLink — 天空端 (发送进程)
================================
单机双进程真实 UDP demo 的发送端。
与 gnd.py 配合: 本进程把视频帧 + 控制消息经 UDP 发给地面端,
接收地面端的 ARQ_REQ 并重传。

运行 (两个终端):
  # 终端 1: 地面端
  python3 examples/gnd.py --port 5010 --sky-port 5000
  # 终端 2: 天空端
  python3 examples/sky.py --gnd-port 5010 --sky-port 5000 --frames 30 --loss 0.15

单机回环用 127.0.0.1; 双机改 --gnd-ip <对端IP>。
"""

import sys
import os
import time
import random
import struct
import argparse
import threading
import socket
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.fragment import Fragmenter
from protocol.arq_full import PacketStore, SkySender
from protocol.multiplex import StreamMultiplexer, StreamType, ReliableChannel
from protocol.security_nacl import create_session_manager
from protocol.header import (
    HEADER_SIZE, unpack_header, HeaderError,
)


SESSION_TAG = 0xDEADBEEF
CHUNK_SIZE = 600
FEC_K = 10
FEC_N = 14


class SkyLink:
    """天空端 UDP 端点: 后台线程收 REQ, send 时按 loss 概率丢弃 (弱网整形)。"""
    def __init__(self, bind_port: int, gnd_addr: tuple, loss_rate: float = 0.0):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", bind_port))
        self._sock.settimeout(0.02)
        self.port = bind_port
        self._gnd = gnd_addr
        self._rng = random.Random(7)
        self.loss_rate = loss_rate
        self.sent = 0
        self.dropped = 0

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
        self.sent += 1
        if self.loss_rate > 0 and self._rng.random() < self.loss_rate:
            self.dropped += 1
            return
        self._sock.sendto(data, self._gnd)

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
    ap = argparse.ArgumentParser(description="SwarmLink 天空端 (发送)")
    ap.add_argument("--gnd-port", type=int, default=5010)
    ap.add_argument("--sky-port", type=int, default=5000)
    ap.add_argument("--gnd-ip", default="127.0.0.1")
    ap.add_argument("--frames", type=int, default=30)
    ap.add_argument("--loss", type=float, default=0.15,
                    help="下行丢包率 (0~1), 默认 0.15 模拟弱网")
    ap.add_argument("--fps", type=int, default=30)
    ap.add_argument("--no-encrypt", action="store_true")
    ap.add_argument("--web-port", type=int, default=0,
                    help="启动 Web 管理界面端口 (0=不启动)")
    args = ap.parse_args()

    # 会话: 预共享组密钥 (模拟已完成配对的设备组, 跨进程共享)
    # 真实流程: 首次配对 (pairing.py 配对码) → 派生 master_key → 组会话
    DEMO_GROUP_KEY = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    sky_sm = create_session_manager(b"sky-001")
    sky_sm.adopt_session_key(DEMO_GROUP_KEY, b"ground-group")

    # 弱网整形在 SkyLink.send 内 (按 loss 概率丢弃)
    link = SkyLink(args.sky_port, (args.gnd_ip, args.gnd_port),
                   loss_rate=args.loss)

    # 复用器: 视频 + 控制统一出口 (WFQ, 控制优先)
    mux = StreamMultiplexer(SESSION_TAG, link.send,
                            chunk_size=CHUNK_SIZE, fec_k=FEC_K, fec_n=FEC_N)

    # 视频流 (SkySender: 分片+FEC+加密+ARQ 兜底)
    fragger = Fragmenter(SESSION_TAG, chunk_size=CHUNK_SIZE,
                         fec_k=FEC_K, fec_n=FEC_N)
    store = PacketStore(max_frames=120, ttl_sec=6.0)
    sender = SkySender(
        session_tag=SESSION_TAG,
        fragmenter=fragger,
        encrypt_func=(None if args.no_encrypt else sky_sm.encrypt_payload),
        send_callback=lambda pkt, r=None: mux.submit_packet(StreamType.VIDEO, pkt),
        chunk_size=CHUNK_SIZE, fec_k=FEC_K, fec_n=FEC_N,
        packet_store=store,
        arq_window_ms=20,
    )

    # 控制流 (ReliableChannel: 加密 + ARQ 必达)
    ctrl = ReliableChannel(
        SESSION_TAG, StreamType.CONTROL,
        encrypt_func=(None if args.no_encrypt else sky_sm.encrypt_payload),
        rto_ms=40, max_retries=10,
    )
    ctrl.set_retransmit_func(
        lambda pkt: mux.submit_packet(StreamType.CONTROL, pkt))

    # 发送帧 (按 fps 节奏)
    print(f"Sky 发送中: {args.frames} 帧, {args.loss*100:.0f}% 丢包, "
          f"加密 {'开' if not args.no_encrypt else '关'}")

    # Web 管理界面 (v1.0)
    if args.web_port:
        import webui
        webui.register_node("sky", lambda: {
            "丢包整形": {"loss_rate": args.loss,
                         "sent": link.sent, "dropped": link.dropped},
            "发送统计": sender.stats(),
            "控制流": ctrl.stats(),
            "复用器": mux.stats(),
        })
        webui.start_webui(args.web_port)

    rng = random.Random(42)
    t0 = time.monotonic()
    for fid in range(args.frames):
        data = os.urandom(rng.randint(4800, 6000))
        sender.send_frame(data, frame_id=fid, stream_id=0,
                          key_frame=(fid % 10 == 0))
        if fid % 7 == 0:
            ctrl.send_message(f"CMD:{fid}:ALT=50m".encode())
        time.sleep(1.0 / args.fps)

    print("发送完成, 等待 ARQ 收尾...")
    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        for pkt in link.drain():
            try:
                hdr = unpack_header(pkt)
            except HeaderError:
                continue
            if not hdr.is_arq_req():
                continue
            cid = 0
            if len(pkt) >= HEADER_SIZE + 4:
                cid = struct.unpack("!I", pkt[HEADER_SIZE:HEADER_SIZE + 4])[0]
            if hdr.stream_id == StreamType.CONTROL:
                ctrl.handle_arq_request(pkt, cid)
            else:
                sender.handle_arq_request(pkt, cid)
        sender.tick_arq()
        ctrl.tick_arq()
        time.sleep(0.002)

    sender.flush_arq()
    ctrl.flush_arq()
    time.sleep(0.3)
    mux.shutdown()
    link.close()
    sky_sm.destroy_session()

    st = sender.stats()
    print(f"Sky 结束: 发送 {st['packets_sent']} 包 "
          f"(重传 {st['retransmits']})  控制消息 {ctrl.stats()['sent']} 条")

    # Web 管理界面: 发送完后保持运行供查看
    if args.web_port:
        print("发送完成, Web 仪表盘保持运行 (Ctrl+C 退出)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
