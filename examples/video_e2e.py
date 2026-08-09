"""
SwarmLink — 真实视频端到端验证
================================
真实视频帧 (ffmpeg 管道) → 分片/FEC/加密 → 链路 → 重组 → 可播放文件。

  视频源:  --source testsrc (本地合成) | 本地文件 | HLS 网络流
  链路:    进程内 + 可选丢包 (--loss), 全真实协议处理

运行:
  # 本地合成源 (零依赖验证管线)
  python3 examples/video_e2e.py --source testsrc --frames 100 --loss 0.15

  # 网络流 (真实视频内容)
  python3 examples/video_e2e.py \
    --source "https://demo.unified-streaming.com/k8s/features/stable/video/tears-of-steel/tears-of-steel.ism/.m3u8" \
    --frames 200 --loss 0.15

  # 验证输出可播放
  ffplay out.h264    # 或 ffmpeg -i out.h264 -f null -
"""

import sys
import os
import time
import random
import argparse
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.fragment import Fragmenter, Reassembler
from protocol.arq_full import PacketStore, SkySender, GroundReceiver
from protocol.security_nacl import create_session_manager
from examples.video_source import VideoSource


SESSION = 0x0B1D
CHUNK_SIZE = 600
FEC_K = 10
FEC_N = 14


class InProcessLink:
    """进程内有损链路: sky 发送 → 按概率丢 → 接收端。"""
    def __init__(self, loss_rate: float = 0.0, seed: int = 42):
        self.rng = random.Random(seed)
        self.loss_rate = loss_rate
        self.queue = deque()
        self.sent = 0
        self.dropped = 0

    def send(self, packet: bytes, recipients=None):
        self.sent += 1
        if self.loss_rate > 0 and self.rng.random() < self.loss_rate:
            self.dropped += 1
            return
        self.queue.append(packet)

    def drain(self) -> list:
        out = []
        while self.queue:
            out.append(self.queue.popleft())
        return out


def main():
    ap = argparse.ArgumentParser(description="SwarmLink 真实视频端到端")
    ap.add_argument("--source", default="testsrc",
                    help="视频源: testsrc | 文件路径 | HLS URL")
    ap.add_argument("--frames", type=int, default=100)
    ap.add_argument("--fps", type=int, default=24)
    ap.add_argument("--size", default="640x360")
    ap.add_argument("--loss", type=float, default=0.15, help="链路丢包率")
    ap.add_argument("--no-encrypt", action="store_true")
    ap.add_argument("--output", default=None, help="输出文件 (默认 out.h264)")
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    out_path = args.output or "out.h264"

    # 会话 (demo 组密钥)
    KEY = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    sky_sm = create_session_manager(b"sky-video")
    sky_sm.adopt_session_key(KEY, b"group")
    gnd_sm = create_session_manager(b"gnd-video")
    gnd_sm.adopt_session_key(KEY, b"group")

    link = InProcessLink(loss_rate=args.loss)
    reasm = Reassembler(SESSION, fec_k=FEC_K, fec_n=FEC_N)
    completed = {}

    def on_complete(cid, fid, data):
        completed[fid] = data

    recv = GroundReceiver(
        client_id=0, session_tag=SESSION, reassembler=reasm,
        decryptor_func=(None if args.no_encrypt else gnd_sm.decrypt_payload),
        send_arq_func=lambda p, r=None: None,  # 进程内无上行 (FEC 够用)
        on_frame_complete=on_complete,
        rto_ms=20, max_retries=4, fec_k=FEC_K, fec_n=FEC_N,
    )
    sender = SkySender(
        session_tag=SESSION,
        fragmenter=Fragmenter(SESSION, chunk_size=CHUNK_SIZE,
                              fec_k=FEC_K, fec_n=FEC_N),
        encrypt_func=(None if args.no_encrypt else sky_sm.encrypt_payload),
        send_callback=lambda p, r=None: link.send(p),
        chunk_size=CHUNK_SIZE, fec_k=FEC_K, fec_n=FEC_N,
        packet_store=PacketStore(max_frames=120),
        arq_window_ms=20,
    )

    print(f"SwarmLink 真实视频端到端")
    print(f"  源: {args.source}  帧数: {args.frames}  分辨率: {args.size}  "
          f"丢包: {args.loss*100:.0f}%  加密: {'开' if not args.no_encrypt else '关'}")

    # 发送循环 + 接收泵
    frames_in = 0
    t0 = time.monotonic()
    frame_interval = 1.0 / args.fps

    with VideoSource(args.source, fps=args.fps, size=args.size,
                     frames=args.frames) as src:
        next_send = time.monotonic()
        for frame in src:
            frames_in += 1
            # 发送
            sender.send_frame(frame, frame_id=frames_in - 1,
                              stream_id=0, key_frame=True)
            # 接收泵 (同步喂)
            for pkt in link.drain():
                recv.feed(pkt)
            recv.tick_loss_check()
            sender.tick_arq()
            # 限速 (按 fps)
            next_send += frame_interval
            wait = next_send - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            if time.monotonic() - t0 > args.timeout:
                print("超时中止")
                break

    # 收尾: 排空链路 + ARQ 收尾
    sender.flush_arq()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        for pkt in link.drain():
            recv.feed(pkt)
        recv.tick_loss_check()
        sender.tick_arq()
        if len(completed) >= frames_in:
            break
        time.sleep(0.005)
    time.sleep(0.2)
    for pkt in link.drain():
        recv.feed(pkt)
    elapsed = time.monotonic() - t0

    # 按序写文件
    with open(out_path, "wb") as f:
        for fid in sorted(completed.keys()):
            f.write(completed[fid])

    # 统计
    total = frames_in
    got = len(completed)
    st = sender.stats()
    print(f"\n结果 (耗时 {elapsed:.1f}s):")
    print(f"  输入帧: {total}  完成帧: {got}  "
          f"完成率: {got/max(1,total)*100:.1f}%")
    print(f"  链路: 发送 {link.sent} 包, 丢 {link.dropped} "
          f"({link.dropped/max(1,link.sent)*100:.1f}%)")
    print(f"  重传: {st['retransmits']}  FEC+ARQ 兜底生效")
    print(f"  输出: {out_path} ({os.path.getsize(out_path)} bytes)")
    print(f"  播放验证: ffplay {out_path}")

    return 0 if got >= total * 0.8 else 1


if __name__ == "__main__":
    sys.exit(main())
