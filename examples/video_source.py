"""
SwarmLink — 视频源读取器
==========================
从 ffmpeg 管道读取 H.264 Annex-B 流, 按访问单元 (帧) 切分。

支持:
  - 本地合成源:  --source testsrc   (零网络依赖, 管线验证)
  - 本地文件:    --source path/to.mp4
  - 网络流:      --source https://.../master.m3u8  (HLS)
  - USB 摄像头:  --source /dev/video0

用法 (内部被 video_e2e.py 调用):
    src = VideoSource("testsrc", fps=24, size="640x360", frames=120)
    for frame in src:          # frame: bytes (H.264 Annex-B 访问单元)
        ...
"""

import subprocess
import sys
import os
from typing import Iterator, Optional


def _build_ffmpeg_cmd(source: str, fps: int, size: str,
                      hw: bool = False) -> list:
    """构造 ffmpeg 命令: 输出裸 H.264 (Annex-B), 每帧一个关键帧。"""
    # 输入侧
    if source == "testsrc":
        input_args = ["-f", "lavfi", "-i",
                      f"testsrc2=size={size}:rate={fps}:duration=60"]
    elif source.startswith(("http://", "https://")):
        input_args = ["-i", source]
    elif os.path.exists(source):
        input_args = ["-i", source]
    else:
        # 假设是设备 (摄像头)
        input_args = ["-f", "v4l2", "-framerate", str(fps), "-i", source]

    # 输出侧: 每帧关键帧 (g=1) 方便按帧切; 无 B 帧; 纯视频
    out_args = [
        "-c:v", "libx264",
        "-preset", "ultrafast",
        "-tune", "zerolatency",
        "-g", "1",          # 每帧 IDR → 帧可独立解码
        "-bf", "0",         # 无 B 帧 → 帧序 = 显示序
        "-pix_fmt", "yuv420p",
        "-an",              # 不要音频
        "-f", "h264",
        "-bsf:v", "h264_mp4toannexb",
        "pipe:1",
    ]
    return ["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin"] \
        + input_args + out_args


class VideoSource:
    """从 ffmpeg 管道读取并切分 H.264 帧。

    帧切分规则 (Annex-B):
      - start code: 00 00 01 或 00 00 00 01
      - 一个访问单元 = 从 start code 到下个 start code 之间的全部 NAL
      - 参数集 (SPS/PPS, NAL 7/8) 与紧随其后的 IDR 帧合并成同一帧
        (避免独立参数集帧被当成一帧)
    """

    def __init__(self, source: str = "testsrc", fps: int = 24,
                 size: str = "640x360", frames: int = 120,
                 hw: bool = False):
        self.source = source
        self.fps = fps
        self.size = size
        self.max_frames = frames
        self.hw = hw
        self._proc: Optional[subprocess.Popen] = None
        self.frame_count = 0
        self.bytes_read = 0
        self._params = b""

    def __enter__(self) -> "VideoSource":
        cmd = _build_ffmpeg_cmd(self.source, self.fps, self.size, self.hw)
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=1 << 20)
        return self

    def __exit__(self, *exc):
        if self._proc:
            try:
                self._proc.stdout.close()
            except Exception:
                pass
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass

    def _read_chunk(self, n: int = 1 << 16) -> bytes:
        data = self._proc.stdout.read(n)
        self.bytes_read += len(data)
        return data

    def __iter__(self) -> Iterator[bytes]:
        """逐帧产出 H.264 Annex-B 访问单元 (bytes)。"""
        buf = b""
        while self.frame_count < self.max_frames:
            chunk = self._read_chunk()
            if not chunk:
                # ffmpeg 结束 (流结束/网络断开)
                if buf:
                    frame = self._emit_frame(buf)
                    if frame:
                        yield frame
                break
            buf += chunk
            # 切分: 找所有 start code
            while True:
                idx = self._next_start_code(buf, skip_first=True)
                if idx is None:
                    break
                frame = buf[:idx]
                buf = buf[idx:]
                emitted = self._emit_frame(frame)
                if emitted:
                    yield emitted

    @staticmethod
    def _next_start_code(buf: bytes, skip_first: bool) -> Optional[int]:
        """找下一个 start code 的位置。skip_first 跳过最开头那个。"""
        i = 0
        while i < len(buf):
            j = buf.find(b"\x00\x00\x01", i)
            k = buf.find(b"\x00\x00\x00\x01", i)
            cand = []
            if j != -1:
                cand.append(j)
            if k != -1:
                cand.append(k)
            if not cand:
                return None
            pos = min(cand)
            if skip_first and pos == 0:
                i = 1
                continue
            return pos
        return None

    def _emit_frame(self, frame: bytes) -> Optional[bytes]:
        """处理一帧: 剥 start code, 合并参数集, 返回完整访问单元。"""
        # 剥掉起始 start code
        if frame.startswith(b"\x00\x00\x00\x01"):
            frame = frame[4:]
        elif frame.startswith(b"\x00\x00\x01"):
            frame = frame[3:]
        if not frame:
            return None
        # 参数集帧 (SPS/PPS, 无 slice) → 缓存, 合并到下一个 IDR
        nal_type = frame[0] & 0x1F
        if nal_type in (7, 8):  # SPS/PPS
            self._params = getattr(self, "_params", b"") + frame
            return None
        # 有 slice 的帧: 前缀参数集 (若有)
        params = getattr(self, "_params", b"")
        self._params = b""
        full = params + frame
        self.frame_count += 1
        return b"\x00\x00\x00\x01" + full
