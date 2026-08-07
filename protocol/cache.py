"""
SwarmLink v0.5 — Stale-While-Revalidate 帧缓存
=================================================
CDN 同款策略 (RFC 5861 思路): 断连/抖动时先用缓存里的旧帧顶上,
同时在后台重新请求新帧 (revalidate), 拿到新帧后替换。

用途:
- 地面端断连恢复瞬间, 先显示旧帧 (不黑屏)
- 弱网抖动时, 用旧帧填住画面, 等新帧到达

行为:
  get(frame_id, stale_ttl):
    - 缓存有且新鲜 (age < fresh_ttl) → 返回新帧
    - 缓存有但过期 (age < stale_ttl) → 返回旧帧 + 触发 revalidate (返回 (data, stale=True))
    - 缓存无 → None, 触发 revalidate
  revalidate 回调由上层实现 (向天空端重新请求该帧)
"""

import time
from typing import Callable, Optional, Tuple
from collections import OrderedDict


class StaleWhileRevalidate:
    """带 TTL 的两级帧缓存: fresh 期直出, stale 期先旧后新。"""

    def __init__(self, fresh_ttl: float = 0.5,
                 stale_ttl: float = 5.0,
                 max_frames: int = 128,
                 revalidate_cb: Optional[Callable] = None):
        """
        fresh_ttl:  帧多久内算"新鲜" (直接返回, 不触发后台刷新)
        stale_ttl:  过期多久内仍可返回旧帧 (stale 期间触发 revalidate)
        revalidate_cb: 刷新回调 (frame_id) -> 由上层重新请求
        """
        self._fresh_ttl = fresh_ttl
        self._stale_ttl = stale_ttl
        self._max = max_frames
        self._revalidate = revalidate_cb
        self._cache: OrderedDict = OrderedDict()  # frame_id -> (data, ts)
        self._inflight: set = set()               # 已触发 revalidate 的帧
        self._stats = {"hit_fresh": 0, "hit_stale": 0, "miss": 0,
                       "revalidated": 0, "evicted": 0}

    # ---------------- 写入 ----------------
    def put(self, frame_id: int, data: bytes):
        """写入/更新帧。新帧到达 → 标记新鲜。"""
        self._cache[frame_id] = (data, time.monotonic())
        self._inflight.discard(frame_id)
        while len(self._cache) > self._max:
            self._cache.popitem(last=False)
            self._stats["evicted"] += 1

    # ---------------- 读取 ----------------
    def get(self, frame_id: int) -> Tuple[Optional[bytes], bool]:
        """
        读取帧。返回 (data, stale):
        - (None, False): 无缓存, 已触发 revalidate
        - (data, False): 新鲜帧
        - (data, True):  旧帧 (stale, 已触发后台刷新)
        """
        now = time.monotonic()
        entry = self._cache.get(frame_id)
        if entry is None:
            self._stats["miss"] += 1
            self._trigger_revalidate(frame_id)
            return None, False
        data, ts = entry
        age = now - ts
        if age < self._fresh_ttl:
            self._stats["hit_fresh"] += 1
            return data, False
        if age < self._stale_ttl:
            self._stats["hit_stale"] += 1
            self._trigger_revalidate(frame_id)
            return data, True
        # 完全过期 (超过 stale_ttl) → 视为无
        self._cache.pop(frame_id, None)
        self._stats["miss"] += 1
        self._trigger_revalidate(frame_id)
        return None, False

    def _trigger_revalidate(self, frame_id: int):
        """触发一次后台刷新 (同帧只触发一次, 防风暴)。"""
        if frame_id in self._inflight:
            return
        self._inflight.add(frame_id)
        self._stats["revalidated"] += 1
        if self._revalidate:
            try:
                self._revalidate(frame_id)
            except Exception:
                pass

    def has(self, frame_id: int) -> bool:
        return frame_id in self._cache

    def stats(self) -> dict:
        s = dict(self._stats)
        s["cached_frames"] = len(self._cache)
        s["inflight_revalidate"] = len(self._inflight)
        return s
