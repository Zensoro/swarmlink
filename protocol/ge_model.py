"""
SwarmLink v0.6 — Gilbert-Elliott 突发丢包模型
===============================================
两状态马尔可夫链模拟真实 Wi-Fi 信道:
  - GOOD 态 (G): 低丢包率 p_g (通常 ≈ 0)
  - BAD 态 (B): 高丢包率 p_b (突发期, 如干扰/遮挡)
  状态转移概率: 每秒 G→B = p_gb, B→G = p_bg

关键参数 (与 ns-3 / IEEE 802.11 文献对齐):
  - 平均突发长度 L_b (bad burst 平均持续包数): L_b = 1 / p_bg
  - 稳态坏态占比 (bad 时间占比): P_B = p_gb / (p_gb + p_bg)
  - 平均丢包率: P_loss = P_B * p_b + (1 - P_B) * p_g

对比均匀丢包:
  - 均匀: 每包独立 p → 丢包分散, 弱网模拟偏乐观
  - GE: 丢包成串 (burst), 更接近真实 Wi-Fi 干扰/遮挡特征
    (KNOWN_LIMITATIONS #3 的修复核心)
"""

import random
from typing import Optional


class GilbertElliott:
    """两状态突发丢包模型 (per-packet 决策)。

    用法:
        ge = GilbertElliott(p_gb=0.02, p_bg=0.3, p_g=0.0, p_b=0.6, seed=7)
        if ge.is_lost():   # 当前包是否丢弃
            ...
    """

    def __init__(self, p_gb: float = 0.02, p_bg: float = 0.3,
                 p_g: float = 0.0, p_b: float = 0.6,
                 seed: int = 42):
        """
        p_gb: GOOD→BAD 每包转移概率
        p_bg: BAD→GOOD 每包转移概率
        p_g:  GOOD 态丢包率
        p_b:  BAD 态丢包率
        """
        assert 0 <= p_gb <= 1 and 0 <= p_bg <= 1
        assert 0 <= p_g <= 1 and 0 <= p_b <= 1
        self.p_gb = p_gb
        self.p_bg = p_bg
        self.p_g = p_g
        self.p_b = p_b
        self.rng = random.Random(seed)
        # 初始态: 稳态分布
        denom = p_gb + p_bg
        self._bad = (denom > 0) and (self.rng.random() < p_gb / denom)

        self._stats = {
            "packets": 0, "lost": 0,
            "bursts": 0, "max_burst": 0, "cur_burst": 0,
            "p_bad": 0.0,
        }

    # ---------------- 核心 ----------------
    def is_lost(self) -> bool:
        """当前包是否丢弃。每包调用一次, 内部推进状态。"""
        # 状态转移
        r = self.rng.random()
        if self._bad:
            if r < self.p_bg:
                self._bad = False
        else:
            if r < self.p_gb:
                self._bad = True
                self._stats["bursts"] += 1

        # 丢包决策
        loss_p = self.p_b if self._bad else self.p_g
        lost = self.rng.random() < loss_p

        # 统计
        self._stats["packets"] += 1
        if lost:
            self._stats["lost"] += 1
            self._stats["cur_burst"] += 1
            self._stats["max_burst"] = max(self._stats["max_burst"],
                                           self._stats["cur_burst"])
        else:
            self._stats["cur_burst"] = 0
        return lost

    # ---------------- 统计 ----------------
    @property
    def average_loss_rate(self) -> float:
        """稳态理论平均丢包率。"""
        denom = self.p_gb + self.p_bg
        if denom == 0:
            return self.p_g
        p_bad = self.p_gb / denom
        return p_bad * self.p_b + (1 - p_bad) * self.p_g

    @property
    def average_burst_len(self) -> float:
        """理论平均突发长度 (连续丢失包数期望)。"""
        if self.p_bg == 0:
            return float("inf")
        return 1.0 / self.p_bg

    def stats(self) -> dict:
        s = dict(self._stats)
        s["loss_rate_actual"] = (self._stats["lost"] /
                                 max(1, self._stats["packets"]))
        s["loss_rate_theory"] = self.average_loss_rate
        s["burst_len_avg"] = self.average_burst_len
        return s
