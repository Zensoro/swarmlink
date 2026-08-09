"""
SwarmLink v0.6 — RLNC (随机线性网络编码) 可插拔 FEC
====================================================
对比 RS(10,14):
  - RS:  固定范德蒙德结构, 丢 ≤4 片可恢复, 码率固定 N/K
  - RLNC: 每包随机系数线性组合, 任意 K 个线性无关包可解码,
          码率灵活 (可渐进解码: 收到第 K 个有用包立刻解码)

编码:
  - 原始 K 个数据块 d1..dK (等长)
  - 编码包 c_j = Σ (coeff_i * d_i), coeff_i 随机取自 GF(256)
  - 每包携带系数向量 (K 字节) + 数据 → 解码端可重建

解码:
  - 高斯消元: 收集 ≥K 个线性无关包, 解线性方程组恢复 d1..dK
  - 渐进: 每收一个有用包 rank+1, rank=K 时解码成功

与 RS 兼容接口 (encode/decode), 供 FEC 引擎切换:
  encode(data_chunks) -> [packets...]
  decode(packets, ...) -> [data...]
"""

import os
import random
import numpy as np

from .rs_codec import GF256


class RandomLinearCode:
    """RLNC: 随机系数线性网络编码 (GF256)。

    后端: 优先 Rust 核心 (swarmlink_core, ~10-50x 加速);
    未安装时自动回退纯 Python + numpy。
    """

    # Rust 核心探测 (懒加载)
    _rust = None

    @classmethod
    def _get_rust(cls):
        if cls._rust is None:
            try:
                import swarmlink_core
                cls._rust = swarmlink_core
            except ImportError:
                cls._rust = None
        return cls._rust

    def __init__(self, seed: int = 42, extra_packets: int = 4):
        """
        extra_packets: 冗余包数 (默认 4, 对齐 RS(10,14) 的 40% 冗余)。
        K 由 encode 时的数据片数决定 (灵活, 不固定 10)。
        """
        self.gf = GF256()
        self.rng = random.Random(seed)
        self.extra = extra_packets

    # ---------------- 编码 ----------------
    def encode(self, data_chunks: list, n_out: int = None) -> list:
        """
        data_chunks: K 片等长数据 → 返回 K+extra 个编码包。
        每个包: [1B K][K 字节系数向量][编码数据]  (先头后体)
        """
        K = len(data_chunks)
        cs = len(data_chunks[0])
        if n_out is None:
            n_out = K + self.extra

        # Rust 后端 (swarmlink_core, 加速 ~10-50x)
        rust = self._get_rust()
        if rust is not None:
            return list(rust.rlnc_encode(
                [bytes(c) for c in data_chunks], n_out - K))

        packets = []
        for _ in range(n_out):
            # 随机系数向量 (K 字节)
            coeffs = [self.rng.randint(1, 255) for _ in range(K)]
            out = bytearray(cs)
            for i in range(K):
                d = data_chunks[i]
                c = coeffs[i]
                for b in range(cs):
                    out[b] ^= self.gf.mul(d[b], c)
            packets.append(bytes([K]) + bytes(coeffs) + bytes(out))
        return packets

    # ---------------- 解码 ----------------
    def decode(self, packets: list) -> list:
        """
        packets: 收到的编码包列表 (每个: [1B K][K 系数][数据])。
        任意 ≥K 个线性无关包 → 恢复 K 片数据。
        返回 K 片原始数据 (等长)。
        """
        if not packets:
            raise ValueError("no packets")
        K = packets[0][0]
        cs = len(packets[0]) - 1 - K
        if len(packets) < K:
            raise ValueError(f"only {len(packets)} packets, need >= {K}")

        # Rust 后端
        rust = self._get_rust()
        if rust is not None:
            return list(rust.rlnc_decode([bytes(p) for p in packets]))

        # 高斯消元: 增广矩阵 [K x (K+cs)]
        rows = []
        for pkt in packets:
            coeffs = np.frombuffer(pkt[1:1 + K], dtype=np.uint8).astype(int)
            data = np.frombuffer(pkt[1 + K:], dtype=np.uint8).astype(int)
            rows.append(np.concatenate([coeffs, data]))

        # 行阶梯化 (GF256), 收集线性无关行
        independent = []
        pivot_cols = []
        for row in rows:
            r = row.copy()
            # 消去已存在的 pivot 列
            for col, pivot_row in zip(pivot_cols, independent):
                if r[col] != 0:
                    factor = self.gf.div(int(r[col]), int(pivot_row[col]))
                    for j in range(col, K + cs):
                        r[j] ^= self.gf.mul(factor, int(pivot_row[j]))
                    r[col] = 0
            # 找新 pivot
            pivot = next((j for j in range(K) if r[j] != 0), None)
            if pivot is not None:
                independent.append(r)
                pivot_cols.append(pivot)
                if len(independent) == K:
                    break

        if len(independent) < K:
            raise ValueError(
                f"rank {len(independent)} < {K}, 包不足或线性相关")

        # 回代求解: 每行主元列, 从后往前消
        # 简化: 用增广矩阵行阶梯, 直接回代
        M = np.array(independent, dtype=int)  # K x (K+cs)
        # 高斯-约当: 消成单位阵
        for i in range(K):
            # 归一化 (系数变为 1)
            pivot = int(M[i, pivot_cols[i]])
            if pivot != 1:
                inv = self.gf.div(1, pivot)
                for j in range(pivot_cols[i], K + cs):
                    M[i, j] = self.gf.mul(int(M[i, j]), inv)
            # 消去其他行的该列
            for k in range(K):
                if k != i and M[k, pivot_cols[i]] != 0:
                    factor = int(M[k, pivot_cols[i]])
                    for j in range(pivot_cols[i], K + cs):
                        M[k, j] ^= self.gf.mul(factor, int(M[i, j]))

        # 提取数据: 每行的数据部分 (pivot 列之后)
        recovered = []
        for i in range(K):
            row = M[i]
            data_part = row[K:K + cs]
            recovered.append(bytes(int(x) for x in data_part))
        return recovered
