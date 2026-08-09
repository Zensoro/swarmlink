"""
Reed-Solomon (10,14) over GF(256) — 正确实现
==============================================
用范德蒙德矩阵 + GF(256) 矩阵求逆，支持任意位置 erasure。
K=10 data, N=14 total, 可恢复任意 ≤4 片丢失。
"""

import numpy as np

GF_POLY = 0x11D  # x^8 + x^4 + x^3 + x^2 + 1


class GF256:
    """伽罗瓦域 GF(2^8) 工具类，预计算 exp/log 表。"""
    def __init__(self):
        exp = [1] * 512
        log = [0] * 256
        x = 1
        for i in range(1, 255):
            x <<= 1
            if x & 0x100:
                x ^= GF_POLY
            exp[i] = x
            log[x] = i
        for i in range(255, 512):
            exp[i] = exp[i - 255]
        self.exp = exp
        self.log = log

    def mul(self, a, b):
        if a == 0 or b == 0:
            return 0
        return self.exp[self.log[a] + self.log[b]]

    def div(self, a, b):
        if b == 0:
            raise ZeroDivisionError
        if a == 0:
            return 0
        return self.exp[self.log[a] - self.log[b] + 255]

    def pow(self, a, n):
        if a == 0:
            return 0
        return self.exp[(self.log[a] * n) % 255]


class ReedSolomon:
    """RS(K=10, N=14) 系统码。data[0..K-1] 原样输出，后 N-K 片为冗余。

    后端: 优先 Rust 核心 (swarmlink_core, ~10-50x 加速);
    未安装时自动回退纯 Python + numpy 实现。
    """
    K = 10
    N = 14

    # Rust 核心探测 (懒加载)
    _rust = None

    @classmethod
    def _get_rust(cls):
        if cls._rust is None:
            try:
                import swarmlink_core
                cls._rust = swarmlink_core
            except ImportError:
                cls._rust = False
        return cls._rust

    @property
    def backend(self) -> str:
        return "rust" if self._get_rust() else "python"

    def __init__(self):
        self.gf = GF256()
        # 生成矩阵 G: (K+R) x K，前 KxK 是单位阵，后 RxK 是校验部分
        R = self.N - self.K
        # 校验矩阵 P: RxK，P[j][i] = α^((R-1-i)*j)  （范德蒙德派生）
        P = np.zeros((R, self.K), dtype=np.uint8)
        for j in range(R):
            for i in range(self.K):
                exp = (R - 1 - i) * j
                P[j, i] = self.gf.exp[exp % 255]
        # G = [I; P]
        I = np.eye(self.K, dtype=np.uint8)
        self.G = np.vstack([I, P])  # (N, K)

    def encode(self, data_chunks: list) -> list:
        """data_chunks: 恰好 K 片等长 → 返回 N 片（前 K 是数据原样，后 R 是冗余）。"""
        rust = self._get_rust()
        if rust:
            return list(rust.rs_encode([bytes(c) for c in data_chunks]))
        assert len(data_chunks) == self.K
        cs = len(data_chunks[0])
        # 矩阵乘：对每个字节位置 b，enc[b] = G @ data_bytes
        out = [bytearray(cs) for _ in range(self.N)]
        for i in range(self.K):
            d = data_chunks[i]
            for j in range(self.N):
                coeff = self.G[j, i]
                if coeff == 0:
                    continue
                for b in range(cs):
                    out[j][b] ^= self.gf.mul(d[b], coeff)
        return [bytes(o) for o in out]

    def decode(self, chunks: list, erasures: list) -> list:
        """
        chunks: 长度 N，缺失位置为 None 或 b''。
        erasures: 已知缺失下标。
        返回修复后的前 K 片数据（等长列表）。
        """
        rust = self._get_rust()
        if rust:
            slots = [None if (c is None or len(c) == 0) else bytes(c)
                     for c in chunks]
            return list(rust.rs_decode(slots))
        R = self.N - self.K
        cs = next((len(c) for c in chunks if c), 0)
        # 找出 K 个幸存片的下标
        survivors = [i for i in range(self.N) if chunks[i] is not None and len(chunks[i]) > 0]
        if len(survivors) < self.K:
            raise ValueError(f"only {len(survivors)} survivors, need {self.K}")
        have = survivors[:self.K]

        # 构建 KxK 范德蒙德子矩阵 V（用 G 的对应行）
        V = np.zeros((self.K, self.K), dtype=np.uint8)
        for row, idx in enumerate(have):
            V[row] = self.G[idx]  # G 的第 idx 行

        # 求 V 的逆
        invV = self._gf_inverse(V)

        # 重建 data: data = invV @ received_vector
        # 每个字节位置独立做矩阵乘
        recovered = [bytearray(cs) for _ in range(self.K)]
        for b in range(cs):
            # 接收向量（只取 have 位置）
            recv = np.array([chunks[i][b] for i in have], dtype=np.uint8)
            # data = invV @ recv
            for i in range(self.K):
                s = 0
                for j in range(self.K):
                    s ^= self.gf.mul(invV[i, j], int(recv[j]))
                recovered[i][b] = s
        return [bytes(r) for r in recovered]

    def _gf_inverse(self, M: np.ndarray) -> np.ndarray:
        """GF(256) 上的 KxK 矩阵求逆（高斯-约当消元）。"""
        K = M.shape[0]
        # 增广 [M | I]
        A = np.zeros((K, 2 * K), dtype=np.uint8)
        A[:, :K] = M.copy()
        for i in range(K):
            A[i, K + i] = 1

        for col in range(K):
            # 找主元
            pivot = None
            for row in range(col, K):
                if A[row, col] != 0:
                    pivot = row
                    break
            if pivot is None:
                raise ValueError("matrix singular in GF(256)")
            if pivot != col:
                A[[col, pivot]] = A[[pivot, col]]
            # 归一化主元行
            inv = self.gf.div(1, A[col, col])
            for j in range(2 * K):
                A[col, j] = self.gf.mul(A[col, j], inv)
            # 消去其他行
            for row in range(K):
                if row != col and A[row, col] != 0:
                    factor = A[row, col]
                    for j in range(2 * K):
                        A[row, j] ^= self.gf.mul(A[col, j], factor)
        return A[:, K:]
