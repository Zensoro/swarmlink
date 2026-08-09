//! Reed-Solomon (K=10, N=14) 编码/解码, 对标 Python protocol/rs_codec.py
//!
//! 生成矩阵 G: (N x K) = [I; P], P[j][i] = α^((R-1-i)*j)
//! 编码: enc = G @ data (GF256 矩阵乘)
//! 解码: 取任意 K 个幸存行的子矩阵 V, data = V^{-1} @ received

use crate::gf256::Gf256;

pub const K: usize = 10;
pub const N: usize = 14;
const R: usize = N - K; // 4 冗余

/// Reed-Solomon 编解码器 (K=10, N=14)。
pub struct ReedSolomon {
    gf: Gf256,
    g: Vec<Vec<u8>>, // N x K 生成矩阵
}

impl ReedSolomon {
    pub fn new() -> Self {
        let gf = Gf256::new();
        // P[j][i] = α^((R-1-i)*j), Python 语义: 负指数用数学取模
        let mut g = vec![vec![0u8; K]; N];
        for i in 0..K {
            g[i][i] = 1; // 前 K 行单位阵
        }
        for j in 0..R {
            for i in 0..K {
                // (R-1-i) 可能为负, 用 i64 数学取模 (与 Python % 一致)
                let base = (R as i64 - 1 - i as i64) * j as i64;
                let e = ((base % 255) + 255) % 255;
                g[K + j][i] = gf.exp[e as usize];
            }
        }
        Self { gf, g }
    }

    /// 编码: K 片等长数据 → N 片 (前 K 原样, 后 R 冗余)。
    pub fn encode(&self, data_chunks: &[Vec<u8>]) -> Vec<Vec<u8>> {
        debug_assert_eq!(data_chunks.len(), K, "需要恰好 {K} 片数据");
        let cs = data_chunks[0].len();
        let mut out = vec![vec![0u8; cs]; N];
        for i in 0..K {
            let d = &data_chunks[i];
            for j in 0..N {
                let coeff = self.g[j][i];
                if coeff == 0 {
                    continue;
                }
                let row = &mut out[j];
                for b in 0..cs {
                    row[b] ^= self.gf.mul(d[b], coeff);
                }
            }
        }
        out
    }

    /// 解码: chunks 长度 N, 缺失位置为 None。返回 K 片恢复数据。
    pub fn decode(&self, chunks: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>, String> {
        debug_assert_eq!(chunks.len(), N, "需要 {N} 槽位");
        // 收集幸存行 (下标 + 数据)
        let mut survivors: Vec<(usize, &Vec<u8>)> = chunks
            .iter()
            .enumerate()
            .filter_map(|(idx, c)| c.as_ref().map(|d| (idx, d)))
            .collect();
        if survivors.len() < K {
            return Err(format!(
                "only {} survivors, need {K}",
                survivors.len()
            ));
        }
        let cs = survivors[0].1.len();
        let have: Vec<usize> = survivors.drain(..K).map(|(i, _)| i).collect();

        // 构建 KxK 子矩阵 V (用 G 的对应行)
        let mut v = vec![vec![0u8; K]; K];
        for (row, &idx) in have.iter().enumerate() {
            v[row] = self.g[idx].clone();
        }

        // 求逆 invV (GF256 高斯-约当)
        let inv_v = self.gf_inverse(&v)?;

        // 恢复: data[i] = Σ_j invV[i][j] * recv[j]
        let mut recovered = vec![vec![0u8; cs]; K];
        for b in 0..cs {
            for i in 0..K {
                let mut s = 0u8;
                for j in 0..K {
                    s ^= self.gf.mul(inv_v[i][j], chunks[have[j]].as_ref().unwrap()[b]);
                }
                recovered[i][b] = s;
            }
        }
        Ok(recovered)
    }

    /// GF(256) 矩阵求逆 (增广 [M|I] 高斯-约当消元)。
    fn gf_inverse(&self, m: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        let k = m.len();
        // 增广矩阵
        let mut a = vec![vec![0u8; 2 * k]; k];
        for i in 0..k {
            for j in 0..k {
                a[i][j] = m[i][j];
            }
            a[i][k + i] = 1;
        }
        for col in 0..k {
            // 找主元行
            let pivot = (col..k)
                .find(|&r| a[r][col] != 0)
                .ok_or_else(|| "矩阵不可逆 (行线性相关)".to_string())?;
            if pivot != col {
                a.swap(pivot, col);
            }
            // 归一化
            let inv = self.gf.div(1, a[col][col]);
            for j in col..2 * k {
                a[col][j] = self.gf.mul(a[col][j], inv);
            }
            // 消去其他行
            for r in 0..k {
                if r != col && a[r][col] != 0 {
                    let factor = a[r][col];
                    for j in col..2 * k {
                        a[r][j] ^= self.gf.mul(factor, a[col][j]);
                    }
                }
            }
        }
        // 取右侧
        Ok((0..k)
            .map(|i| a[i][k..2 * k].to_vec())
            .collect())
    }
}

impl Default for ReedSolomon {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks() -> Vec<Vec<u8>> {
        (0..K).map(|i| vec![i as u8; 16]).collect()
    }

    #[test]
    fn roundtrip() {
        let rs = ReedSolomon::new();
        let data = chunks();
        let enc = rs.encode(&data);
        assert_eq!(enc.len(), N);
        assert_eq!(enc[0], data[0], "系统码: 前 K 片原样");
        let decoded = rs
            .decode(&(0..N).map(|i| Some(enc[i].clone())).collect::<Vec<_>>())
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn recovers_4_erasures() {
        let rs = ReedSolomon::new();
        let data = chunks();
        let enc = rs.encode(&data);
        // 丢 4 片 (下标 3, 7, 11, 13)
        let mut slots: Vec<Option<Vec<u8>>> = (0..N).map(|i| Some(enc[i].clone())).collect();
        for i in [3, 7, 11, 13] {
            slots[i] = None;
        }
        let decoded = rs.decode(&slots).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn rejects_too_many_erasures() {
        let rs = ReedSolomon::new();
        let data = chunks();
        let enc = rs.encode(&data);
        let mut slots: Vec<Option<Vec<u8>>> = (0..N).map(|i| Some(enc[i].clone())).collect();
        for i in 0..5 {
            slots[i] = None; // 丢 5 片 > R=4
        }
        assert!(rs.decode(&slots).is_err());
    }
}
