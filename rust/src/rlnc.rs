//! RLNC 随机线性网络编码 (对标 Python protocol/rlnc.py)
//!
//! 编码: 每包 = 随机系数向量 (K 字节) + 线性组合数据
//! 解码: 高斯消元 (逐包消元 + 秩判断), 收集 K 个线性无关包后回代求解

use crate::gf256::Gf256;
use rand::Rng;

/// 包结构: [1B K][K 字节系数][cs 字节数据]
pub struct Rlnc;

impl Rlnc {
    /// 编码: K 片数据 → K+extra 个编码包。
    pub fn encode(data_chunks: &[Vec<u8>], extra: usize) -> Vec<Vec<u8>> {
        let gf = Gf256::new();
        let k = data_chunks.len();
        let cs = data_chunks[0].len();
        let n_out = k + extra;

        let mut rng = rand::rng();
        let mut packets = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            // 随机系数 (1..255, 非零保证有效)
            let coeffs: Vec<u8> = (0..k)
                .map(|_| rng.random_range(1..=255u8))
                .collect();
            let mut out = vec![0u8; cs];
            for (i, d) in data_chunks.iter().enumerate() {
                let c = coeffs[i];
                for b in 0..cs {
                    out[b] ^= gf.mul(d[b], c);
                }
            }
            let mut pkt = vec![k as u8];
            pkt.extend_from_slice(&coeffs);
            pkt.extend_from_slice(&out);
            packets.push(pkt);
        }
        packets
    }

    /// 解码: 任意 ≥K 个线性无关包 → K 片数据。
    /// 包格式: [1B K][K 系数][数据]
    pub fn decode(packets: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        let gf = Gf256::new();
        if packets.is_empty() {
            return Err("no packets".into());
        }
        let k = packets[0][0] as usize;
        let cs = packets[0].len() - 1 - k;
        if packets.len() < k {
            return Err(format!("only {} packets, need >= {k}", packets.len()));
        }

        // 逐包消元: 维护行阶梯矩阵 (每行: [K 系数 | cs 数据])
        let mut rows: Vec<Vec<u8>> = Vec::new();
        let mut pivots: Vec<usize> = Vec::new();

        for pkt in packets {
            if pkt.len() < 1 + k + cs {
                continue; // 坏包
            }
            let mut row = vec![0u8; k + cs];
            row[..k].copy_from_slice(&pkt[1..1 + k]);
            row[k..].copy_from_slice(&pkt[1 + k..]);

            // 用已存在的 pivot 列消元
            let mut r = row;
            for (idx, &col) in pivots.iter().enumerate() {
                if r[col] != 0 {
                    let factor = gf.div(r[col], rows[idx][col]);
                    for j in col..k + cs {
                        r[j] ^= gf.mul(factor, rows[idx][j]);
                    }
                    r[col] = 0;
                }
            }
            // 找新 pivot
            let pivot = (0..k).find(|&j| r[j] != 0);
            if let Some(p) = pivot {
                rows.push(r);
                pivots.push(p);
                if rows.len() == k {
                    break;
                }
            }
        }

        if rows.len() < k {
            return Err(format!(
                "rank {} < {k}, 包不足或线性相关",
                rows.len()
            ));
        }

        // 回代求解 (高斯-约当): 每行主元归一 + 消去其他行
        let mut m = rows;
        for i in 0..k {
            let pc = pivots[i];
            // 归一化
            let pivot_val = m[i][pc];
            if pivot_val != 1 {
                let inv = gf.div(1, pivot_val);
                for j in pc..k + cs {
                    m[i][j] = gf.mul(m[i][j], inv);
                }
            }
            // 消去其他行
            for r in 0..k {
                if r != i && m[r][pc] != 0 {
                    let factor = m[r][pc];
                    for j in pc..k + cs {
                        m[r][j] ^= gf.mul(factor, m[i][j]);
                    }
                }
            }
        }

        // 提取数据部分 (系数列之后)
        Ok(m.iter()
            .map(|row| row[k..k + cs].to_vec())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(k: usize, cs: usize) -> Vec<Vec<u8>> {
        (0..k).map(|i| vec![i as u8; cs]).collect()
    }

    #[test]
    fn roundtrip() {
        let data = chunks(10, 600);
        let packets = Rlnc::encode(&data, 4);
        assert_eq!(packets.len(), 14);
        let rec = Rlnc::decode(&packets).unwrap();
        assert_eq!(rec, data);
    }

    #[test]
    fn recovers_loss() {
        let data = chunks(10, 600);
        let packets = Rlnc::encode(&data, 4);
        // 丢 4 个 (任意位置)
        let survived: Vec<Vec<u8>> = packets.iter().take(10).cloned().collect();
        assert_eq!(survived.len(), 10);
        let rec = Rlnc::decode(&survived).unwrap();
        assert_eq!(rec, data);
    }

    #[test]
    fn rejects_insufficient() {
        let data = chunks(10, 600);
        let packets = Rlnc::encode(&data, 4);
        assert!(Rlnc::decode(&packets[..9]).is_err());
    }

    #[test]
    fn flexible_k() {
        let data = chunks(2, 600);
        let packets = Rlnc::encode(&data, 1);
        assert_eq!(packets.len(), 3);
        let rec = Rlnc::decode(&packets[..2]).unwrap();
        assert_eq!(rec, data);
    }
}
