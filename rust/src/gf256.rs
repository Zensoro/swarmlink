//! GF(2^8) 有限域运算 (查表法, 对标 Python protocol/rs_codec.py 的 GF256)
//!
//! 多项式: x^8 + x^4 + x^3 + x^2 + 1 (0x11D, 与 Python 版一致)

/// GF(256) 查表运算器。
pub struct Gf256 {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

impl Gf256 {
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        // 255..512 周期重复
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let la = self.log[a as usize] as u16;
        let lb = self.log[b as usize] as u16;
        self.exp[(la + lb) as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        debug_assert!(b != 0, "GF256 除以零");
        if a == 0 {
            return 0;
        }
        let la = self.log[a as usize] as u16;
        let lb = self.log[b as usize] as u16;
        self.exp[(la + 255 - lb) as usize]
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_identity() {
        let gf = Gf256::new();
        for i in 0..=255u8 {
            assert_eq!(gf.mul(i, 1), i);
            assert_eq!(gf.mul(i, 0), 0);
        }
    }

    #[test]
    fn mul_div_inverse() {
        let gf = Gf256::new();
        for i in 1..=255u8 {
            for j in 1..=255u8 {
                let m = gf.mul(i, j);
                assert_eq!(gf.div(m, j), i, "mul/div 逆运算失败 {i}*{j}");
            }
        }
    }

    #[test]
    fn matches_python_vectors() {
        // 与 Python GF256 实际运算结果对照 (protocol/rs_codec.py)
        let gf = Gf256::new();
        assert_eq!(gf.mul(0x02, 0x03), 0x06);
        assert_eq!(gf.mul(0x57, 0x83), 0x31); // Python: hex(0x57*0x83)=0x31
        assert_eq!(gf.mul(0xCA, 0x53), 0x8F); // Python: hex(0xCA*0x53)=0x8f
    }
}
