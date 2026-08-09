//! SwarmLink Rust 核心 — PyO3 绑定
//!
//! Python 侧通过 `from swarmlink_core import rs_encode, rs_decode` 使用。
//! 性能热路径: GF(256) 查表 + RS 矩阵运算 (纯 Rust, 无 Python 循环)。

mod gf256;
mod rs;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// RS 编码: K 片数据 → N 片 (含 4 冗余)。返回 bytes 列表。
#[pyfunction]
fn rs_encode<'py>(py: Python<'py>, data_chunks: Vec<Vec<u8>>) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let rs = rs::ReedSolomon::new();
    if data_chunks.len() != rs::K {
        return Err(PyValueError::new_err(format!(
            "需要恰好 {} 片数据, 实际 {}",
            rs::K,
            data_chunks.len()
        )));
    }
    let out = rs.encode(&data_chunks);
    Ok(out.iter().map(|d| PyBytes::new_bound(py, d)).collect())
}

/// RS 解码: N 槽位 (缺失为 None) → K 片恢复数据 (bytes 列表)。
#[pyfunction]
fn rs_decode<'py>(py: Python<'py>, chunks: Vec<Option<Vec<u8>>>) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    let rs = rs::ReedSolomon::new();
    if chunks.len() != rs::N {
        return Err(PyValueError::new_err(format!(
            "需要 {} 槽位, 实际 {}",
            rs::N,
            chunks.len()
        )));
    }
    let out = rs
        .decode(&chunks)
        .map_err(|e| PyValueError::new_err(e))?;
    Ok(out.iter().map(|d| PyBytes::new_bound(py, d)).collect())
}

/// 模块元信息 (Python 侧探测用)。
#[pyfunction]
fn backend_info() -> String {
    format!("rust-core v{} (K={}, N={})", env!("CARGO_PKG_VERSION"), rs::K, rs::N)
}

#[pymodule]
fn swarmlink_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rs_encode, m)?)?;
    m.add_function(wrap_pyfunction!(rs_decode, m)?)?;
    m.add_function(wrap_pyfunction!(backend_info, m)?)?;
    Ok(())
}
