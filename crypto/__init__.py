"""
SwarmLink Crypto Layer (P1)
===================================
- ChaCha20-Poly1305 AEAD
- per-packet key 派生（session_key + nonce → sub_key）
- 防重放（replay window）

依赖：libsodium / PyNaCl

⚠️ 当前为占位模块，v0.2 实现
"""
