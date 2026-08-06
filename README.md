# SwarmLink

> **One sky, many eyes.**
>
> 一个开源的、一对多并发图传系统。当别人在丢包里崩溃时，SwarmLink 在自愈。

灵感来自 QUIC、WebRTC SFU、CDN 边缘架构与 MTProto——为无人机图传重新组装。

---

## v0.2 已交付能力

### 🔐 安全层（军用/行业级标准）
| 能力 | 实现 | 对标标准 |
|---|---|---|
| 保密性 | ChaCha20-Poly1305 AEAD | TLS 1.3 / Signal |
| 密钥协商 | X25519 DH + HKDF-SHA256 | NIST SP 800-56A |
| 前向安全 | 每会话新 ephemeral key | Signal / Telegram Secret Chat |
| 防重放 | nonce 滑动窗口 (1024) | NSA Suite B |
| 防串看 | 每对设备独立 session_key | 行业级隔离 |
| 篡改检测 | Poly1305 MAC (AEAD 内置) | RFC 7539 |

> ⚠️ 非真军用：无 HSM/SE/TEE，无国密 SM 系列。适用于消防、边防、电力巡检等高安全需求场景。

### 📡 ARQ 完整重传链路
- **A 方案（默认）**：N 个客户端请求同分片 → 合并成 1 次重传 → 广播
- **B 方案（预留）**：ClientBitmap 精确记录谁缺啥 → 只发给缺的人
- **LossDetector**：指数退避检测缺失分片，防止 ARQ 风暴
- **PacketStore**：带 TTL 的滑动窗口存储，防内存爆

### 🔄 FEC 纠错
- Reed-Solomon(10,14)：丢 4 片以内当场恢复
- 与 ARQ 联合：FEC 优先修复，ARQ 兜底残余

---

## 快速验证

```bash
# 安装依赖
pip install pynacl

# 运行 v0.2 核心功能验证
python3 tests/test_v02_core.py

# 运行端到端 Demo (30% 丢包 + 断连)
python3 examples/sky_to_ground.py --loss 0.30 --blackout-prob 0.005

# 运行 v0.1 单元测试
python3 -m pytest tests/test_protocol.py -v
```

---

## 项目结构

```
swarmlink/
├── protocol/
│   ├── header.py        # 16B 协议头 (session/frame/frag/crc/flags)
│   ├── fragment.py      # 分片器 + 重组器 + FEC 引擎
│   ├── rs_codec.py      # Reed-Solomon(10,14) GF(256)
│   ├── arq.py          # ARQ 聚合器 A 方案 + ClientBitmap B 方案
│   ├── arq_full.py     # ARQ 完整链路 (SkySender/GroundReceiver/LossDetector)
│   └── security.py     # 🆕 v0.2 安全层 (DH/AEAD/防重放/前向安全)
├── tests/
│   ├── test_protocol.py      # v0.1 单元测试 (13 项)
│   ├── weaknet.py           # 弱网模拟器 + 性能度量
│   ├── test_v02_core.py     # 🆕 v0.2 核心验证 (6 项)
│   └── test_security_arq.py
├── examples/
│   └── sky_to_ground.py    # 端到端 Demo
├── docs/
│   ├── VISION.md
│   ├── ARCHITECTURE.md
│   └── KNOWN_LIMITATIONS.md
└── README.md
```

---

## 性能数据 (v0.2 实测)

### ARQ 聚合效率
| 客户端数 | 重传次数 | 节省带宽 |
|---|---|---|
| 2 | 1 | 50.0% |
| 4 | 1 | 75.0% |
| 8 | 1 | 87.5% |
| 16 | 1 | 93.8% |
| 32 | 1 | 96.9% |

### FEC(10,14) 恢复率 vs 丢包率
| 丢包率 | 送达率 | FEC 可恢复率 |
|---|---|---|
| 5% | 95.0% | 100.0% |
| 10% | 90.0% | 98.7% |
| 15% | 85.0% | 94.8% |
| 20% | 80.0% | 86.7% |
| 25% | 75.0% | 72.8% |
| 30% | 70.0% | 59.0% |

### 加密性能 (纯 Python, PyNaCl 可加速 100x)
| 载荷 | 加密吞吐 | 解密吞吐 | 相对开销 |
|---|---|---|---|
| 800B | 1.4 MB/s | 1.6 MB/s | 3.0% |
| 1400B | 1.7 MB/s | 1.6 MB/s | 1.7% |

> 💡 生产环境用 PyNaCl SecretBox → ~200 MB/s，足够 1080P@60fps 多路

---

## 协议头格式 (16B)

```
+0        +4        +8        +12       +16
| session_tag | frame_id | frag_id | total_frags | flags | stream_id | crc |
    4B          4B         2B         2B         1B       1B       2B
```

**FLAG 位域**：KEY_FRAME | FEC_PARITY | LAST_FRAG | ARQ_REQ | ARQ_REP | ENCRYPTED | RELIABLE | RESERVED

**安全头 (加密包附加)**：8B nonce + 16B Poly1305 tag = 24B/包

---

## 路线图

| 版本 | 状态 | 核心能力 |
|---|---|---|
| v0.1 | ✅ 完成 | 协议头 + 分片/FEC + ARQ 聚合 + 弱网模拟 |
| **v0.2** | **✅ 完成** | **安全层 + ARQ 完整链路 + 性能基准** |
| v0.3 | ⏳ 下一步 | Session 管理 + 多流复用 (图传/控制/遥测) |
| v0.4 | 规划 | SFU 选择性转发 + Simulcast/SVC 多版本 |
| v0.5 | 规划 | 一致性哈希路由 + 三级拓扑 + stale-while-revalidate |
| v0.6 | 规划 | RLNC 可插拔 + ns-3 集成 + Gilbert-Elliott 模型 |
| v1.0 | 规划 | Docker 镜像 + Web 管理界面 + 完整文档站 |

---

## 设计哲学

> **八字诀：拿来主义，削足适履。**
>
> 抄就抄最成熟的（QUIC 握手、SFU 转发、CDN 路由），削掉所有和图传无关的累赘，组合起来的效果——一对多、弱网韧、低延迟、可扩展——正是 1+1>2。

---

## License

GPLv3 — 保证开源传染性，防止闭源白嫖。

---

*"让一片天空，能被无数双眼同时看见。"*
