# SwarmLink

> **One sky, many eyes.**
>
> 一个开源的、一对多并发图传系统。当别人在丢包里崩溃时，SwarmLink 在自愈。

灵感来自 QUIC、WebRTC SFU、CDN 边缘架构与 MTProto——为无人机图传重新组装。

---

## v0.2 已交付能力

### 🔐 安全层（软件级端到端加密）
| 能力 | 实现 | 设计参考 |
|---|---|---|
| 保密性 | ChaCha20-Poly1305 AEAD | TLS 1.3 常用套件 |
| 密钥协商 | X25519 DH + HKDF-SHA256 | 通用实践 |
| 前向安全 | 每会话新 ephemeral key | Signal / MTProto |
| 防重放 | nonce 滑动窗口 (1024) | 通用实践 |
| 防串看 | 每对设备独立 session_key | 按对隔离 |
| 篡改检测 | AEAD 内置 MAC | RFC 8439 |

> ⚠️ 范围与边界：
> - 安全层由 **`security_nacl.py`** 提供：PyNaCl / libsodium 真 AEAD（ChaCha20-Poly1305 IETF 构造），PyNaCl 为硬依赖
> - 无 HSM/SE/TEE 硬件保护，无国密 SM 系列，不面向军用/涉密场景
> - 适用场景：消防、边防巡逻、电力巡检等民用高安全需求

### 📡 ARQ 完整重传链路
- **A 方案（默认）**：N 个客户端请求同分片 → 合并成 1 次重传 → 广播
- **B 方案（预留）**：ClientBitmap 精确记录谁缺啥 → 只发给缺的人
- **LossDetector**：指数退避检测缺失分片，防止 ARQ 风暴
- **PacketStore**：带 TTL 的滑动窗口存储，防内存爆
- **ReliableChannel（控制/遥测流）**：单包 + 滑窗空洞检测 + 静默探测 + ARQ 重传，15% 丢包下实测 4/4 必达

### 🔄 FEC 纠错
- Reed-Solomon(10,14)：丢 4 片以内当场恢复
- 与 ARQ 联合：FEC 优先修复，ARQ 兜底残余

---

## 快速验证

```bash
# 安装依赖
pip install pynacl pytest numpy

# 运行全部测试 (64 项)
python3 -m pytest tests/ -q

# 运行 v0.3 真实 UDP 三档弱网联调 (正常/15%/40%+断连/多流复用/SFU)
python3 examples/udp_e2e_test.py

# 单机双进程 demo (两个终端, 本地回环真实 UDP socket)
#   终端 1: python3 examples/gnd.py --frames 30
#   终端 2: python3 examples/sky.py --frames 30 --loss 0.15

# 运行 v0.2 核心功能验证
python3 tests/test_v02_core.py
```

---

## 项目结构

```
swarmlink/
├── protocol/
│   ├── header.py        # 20B 协议头 (session/frame/frag/crc/flags/frame_len)
│   ├── fragment.py      # 分片器 + 重组器 (按 frame_len 裁剪补零) + FEC 引擎
│   ├── rs_codec.py      # Reed-Solomon(10,14) GF(256)
│   ├── arq.py          # ARQ 聚合器 A 方案 + ClientBitmap B 方案
│   ├── arq_full.py     # ARQ 完整链路 (SkySender/GroundReceiver/LossDetector)
│   ├── multiplex.py    # 多流复用 (WFQ 调度) + ReliableChannel 可靠控制流
│   └── security_nacl.py # 安全层 (PyNaCl 真 AEAD, 硬依赖)
├── session/
│   └── pairing.py      # 设备配对 (配对码 + keystore) + 多会话管理
├── tests/              # 64 项测试, pytest 全绿
│   ├── test_protocol.py
│   ├── weaknet.py           # 弱网模拟器 + 性能度量
│   ├── test_v02_core.py
│   ├── test_security_arq.py
│   ├── test_multiplex.py    # 多流复用 + 控制流优先
│   ├── test_reliable_channel.py  # 可靠通道 (滑窗/空洞/静默探测)
│   ├── test_pairing.py      # 设备配对 + 多会话
│   └── test_sfu.py          # SFU 选择性转发 (精确寻址/带宽节省)
├── examples/
│   ├── udp_e2e_test.py    # ✅ 主线联调: 真实 UDP 三档弱网 + 多流复用
│   ├── sky.py             # (P1) 天空端: 真实 UDP 发送, 单机双进程 demo
│   └── gnd.py             # (P1) 地面端: 真实 UDP 接收, 单机双进程 demo
├── docs/
│   ├── VISION.md
│   ├── ARCHITECTURE.md
│   ├── KNOWN_LIMITATIONS.md
│   └── archive/            # v0.2 及之前的历史文档
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

## 协议头格式 (20B)

```
+0        +4        +8        +12       +16       +20
| session_tag | frame_id | frag_id | total_frags | flags | stream_id | frame_len | crc |
    4B          4B         2B         2B         1B       1B         4B         2B
```

**FLAG 位域**：KEY_FRAME | FEC_PARITY | LAST_FRAG | ARQ_REQ | ARQ_REP | ENCRYPTED | RELIABLE | RESERVED

**frame_len**：原始帧真实长度（4B）。分片补零在重组时按此裁剪，接收端拿到的帧与发送端逐字节一致。

**安全头 (加密包附加)**：8B nonce + 16B tag = 24B/包

---

## 路线图

| 版本 | 状态 | 核心能力 |
|---|---|---|
| v0.1 | ✅ 完成 | 协议头 + 分片/FEC + ARQ 聚合 + 弱网模拟 |
| **v0.2** | **✅ 完成** | **安全层 + ARQ 完整链路 + 性能基准** |
| **v0.3** | **✅ 完成** | **多流复用 + 可靠控制流 (ReliableChannel) + 设备配对/会话管理 + 真实 UDP 联调 + frame_len 帧长保真** |
| **v0.4** | **🛠 进行中** | **SFU 选择性转发** ✅ (不同地面端缺不同片 → 只发给缺的人, 重传带宽节省 ≥49%) |
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
