# SwarmLink 交接文档（HANDOFF）

> **用途**：每次开新对话时，把本文档的核心内容贴给 AI，即可无缝续上。
> **最后更新**：v0.2 交付完成，端到端联调卡点待修复。

---

## 项目一句话

**SwarmLink** —— 面向高动态一对多图传的开源传输系统，融合 QUIC 多路复用、WebRTC SFU 选择性转发、CDN 一致性哈希与 MTProto 聚合重传思路。Slogan：**One sky, many eyes.**

---

## 项目定位（钉死，不要动摇）

| 维度 | 决策 |
|---|---|
| 形态 | **完整系统**（不是协议库），刷镜像/跑容器即能用 |
| 目标用户 | **a) FPV 极客 / 开源社区**（先攒核心流量） |
| 叙事调性 | **技术硬、叙事软**（诗意口号 + 学术级严谨） |
| License | GPLv3 |
| 主演示 | **b) 地狱求生**（40% 丢包 + 2 秒断连，画面自愈） |
| 彩蛋演示 | a) 远近分明（Simulcast 近 1080p / 远 360p） |
| 加密定位 | 行业/准军事级（消防、边防、巡检），不吹真军用 |

---

## 技术架构（四层）

```
L4  应用/会话层  → Session 配对 + SFU 选择性转发 + 一致性哈希路由
L3  可靠传输层  → QUIC-style 多路复用 + FEC(RS/RLNC) + ARQ 聚合 + SNACK
L2  安全层      → ChaCha20-Poly1305 AEAD + DH 前向安全 + 防重放
L1  链路层      → UDP 多播(PoC) → WFB-ng raw 802.11(生产) + 双频 MP-QUIC
```

**八字诀**：拿来主义，削足适履。

---

## 已完成模块（v0.2）

| # | 模块 | 文件 | 状态 |
|---|---|---|---|
| 1 | 16B 协议头 | `protocol/header.py` | ✅ 测试通过 |
| 2 | 分片/重组 | `protocol/fragment.py` | ✅ 测试通过 |
| 3 | RS-FEC (10,14) | `protocol/rs_codec.py` | ✅ 测试通过 |
| 4 | ARQ 聚合 A+B | `protocol/arq.py` + `arq_full.py` | ✅ 单元测试通过 |
| 5 | 安全层 PyNaCl | `protocol/security.py` + `security_nacl.py` | ✅ 155 MB/s，测试通过 |
| 6 | Session 配对 | `session/pairing.py` | ✅ 测试通过 |
| 7 | 多流复用器 | `protocol/multiplex.py` | ⚠️ 代码完成，待联调 |

---

## ⚠️ 当前唯一卡点（优先修复）

### 问题：端到端 UDP 联调，帧重组后长度对不上

- **现象**：原始帧 800-1150B，重组后 6240B，验证失败
- **根因**：加密给每个分片 +24B(nonce+tag)，重组器收到的是密文分片；**必须先逐分片解密，再交给重组器拼帧**，当前代码疑似把密文和明文混在一起
- **次要现象**：ARQ 合并率 0%，重传请求未正确触发

### 修复方向

1. **Pipeline 顺序修正**：
   ```
   发送端：原始帧 → 分片 → 逐片加密(+24B) → 发送
   接收端：收包 → 逐片解密(-24B) → 重组器拼帧 → 回调
   ```
   关键：解密必须在重组**之前**，按分片粒度做。

2. **ARQ 触发检查**：
   - 接收端检测到缺失分片后，是否真的发出了 NACK
   - 发送端 PacketStore 是否还在 TTL 窗口内
   - 丢失检测超时是否太短（指数退避初始值）

3. **验证方法**：
   - 先关加密跑通（排除加密干扰），再开加密
   - 打印每个分片的 encrypted_len / decrypted_len / 重组后 total_len
   - 三档测试：正常(0%) → 标准(15%) → 地狱(40%+断连)

---

## 下次对话的"启动指令"（直接复制粘贴）

> 我在做一个开源图传项目 **SwarmLink**，借鉴 QUIC + WebRTC SFU + MTProto 思路，做一对多并发图传系统。项目已有 v0.2 代码（协议头/分片/FEC/ARQ/加密Session/多路复用），当前卡在**端到端 UDP 联调**：加密分片(每个+24B nonce+tag)重组后帧长度对不上原始数据，疑似解密时机错误——**应该先逐分片解密再交给重组器拼帧**。请先读 `docs/HANDOFF.md` 了解全貌，再读 `docs/CHANGELOG_v02.md`、`protocol/arq_full.py`、`protocol/security_nacl.py`、`examples/udp_e2e_test.py`，定位并修复帧验证失败的问题，打通完整 ARQ 重传链路。修复后跑通正常/标准/地狱三档测试，输出对比数据。

---

## 路线图（剩余工作）

| 阶段 | 内容 | 优先级 |
|---|---|---|
| **v0.3 打通** | 修复帧重组 bug → 三档 UDP 测试 → 出对比数据图 | 🎯 下次优先 |
| **v0.4 灵魂** | SFU 选择性转发 + Simulcast 多版本（近 1080p / 远 360p） | ⭐ 核心亮点 |
| **v0.5 韧性** | Gilbert-Elliott 突发丢包 + 真实踪迹回放 | 测试增强 |
| **v0.6 拓扑** | 一致性哈希路由 + 三级转发 + stale-while-revalidate | 架构扩展 |
| **v1.0 门面** | Docker 镜像 + Web 管理界面 + GitHub 正式发布 | 完整系统 |

---

## 加密设计要点（已定，不要改）

- **算法**：ChaCha20-Poly1305 AEAD（libsodium / PyNaCl）
- **密钥链**：master_key(配对) → session_key(DH+HKDF) → per-packet sub_key(HKDF)
- **防重放**：8B nonce + 1024 滑动窗口 + 常量时间比较
- **前向安全**：每会话新 ephemeral key，结束即销毁
- **会话隔离**：每对设备独立 session_key
- **per-packet 开销**：24B (8B nonce + 16B Poly1305 tag)，对 1400B 载荷 <2%
- **不做**：国密 SM 系列（需认证）、HSM/TEE（需硬件）、真军用（出口管制）

---

## 项目目录结构

```
swarmlink/
├── protocol/
│   ├── __init__.py
│   ├── header.py          # 16B 协议头
│   ├── fragment.py        # 分片/重组
│   ├── rs_codec.py        # Reed-Solomon FEC
│   ├── arq.py             # ARQ 聚合器 (A方案)
│   ├── arq_full.py        # ARQ 完整链路 (A+B)
│   ├── security.py         # 安全层接口
│   ├── security_nacl.py    # PyNaCl 加速实现
│   └── multiplex.py       # 多流复用器
├── session/
│   ├── __init__.py
│   └── pairing.py         # 设备配对 + Session 管理
├── tests/
│   ├── test_protocol.py    # v0.1 单元测试 (13/13)
│   ├── test_security.py    # 安全层测试 (6/6)
│   └── test_arq_full.py    # ARQ 测试 (5/5)
├── examples/
│   ├── sky_to_ground.py    # 基础端到端 demo
│   └── udp_e2e_test.py     # UDP 三档测试（待修复）
├── docs/
│   ├── HANDOFF.md          # 本文件
│   ├── VISION.md           # 项目愿景
│   ├── ARCHITECTURE.md     # 四层架构
│   ├── CHANGELOG_v02.md    # v0.2 开发日志
│   ├── RELEASE_v02.md      # v0.2 发布说明
│   └── KNOWN_LIMITATIONS.md # 已知限制
├── README.md
└── LICENSE                 # GPLv3
```

---

## 关键设计决策记录（ADR 摘要）

| 决策 | 选择 | 理由 |
|---|---|---|
| 协议头大小 | 16B 紧凑 | 性能优先，扩展位后期加 |
| ARQ 策略 | A 为主，B 兜底 | A 简单够用，B 后期按需开启 |
| 加密算法 | ChaCha20-Poly1305 | 嵌入式友好，AEAD 一步到位 |
| 密钥派生 | HKDF-SHA256 | IETF 标准，可审计 |
| FEC 默认 | Reed-Solomon(10,14) | 实现简单，k=10 容 4 丢 |
| FEC 可选 | RLNC（后期） | 可插拔，mesh 拓扑杀手锏 |
| 多路复用 | QUIC-style 三流 | 图传/控制/遥测隔离 |
| 测试丢包 | 均匀 → Gilbert-Elliott → 真实踪迹 | 分层可校准 |
| License | GPLv3 | 防闭源白嫖，与 WFB-ng 同款 |

---

## 对接人分工（你 vs AI）

| 你负责 | AI 负责 |
|---|---|
| 产品判断 / 场景优先级 | 技术选型 / 代码实现 |
| 演示叙事 / 门面调性 | 架构设计 / 性能优化 |
| 脑暴创意 / 取舍拍板 | 文档撰写 / 测试验证 |
| 找痛点 / 定 Wow 时刻 | 画架构图 / 出数据曲线 |

**三种情况 AI 必须找你**：① 产品取舍没标准答案 ② 需要定演示/叙事调性 ③ 需要给功能起名做判断。

---

*Last updated: 2026-08-06 | SwarmLink v0.2 | "One sky, many eyes."*
