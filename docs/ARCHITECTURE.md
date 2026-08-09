# SwarmLink 架构设计

> 一个开源的、一对多并发图传系统。One sky, many eyes.

---

## 设计理念

> 为无人机弱网图传场景，在成熟设计中选择适用的部分并工程化落地：
> 一对多、弱网韧、低延迟、可扩展——组合成完整可用的系统。

---

## 技术参考与取舍

| 来源领域 | 借鉴的设计 | 舍去的部分 | 保留理由 |
|---|---|---|---|
| **QUIC / HTTP3** | 0-RTT 握手、stream 多路复用、可插拔拥塞控制 | TLS 证书链、HTTP/3 帧 | 握手秒连、三流复用、BBR 拉满 |
| **WebRTC SFU** | Simulcast 多版本、SVC 分层转发、NACK/SNACK | ICE/SDP/WebRTC API | 不同眼镜看不同码率 |
| **CDN (Traffic Control)** | 一致性哈希路由、分层缓存、stale-while-revalidate | 全量 DNS/GeoIP | 三级拓扑路由、断连时返回旧帧 |
| **Starlink RLC** | 透明/确认模式自适应切换 | 卫星轨道预测 | 图传流不确认、控制流必确认 |
| **Signal / MTProto** | DH 密钥派生、per-message key、前向安全 | IGE 加密、云同步 | ARQ 聚合、会话管理 |
| **TLS 1.3** | HKDF 密钥派生链、AEAD 加密 | 证书验证、SNI | 安全层核心 |
| **NSA Suite B（参考）** | ChaCha20-Poly1305、防重放窗口 | 国密算法 | 强加密算法参考, 非认证体系 |

---

## 系统架构（四级）

```
┌──────────────────────────────────────────────────────────┐
│                   SwarmLink 完整系统                      │
├──────────────────────────────────────────────────────────┤
│  L4  应用/会话层  (Session & SFU)                       │
│   • DH 0-RTT 入网  • 一致性哈希路由                       │
│   • SFU 选择性转发  • Simulcast/SVC 多版本                │
│   • stale-while-revalidate  • 设备配对/撤销                 │
├──────────────────────────────────────────────────────────┤
│  L3  可靠传输层  (Transport)                              │
│   • QUIC-style 多路复用 (图传/控制/遥测)                   │
│   • FEC 可插拔: RS(默认) ↔ RLNC(可选)                    │
│   • ARQ 聚合 (A方案) + 位图精发 (B方案)                   │
│   • SNACK 空洞补发  • RLC 模式自适应                      │
│   • LossDetector 指数退避  • PacketStore TTL               │
├──────────────────────────────────────────────────────────┤
│  L2  安全层  (Security)  🆕 v0.2                         │
│   • X25519 DH + HKDF-SHA256 → 32B session_key            │
│   • ChaCha20-Poly1305 AEAD (per-packet sub_key)           │
│   • nonce 滑动窗口防重放 (1024)                           │
│   • 前向安全 (每会话 ephemeral key)                         │
│   • 会话隔离 (每对设备独立 key)                            │
│   • 篡改检测 (Poly1305 MAC)                                │
├──────────────────────────────────────────────────────────┤
│  L1  链路层  (Link)                                      │
│   • UDP 多播 (PoC)  →  WFB-ng raw 802.11 (生产)         │
│   • 双频 2.4G/5.8G 并发 (MP-QUIC 思路)                  │
│   • Gilbert-Elliott 突发模型 (v0.6)                       │
│   • ns-3 集成 + 真实踪迹回放 (v0.6)                      │
└──────────────────────────────────────────────────────────┘

        ┌──────── 横切关注点（Cross-cutting）────────┐
        │  • 弱网模拟器 (均匀/突发/断连)                │
        │  • 性能度量 + 可视化仪表盘                    │
        │  • YAML 配置 + Web 管理界面                   │
        │  • Docker 一键部署 + 镜像构建                 │
        └───────────────────────────────────────────────┘
```

---

## 数据流向

### 发送端 (天空端)
```
原始帧
  │
  ▼
[Fragmenter] ─── 分片 (800B) + FEC(10,14)
  │
  ▼
[Encryptor] ─── ChaCha20-Poly1305 (per-packet key)
  │
  ▼
[PacketStore] ─── 存最近 60 帧 (TTL 3s)
  │
  ▼
[SkySender] ─── 发送 + ARQ 聚合器监听
  │
  ▼
[Link] ─── UDP / raw 802.11
```

### 接收端 (地面端/眼镜)
```
[Link]
  │
  ▼
[Decryptor] ─── ChaCha20-Poly1305 (nonce 窗口防重放)
  │
  ▼
[Reassembler] ─── FEC 修复 + 分片重组
  │
  ├── 完整帧 → 回调 (解码显示)
  │
  ▼
[LossDetector] ─── 检测缺失 → ARQClient → 发 REQ
```

### ARQ 重传回路
```
GroundReceiver.LossDetector
  │ (检测缺失, 指数退避)
  ▼
ARQClient.request(fid, frag_id)
  │ (发送 ARQ_REQ 包)
  ▼
[Link] → 天空端
  │
  ▼
ARQAggregatorV2.receive_request()
  │ (合并同 frag 的 N 个请求)
  ▼
flush() → 1 次重传 (广播或位图精确发送)
  │
  ▼
[Link] → 所有/部分地面端
  │
  ▼
GroundReceiver.feed() → Reassembler → 帧完成 ✓
```

---

## 协议头格式

### 16B 主头 (明文, 用于路由/分片/FEC)
```
+0        +4        +8        +12       +16
| session_tag | frame_id | frag_id | total_frags | flags | stream_id | crc |
    4B          4B         2B         2B         1B       1B       2B
```

### 安全头 (加密包附加, 24B)
```
+0              +8              +24
| nonce (8B)    | Poly1305 tag (16B) | ciphertext |
```

### FLAG 位域
| Bit | 名称 | 含义 |
|---|---|---|
| 7 | KEY_FRAME | I 帧, ARQ 优先级最高 |
| 6 | FEC_PARITY | 此包是 FEC 冗余包 |
| 5 | LAST_FRAG | 本帧最后分片 |
| 4 | ARQ_REQ | 重传请求 |
| 3 | ARQ_REP | 重传回复 |
| 2 | ENCRYPTED | 载荷已加密 |
| 1 | RELIABLE | 必须可靠到达 |
| 0 | RESERVED | 预留 |

---

## 密钥派生链

```
X25519 ephemeral keypair (每会话新生成)
        │
        ▼
DH 共享秘密 (32B)
        │
        ▼
HKDF-Extract(salt, shared) → PRK
        │
        ▼
HKDF-Expand(PRK, "SwarmLink-v0.2:session", 32) → session_key
        │
        ├──▶ Encryptor/Decryptor (ChaCha20-Poly1305)
        │
        ▼
HKDF-Expand(PRK, "SwarmLink-v0.2:subkey"||nonce, 32) → per-packet key
        │
        ▼
ChaCha20 流加密 + Poly1305 MAC
```

---

## 威胁模型

| 威胁 | 防御 | 强度 |
|---|---|---|
| 窃听 | ChaCha20 + per-packet key | ⭐⭐⭐⭐⭐ |
| 篡改 | Poly1305 MAC (AEAD) | ⭐⭐⭐⭐⭐ |
| 重放 | nonce 滑动窗口 (1024) | ⭐⭐⭐⭐ |
| 串看 | 每对设备独立 session_key | ⭐⭐⭐⭐⭐ |
| 密钥泄露回溯 | 前向安全 (ephemeral key) | ⭐⭐⭐⭐ |
| 中间人 | ⚠️ v0.3 加入设备配对码 | ⭐⭐ (v0.2) |
| 物理提取 | ❌ 无 HSM/SE | ⭐ (需硬件) |
| 国密合规 | ❌ 无 SM 系列 | ❌ (需认证) |

---

## 架构决策记录 (ADR)

### ADR-001: 16B 协议头 (v0.1)
- **决策**: 选 16B 紧凑版, 不选 24B 扩展版
- **理由**: 省 8B/包, @1000 包/秒 = 省 8KB/s; 解析更快; 预留位够后期扩展
- **代价**: 扩展字段需塞 reserved 或加扩展头

### ADR-002: Reed-Solomon(10,14) (v0.1)
- **决策**: K=10, N=14, 丢 4 片以内可恢复
- **理由**: 图传帧 ~3500B / 800B 分片 = ~5 片, K=10 留余量; 4 片冗余 ≈ 28% 开销
- **代价**: RS 解码需高斯消元, CPU 比 XOR 重; 后期可换 RLNC

### ADR-003: ChaCha20-Poly1305 (v0.2)
- **决策**: 选 ChaCha20-Poly1305 AEAD, 不选 AES-GCM
- **理由**: 256bit key 强度充足; 无 AES 硬件时快 3-5x; ARX 抗侧信道; WFB-ng 已验证
- **代价**: 纯 Python 实现仅 1.5 MB/s, 需 PyNaCl 加速

### ADR-004: X25519 + HKDF (v0.2)
- **决策**: DH → HKDF → session_key → per-packet sub_key
- **理由**: TLS 1.3 / Signal 成熟方案; 前向安全; per-packet key 隔离
- **代价**: 比 MTProto IGE 多 1 次 HKDF, 但安全性天壤之别

### ADR-005: nonce 滑动窗口 (v0.2)
- **决策**: 8B nonce + 1024 窗口 + 常量时间比较
- **理由**: TLS/IPsec/5G 标准做法; 支持乱序 ±512 包
- **代价**: 接收端维护窗口状态

### ADR-006: ARQ A+B 双方案 (v0.2)
- **决策**: A 默认 (合并广播), B 可选 (位图精确)
- **理由**: A 简单够用 (87.5-96.9% 节省); B 给高带宽场景; 协议头兼容
- **代价**: B 方案需维护 client_bitmap, 内存略增

---

## 性能特征

### 开销分析
| 项目 | 开销 | 说明 |
|---|---|---|
| 协议头 | 16B/包 | 固定 |
| 安全头 | 24B/包 (可选) | 8B nonce + 16B tag |
| FEC 冗余 | ~28% (4/14) | RS(10,14) |
| 加密 | 1.7-3.0% | 相对 800-1400B 载荷 |
| **总开销 (加密开)** | **~32%** | 1400B 载荷时 ~28% |

### 吞吐 (纯 Python, PyNaCl 可 100x)
| 操作 | 吞吐 | 备注 |
|---|---|---|
| 加密 | 1.4-1.7 MB/s | 足够 720p@15fps 测试 |
| 解密 | 1.6 MB/s | 同上 |
| FEC 编码 | ~50 MB/s | numpy 加速 |
| FEC 解码 | ~30 MB/s | 高斯消元瓶颈 |

---

## 路线图

| 版本 | 状态 | 核心能力 |
|---|---|---|
| v0.1 | ✅ | 协议头 + 分片/FEC + ARQ 聚合 + 弱网模拟 |
| **v0.2** | **✅** | **安全层 + ARQ 完整链路 + 性能基准** |
| v0.3 | ⏳ 下一步 | Session 管理 + 多流复用 + PyNaCl 加速 |
| v0.4 | 规划 | SFU 选择性转发 + Simulcast/SVC |
| v0.5 | 规划 | 一致性哈希路由 + 三级拓扑 |
| v0.6 | 规划 | RLNC 可插拔 + ns-3 + Gilbert-Elliott |
| v1.0 | 规划 | Docker 镜像 + Web 界面 + 完整文档 |
