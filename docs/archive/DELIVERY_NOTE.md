# SwarmLink v0.1 — 交付说明

## 本轮完成内容

### ✅ 已有（v0.1 协议骨架 + 文档体系）

| 文件 | 说明 |
|---|---|
| `README.md` | 项目门面，极客风，强调差异化不引战 |
| `LICENSE` | MIT |
| `.gitignore` | 标准 Python 忽略规则 |
| `docs/VISION.md` | 愿景文档——"为什么存在"的软叙事 |
| `docs/ARCHITECTURE.md` | 四层架构 + 数据流向 + ADR 决策记录 |
| `docs/KNOWN_LIMITATIONS.md` | 诚实记录当前限制 + 修复路线图 |
| `protocol/header.py` | 16 字节协议头（已锁定） |
| `protocol/fragment.py` | 分片器 + 重组器 |
| `protocol/rs_codec.py` | Reed-Solomon(10,14) FEC 引擎 |
| `protocol/arq.py` | ARQ 聚合器(A 方案) + 客户端 + B 方案位图预留 |
| `tests/test_protocol.py` | 13 项单元测试（全通过） |
| `tests/weaknet.py` | 弱网模拟器 + 性能度量 |
| `examples/sky_to_ground.py` | 端到端 demo |
| `examples/hellmode_demo.py` | 地狱档 demo（30% 丢包 + 断连） |
| `examples/compare_demo.py` | 裸广播 vs SwarmLink 对比 |
| `tools/plot_metrics.py` | 性能曲线生成器 |
| `tools/swarmlink_performance.png` | 三张性能图 |
| `tools/tc_qdisc_setup.sh` | 真实网卡弱网注入脚本 |
| `session/`, `crypto/`, `link/` | P1 阶段占位模块 |

### 📊 验证数据

- **单元测试**：13/13 通过
- **FEC 正确性**：30/30 帧无丢包下全部正确重组
- **数据校验失败**：0 次（所有测试场景）
- **ARQ 聚合理论带宽节省**：87.5%（8 客户端）

### 🔬 测试中发现的关键洞察

1. **均匀随机丢包 vs 突发丢包**：当前模拟器用均匀随机，会高估 FEC 效果。真实 Wi-Fi 是 burst 模式，这是 P0.3 要修的。
2. **ARQ 重传链路未完全打通**：当前 demo 里客户端→天空端的 ARQ_REQ 通道还是占位状态。这是**下一个要打的 boss**，打通后 SwarmLink vs 裸广播的差异会真正显现。
3. **帧大小上限 5000B**：当前 chunk_size=500 × K=10。1080P 帧（5-20KB）需要调大 K 或 chunk_size。

---

## 下一步（按你的决策排序）

### P0 核心（先做这两个，项目就有灵魂了）

1. **打通 ARQ 重传链路**
   - 客户端检测缺失 → 发 ARQ_REQ → 天空端聚合 → 重传 1 次 → 所有缺片客户端收齐
   - 打通后跑对比测试，预期 SwarmLink 在 30% 丢包下完成度比裸广播高 10-30 个百分点
   - **这是你项目的最大卖点，必须证明它能 work**

2. **加密层 ChaCha20-Poly1305**
   - 集成 PyNaCl（libsodium 的 Python 绑定）
   - per-packet key = session_key XOR nonce
   - 没加密的图传进不了景区（防串看是刚需）

### P1 系统感

3. **Session 管理（DH 0-RTT 建邻）**
4. **多流复用器**（图传/控制/遥测三流）
5. **Gilbert-Elliott 突发丢包模型**（让测试更真实）
6. **增大帧支持**（K=20, chunk=1200 → 支持 1080P）

### P2 灵魂

7. **SFU 选择性转发 + Simulcast 多版本**（项目的"哇塞时刻"）
8. **Web 管理界面 + Docker 镜像**（完整系统 vs 协议库的分界线）

---

## 怎么跑

```bash
# 1. 单元测试
cd swarmlink && python3 -m pytest tests/ -v

# 2. 端到端 demo（默认 8 客户端 / 30% 丢包）
python3 examples/sky_to_ground.py

# 3. 地狱档（30% 丢包 + 2 秒断连）
python3 examples/hellmode_demo.py

# 4. 裸广播 vs SwarmLink 对比
python3 examples/compare_demo.py

# 5. 生成性能曲线图
python3 tools/plot_metrics.py
```

---

## 项目定位（钉死版）

> **SwarmLink** — 一个开源的、一对多并发图传**系统**。
> 
> 不是协议库，是刷镜像开机即飞、眼镜零配置接入、Web 界面看状态的**完整产品**。
> 
> 比 WFB-ng 多一层会话管理和 ARQ 聚合；
> 比闭源方案透明，每一行代码可审计；
> 比通用视频协议轻量，为"一对多 + 弱网"专门优化。
> 
> **我们不是要赢谁，是要把图传协议层的天花板再抬高一寸。**

---

*Last updated: 2025-08*
*Maintainer: 你（产品脑洞官）+ AI（技术合伙人）*
