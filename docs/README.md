# SwarmLink 文档站

> **One sky, many eyes.** — 一对多并发图传系统

## 快速导航

| 文档 | 内容 |
|---|---|
| [根 README](../README.md) | 项目总览、能力清单、快速验证 |
| [部署指南](DEPLOYMENT.md) | Docker / 单机双进程 / 双机部署 |
| [架构设计](ARCHITECTURE.md) | 四级架构、ADR 决策记录 |
| [API / 模块速查](API.md) | 协议头、核心类、集成方式 |
| [已知限制](KNOWN_LIMITATIONS.md) | 诚实记录 + 修复状态 |
| [愿景](VISION.md) | 设计哲学、路线图背景 |
| [变更日志](../CHANGELOG.md) | v0.1 → v0.6 版本记录 |

## 版本状态

| 版本 | 状态 | 核心能力 |
|---|---|---|
| v0.1 | ✅ | 协议头 + 分片/FEC + ARQ 聚合 |
| v0.2 | ✅ | 安全层 (PyNaCl AEAD) + ARQ 完整链路 |
| v0.3 | ✅ | 多流复用 + 可靠控制流 + 设备配对 + 真实 UDP 联调 |
| v0.4 | ✅ | SFU 选择性转发 (bitmap 补片 + 订阅式多码率) |
| v0.5 | ✅ | 一致性哈希路由 + 三级拓扑 + stale-while-revalidate |
| v0.6 | 🛠 | Gilbert-Elliott 突发模型 + RLNC (ns-3 ⏳) |
| v1.0 | 🛠 | Docker + Web 管理界面 (文档站 ✅) |
| v1.1 | ✅ | 真实视频传输 (video_source + sky/gnd 视频模式) |

## 测试

```bash
pip install pynacl pytest numpy
python3 -m pytest tests/ -q        # 103 项
python3 examples/udp_e2e_test.py   # 真实 UDP 三档弱网 + 多流/SFU/GE 联调
```

## 演示入口

```bash
# 单机双进程 (本地回环)
python3 examples/gnd.py --frames 30
python3 examples/sky.py --frames 30 --loss 0.15

# 三级拓扑中继
python3 examples/relay_demo.py

# Web 管理界面
python3 examples/sky.py --frames 30 --web-port 8080
# 浏览器打开 http://localhost:8080/
```
