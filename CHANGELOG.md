# Changelog

本项目所有重要变更均记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号与 README 路线图保持一致（v0.1 → v0.6）。

---

## [v0.4] - 2026-08-07

### 新增
- **SFU 选择性转发完整版**（`protocol/sfu.py`: `SFUForwarder` + `SFUReceiver` + `Quality`）：
  - 订阅式多码率：天空端每帧发布 LOW/HIGH 两档（独立分片/FEC/加密），地面端订阅其一 → 只发对应档
  - 按订阅分配带宽：实测 LOW 12.5% / HIGH 87.5%（2 端订 HIGH、1 端订 LOW）
  - bitmap 精确补片：重传只发给缺片者，节省 ≥49% 重传带宽
  - 省带宽关键：只发实际数据片不补零（短帧不占满 `fec_k`）
- `tests/test_sfu_full.py`：6 项新测试（订阅路由 / 带宽差异 / 动态切换 / 未订阅层零带宽 / 无订阅者零包 / 多客户端同层）
- `examples/udp_e2e_test.py`：SFU 完整版场景 + SFU bitmap 对照组（15% 丢包下验证率 100%）

### 修复
- **#12 ARQ_REP 防重放误杀**：重传的 REP 与原包同 nonce，低丢包/0% 丢包下原包已入防重放窗口 → REP 到达被判重放丢弃。
  - `Decryptor.decrypt_for_rep` 豁免防重放（AEAD 完整性保留，不污染 nonce 去重）
  - `LossDetector.on_packet_received/on_rep_received` 跳过已交付帧（completed set），修复"帧完成后的迟到分片重建状态 → 误 REQ"的泄漏 bug
- **效果**：0% 丢包重传 109→0，15% 丢包重传 ~700→19，overhead 11.6x→4.3x

---

## [v0.3] - 2026-08-07

### 新增
- **多流复用 + 可靠控制流**（`protocol/multiplex.py`）：
  - WFQ 调度，视频流与控制流分优先级
  - `ReliableChannel`：单包 + 滑窗空洞检测 + 静默探测 + ARQ 重传，15% 丢包下实测 4/4 控制消息必达
- **设备配对与会话管理**（`session/pairing.py`）：配对码（Bluetooth Pairing 风格）+ keystore 持久化 + 多会话管理；配对码混入 master_key 派生，码不一致则加密必失败
- **真实 UDP 端到端联调**（`examples/udp_e2e_test.py`）：1 天空端 → 3 地面端真实 socket，每方向独立弱网整形（丢包/延迟/抖动/断连），三档场景（正常 0% / 标准 15% / 地狱 40%+断连）+ 对照组
- **单机双进程 demo**（`examples/sky.py` / `examples/gnd.py`）：本地回环真实 UDP socket
- 测试：`test_multiplex.py` / `test_reliable_channel.py` / `test_pairing.py`
- `frame_len` 帧长保真：分片补零在重组时按原始长度裁剪，接收帧与发送端逐字节一致

### 修复
- **端到端帧重组 bug（核心）**：加密分片需先逐片解密再重组——原实现把 `8B nonce + 16B tag + 密文` 当明文拼接，产生 6240B 垃圾帧（`10 × (600+24)`）；修复为 `SkySender._seal` 逐片加密并置 `FLAG_ENCRYPTED`、`GroundReceiver._open` 逐片解密
- **ARQ 多轮重传闭环**：
  - inflight 永久卡死：REQ/REP 任一方向丢包导致 key 永久在 inflight → `request(allow_resend=True)` + `clear_frame`
  - 合并窗口失效：`flush()` 每轮无条件调用 → 20ms 窗口节流 `maybe_flush()`
  - ARQ_REP 头部字段保真：`total_frags`/`stream_id`/`ENCRYPTED`/`frame_len` 不再丢失
  - Reassembler 允许 ARQ_REP（携带真实分片数据）进入重组
- **LossDetector 改为 FEC 感知**：只请求 `k - len(recv)` 个缺失数据片（优先数据片），防 ARQ 风暴
- **安全层换 PyNaCl**：纯 Python 实现（~1.5 MB/s）→ libsodium C 绑定（~500 MB/s）；删除 `security.py`
- **一对多组播加密**：`SessionManager.adopt_session_key` 采用已分发的组会话密钥（逐客户端 DH 会派生不同 key，无法解同一份密文）
- **测试基建**：`UDPLink` 假 UDP（自回环队列）→ 真 socket 收发；`WeakNetSimulator` 线程安全（加锁 + 稳定堆排序）

### 性能（v0.3/v0.4 实测，见 README「性能数据」）
| 场景 | 验证率 | 实测下行丢包 | 带宽放大 |
|---|---|---|---|
| 正常 (0%) | 100% | 0.0% | 5.1x |
| 标准 (15%) | 100% | 16.1% | 4.45x |
| 地狱 (40%+断连) | 64.4% | 54.6% | 3.85x |

---

## [v0.2] - 2026-08-06

- **安全层**：ChaCha20-Poly1305 AEAD + X25519 DH + HKDF-SHA256 + nonce 滑动窗口防重放 + 每会话 ephemeral key（前向安全）
- **ARQ 完整链路**：`SkySender` / `GroundReceiver` / `LossDetector` / `PacketStore`（TTL 滑动窗口）+ A 方案聚合重传
- **FEC 纠错**：Reed-Solomon(10,14)（GF(256)），丢 ≤4 片当场恢复，与 ARQ 联合兜底
- 详细开发日志与 ADR（ADR-003 加密选型 / ADR-004 密钥派生链 / ADR-005 防重放）见 `docs/archive/CHANGELOG_v02.md`

---

## [v0.1] - 2026-08-06

- 协议头（20B：session/frame/frag/flags/stream/frame_len/crc）+ 分片/重组 + RS(10,14) FEC + ARQ 聚合（A 方案）+ 弱网模拟器
- 基础测试套件 `tests/test_protocol.py` / `test_v02_core.py`
