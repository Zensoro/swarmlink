# Changelog

本项目所有重要变更均记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号与 README 路线图保持一致（v0.1 → v1.1）。

---

## [v1.1] - 2026-08-09

### 新增
- **真实视频传输**：
  - `examples/video_source.py`：ffmpeg 管道读帧 + H.264 Annex-B 帧切分器
    （支持 testsrc / 本地文件 / HLS 网络流 / 摄像头; SPS/PPS 与 IDR 合并）
  - `examples/video_e2e.py`：单进程真实视频全链路验证
  - `sky.py --source`：天空端接入真实视频源（默认 random 向后兼容）
  - `gnd.py --output`：地面端按序写出 .h264 可播放文件
- **实测**（真实 UDP 双进程 + 15% 丢包 + 加密）：
  - testsrc 合成源：68 帧 100% 完成，解密 0 失败
  - Tears of Steel HLS 云流：89 帧 100% 完成，1680x750 真实电影画面
- **文档**：README / DEPLOYMENT / API 新增真实视频演示与集成示例

---

## [v1.0] - 2026-08-07

### 新增
- **Docker 化**（`Dockerfile` + `docker-compose.yml` + `requirements.txt`）：
  - 单镜像双服务 (sky/gnd), Docker Compose 一键部署
  - UDP 端口映射 (5000/5010-5012), 容器间经 Docker 网络互连
  - ⚠️ 当前网络环境无法拉取基础镜像, 构建验证待网络恢复
- **Web 管理界面**（`webui.py`, 标准库零依赖）：
  - `register_node` + `start_webui`, 任意组件注册状态源
  - `/` HTML 仪表盘 (深色主题, 每 2s 自动刷新) + `/api/stats` JSON
  - `examples/sky.py --web-port 8080` 一键启用, 实测实时展示
    丢包整形/发送统计/重传/ARQ
- **文档站**（`docs/README.md` 索引 + `docs/DEPLOYMENT.md` + `docs/API.md`）：
  - 部署指南 (Docker/单机双进程/双机), API/模块速查, 集成示例
- `tests/test_webui.py`：4 项新测试 (HTML/API/异常隔离/多节点)

---

## [v0.6] - 2026-08-07

### 新增
- **Gilbert-Elliott 突发丢包模型**（`protocol/ge_model.py` + 接入 `tests/weaknet.py`）：
  - 两状态马尔可夫（GOOD/BAD），突发成串丢包，对齐 802.11 干扰特征
  - `loss_model="ge"` 参数切换，`ge_p_gb/ge_p_bg/ge_p_g/ge_p_b` 调参
  - 理论均值/突发长度与实测对齐（±30%），修复 KNOWN_LIMITATIONS #3（部分）
  - 接入 `udp_e2e_test.py` 场景：平均 4.8% 丢包成串，验证率仍 100%
- **RLNC 随机线性网络编码**（`protocol/rlnc.py`）：
  - 随机系数线性组合，任意 K 个线性无关包可解码（渐进解码）
  - K 灵活（RS 固定 10，RLNC 任意片数），与 RS 接口兼容可切换
  - 实测：丢 4 包恢复、少于 K 包拒绝、与 RS(10,14) 同条件对比通过
- `tests/test_v06.py`：11 项新测试（GE 突发性/统计对齐/接入 + RLNC 闭环/恢复/灵活 K/对比）

---

## [v0.5] - 2026-08-07

### 新增
- **一致性哈希路由**（`protocol/routing.py` `ConsistentHash`）：
  - 虚拟节点均匀分布（1000 key 3 节点偏差 <20%）
  - 平滑扩容：加节点只迁移 1/N；缩容 key 守恒、均匀迁移
- **三级拓扑中继**（`RelayNode`）：Sky→Relay→Gnd 广播转发、防环 TTL、
  断连缓存补发（serve_stale）、下游 REQ 经中继上行
- **stale-while-revalidate 缓存**（`protocol/cache.py`）：fresh 直出 /
  stale 先旧后新 + 后台刷新 / 同帧防重刷防风暴
- `examples/relay_demo.py`：三级拓扑演示（20/20 广播、断连补 5 帧、扩容平滑迁移）
- `tests/test_routing.py`：14 项新测试

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
