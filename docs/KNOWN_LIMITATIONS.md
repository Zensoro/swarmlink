# SwarmLink 已知限制

> 诚实记录当前版本做不到/没做好的事，以及修复路线图。

---

## v0.2 当前限制

### 1. ~~纯 Python 加密性能低~~ ✅ v0.3 已修复
- **现状**: ChaCha20-Poly1305 纯 Python 实现 ~1.5 MB/s
- **影响**: 1080p@30fps ≈ 3-8 MB/s → 纯 Python 加密不够实时
- **修复 (v0.3)**: 切换到 PyNaCl (libsodium C 绑定) → ~500 MB/s; `security.py`
  纯 Python 实现已删除, 统一用 `security_nacl.py` (PyNaCl 硬依赖)

### 2. ~~ARQ 多轮重传在测试脚本中未完全闭环~~ ✅ v0.3 已修复
- **现状**: 单轮重传 + FEC 恢复验证通过, 但多轮迭代的端到端自动化测试有循环时序问题
- **影响**: 30%+ 高丢包率下需多轮 ARQ 才能凑齐 10 片, 当前测试未覆盖
- **根因**: 测试用 deque 模拟链路, 循环顺序需更精细的时序控制
- **修复 (v0.3)**: `examples/udp_e2e_test.py` 真实 UDP socket + 弱网整形, 多轮 ARQ 已闭环;
  修复 inflight 永久卡死 (REQ/REP 单向丢包时 `allow_resend`)、合并窗口 (20ms `maybe_flush`)、
  ARQ_REP 头部字段保真 (`total_frags`/`stream_id`/`ENCRYPTED`/`frame_len` 不再丢失)

### 3. ~~弱网模拟精度有限~~ ✅ v0.6 已修复 (部分)
- **现状**: 均匀随机丢包, 非真实 Wi-Fi 突发模型
- **影响**: 性能数据偏乐观 (真实景区干扰是 burst + 相关丢包)
- **修复 (v0.6)**: `protocol/ge_model.py` Gilbert-Elliott 两状态马尔可夫模型
  (GOOD/BAD 态, 突发成串丢包), 已接入 WeakNetSimulator (`loss_model="ge"`)
  和 udp_e2e 场景; 实测平均 4.8% 丢包成串, 验证率仍 100%
- **剩余**: ns-3 集成 + 真实信道踪迹回放 (⏳ 未做)

### 4. 无国密 SM 系列支持
- **现状**: 仅 ChaCha20-Poly1305 (国际算法)
- **影响**: 需国密合规的政务/涉密场景不可用
- **修复**: 需国家密码管理局认证, 开源项目无法独立获取
- **建议**: 合规场景由部署方在外层套 SM 算法, SwarmLink 提供 hook 接口

### 5. 无硬件安全模块 (HSM/SE/TEE)
- **现状**: 密钥存在内存, 无安全芯片保护
- **影响**: 物理接触设备可提取密钥
- **修复**: 需硬件, 超出纯软件项目范围
- **标注**: 高物理安全要求的场景需搭配安全芯片

### 6. 单线程安全层
- **现状**: Encryptor/Decryptor 用 threading.Lock 保护 counter
- **影响**: 高并发下可能成瓶颈
- **修复**: v0.4 改为 per-thread counter + 批量处理

### 12. ~~ARQ_REP 与原包同 nonce, 防重放会误杀低丢包场景的重传~~ ✅ v0.4 已修复
- **现状**: PacketStore 重传的 REP 就是原包 (同 nonce 同密文)。低丢包/0% 丢包下
  原包已入防重放窗口 → REP 到达被判重放丢弃 (decrypt_fail), 重传成为浪费
- **影响**: 功能正确 (帧必达), 但统计上出现"重传+解密失败"的噪音;
  LossDetector 对慢到帧 (网络抖动) 发 REQ, 即使最终 FEC 可恢复
- **修复 (v0.4)**:
  * Decryptor.decrypt_for_rep 豁免防重放 (AEAD 完整性保留, 不污染 nonce 去重)
  * LossDetector.on_packet_received/on_rep_received 跳过已交付帧 (completed set),
    修复"帧完成后的迟到分片重建状态 → 触发误 REQ"的 bug
- **效果**: 0% 丢包重传 109→0, 15% 丢包重传 ~700→19, overhead 11.6x→4.3x

---

## v0.1 遗留限制 (仍有效)

### 7. 协议头不加密
- **现状**: 20B 头明文 (路由/分片/FEC 需要), 仅 payload 加密
- **影响**: 攻击者可知 session/frame/frag 结构 (但看不到内容)
- **评估**: WFB-ng / MTProto 同样做法, 可接受

### 8. ~~无设备证书体系~~ ✅ v0.3 已修复
- **现状**: DH 握手无身份认证, 中间人攻击理论上可行
- **影响**: 开放网络中需额外信任通道
- **修复 (v0.3)**: `session/pairing.py` 首次配对码 (Bluetooth Pairing 风格)
  + keystore 持久化; 配对码混入 master_key 派生, 码不一致则加密必失败
- **权衡**: 景区封闭环境风险低, 已提供可选配对流程

---

## 不会修的事 (by design)

### 9. 不做端到端视频编码
- SwarmLink 是传输协议, 不绑死编码器
- 支持任何 H.264/H.265/AV1 输出

### 10. 不做射频物理层
- 不碰 802.11 以下, 不造硬件
- 基于 UDP/Wi-Fi/raw 802.11 之上

### 11. 不做完整 PKI / CA 体系
- 图传场景不需要证书链
- 设备配对 + 密钥派生足够

---

## 修复路线图

| 限制编号 | 修复版本 | 状态 |
|---|---|---|
| #1 加密性能 | v0.3 | ✅ 已修复 (PyNaCl / libsodium C, ~500 MB/s) |
| #2 ARQ 闭环 | v0.3 | ✅ 已修复 (真实 UDP 联调 + 多轮重传) |
| #8 设备认证 | v0.3 | ✅ 已修复 (pairing.py 配对码 + keystore) |
| #12 ARQ_REP nonce | v0.4 | ✅ 已修复 (REP 豁免防重放 + 帧完成态隔离) |
| #3 弱网模型 | v0.6 | ✅ 部分修复 (GE 模型已接入; ns-3 回放 ⏳) |
| #4 国密支持 | 外部 | 需认证, 不在路线图 |
| #5 HSM | 硬件 | 超出范围 |
