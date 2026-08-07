# SwarmLink API / 模块速查

## 协议头 (20B)

```
+0        +4        +8        +12       +16       +20
| session_tag | frame_id | frag_id | total_frags | flags | stream_id | frame_len | crc |
    4B          4B         2B         2B         1B       1B        4B        2B
```

FLAG: KEY_FRAME(0x80) FEC_PARITY(0x40) LAST_FRAG(0x20) ARQ_REQ(0x10)
      ARQ_REP(0x08) ENCRYPTED(0x04) RELIABLE(0x02) RESERVED(0x01)

安全头 (加密包附加): 8B nonce + 16B tag = 24B/包

## 核心模块

| 模块 | 类/函数 | 职责 |
|---|---|---|
| `protocol/header.py` | `pack_header`/`unpack_header` | 协议头编解码 (CRC16 校验) |
| `protocol/fragment.py` | `Fragmenter`/`Reassembler` | 分片/FEC 编码/重组 (frame_len 裁剪) |
| `protocol/rs_codec.py` | `ReedSolomon` | RS(10,14) GF(256) 纠错 |
| `protocol/rlnc.py` | `RandomLinearCode` | RLNC 可插拔 FEC (K 灵活) |
| `protocol/arq_full.py` | `SkySender`/`GroundReceiver`/`LossDetector`/`ARQAggregatorV2` | ARQ 完整链路 |
| `protocol/multiplex.py` | `StreamMultiplexer`/`ReliableChannel` | 多流复用 + 可靠控制流 |
| `protocol/sfu.py` | `SFUForwarder`/`SFUReceiver`/`Quality` | 订阅式多码率转发 |
| `protocol/routing.py` | `ConsistentHash`/`RelayNode` | 一致性哈希 + 三级拓扑 |
| `protocol/cache.py` | `StaleWhileRevalidate` | 断连缓存 (先旧后新) |
| `protocol/ge_model.py` | `GilbertElliott` | 突发丢包模型 |
| `protocol/security_nacl.py` | `create_session_manager` | PyNaCl 加密会话 |
| `session/pairing.py` | `PairingManager`/`MultiSessionManager` | 设备配对 + 会话管理 |
| `webui.py` | `register_node`/`start_webui` | Web 管理仪表盘 |
| `tests/weaknet.py` | `WeakNetSimulator` | 弱网模拟 (均匀/GE/断连) |

## 快速集成示例

### 发送一帧 (天空端)

```python
from protocol.fragment import Fragmenter
from protocol.arq_full import SkySender, PacketStore
from protocol.security_nacl import create_session_manager

sm = create_session_manager(b"sky-001")
sm.adopt_session_key(GROUP_KEY, b"group")

sender = SkySender(
    session_tag=0xDEADBEEF,
    fragmenter=Fragmenter(0xDEADBEEF, chunk_size=600, fec_k=10, fec_n=14),
    encrypt_func=sm.encrypt_payload,
    send_callback=udp_send,          # 你的发送函数
    chunk_size=600, fec_k=10, fec_n=14,
    packet_store=PacketStore(max_frames=120),
    arq_window_ms=20,
)
sender.send_frame(frame_data, frame_id=0, stream_id=0, key_frame=True)
```

### 接收 (地面端)

```python
from protocol.fragment import Reassembler
from protocol.arq_full import GroundReceiver

receiver = GroundReceiver(
    client_id=0, session_tag=0xDEADBEEF,
    reassembler=Reassembler(0xDEADBEEF, fec_k=10, fec_n=14),
    decryptor_func=sm.decrypt_payload,
    send_arq_func=udp_send,          # 发 ARQ_REQ 的通道
    on_frame_complete=on_frame,
    rto_ms=40, max_retries=8, fec_k=10, fec_n=14,
)
# 主循环: receiver.feed(pkt); receiver.tick_loss_check()
```

### Web 仪表盘

```python
import webui
webui.register_node("sky", lambda: sender.stats())
webui.start_webui(8080)   # http://localhost:8080/
```

## 调试技巧

- `python3 examples/udp_e2e_test.py` — 全部场景联调 (含 GE 突发/SFU/多流)
- `python3 -m pytest tests/ -q -x` — 单测, 挂第一个错就停
- 网络抖动问题先看 `tools/v03_results.json` (每次联调自动落盘)
