"""
调试: 最小可工作 ARQ 链路
"""
import sys, os, time, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.header import pack_header, unpack_header, FLAG_ARQ_REQ, HEADER_SIZE
from protocol.fragment import Fragmenter, Reassembler
from protocol.arq_full import PacketStore, ARQAggregatorV2

SESSION = 0xAAAA
rng = random.Random(42)

# 链路
sky_to_ground = []
ground_to_sky = []
lost_count = 0
sent_count = 0

def sky_send(pkt, recipients=None):
    global sent_count, lost_count
    sent_count += 1
    if rng.random() < 0.20:
        lost_count += 1
    else:
        sky_to_ground.append(pkt)

def ground_send(pkt):
    ground_to_sky.append(pkt)

# 天空端
fragger = Fragmenter(SESSION, chunk_size=400, fec_k=10, fec_n=14)
store = PacketStore(max_frames=60)
agg = ARQAggregatorV2(
    session_tag=SESSION,
    packet_store=store,
    retransmit_callback=sky_send,  # 重传走同一链路
    window_ms=5,
)

# 第一帧: 先发, 手动收集
fid = 0
data = b"x" * 3500
packets = fragger.fragment(data, stream_id=0, key_frame=True)
store.put(fid, packets)
for pkt in packets:
    sky_send(pkt)

print(f"第一波: 发送 {sent_count} 包, 丢失 {lost_count}")

# 地面端: 收包 + 检测缺失 + 发 ARQ
reasm = Reassembler(SESSION, fec_k=10, fec_n=14)
received_frags = set()

# 第一轮: 收初始包
for pkt in sky_to_ground:
    try:
        hdr = unpack_header(pkt)
        received_frags.add(hdr.frag_id)
        r = reasm.feed(pkt)
        if r is not None:
            print(f"  ✓ 第一轮就完成了! ({len(r)}B)")
    except: pass

sky_to_ground.clear()
print(f"第一轮后收到分片: {sorted(received_frags)}")

# 检查缺哪些
all_frags = set(range(14))
missing = all_frags - received_frags
print(f"缺失: {sorted(missing)}")

# 发 ARQ 请求
for mid in sorted(missing)[:5]:  # 请求前5个缺失
    req = pack_header(SESSION, fid, mid, 1, FLAG_ARQ_REQ, 0)
    ground_send(req)

print(f"发了 {len(ground_to_sky)} 个 ARQ 请求")

# 天空端处理 ARQ
for req in ground_to_sky:
    try:
        hdr = unpack_header(req)
        if hdr.is_arq_req():
            agg.receive_request(req, client_id=0)
    except: pass

ground_to_sky.clear()
agg.flush()

print(f"重传了 {sent_count - 14} 个包 (前14是第一波)")

# 第二轮: 收重传包
new_received = 0
for pkt in sky_to_ground:
    try:
        hdr = unpack_header(pkt)
        if hdr.frag_id not in received_frags:
            received_frags.add(hdr.frag_id)
            new_received += 1
        r = reasm.feed(pkt)
        if r is not None:
            print(f"  ✓ 第二轮完成! ({len(r)}B) 新收 {new_received} 片")
    except: pass

print(f"\n最终收到分片: {sorted(received_frags)}")
print(f"总发送: {sent_count}, 总丢失: {lost_count}")
print(f"Reassembler buffers: {list(reasm._buffers.keys())}")
if 0 in reasm._buffers:
    buf = reasm._buffers[0]
    print(f"  Frame 0 buf: {len(buf)} entries, keys={sorted(buf.keys())}")
