"""
最小循环调试: 看 ARQ 为什么没补回缺失包
"""
import sys, os, time, random
sys.path.insert(0, '.')

from protocol.header import pack_header, unpack_header, FLAG_ARQ_REQ
from protocol.fragment import Fragmenter, Reassembler
from protocol.arq_full import PacketStore, ARQAggregatorV2

SESSION = 0xAAAA
rng = random.Random(123)

# 链路
ab_q = []
ba_q = []
sent_count = 0
lost_count = 0

def send_ab(pkt, recipients=None):
    global sent_count, lost_count
    sent_count += 1
    if rng.random() < 0.20:
        lost_count += 1
    else:
        ab_q.append(pkt)

def send_ba(pkt, recipients=None):
    ba_q.append(pkt)

# 天空端
fragger = Fragmenter(SESSION, chunk_size=400, fec_k=10, fec_n=14)
store = PacketStore(max_frames=60)
agg = ARQAggregatorV2(
    session_tag=SESSION, packet_store=store,
    retransmit_callback=send_ab, window_ms=5,
)

# 发 5 帧
all_original = {}
for fid in range(5):
    data = f"frame-{fid}-data-".encode() * (20 + fid * 5)
    all_original[fid] = data
    packets = fragger.fragment(data, stream_id=0, key_frame=(fid == 0))
    store.put(fid, packets)
    for pkt in packets:
        send_ab(pkt)

print(f"初始发送: {sent_count} 包, 丢失 {lost_count}")

# 地面端
reasm = Reassembler(SESSION, fec_k=10, fec_n=14)
completed = {}

# 第一轮: 收所有初始包
for pkt in ab_q:
    try:
        hdr = unpack_header(pkt)
        r = reasm.feed(pkt)
        if r is not None:
            completed[hdr.frame_id] = r
    except: pass
ab_q.clear()

print(f"第一轮完成: {len(completed)}/5")
for fid in range(5):
    if fid in reasm._buffers:
        buf = reasm._buffers[fid]
        data_keys = sorted(k for k in buf if isinstance(k, int) and k < 10)
        print(f"  Frame {fid}: {len(data_keys)}/10 数据片, keys={data_keys}")

# 检测缺失并发 ARQ
arq_client = None  # 简化: 直接构造请求
requests_made = 0
for fid in range(5):
    if fid in completed: continue
    buf = reasm._buffers.get(fid, {})
    missing = [i for i in range(10) if i not in buf]
    # 只请求前几个
    for mid in missing[:3]:
        req = pack_header(SESSION, fid, mid, 1, FLAG_ARQ_REQ, 0)
        send_ba(req)
        requests_made += 1

print(f"\n发出 {requests_made} 个 ARQ 请求")

# 天空端处理 ARQ
processed = 0
for req in ba_q:
    try:
        hdr = unpack_header(req)
        if hdr.is_arq_req():
            agg.receive_request(req, client_id=0)
            processed += 1
    except: pass
ba_q.clear()

print(f"天空端处理 {processed} 个请求")
agg.flush()
print(f"重传发出: {sent_count - 14*5} 包 (减去初始 70)")

# 第二轮: 收重传包
for pkt in ab_q:
    try:
        hdr = unpack_header(pkt)
        r = reasm.feed(pkt)
        if r is not None:
            completed[hdr.frame_id] = r
    except: pass

print(f"\n最终完成: {len(completed)}/5")
for fid in range(5):
    mark = "✓" if fid in completed else "✗"
    in_buf = fid in reasm._buffers
    buf_len = len(reasm._buffers.get(fid, {}))
    print(f"  {mark} Frame {fid}: completed={fid in completed}, "
          f"in_buffer={in_buf}, buf_size={buf_len}")
    if in_buf:
        buf = reasm._buffers[fid]
        keys = sorted(buf.keys())
        print(f"    keys={keys}")
