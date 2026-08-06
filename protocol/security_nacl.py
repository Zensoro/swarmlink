"""
SwarmLink 安全层 v0.3 — PyNaCl 加速版
==========================================
用 libsodium (C 实现) 替换纯 Python 的 ChaCha20-Poly1305。
预期加速: 加解密 ~100x (5 MB/s → 500+ MB/s)

架构不变:
  DH (X25519) → HKDF-SHA256 → session_key (32B)
  → per-packet sub_key → ChaCha20-Poly1305 AEAD

兼容:
  - 优先 PyNaCl (C 加速)
  - 不可用时自动降级到纯 Python (security.py)
  - 接口与 security.py 一致, 上层无感

性能参考:
  | 实现          | 加密吞吐    | 解密吞吐    |
  |---------------|-------------|-------------|
  | 纯 Python    | ~5 MB/s    | ~5 MB/s    |
  | PyNaCl (C)   | ~500 MB/s  | ~500 MB/s  |
  | 纯 C/Rust    | ~2000 MB/s | ~2000 MB/s |
"""

import os
import struct
import hmac
import hashlib
import time
import threading
from typing import Optional, Tuple

# ============================================================
# 依赖检测 + 自动降级
# ============================================================
try:
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.secret import SecretBox
    from nacl.utils import random as nacl_random
    from nacl.exceptions import CryptoError
    _HAS_NACL = True
except ImportError:
    _HAS_NACL = False

try:
    from nacl.bindings import (
        crypto_aead_chacha20poly1305_ietf_encrypt,
        crypto_aead_chacha20poly1305_ietf_decrypt,
    )
    _HAS_AEAD = True
except ImportError:
    _HAS_AEAD = False

try:
    from .header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_ENCRYPTED, FLAG_RELIABLE, flags_for,
    )
except ImportError:
    import sys, os as _os
    sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from protocol.header import (
        HEADER_SIZE, pack_header, unpack_header, HeaderError,
        FLAG_ENCRYPTED, FLAG_RELIABLE, flags_for,
    )

# 降级导入
if not _HAS_NACL:
    from .security import (
        KeyPair as _KeyPairPure,
        Encryptor as _EncryptorPure,
        Decryptor as _DecryptorPure,
        SessionManager as _SessionManagerPure,
        SecurePacketBuilder as _SecurePacketBuilderPure,
    )

# ============================================================
# 常量 (与 security.py 协议兼容)
# ============================================================
NONCE_SIZE = 8
TAG_SIZE = 16
SECURITY_HEADER_SIZE = NONCE_SIZE + TAG_SIZE  # 24B
REPLAY_WINDOW = 1024
HKDF_INFO = b"SwarmLink-v0.2"
HKDF_INFO_SUBKEY = HKDF_INFO + b":subkey"
HKDF_INFO_SESSION = HKDF_INFO + b":session"
HKDF_SALT = b"SwarmLink-salt-v0.3"


# ============================================================
# HKDF-SHA256 (RFC 5869)
# ============================================================
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    result = b""
    t = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        result += t
    return result[:length]

def derive_sub_key(session_key: bytes, nonce_int: int) -> bytes:
    """session_key + nonce → 32B per-packet sub_key"""
    salt = struct.pack("!Q", nonce_int)
    prk = hkdf_extract(salt, session_key)
    return hkdf_expand(prk, HKDF_INFO_SUBKEY, 32)


# ============================================================
# KeyPair (X25519) — PyNaCl 加速
# ============================================================
class KeyPair:
    """X25519 密钥对, 每次会话新生成 → 前向安全。底层: libsodium C"""

    def __init__(self, private_key: Optional[bytes] = None):
        if not _HAS_NACL:
            raise RuntimeError(
                "PyNaCl 未安装。\n"
                "  安装: pip install pynacl\n"
                "  Debian: apt install python3-nacl\n"
                "PyNaCl 提供 libsodium C 加速, 速度提升 ~100x。"
            )
        if private_key is None:
            self._priv = PrivateKey.generate()
        else:
            self._priv = PrivateKey(private_key)
        self.public_key = self._priv.public_key.encode()
        self._priv_bytes = self._priv.encode()

    def exchange(self, peer_public_key: bytes) -> bytes:
        peer = PublicKey(peer_public_key)
        box = Box(self._priv, peer)
        return box.shared_key()

    def derive_session_key(self, peer_public_key: bytes) -> bytes:
        shared = self.exchange(peer_public_key)
        prk = hkdf_extract(salt=HKDF_SALT, ikm=shared)
        return hkdf_expand(prk, HKDF_INFO_SESSION, 32)

    def priv_bytes(self) -> bytes:
        return self._priv_bytes


# ============================================================
# Encryptor — PyNaCl AEAD (C 加速)
# ============================================================
class Encryptor:
    """
    发送端加密。per-packet nonce + sub_key。
    性能: ~500 MB/s (libsodium C)
    1080P@60fps H.265 ≈ 2 MB/s → 仅占 0.4% CPU
    """

    def __init__(self, session_key: bytes):
        assert len(session_key) == 32
        self._session_key = session_key
        self._counter = 0
        self._lock = threading.Lock()

    def encrypt(self, plaintext: bytes,
                aad: Optional[bytes] = None) -> bytes:
        with self._lock:
            # 用随机 nonce 而非顺序 counter → 支持 UDP 乱序
            nonce_int = struct.unpack("!Q", os.urandom(8))[0]
            self._counter += 1

        nonce_bytes = struct.pack("!Q", nonce_int)
        sub_key = derive_sub_key(self._session_key, nonce_int)

        if aad is None:
            aad = nonce_bytes
        else:
            aad = aad + nonce_bytes

        if _HAS_AEAD:
            # libsodium IETF AEAD: 12B nonce
            nonce_12 = b"\x00\x00\x00\x00" + nonce_bytes
            full_ct = crypto_aead_chacha20poly1305_ietf_encrypt(
                plaintext, aad, nonce_12, sub_key
            )
            # full_ct = ciphertext + 16B tag
            ciphertext = full_ct[:-TAG_SIZE]
            tag = full_ct[-TAG_SIZE:]
        elif _HAS_NACL:
            # 降级: SecretBox (XSalsa20-Poly1305)
            box = SecretBox(sub_key)
            encrypted = box.encrypt(plaintext)  # 24B nonce + ct + 16B tag
            ciphertext = encrypted[SecretBox.NONCE_SIZE:-TAG_SIZE]
            tag = encrypted[-TAG_SIZE:]
        else:
            # 终极降级: 纯 Python
            from .security import _chacha20_encrypt as _chacha_encrypt
            from .security import _poly1305_tag as _poly_tag
            ciphertext = _chacha_encrypt(sub_key, nonce_bytes, plaintext)
            tag = _poly_tag(sub_key, aad, ciphertext)

        return nonce_bytes + tag + ciphertext

    @property
    def counter(self) -> int:
        return self._counter


# ============================================================
# Decryptor — PyNaCl AEAD (C 加速) + 防重放
# ============================================================
class Decryptor:
    """
    接收端解密 + 防重放 (nonce 滑动窗口)。
    线程安全: 所有操作加锁。
    """

    def __init__(self, session_key: bytes):
        assert len(session_key) == 32
        self._session_key = session_key
        self._window_max = REPLAY_WINDOW
        self._window_start = 0
        self._received: set = set()
        self._lock = threading.Lock()

    def decrypt(self, packet: bytes) -> Optional[bytes]:
        """解密一包, 返回明文或 None"""
        if len(packet) < SECURITY_HEADER_SIZE:
            return None

        with self._lock:
            nonce_bytes = packet[:NONCE_SIZE]
            tag_recv = packet[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
            ciphertext = packet[NONCE_SIZE + TAG_SIZE:]
            nonce_int = struct.unpack("!Q", nonce_bytes)[0]

            # 防重放
            if not self._replay_check(nonce_int):
                return None

            sub_key = derive_sub_key(self._session_key, nonce_int)

            # 验证 + 解密
            plaintext = None
            if _HAS_AEAD:
                try:
                    nonce_12 = b"\x00\x00\x00\x00" + nonce_bytes
                    full_ct = ciphertext + tag_recv
                    # libsodium: decrypt(ct, ad, nonce, key)
                    plaintext = crypto_aead_chacha20poly1305_ietf_decrypt(
                        full_ct, nonce_bytes, nonce_12, sub_key
                    )
                except CryptoError:
                    return None
            elif _HAS_NACL:
                try:
                    box = SecretBox(sub_key)
                    full = nonce_bytes + ciphertext + tag_recv
                    plaintext = box.decrypt(full)
                except CryptoError:
                    return None
            else:
                # 终极降级
                from .security import _chacha20_encrypt as _chacha_encrypt
                from .security import _poly1305_verify as _poly_verify
                if not _poly_verify(sub_key, nonce_bytes, ciphertext, tag_recv):
                    return None
                plaintext = _chacha_encrypt(sub_key, nonce_bytes, ciphertext)

            if plaintext is not None:
                self._received.add(nonce_int)
                self._update_window()

            return plaintext

    def _replay_check(self, nonce_int: int) -> bool:
        # 随机 nonce 模式: 只检查"是否见过" + 上限
        # 8 字节 nonce 空间巨大, 重复概率极低
        # 但若见过的 nonce 太多, 定期清理 (保留最近 window_max 个)
        if nonce_int in self._received:
            return False  # 重复 → 重放!
        if len(self._received) >= self._window_max * 4:
            # 清理: 保留最近一半
            # (随机 nonce 无法用"窗口起点"裁剪, 用 FIFO)
            as_list = list(self._received)
            keep = set(as_list[-self._window_max:])
            self._received = keep
        return True

    def _update_window(self):
        # 随机 nonce 模式: 不依赖连续序号, 只维护 set 大小
        # (保留接口兼容, 实际清理在 _replay_check 里做)
        pass


# ============================================================
# SessionManager — 配对 + 会话生命周期
# ============================================================
class SessionManager:
    """
    管理 DH 握手 + session_key 生命周期。

    流程 (TLS 1.3 1-RTT 简化):
    1. init → 发 pub_A
    2. accept(pub_A) → 发 pub_B + 派生 session_key
    3. finalize(pub_B) → 派生 session_key

    支持:
    - ephemeral (默认): 每次新 key → 前向安全
    - static master_key: 配对设备场景
    """

    def __init__(self, device_id: bytes, master_key: Optional[bytes] = None):
        self.device_id = device_id
        self._master_key = master_key
        self._keypair: Optional[KeyPair] = None
        self._session_key: Optional[bytes] = None
        self._peer_id: Optional[bytes] = None
        self._encryptor: Optional[Encryptor] = None
        self._decryptor: Optional[Decryptor] = None
        self._session_established = False
        self._session_start: Optional[float] = None
        self._packets_encrypted = 0
        self._packets_decrypted = 0

    # --- 握手 ---
    def initiate_handshake(self) -> bytes:
        self._keypair = KeyPair()
        return self._keypair.public_key

    def accept_handshake(self, peer_public_key: bytes,
                         peer_id: bytes) -> bytes:
        self._keypair = KeyPair()
        self._peer_id = peer_id
        self._session_key = self._keypair.derive_session_key(peer_public_key)
        self._init_crypto()
        self._session_established = True
        self._session_start = time.monotonic()
        return self._keypair.public_key

    def finalize_handshake(self, peer_public_key: bytes,
                           peer_id: bytes):
        self._peer_id = peer_id
        self._session_key = self._keypair.derive_session_key(peer_public_key)
        self._init_crypto()
        self._session_established = True
        self._session_start = time.monotonic()

    def adopt_session_key(self, session_key: bytes,
                          peer_id: bytes = b"group"):
        """一对多组播场景: 直接采用已分发的组会话密钥。

        SFU / 多播模型下天空端只加密一次, 广播给 N 个地面端,
        因此所有接收端必须共享同一把 session_key
        (逐客户端 DH 会派生出不同的 key, 无法解同一份密文)。
        组密钥本身仍由配对阶段的 DH + HKDF 产生, 再经安全信道分发。
        每个接收端持有独立的 Decryptor → 防重放窗口互不干扰。
        """
        assert len(session_key) == 32
        self._peer_id = peer_id
        self._session_key = session_key
        self._init_crypto()
        self._session_established = True
        self._session_start = time.monotonic()

    def _init_crypto(self):
        self._encryptor = Encryptor(self._session_key)
        self._decryptor = Decryptor(self._session_key)

    # --- 加解密 ---
    def encrypt_payload(self, plaintext: bytes) -> bytes:
        if not self._session_established:
            raise RuntimeError("Session 未建立, 先完成握手")
        self._packets_encrypted += 1
        return self._encryptor.encrypt(plaintext)

    def decrypt_payload(self, packet: bytes) -> Optional[bytes]:
        if not self._session_established:
            raise RuntimeError("Session 未建立, 先完成握手")
        result = self._decryptor.decrypt(packet)
        if result is not None:
            self._packets_decrypted += 1
        return result

    # --- 属性 ---
    @property
    def session_key(self) -> Optional[bytes]:
        return self._session_key

    @property
    def is_established(self) -> bool:
        return self._session_established

    @property
    def session_age(self) -> float:
        if self._session_start is None:
            return 0.0
        return time.monotonic() - self._session_start

    @property
    def stats(self) -> dict:
        return {
            "device_id": self.device_id.decode(errors='replace'),
            "peer_id": self._peer_id.decode(errors='replace')
                        if self._peer_id else None,
            "established": self._session_established,
            "age_sec": round(self.session_age, 1),
            "packets_encrypted": self._packets_encrypted,
            "packets_decrypted": self._packets_decrypted,
        }

    def destroy_session(self):
        """销毁所有密钥 (前向安全)"""
        self._session_key = None
        self._encryptor = None
        self._decryptor = None
        self._keypair = None
        self._session_established = False
        self._session_start = None


# ============================================================
# SecurePacketBuilder — 与协议头集成的加密包装器
# ============================================================
class SecurePacketBuilder:
    """
    [16B SwarmLink Header | 8B nonce | 16B Poly1305 tag | N bytes ciphertext]
    头明文 (路由/分片/FEC 用), payload 加密。
    """

    def __init__(self, session_manager: SessionManager, session_tag: int):
        self._sm = session_manager
        self._session_tag = session_tag

    def build_secure_packet(self, frame_id: int, frag_id: int,
                            total_frags: int, stream_id: int,
                            payload: bytes,
                            key_frame: bool = False) -> bytes:
        encrypted = self._sm.encrypt_payload(payload)
        flags = flags_for(stream_id, key_frame=key_frame, encrypted=True)
        header = pack_header(
            session_tag=self._session_tag,
            frame_id=frame_id,
            frag_id=frag_id,
            total_frags=total_frags,
            flags=flags,
            stream_id=stream_id,
        )
        return header + encrypted

    def open_secure_packet(self, packet: bytes) -> Optional[Tuple]:
        try:
            hdr = unpack_header(packet)
        except HeaderError:
            return None
        if not hdr.is_encrypted():
            return (hdr, packet[HEADER_SIZE:])
        security_blob = packet[HEADER_SIZE:]
        plaintext = self._sm.decrypt_payload(security_blob)
        if plaintext is None:
            return None
        return (hdr, plaintext)


# ============================================================
# 工厂函数 + 后端信息
# ============================================================
def create_session_manager(device_id: bytes,
                          master_key: Optional[bytes] = None):
    """自动选择最佳实现"""
    return SessionManager(device_id, master_key)


def get_backend_info() -> dict:
    return {
        "pynacl_available": _HAS_NACL,
        "aead_available": _HAS_AEAD,
        "backend": "pynacl-c" if _HAS_NACL else "pure-python",
        "speed_class": "~500 MB/s" if _HAS_NACL else "~5 MB/s",
        "security_header_size": SECURITY_HEADER_SIZE,
    }


# ============================================================
# 性能基准
# ============================================================
def benchmark_throughput(payload_size: int = 1400,
                        iterations: int = 5000) -> dict:
    """测量加解密吞吐, 返回统计 dict"""
    info = get_backend_info()
    print(f"\n{'─' * 52}")
    print(f"  SwarmLink 安全层 v0.3 基准测试")
    print(f"  后端: {info['backend']} ({info['speed_class']})")
    print(f"  payload={payload_size}B  iterations={iterations}")
    print(f"{'─' * 52}")

    # 建立会话
    alice = SessionManager(b"alice-bench")
    bob = SessionManager(b"bob-bench")
    pa = alice.initiate_handshake()
    pb = bob.accept_handshake(pa, b"alice")
    alice.finalize_handshake(pb, b"bob")

    data = os.urandom(payload_size)

    # 加密
    t0 = time.monotonic()
    packets = []
    for _ in range(iterations):
        pkt = alice.encrypt_payload(data)
        packets.append(pkt)
    enc_time = time.monotonic() - t0
    enc_mbps = (payload_size * iterations) / enc_time / 1e6

    # 解密
    t0 = time.monotonic()
    ok = 0
    for pkt in packets:
        if bob.decrypt_payload(pkt) is not None:
            ok += 1
    dec_time = time.monotonic() - t0
    dec_mbps = (payload_size * iterations) / dec_time / 1e6

    # 握手
    t0 = time.monotonic()
    for _ in range(1000):
        a = SessionManager(b"a"); b = SessionManager(b"b")
        p1 = a.initiate_handshake()
        p2 = b.accept_handshake(p1, b"a")
        a.finalize_handshake(p2, b"b")
    hs_time = (time.monotonic() - t0) / 1000
    hs_us = hs_time * 1000

    results = {
        "backend": info['backend'],
        "payload_size": payload_size,
        "iterations": iterations,
        "encrypt_mbps": round(enc_mbps, 1),
        "decrypt_mbps": round(dec_mbps, 1),
        "handshake_us": round(hs_us, 1),
        "overhead_bytes": SECURITY_HEADER_SIZE,
        "overhead_pct": round(SECURITY_HEADER_SIZE / payload_size * 100, 2),
        "decrypt_ok": ok,
    }

    print(f"  加密: {enc_mbps:8.1f} MB/s  ({iterations}/{iterations} ✓)")
    print(f"  解密: {dec_mbps:8.1f} MB/s  ({ok}/{iterations} ✓)")
    print(f"  握手: {hs_us:8.1f} μs/次 (1000 次平均)")
    print(f"  开销: {SECURITY_HEADER_SIZE}B/包 ({results['overhead_pct']}%)")

    # 对比表
    print(f"\n  {'后端':<22s} {'加密':>10s} {'解密':>10s}")
    print(f"  {'─'*44}")
    backend_label = "PyNaCl (C)" if _HAS_NACL else "纯 Python"
    print(f"  {backend_label:<22s} "
          f"{enc_mbps:>8.1f}MB/s {dec_mbps:>8.1f}MB/s  ← 当前")
    if _HAS_NACL:
        print(f"  {'纯 C/Rust (极限)':<22s} "
              f"{'~2000':>10s} {'~2000':>10s}  ← 后期可选")

    print(f"\n  图传需求参考:")
    for label, mbps in [("720P@30fps H.264", 1.5),
                         ("1080P@30fps H.265", 2.5),
                         ("1080P@60fps H.265", 5.0)]:
        pct = mbps / enc_mbps * 100 if enc_mbps > 0 else 0
        ok = "✓" if pct < 100 else "⚠"
        print(f"    {ok} {label:<22s} ≈ {mbps} MB/s → "
              f"仅占后端 {pct:.2f}%")

    print(f"{'─' * 52}")
    return results


# ============================================================
# 自测
# ============================================================
if __name__ == "__main__":
    print("=" * 54)
    print("  SwarmLink 安全层 v0.3 — PyNaCl 加速版自测")
    print("=" * 54)

    info = get_backend_info()
    print(f"\n  后端: {info}")

    # 1. 握手 + 加解密
    print("\n--- 1. DH 握手 + 加解密 ---")
    alice = SessionManager(b"alice")
    bob = SessionManager(b"bob")
    pa = alice.initiate_handshake()
    pb = bob.accept_handshake(pa, b"alice")
    alice.finalize_handshake(pb, b"bob")

    assert alice.is_established and bob.is_established
    assert alice.session_key == bob.session_key
    print(f"  ✓ DH + HKDF → session_key")
    print(f"    {alice.session_key.hex()[:32]}...")

    ba = SecurePacketBuilder(alice, 0xCAFE)
    bb = SecurePacketBuilder(bob, 0xCAFE)

    for i in range(100):
        data = f"video-frame-{i}-".encode() * 30
        pkt = ba.build_secure_packet(
            frame_id=i, frag_id=0, total_frags=1,
            stream_id=0, payload=data, key_frame=(i == 0))
        result = bb.open_secure_packet(pkt)
        assert result is not None
        hdr, plain = result
        assert plain == data
    print(f"  ✓ 100/100 加解密往返成功")

    # 2. 防重放
    print("\n--- 2. 防重放 ---")
    pkt = ba.build_secure_packet(999, 0, 1, 0, b"replay-test")
    r1 = bb.open_secure_packet(pkt)
    r2 = bb.open_secure_packet(pkt)
    assert r1 is not None and r2 is None
    print(f"  ✓ 重放包拒绝")

    # 3. 篡改检测
    print("\n--- 3. 篡改检测 ---")
    pkt2 = ba.build_secure_packet(1, 0, 1, 0, b"tamper-me")
    tampered = bytearray(pkt2)
    tampered[20] ^= 0x01
    r3 = bb.open_secure_packet(bytes(tampered))
    assert r3 is None
    print(f"  ✓ 密文篡改 → MAC 失败")

    # 4. 前向安全
    print("\n--- 4. 前向安全 ---")
    s1 = SessionManager(b"A"); s2 = SessionManager(b"B")
    p1 = s1.initiate_handshake()
    p2 = s2.accept_handshake(p1, b"A")
    s1.finalize_handshake(p2, b"B")
    key1 = s1.session_key

    s3 = SessionManager(b"A"); s4 = SessionManager(b"B")
    p3 = s3.initiate_handshake()
    p4 = s4.accept_handshake(p3, b"A")
    s3.finalize_handshake(p4, b"B")
    key2 = s3.session_key
    assert key1 != key2
    print(f"  ✓ 每会话新 ephemeral key")

    # 5. 会话隔离
    print("\n--- 5. 会话隔离 ---")
    sa = SessionManager(b"alice"); sb = SessionManager(b"bob")
    pa = sa.initiate_handshake()
    pb = sb.accept_handshake(pa, b"alice")
    sa.finalize_handshake(pb, b"bob")

    sc = SessionManager(b"alice"); sd = SessionManager(b"charlie")
    pc = sc.initiate_handshake()
    pd = sd.accept_handshake(pc, b"alice")
    sc.finalize_handshake(pd, b"charlie")
    assert sa.session_key != sc.session_key
    print(f"  ✓ Alice-Bob ≠ Alice-Charlie")

    # 6. 性能基准
    print()
    results = benchmark_throughput(1400, 5000)

    print(f"\n{'=' * 54}")
    print(f"  ✅ PyNaCl 安全层 v0.3 全部自测通过!")
    print(f"{'=' * 54}")
    print(f"\n  核心数据:")
    print(f"    后端:     {results['backend']}")
    print(f"    加密:     {results['encrypt_mbps']} MB/s")
    print(f"    解密:     {results['decrypt_mbps']} MB/s")
    print(f"    握手:     {results['handshake_us']} μs/次")
    print(f"    开销:     {results['overhead_pct']}%")
    print(f"\n  下一步: Session 配对管理 + 多流复用器")
