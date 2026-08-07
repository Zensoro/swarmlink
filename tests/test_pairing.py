"""
SwarmLink v0.3 — 设备配对 / 多会话管理测试
============================================
验证 session/pairing.py:
  1. 完整配对流程: 发起 → 接受 → 完成, 双方 master_key 一致
  2. keystore 持久化: 配对后重建实例仍能加载
  3. 配对码验证: 错误码拒绝, MITM 防护生效
  4. 撤销配对: revoke 后 is_paired 为 False, keystore 同步
  5. MultiSessionManager: 每设备独立会话, 密钥隔离
  6. MultiSessionManager.stats 可调用 (回归: 属性/方法 bug)
"""

import sys
import os
import time
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from session.pairing import (
    PairingManager, MultiSessionManager, gen_pairing_code,
    derive_master_key,
)


class TmpKeystore:
    """每个测试独立的临时 keystore 目录。"""
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="swarmlink-test-")

    def path(self, device_id: bytes) -> str:
        safe = device_id.decode(errors="replace").replace("/", "_")
        return os.path.join(self.dir, f"{safe}.keys")

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def test_full_pairing_flow():
    """完整配对: 发起方展示配对码 → 接受方完成 → master_key 一致"""
    ks = TmpKeystore()
    try:
        sky = PairingManager(b"sky-001", keystore_path=ks.path(b"sky-001"))
        gnd = PairingManager(b"gnd-000", keystore_path=ks.path(b"gnd-000"))

        # 1) 天空端发起配对
        sky_pub, code = sky.start_pairing(b"gnd-000")
        assert len(code) == 6 and code.isdigit(), f"配对码应为 6 位数字: {code}"

        # 2) 眼镜端接受 (从屏幕/语音获得配对码, 输入验证)
        gnd_pub = gnd.accept_pairing(sky_pub, b"sky-001",
                                     expected_code=code)

        # 3) 天空端完成 (输入配对码验证)
        ok = sky.finalize_pairing(gnd_pub, b"gnd-000", verify_code=code)
        assert ok, "配对应成功"

        # 4) 双方 master_key 一致 (配对建立)
        assert sky.is_paired(b"gnd-000")
        assert gnd.is_paired(b"sky-001")
        assert sky.get_master_key(b"gnd-000") == gnd.get_master_key(b"sky-001"), \
            "双方 master_key 应一致"
    finally:
        ks.cleanup()


def test_pairing_code_mismatch_rejected():
    """错误配对码 → 拒绝配对"""
    ks = TmpKeystore()
    try:
        sky = PairingManager(b"sky-002", keystore_path=ks.path(b"sky-002"))
        gnd = PairingManager(b"gnd-001", keystore_path=ks.path(b"gnd-001"))

        sky_pub, code = sky.start_pairing(b"gnd-001")
        gnd_pub = gnd.accept_pairing(sky_pub, b"sky-002",
                                     expected_code=code)

        wrong = ("0" if code[0] != "0" else "1") + code[1:]
        ok = sky.finalize_pairing(gnd_pub, b"gnd-001", verify_code=wrong)
        assert not ok, "错误配对码应拒绝"
        assert not sky.is_paired(b"gnd-001"), "配对失败后不应记录"
    finally:
        ks.cleanup()


def test_pairing_code_mismatch_key_divergence():
    """接受端输入错误配对码 → 双方 master_key 不同 (隐式验证)"""
    ks = TmpKeystore()
    try:
        sky = PairingManager(b"sky-005", keystore_path=ks.path(b"sky-005"))
        gnd = PairingManager(b"gnd-004", keystore_path=ks.path(b"gnd-004"))

        sky_pub, code = sky.start_pairing(b"gnd-004")
        wrong = ("0" if code[0] != "0" else "1") + code[1:]

        # 眼镜端输错码, 但双方仍完成配对 (码不同, key 必然不同)
        gnd_pub = gnd.accept_pairing(sky_pub, b"sky-005",
                                     expected_code=wrong)
        sky.finalize_pairing(gnd_pub, b"gnd-004", verify_code=code)

        assert sky.is_paired(b"gnd-004") and gnd.is_paired(b"sky-005")
        assert sky.get_master_key(b"gnd-004") != gnd.get_master_key(b"sky-005"), \
            "配对码不一致 → master_key 必须不同 (后续加密必然失败)"
    finally:
        ks.cleanup()


def test_keystore_persistence():
    """配对后重建实例 → master_key 从磁盘加载"""
    ks = TmpKeystore()
    try:
        sky = PairingManager(b"sky-003", keystore_path=ks.path(b"sky-003"))
        gnd = PairingManager(b"gnd-002", keystore_path=ks.path(b"gnd-002"))

        sky_pub, code = sky.start_pairing(b"gnd-002")
        gnd_pub = gnd.accept_pairing(sky_pub, b"sky-003",
                                     expected_code=code)
        sky.finalize_pairing(gnd_pub, b"gnd-002", verify_code=code)

        mk = sky.get_master_key(b"gnd-002")

        # 模拟重启: 新实例从同一 keystore 加载
        sky2 = PairingManager(b"sky-003", keystore_path=ks.path(b"sky-003"))
        assert sky2.is_paired(b"gnd-002"), "重启后应保留配对"
        assert sky2.get_master_key(b"gnd-002") == mk, "master_key 应持久化一致"
    finally:
        ks.cleanup()


def test_revoke_peer():
    """撤销配对 → is_paired False + keystore 同步"""
    ks = TmpKeystore()
    try:
        sky = PairingManager(b"sky-004", keystore_path=ks.path(b"sky-004"))
        gnd = PairingManager(b"gnd-003", keystore_path=ks.path(b"gnd-003"))

        sky_pub, code = sky.start_pairing(b"gnd-003")
        gnd_pub = gnd.accept_pairing(sky_pub, b"sky-004",
                                     expected_code=code)
        sky.finalize_pairing(gnd_pub, b"gnd-003", verify_code=code)
        assert sky.paired_count == 1

        assert sky.revoke_peer(b"gnd-003") is True
        assert not sky.is_paired(b"gnd-003")
        assert sky.paired_count == 0

        # 撤销持久化
        sky2 = PairingManager(b"sky-004", keystore_path=ks.path(b"sky-004"))
        assert not sky2.is_paired(b"gnd-003"), "撤销后重启不应恢复"

        # 撤销不存在的
        assert sky.revoke_peer(b"nobody") is False
    finally:
        ks.cleanup()


def test_pairing_code_format():
    codes = [gen_pairing_code() for _ in range(50)]
    for c in codes:
        assert len(c) == 6 and c.isdigit(), f"配对码格式错: {c}"
    # 统计: 50 次内至少有 2 个不同的码
    assert len(set(codes)) >= 2, "配对码应有随机性"


def test_derive_master_key_symmetric():
    """master_key 派生对称性: 交换 A/B 参数结果相同"""
    shared = os.urandom(32)
    a, b = b"device-a", b"device-b"
    assert derive_master_key(shared, a, b) == derive_master_key(shared, b, a)
    # 不同 shared → 不同 key
    assert derive_master_key(shared, a, b) != derive_master_key(os.urandom(32), a, b)


def test_multisession_isolation():
    """MultiSessionManager: 每设备独立会话 + 会话密钥隔离"""
    ks = TmpKeystore()
    try:
        pm = PairingManager(b"sky-multi", keystore_path=ks.path(b"sky-multi"))
        msm = MultiSessionManager(b"sky-multi", pairing_manager=pm)
        try:
            # 配对两台设备
            for dev in (b"gnd-a", b"gnd-b"):
                pub, code = pm.start_pairing(dev)
                peer = PairingManager(dev, keystore_path=ks.path(dev))
                peer_pub = peer.accept_pairing(pub, b"sky-multi",
                                                expected_code=code)
                assert pm.finalize_pairing(peer_pub, dev, verify_code=code)

            sa = msm.create_session(b"gnd-a")
            sb = msm.create_session(b"gnd-b")

            # 同一 peer 返回同一会话
            assert msm.create_session(b"gnd-a") is sa
            # 不同 peer 不同会话
            assert sa is not sb

            # 会话密钥隔离: 建立握手后各 session_key 不同
            a_pub = sa.initiate_handshake()
            b_pub = sb.initiate_handshake()
            assert a_pub != b_pub

            # stats 可调用 (回归: sm.stats 是方法不是属性)
            st = msm.stats()
            assert st["active_sessions"] == 2
        finally:
            msm.shutdown()
    finally:
        ks.cleanup()


def test_multisession_destroy():
    """销毁会话 → 密钥清理"""
    ks = TmpKeystore()
    try:
        msm = MultiSessionManager(b"sky-destroy")
        try:
            sm = msm.create_session(b"gnd-x")
            assert sm is not None
            msm.destroy_session(b"gnd-x")
            assert msm.get_session(b"gnd-x") is None
        finally:
            msm.shutdown()
    finally:
        ks.cleanup()
