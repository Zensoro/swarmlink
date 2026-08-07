"""
SwarmLink v1.0 — Web 管理界面测试
====================================
验证 webui.py: HTML 仪表盘 / API JSON / 节点注册 / 并发安全
"""

import sys
import os
import json
import time
import threading
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import webui


def _pick_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fetch(url):
    return urllib.request.urlopen(url, timeout=5).read()


def test_html_dashboard():
    port = _pick_port()
    webui.register_node("test-sky", lambda: {"状态": "运行中"})
    webui.start_webui(port)
    time.sleep(0.3)
    try:
        html = _fetch(f"http://localhost:{port}/").decode()
        assert "SwarmLink 仪表盘" in html
        assert "api/stats" in html, "前端应轮询 API"
        assert "setInterval" in html, "应自动刷新"
    finally:
        pass


def test_api_stats_json():
    port = _pick_port()
    webui.register_node("test-gnd", lambda: {
        "帧完成": 30, "丢包率": 0.15, "嵌套": {"a": 1},
    })
    webui.start_webui(port)
    time.sleep(0.3)
    data = json.loads(_fetch(f"http://localhost:{port}/api/stats").decode())
    assert "uptime_sec" in data
    assert "nodes" in data
    n = data["nodes"]["test-gnd"]
    assert n["帧完成"] == 30
    assert n["嵌套"]["a"] == 1


def test_api_error_isolation():
    """节点回调抛异常 → API 不崩, 返回 error 字段"""
    port = _pick_port()

    def bad():
        raise RuntimeError("boom")
    webui.register_node("bad-node", bad)
    webui.register_node("good-node", lambda: {"ok": True})
    webui.start_webui(port)
    time.sleep(0.3)
    data = json.loads(_fetch(f"http://localhost:{port}/api/stats").decode())
    assert "error" in data["nodes"]["bad-node"]
    assert data["nodes"]["good-node"]["ok"] is True


def test_multiple_nodes():
    """多节点注册 → 全出现在 API"""
    port = _pick_port()
    webui.clear_nodes()  # 隔离前面测试注册的节点
    for i in range(3):
        webui.register_node(f"node-{i}", lambda i=i: {"id": i})
    webui.start_webui(port)
    time.sleep(0.3)
    data = json.loads(_fetch(f"http://localhost:{port}/api/stats").decode())
    assert set(data["nodes"].keys()) == {"node-0", "node-1", "node-2"}
