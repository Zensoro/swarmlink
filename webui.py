"""
SwarmLink v1.0 — Web 管理界面 (零依赖)
========================================
标准库 http.server 实现的轻量仪表盘, 无第三方依赖。

用法:
  1. 任意组件调用 register_node(name, get_stats_fn) 注册状态源
  2. start_webui(port=8080) 启动 HTTP 服务
  3. 浏览器打开 http://localhost:8080/ 看实时状态

页面:
  - /            仪表盘 (HTML, 每 2s 自动刷新)
  - /api/stats   状态 JSON (供前端/脚本消费)
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional

# 模块级注册表: node_name -> get_stats() 可调用
_NODES: Dict[str, Callable] = {}
_NODES_LOCK = threading.Lock()
_START_TIME = time.monotonic()


def register_node(name: str, get_stats_fn: Callable):
    """注册一个状态源。get_stats_fn() 返回 dict。"""
    with _NODES_LOCK:
        _NODES[name] = get_stats_fn


def clear_nodes():
    """清空全部节点 (测试隔离用)。"""
    with _NODES_LOCK:
        _NODES.clear()


def collect_stats() -> dict:
    """收集所有节点状态 + 全局信息。"""
    nodes = {}
    with _NODES_LOCK:
        for name, fn in list(_NODES.items()):
            try:
                nodes[name] = fn()
            except Exception as e:
                nodes[name] = {"error": str(e)}
    return {
        "uptime_sec": round(time.monotonic() - _START_TIME, 1),
        "nodes": nodes,
        "ts": time.time(),
    }


# ---------------- HTTP ----------------
_HTML = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>SwarmLink 仪表盘</title>
<style>
  body { font-family: -apple-system, sans-serif; margin: 0; background: #0f1420; color: #d7e0f0; }
  header { padding: 14px 24px; background: #161c2c; border-bottom: 1px solid #26304a; }
  header h1 { margin: 0; font-size: 18px; }
  header small { color: #7f8db0; }
  main { padding: 20px 24px; display: grid; gap: 14px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
  .card { background: #161c2c; border: 1px solid #26304a; border-radius: 10px; padding: 14px 18px; }
  .card h2 { margin: 0 0 10px; font-size: 14px; color: #9fb2d8; text-transform: uppercase; letter-spacing: .5px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  td, th { padding: 5px 8px; text-align: left; border-bottom: 1px solid #20293f; }
  th { color: #7f8db0; font-weight: 500; }
  .big { font-size: 26px; font-weight: 700; color: #6ee7b7; }
  .ok { color: #6ee7b7; } .warn { color: #fbbf24; } .bad { color: #f87171; }
  .muted { color: #7f8db0; }
  footer { padding: 10px 24px; color: #4a5578; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>SwarmLink 仪表盘 <small id="uptime"></small></h1>
</header>
<main>
  <div class="grid" id="cards"></div>
</main>
<footer>SwarmLink v1.0 — Web 管理界面 (标准库零依赖) · 每 2s 自动刷新</footer>
<script>
async function refresh() {
  const r = await fetch('/api/stats');
  const d = await r.json();
  document.getElementById('uptime').textContent =
    '运行 ' + Math.round(d.uptime_sec) + 's';
  const cards = document.getElementById('cards');
  cards.innerHTML = '';
  for (const [name, s] of Object.entries(d.nodes)) {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = '<h2>' + esc(name) + '</h2>' + renderStats(s);
    cards.appendChild(card);
  }
}
function renderStats(s) {
  if (s.error) return '<p class="bad">错误: ' + esc(s.error) + '</p>';
  let rows = '';
  for (const [k, v] of Object.entries(s)) {
    if (typeof v === 'object' && v !== null) {
      rows += '<tr><td colspan="2"><b>' + esc(k) + '</b></td></tr>';
      rows += renderNested(v);
    } else {
      rows += '<tr><td>' + esc(k) + '</td><td>' + fmt(v) + '</td></tr>';
    }
  }
  return '<table>' + rows + '</table>';
}
function renderNested(o) {
  let rows = '';
  for (const [k, v] of Object.entries(o)) {
    rows += '<tr><td class="muted">↳ ' + esc(k) + '</td><td>' + fmt(v) + '</td></tr>';
  }
  return rows;
}
function fmt(v) {
  if (typeof v === 'number') {
    if (v % 1 === 0) return v.toLocaleString();
    return v.toFixed(1);
  }
  return esc(String(v));
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => (
    {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/stats"):
            body = json.dumps(collect_stats(), ensure_ascii=False).encode()
            self._send(200, "application/json", body)
        else:
            self._send(200, "text/html; charset=utf-8", _HTML.encode())

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # 静默


def start_webui(port: int = 8080, bind: str = "0.0.0.0") -> threading.Thread:
    """启动仪表盘 HTTP 服务 (后台线程)。"""
    server = ThreadingHTTPServer((bind, port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"  Web 管理界面: http://localhost:{port}/")
    return t
