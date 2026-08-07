# SwarmLink 部署指南

## 方式一: Docker Compose (一键)

```bash
# 构建并启动地面端 (后台)
docker compose up -d gnd

# 启动天空端 (前台, 15% 弱网)
docker compose up sky

# 查看日志
docker compose logs -f
```

单机双容器模拟两台机器 (sky→gnd 经 Docker 网络互连)。
真实跨机部署改 `docker-compose.yml` 里的 `--gnd-ip` / `--sky-ip` 为对端主机 IP。

## 方式二: 单机双进程 (无 Docker)

两个终端:

```bash
# 终端 1: 地面端 (接收)
python3 examples/gnd.py --frames 30 --timeout 60

# 终端 2: 天空端 (发送, 15% 弱网 + Web 仪表盘)
python3 examples/sky.py --frames 30 --loss 0.15 --web-port 8080
```

浏览器打开 http://localhost:8080/ 查看实时状态 (丢包/重传/带宽)。

## 方式三: 双机部署 (真实网络)

| 角色 | 准备 | 命令 |
|---|---|---|
| 地面端 (机器 A) | 放行 UDP 5010 | `python3 examples/gnd.py --port 5010 --sky-port 5000 --sky-ip <B的IP>` |
| 天空端 (机器 B) | 放行 UDP 5000 | `python3 examples/sky.py --gnd-port 5010 --gnd-ip <A的IP> --loss 0.0` |

注意:
- 两端需放行对应 UDP 端口 (安全组/防火墙)
- 预共享组密钥已在 sky.py/gnd.py 内置 (demo 用途); 生产用 pairing.py 配对

## 依赖

```bash
pip install pynacl pytest numpy
```

| 依赖 | 用途 |
|---|---|
| pynacl | 加密 (X25519 + ChaCha20-Poly1305) |
| numpy | Reed-Solomon / RLNC GF(256) 运算 |
| pytest | 测试 |

## 常见问题

- **端口被占**: 换 `--sky-port`/`--port`, 或 `lsof -i :5000`
- **解密全部失败**: 两端组密钥不一致 (检查 sky.py/gnd.py 的 DEMO_GROUP_KEY)
- **Docker 拉镜像慢**: 配置镜像加速器 (国内网络)
