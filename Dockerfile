# SwarmLink — 天空端/地面端 通用镜像
# 构建: docker build -t swarmlink:latest .
# 运行: docker compose up sky / docker compose up gnd
FROM python:3.12-slim

WORKDIR /app

# 系统依赖: 无 (纯 Python + numpy/pynacl)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 代码 (排除测试缓存/日志)
COPY protocol/ protocol/
COPY session/ session/
COPY examples/ examples/
COPY tests/weaknet.py tests/weaknet.py
COPY tools/ tools/

# UDP 端口 (sky: 5000 收 REQ, gnd: 5010+ 收数据)
EXPOSE 5000/udp 5010/udp 5011/udp 5012/udp

# 默认: 显示帮助
CMD ["python3", "examples/sky.py", "--help"]
