#!/bin/bash
# SwarmLink 弱网注入脚本（需 root 权限）
# 用法: sudo ./tools/tc_qdisc_setup.sh [loss] [delay_ms] [jitter_ms] [iface]
# 示例: sudo ./tools/tc_qdisc_setup.sh 30% 50ms 20ms lo

LOSS=${1:-30%}
DELAY=${2:-50ms}
JITTER=${3:-20ms}
IFACE=${4:-lo}

echo "🌐 SwarmLink: applying netem on $IFACE"
echo "   loss=$LOSS  delay=$DELAY ±$JITTER"

# 清除旧规则
tc qdisc del dev $IFACE root 2>/dev/null

# 注入弱网
tc qdisc add dev $IFACE root netem loss $LOSS $JITTER delay $DELAY $JITTER

echo ""
echo "✅ 当前 qdisc:"
tc qdisc show dev $IFACE
echo ""
echo "⚠️  测试完记得清理: sudo tc qdisc del dev $IFACE root"
