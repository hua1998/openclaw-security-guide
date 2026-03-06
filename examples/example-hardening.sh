#!/bin/bash
# OpenClaw 安全加固脚本示例
# 用途：参考此脚本了解加固流程

set -e

echo "========================================"
echo "OpenClaw 安全加固脚本"
echo "========================================"
echo ""

# 1. 启用沙箱
echo "[1/4] 启用沙箱隔离..."
openclaw config set agents.default.sandbox.enabled true
openclaw config set agents.default.sandbox.mode session
echo "✅ 沙箱已启用"
echo ""

# 2. 配置审批人
echo "[2/4] 配置审批人..."
cat > config/approvers.yaml << 'EOF'
approvers:
  developer:
    level_1: "ou_xxx"
    level_2: "ou_yyy"
  escalation:
    timeout: 30m
    escalate_to: level_2
EOF
echo "✅ 审批人已配置"
echo ""

# 3. 配置监控
echo "[3/4] 配置监控告警..."
cat > config/monitoring.yaml << 'EOF'
metrics:
  security_incidents:
    enabled: true
    target: 0
  auto_approval_rate:
    enabled: true
    target: 70%
notifications:
  feishu:
    enabled: true
    webhook: "YOUR_WEBHOOK_URL"
EOF
echo "✅ 监控已配置"
echo ""

# 4. 启用审计日志
echo "[4/4] 启用审计日志..."
openclaw config set audit.enabled true
openclaw config set audit.format json
echo "✅ 审计日志已启用"
echo ""

# 重启服务
echo "重启 OpenClaw 服务..."
openclaw restart
echo ""

echo "========================================"
echo "加固完成!"
echo "========================================"
echo ""
echo "请运行自我评估验证效果:"
echo "  python scripts/self_assessment.py"
echo ""
