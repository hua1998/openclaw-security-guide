#!/bin/bash
# OpenClaw 自动加固脚本
# 生成时间：2026-02-26T17:12:46.585651

set -e

# 2. 配置审批人
echo '配置审批人...'
cat > config/approvers.yaml << 'EOF'
approvers:
  developer:
    level_1: "ou_xxx"  # 替换为团队主管飞书 ID
    level_2: "ou_yyy"  # 替换为运维主管飞书 ID
EOF

# 3. 配置监控
echo '配置监控告警...'
cat > config/monitoring.yaml << 'EOF'
metrics:
  security_incidents:
    enabled: true
    target: 0
EOF

# 重启服务
echo '重启 OpenClaw 服务...'
openclaw restart

echo '加固完成!'