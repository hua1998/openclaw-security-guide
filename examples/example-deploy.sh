#!/bin/bash
# OpenClaw 快速部署脚本示例
# 用途：参考此脚本了解部署流程

set -e

echo "========================================"
echo "OpenClaw 快速部署脚本"
echo "========================================"
echo ""

# 环境检查
echo "[检查] 环境准备..."
python --version || exit 1
openclaw --version || exit 1
echo "✅ 环境检查通过"
echo ""

# 创建配置目录
echo "[1/5] 创建配置目录..."
mkdir -p /etc/openclaw
mkdir -p /var/log/openclaw
echo "✅ 目录已创建"
echo ""

# 复制配置文件
echo "[2/5] 复制配置文件..."
cp config/security-config.yaml /etc/openclaw/
cp config/openclaw.json /etc/openclaw/
cp config/approvers.yaml /etc/openclaw/
cp config/monitoring.yaml /etc/openclaw/
echo "✅ 配置文件已复制"
echo ""

# 修改配置 (根据实际情况)
echo "[3/5] 修改配置..."
# 示例：修改飞书 Webhook
# sed -i 's/YOUR_WEBHOOK_URL/实际 URL/g' /etc/openclaw/monitoring.yaml

# 示例：修改审批人 ID
# sed -i 's/ou_xxx/实际 ID/g' /etc/openclaw/approvers.yaml
echo "✅ 配置已修改 (请根据实际情况修改)"
echo ""

# 应用配置
echo "[4/5] 应用配置..."
openclaw config apply /etc/openclaw/security-config.yaml
openclaw config apply /etc/openclaw/openclaw.json
echo "✅ 配置已应用"
echo ""

# 启动服务
echo "[5/5] 启动服务..."
openclaw start
echo "✅ 服务已启动"
echo ""

# 验证部署
echo "验证部署..."
python scripts/self_assessment.py
echo ""

echo "========================================"
echo "部署完成!"
echo "========================================"
echo ""
echo "下一步:"
echo "1. 修改配置中的飞书 ID 和 Webhook"
echo "2. 运行自我评估验证安全状态"
echo "3. 根据建议进行加固"
echo ""
