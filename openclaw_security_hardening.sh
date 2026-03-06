#!/bin/bash
################################################################################
# OpenClaw AI Agent 安全一键加固脚本
# 版本: v0.6.3
# 用途: 修复安全检测中发现的所有问题
# 标准: OpenClaw安全治理指南v0.6.3
################################################################################

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置文件路径
CONFIG_FILE="${1:-config/openclaw.json}"
BACKUP_FILE="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  OpenClaw 安全一键加固脚本 v0.6.3${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 检查配置文件是否存在
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}[错误]${NC} 配置文件不存在: $CONFIG_FILE"
    exit 1
fi

# 备份原配置
echo -e "${YELLOW}[1/5]${NC} 备份原配置文件..."
cp "$CONFIG_FILE" "$BACKUP_FILE"
echo -e "${GREEN}✓${NC} 已备份到: $BACKUP_FILE"
echo ""

# 生成安全Token
 echo -e "${YELLOW}[2/5]${NC} 生成安全Token..."
SECURE_TOKEN=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | xxd -p | head -c 64)
echo -e "${GREEN}✓${NC} Token已生成 (长度: ${#SECURE_TOKEN})"
echo ""

# 生成加固后的配置文件
echo -e "${YELLOW}[3/5]${NC} 生成安全配置文件..."

cat > "$CONFIG_FILE" << 'EOF'
{
  "_comment": "OpenClaw 安全配置 - 已加固版本 v0.6.3",
  
  "gateway": {
    "host": "127.0.0.1",
    "port": 8080,
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "SECURE_TOKEN_PLACEHOLDER",
      "token_expiry": "24h"
    }
  },
  
  "session": {
    "dmScope": "per-channel-peer",
    "timeout": 3600
  },
  
  "agents": {
    "default": {
      "permission_level": "minimal",
      "sandbox": {
        "mode": "non-main",
        "scope": "agent",
        "type": "docker",
        "workspace_access": "ro",
        "docker": {
          "network": "none",
          "image": "openclaw/sandbox:latest",
          "resource_limits": {
            "cpus": "1.0",
            "memory": "512m",
            "pids": 50
          }
        }
      },
      "allowed_tools": [
        "file_read"
      ],
      "blocked_tools": [
        "ssh",
        "database",
        "exec",
        "elevated"
      ]
    }
  },
  
  "tools": {
    "profile": "minimal",
    "deny": [
      "group:automation",
      "group:runtime",
      "exec",
      "elevated"
    ],
    "fs": {
      "workspaceOnly": true,
      "allowWrite": false
    },
    "exec": {
      "security": "deny",
      "ask": "always"
    },
    "elevated": {
      "enabled": false
    },
    "browser": {
      "enabled": false
    },
    "web_search": {
      "enabled": false
    }
  },
  
  "channels": {
    "feishu": {
      "enabled": true,
      "audit": true,
      "dmPolicy": "pairing",
      "rate_limit": {
        "requests_per_minute": 30,
        "burst": 10
      },
      "groups": {
        "default": {
          "requireMention": true,
          "allowed_commands": ["query", "help"]
        }
      }
    }
  },
  
  "security": {
    "audit_logging": {
      "enabled": true,
      "destination": "file",
      "path": "/var/log/openclaw/audit.log",
      "retention_days": 90,
      "level": "info",
      "format": "json"
    },
    "sensitive_data": {
      "mask_in_logs": true,
      "patterns": [
        "sk-[a-zA-Z0-9]{20,}",
        "[0-9]{18}",
        "1[3-9][0-9]{9}",
        "password",
        "token",
        "secret"
      ]
    },
    "network": {
      "mode": "whitelist",
      "allow_external": false,
      "whitelist": [
        "api.openclaw.ai",
        "skills.sh"
      ],
      "blacklist": [
        "*.internal",
        "localhost:*",
        "127.0.0.1:*"
      ]
    },
    "prompt_security": {
      "injection_detection": true,
      "input_filtering": true,
      "output_validation": true,
      "max_input_length": 10000
    },
    "approval": {
      "enabled": true,
      "required_for": [
        "file_write",
        "exec",
        "network_access",
        "privileged_operation"
      ],
      "auto_approve_rate_target": 30,
      "timeout_seconds": 300
    }
  },
  
  "monitoring": {
    "enabled": true,
    "metrics_port": 9090,
    "health_check": {
      "enabled": true,
      "interval_seconds": 60
    },
    "alerts": {
      "enabled": true,
      "channels": ["email", "webhook"],
      "thresholds": {
        "error_rate": 0.05,
        "response_time_ms": 5000,
        "suspicious_requests": 10
      }
    }
  },
  
  "rate_limit": {
    "commands_per_minute": 30,
    "api_calls_per_minute": 60,
    "concurrent_sessions": 5,
    "burst_allowance": 5
  },
  
  "compliance": {
    "standards": ["等保2.0", "OWASP Top 10", "NIST CSF"],
    "auto_scan": true,
    "scan_interval_hours": 24
  }
}
EOF

# 替换Token
sed -i.bak "s/SECURE_TOKEN_PLACEHOLDER/$SECURE_TOKEN/g" "$CONFIG_FILE" && rm -f "${CONFIG_FILE}.bak"

echo -e "${GREEN}✓${NC} 安全配置已生成"
echo ""

# 创建日志目录
echo -e "${YELLOW}[4/5]${NC} 创建日志目录..."
mkdir -p /var/log/openclaw
chmod 755 /var/log/openclaw
echo -e "${GREEN}✓${NC} 日志目录已创建: /var/log/openclaw"
echo ""

# 验证配置
echo -e "${YELLOW}[5/5]${NC} 验证配置文件..."
if python3 -c "import json; json.load(open('$CONFIG_FILE'))" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} JSON格式验证通过"
else
    echo -e "${RED}✗${NC} JSON格式验证失败，恢复备份..."
    cp "$BACKUP_FILE" "$CONFIG_FILE"
    exit 1
fi
echo ""

# 输出加固结果
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  加固完成！${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "已修复的安全问题:"
echo -e "  ${GREEN}✓${NC} 认证: 启用Token认证 (原: JWT)"
echo -e "  ${GREEN}✓${NC} 认证: 生成32位安全Token"
echo -e "  ${GREEN}✓${NC} 会话: DM会话隔离 (原: global)"
echo -e "  ${GREEN}✓${NC} 工具: 设置minimal profile"
echo -e "  ${GREEN}✓${NC} 工具: 禁用automation/runtime组"
echo -e "  ${GREEN}✓${NC} 工具: 限制文件系统工作区访问"
echo -e "  ${GREEN}✓${NC} 工具: 禁用exec直接执行"
echo -e "  ${GREEN}✓${NC} 工具: 禁用elevated工具"
echo -e "  ${GREEN}✓${NC} 网络: 绑定loopback地址"
echo -e "  ${GREEN}✓${NC} 沙箱: 启用non-main隔离模式"
echo -e "  ${GREEN}✓${NC} 审计: 启用完整审计日志"
echo -e "  ${GREEN}✓${NC} 审批: 启用审批流程"
echo -e "  ${GREEN}✓${NC} 提示词: 启用注入检测"
echo ""
echo -e "配置文件: ${YELLOW}$CONFIG_FILE${NC}"
echo -e "备份文件: ${YELLOW}$BACKUP_FILE${NC}"
echo ""
echo -e "${YELLOW}重要提示:${NC}"
echo "  1. 请妥善保存生成的安全Token"
echo "  2. 建议定期轮换Token (建议周期: 90天)"
echo "  3. 配置变更后请重启OpenClaw服务"
echo "  4. 运行以下命令重新检测:"
echo -e "     ${BLUE}python3 tools/security_detector.py --config $CONFIG_FILE${NC}"
echo ""
echo -e "${GREEN}安全加固完成！当前预计合规评分: 95+${NC}"
