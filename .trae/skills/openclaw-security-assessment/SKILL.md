---
name: "openclaw-security-assessment"
description: "对 OpenClaw AI Agent 进行全面的安全评估，输出安全评分、风险清单和加固建议。Invoke when user asks for OpenClaw security assessment, AI Agent security evaluation, or security hardening recommendations."
---

# OpenClaw AI Agent 安全评估 Skill

## 功能说明

本 Skill 用于对 OpenClaw 平台的 AI Agent 进行全面的安全评估，包括：
1. 安全评分计算 (0-100)
2. 风险清单识别 (P0/P1/P2 分级)
3. 加固建议生成
4. 输出 Markdown 格式报告

## 评估维度

### 1. 认证与访问控制
- `gateway.auth.mode` - Token 认证模式
- `gateway.auth.token` - Token 强度
- `session.dmScope` - 会话隔离策略

### 2. 工具权限控制
- `tools.profile` - 工具配置文件
- `tools.deny` - 禁用危险工具组
- `tools.fs.workspaceOnly` - 文件系统限制
- `tools.exec.security` - 命令执行安全
- `tools.elevated.enabled` - 特权工具控制

### 3. 网络安全
- `gateway.bind` - Gateway 绑定地址
- `network.mode` - 网络策略模式

### 4. 沙箱安全
- `agents.defaults.sandbox.mode` - 沙箱隔离模式
- `agents.defaults.sandbox.scope` - 沙箱作用域
- `agents.defaults.sandbox.workspaceAccess` - 工作区访问权限
- `agents.defaults.sandbox.docker.network` - 容器网络模式

### 5. 频道安全
- `channels.*.dmPolicy` - DM 消息策略
- `channels.*.groups.*.requireMention` - 群组提及要求

## 使用方法

### 基本用法

当用户请求安全评估时，执行以下步骤：

1. **读取配置文件**
   - 检查 `config/openclaw.json` 或用户指定的配置文件
   - 验证 JSON 格式有效性

2. **执行安全检测**
   ```bash
   python3 06-工具集/security_detector.py --config <config_path> --json
   ```

3. **分析检测结果**
   - 计算风险评分
   - 分级风险清单 (P0/P1/P2)
   - 生成加固建议

4. **输出评估报告**
   - 安全评分 (0-100)
   - 风险清单表格
   - 分级加固建议
   - 一键加固脚本

### 风险分级标准

| 级别 | 风险值 | 说明 | 响应时间 |
|------|--------|------|----------|
| P0 - 严重 | 🔴 CRITICAL | 可能导致系统完全失控 | 立即修复 |
| P1 - 高 | 🟠 HIGH | 可能导致严重安全事件 | 24小时内修复 |
| P2 - 中 | 🟡 MEDIUM | 存在潜在安全风险 | 一周内修复 |
| P3 - 低 | 🟢 LOW | 建议优化 | 下次迭代修复 |

### 评分计算规则

```python
risk_weights = {
    "critical": 10,  # P0
    "high": 5,       # P1
    "medium": 2,     # P2
    "low": 1         # P3
}

# 合规率 = max(0, 100 - 总风险分)
# 等级: A(>=90), B(>=70), C(>=50), D(<50)
```

## 输出格式

### 1. 安全评分

```markdown
| 指标 | 结果 |
|------|------|
| **安全评分** | **XX / 100** |
| **风险等级** | 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW |
| **合规等级** | A / B / C / D |
| **发现问题** | X 项 |
```

### 2. 风险清单

按 P0/P1/P2 分级列出所有问题，包含：
- 检测项路径
- 问题描述
- 当前值
- 期望值

### 3. 加固建议

按优先级提供修复命令：

**P0 - 立即执行**
```bash
# 认证加固
openclaw config set gateway.auth.mode token
openclaw config set gateway.auth.token $(openssl rand -hex 32)
openclaw config set gateway.bind loopback

# 工具加固
openclaw config set tools.exec.security deny
openclaw config set tools.elevated.enabled false

# 网络加固
openclaw config set agents.defaults.sandbox.docker.network bridge
```

**P1 - 高优先级**
```bash
# 会话隔离
openclaw config set session.dmScope per-channel-peer

# 工具限制
openclaw config set tools.deny '["group:automation", "group:runtime"]'
openclaw config set tools.fs.workspaceOnly true

# 沙箱启用
openclaw config set agents.defaults.sandbox.mode non-main
```

**P2 - 推荐配置**
```bash
# 优化配置
openclaw config set tools.profile messaging
openclaw config set agents.defaults.sandbox.scope session
```

### 4. 完整配置模板

提供安全的 JSON 配置模板供参考。

### 5. 一键加固脚本

生成可执行的 Bash 脚本，包含所有修复命令。

## 示例对话

**用户**: 对我的 AI Agent 进行安全评估

**助手**: 
1. 检查配置文件位置
2. 运行安全检测工具
3. 分析检测结果
4. 生成评估报告：
   - 安全评分: 2/100 (CRITICAL)
   - 风险清单: 17项 (P0: 5项, P1: 7项, P2: 3项)
   - 加固建议: 分级修复命令
   - 输出 Markdown 报告

## 注意事项

1. **配置文件格式**: 确保配置文件为有效 JSON，不包含注释
2. **权限要求**: 执行加固命令需要 OpenClaw 管理权限
3. **备份建议**: 加固前建议备份现有配置
4. **验证修复**: 加固后重新运行评估验证效果

## 相关文件

- 检测工具: `06-工具集/security_detector.py`
- 配置模板: `config/openclaw.json`
- 检测清单: `07-检测清单/security-checklist-complete.md`
- 项目地址: https://github.com/openclaw-security/agent-security-guide
