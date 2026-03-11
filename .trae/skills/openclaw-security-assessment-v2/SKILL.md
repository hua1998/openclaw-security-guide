---
name: " "
description: "基于OpenClaw安全治理指南v0.6.3，对AI Agent进行全面的多维度安全评估，输出安全评分、风险清单(P0-P3分级)、加固建议和合规映射。Invoke when user asks for OpenClaw security assessment, AI Agent security evaluation, security hardening, or compliance check."
---

# OpenClaw AI Agent 安全评估 Skill V2

> **版本**: v0.6.3  
> **标准**: OpenClaw安全治理指南  
> **合规**: 等保2.0 / OWASP Top 10 / NIST CSF

---

## 功能说明

本 Skill 用于对 AI Agent 进行全面的多维度安全评估，包括：

1. **多维度安全评分** (11维度加权计算)
2. **分级风险清单** (P0/P1/P2/P3 四级)
3. **可执行加固建议** (含具体命令和配置)
4. **合规标准映射** (等保2.0/OWASP/NIST)
5. **复测验证方案**

---

## 评估维度

### 1. 认证与访问控制 (权重15%)
- `gateway.auth.mode` - Token/JWT认证模式
- `gateway.auth.token` - Token强度(>=32位)
- `session.dmScope` - 会话隔离策略
- `gateway.bind` - Gateway绑定地址

### 2. 数据与隐私保护 (权重10%)
- `security.sensitive_data.mask_in_logs` - 日志脱敏
- `security.sensitive_data.patterns` - 敏感数据模式
- 数据加密传输与存储

### 3. 网络安全 (权重10%)
- `network.mode` - 网络策略模式(白名单/黑名单)
- `network.allow_external` - 外部网络访问控制
- `agents.defaults.sandbox.docker.network` - 容器网络隔离

### 4. 应用安全 (权重10%)
- `tools.profile` - 工具配置文件
- `tools.deny` - 禁用危险工具组
- `tools.fs.workspaceOnly` - 文件系统限制
- `tools.exec.security` - 命令执行安全
- `tools.elevated.enabled` - 特权工具控制

### 5. 运行时安全 (权重10%)
- `agents.defaults.sandbox.mode` - 沙箱隔离模式
- `agents.defaults.sandbox.scope` - 沙箱作用域
- `agents.defaults.sandbox.workspaceAccess` - 工作区访问权限
- `sandbox.resource_limits` - 资源限制

### 6. 审计与合规 (权重10%)
- `security.audit_logging.enabled` - 审计日志启用
- `security.audit_logging.retention_days` - 日志保留期限
- `approval.enabled` - 审批流程配置
- `monitoring.enabled` - 监控告警配置

### 7. 供应链安全 (权重10%)
- `plugins.entries.*.source` - 插件来源验证
- `skills.allow` - 技能包白名单
- 第三方依赖安全

### 8. 互联网暴露 (权重10%)
- `network.allow_external` - 外部网络访问控制
- `gateway.bind` - 网关绑定地址
- 端口暴露检测

### 9. 权限控制 (权重5%)
- `tools.exec.security` - 命令执行权限
- `agents.defaults.sandbox.workspaceAccess` - 工作区访问权限
- 最小权限原则验证

### 10. 社会工程学攻击防范 (权重5%)
- `security.prompt_security.injection_detection` - 提示词注入检测
- `browser.sandbox` - 浏览器沙箱启用
- 社会工程学攻击防护配置

### 11. 场景特定安全 (权重5%)
- 智能办公场景安全
- 开发运维场景安全
- 个人助手场景安全
- 金融交易场景安全

---

## 使用方法

### 输入要求

用户提供AI Agent配置信息，格式可为：

1. **配置文件路径** (JSON/YAML)
   ```
   我的配置在 config/openclaw.json
   ```

2. **配置内容粘贴** (代码块格式)
   ```json
   { "gateway": { "auth": { "mode": "jwt" } } }
   ```

3. **部署环境描述**
   ```
   Docker部署，使用默认配置
   ```

### 执行流程

```
输入接收 → 配置解析 → 11维度检查 → 风险评级 → 生成报告 → 提供加固方案 → 合规映射
```

### 工具调用

```bash
# 运行安全检测
python3 tools/security_detector.py --config <config_path> --json

# 生成加固脚本
./openclaw_security_hardening.sh <config_path>
```

---

## 风险分级标准

| 级别 | 风险值 | 权重 | 说明 | 响应时间 | 图标 |
|------|--------|------|------|----------|------|
| **P0 - 严重** | CRITICAL | 10 | 可能导致系统完全失控 | 立即修复 (0-24h) | 🔴 |
| **P1 - 高** | HIGH | 5 | 可能导致严重安全事件 | 短期修复 (1-7天) | 🟠 |
| **P2 - 中** | MEDIUM | 2 | 存在潜在安全风险 | 计划修复 (1-4周) | 🟡 |
| **P3 - 低** | LOW | 1 | 建议优化 | 下次迭代 | 🟢 |

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
# 风险等级: Critical(>=30), High(>=15), Medium(>=5), Low(<5)
```

---

## 输出格式

### 1. 执行摘要

```markdown
评估对象: [AI Agent名称/类型]
评估时间: [ISO 8601格式]
评估标准: OpenClaw安全治理指南 v0.6.3
总体状态: [通过/有条件通过/不通过]
```

### 2. 安全评分 (0-100)

| 安全维度 | 得分 | 权重 | 加权得分 |
|----------|------|------|----------|
| 认证与访问控制 | XX/100 | 15% | XX |
| 数据与隐私保护 | XX/100 | 10% | XX |
| 网络安全 | XX/100 | 10% | XX |
| 应用安全 | XX/100 | 10% | XX |
| 运行时安全 | XX/100 | 10% | XX |
| 审计与合规 | XX/100 | 10% | XX |
| 供应链安全 | XX/100 | 10% | XX |
| 互联网暴露 | XX/100 | 10% | XX |
| 权限控制 | XX/100 | 5% | XX |
| 社会工程学攻击防范 | XX/100 | 5% | XX |
| 场景特定安全 | XX/100 | 5% | XX |
| **综合评分** | **XX/100** | 100% | **XX** |

**评级**: 
- 🅰️ A (90-100): 优秀
- 🅱️ B (70-89): 良好
- ©️ C (50-69): 及格
- D (0-49): 不及格

**风险等级**: 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low

### 3. 风险清单 (按优先级排序)

#### 🔴 P0 - 关键风险 (立即修复，0-24小时)

| # | 检查项 | 检测规则 | 当前值 | 期望值 | 风险描述 | 修复命令 |
|---|--------|----------|--------|--------|----------|----------|
| 1 | | | | | | |

#### 🟠 P1 - 高风险 (短期内修复，1-7天)

| # | 检查项 | 检测规则 | 当前值 | 期望值 | 风险描述 | 修复命令 |
|---|--------|----------|--------|--------|----------|----------|
| 1 | | | | | | |

#### 🟡 P2 - 中风险 (计划修复，1-4周)

| # | 检查项 | 检测规则 | 当前值 | 期望值 | 风险描述 | 修复建议 |
|---|--------|----------|--------|--------|----------|----------|
| 1 | | | | | | |

#### 🟢 P3 - 低风险 (持续改进)

| # | 检查项 | 检测规则 | 当前值 | 期望值 | 优化建议 |
|---|--------|----------|--------|--------|----------|
| 1 | | | | | | |

### 4. 加固建议

#### 4.1 立即执行 (Critical)

```bash
#!/bin/bash
# 一键加固脚本 - Critical修复

# 生成32位安全Token
SECURE_TOKEN=$(openssl rand -hex 32)

# 认证加固
jq '.gateway.auth.mode = "token" | 
    .gateway.auth.token = "'"$SECURE_TOKEN"'" | 
    .gateway.bind = "loopback"' config.json > config.json.tmp

# 工具加固
jq '.tools.exec.security = "deny" | 
    .tools.elevated.enabled = false' config.json.tmp > config.json

rm config.json.tmp
echo "Critical加固完成"
```

#### 4.2 配置优化 (完整安全基线)

```json
{
  "_comment": "OpenClaw安全配置 - 加固版本 v0.6.3",
  "gateway": {
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "[32+随机字符串]"
    }
  },
  "agents": {
    "default": {
      "sandbox": {
        "enabled": true,
        "mode": "non-main",
        "scope": "agent"
      }
    }
  },
  "tools": {
    "profile": "minimal",
    "deny": ["group:automation", "group:runtime", "exec", "elevated"],
    "fs": { "workspaceOnly": true },
    "exec": { "security": "deny", "ask": "always" }
  },
  "security": {
    "audit_logging": {
      "enabled": true,
      "retention_days": 90
    },
    "prompt_security": {
      "injection_detection": true
    }
  }
}
```

#### 4.3 持续监控配置

```yaml
# 审计日志配置
audit:
  enabled: true
  level: info
  format: json
  destination: /var/log/openclaw/audit.log
  retention_days: 90

# 监控告警
monitoring:
  enabled: true
  alerts:
    - rule: 异常认证尝试
      threshold: 5
      window: 5m
      action: notify
    - rule: 高风险操作
      threshold: 1
      action: block_and_notify
```

### 5. 合规映射

| 检测项 | 等保2.0 | OWASP Top 10 | NIST CSF |
|--------|---------|--------------|----------|
| 认证机制 | 8.1.4 | A07:2021 | PR.AC-1 |
| 访问控制 | 8.1.2 | A01:2021 | PR.AC-3 |
| 数据加密 | 8.1.5 | A02:2021 | PR.DS-1 |
| 日志审计 | 8.1.2 | A09:2021 | PR.PT-1 |
| 输入验证 | 8.1.6 | A03:2021 | PR.IP-3 |
| 安全配置 | 8.1.10 | A05:2021 | PR.IP-1 |
| 沙箱隔离 | 8.1.1 | A08:2021 | PR.AC-5 |
| 供应链安全 | - | A06:2021 | PR.DS-8 |

### 6. 复测验证

修复后运行以下命令验证：

```bash
# 重新评估
python3 tools/security_detector.py --config config/openclaw.json --json

# 预期结果
# - 综合评分 >= 90
# - 无P0风险
# - 无P1风险
# - 评级达到A级
```

---

## 示例对话

### 示例1: 完整评估

**用户**: 请对我的OpenClaw AI Agent进行安全评估，配置文件在 `config/openclaw.json`

**助手**:
1. 读取并解析配置文件
2. 执行11维度安全检测
3. 生成评分报告
4. 输出风险清单(P0-P3)
5. 提供加固脚本
6. 映射合规标准

**输出**:
```
评估对象: OpenClaw AI Agent
评估时间: 2026-03-06T14:00:00Z
评估标准: OpenClaw v0.6.3

安全评分: 23/100 (D级)
风险等级: CRITICAL
发现问题: 12项 (P0:4, P1:5, P2:1, P3:2)

[详细报告...]
```

### 示例2: 快速检查

**用户**: 检查我的配置是否安全

**助手**: 快速扫描关键配置项，输出是否存在P0/P1风险

---

## 注意事项

1. **保密性**: 评估过程中发现的Token/密钥需要脱敏处理，不在报告中显示完整值
2. **可追溯**: 每次评估记录时间戳、版本信息、检测规则版本
3. **可操作性**: 所有建议必须包含具体配置或命令，避免模糊描述
4. **可验证**: 提供复测方法确认修复效果，明确预期目标
5. **备份建议**: 执行加固前自动备份原配置
6. **权限要求**: 执行加固命令需要OpenClaw管理权限

---

## 相关文件

- **检测工具**: [`tools/security_detector.py`](tools/security_detector.py)
- **加固脚本**: [`openclaw_security_hardening.sh`](openclaw_security_hardening.sh)
- **配置模板**: [`config/openclaw.json`](config/openclaw.json)
- **安全基线**: [`config/security-config.yaml`](config/security-config.yaml)
- **检测清单**: [`07-检测清单/security-checklist-complete.md`](07-检测清单/security-checklist-complete.md)
- **项目地址**: https://github.com/hua1998/openclaw-security-guide

---

## 版本历史

| 版本 | 日期 | 更新内容 |
|------|------|----------|
| v2.1 | 2026-03-11 | 增强版：11维度评分、供应链安全检测、互联网暴露检测、社会工程学攻击防范、场景特定安全检测 |
| v2.0 | 2026-03-06 | 优化版：多维度评分、P0-P3分级、合规映射、复测验证 |
| v1.0 | 2026-03-05 | 初始版：基础评分、P0-P2分级、基础加固建议 |
