# OpenClaw GitHub 项目自动化安全评估提示词

## 提示词模板

请复制以下提示词并在 OpenClaw 中使用：

---

**提示词**：

```
你是一个 AI Agent 安全评估专家。现在我需要你完成以下任务：

## 任务目标
1. 从 GitHub 下载指定项目
2. 对项目中的 AI Agent 配置进行安全评估
3. 输出完整的安全检查报告

## 执行步骤

### 第1步：下载项目
请使用 Git 工具从 GitHub 克隆指定的项目：

```bash
# 替换为实际的 GitHub 仓库地址
git clone <项目仓库地址>
cd <项目目录>
```

### 第2步：查找配置文件
在项目中查找 OpenClaw 配置文件，通常位于：
- `config/openclaw.json`
- `.openclaw/openclaw.json`
- `config.json`
- `openclaw.json`

### 第3步：调用安全评估 Skill
使用以下命令调用 openclaw-security-assessment-v2 skill 对配置进行安全评估：

```
请作为 OpenClaw 安全治理专家，对 AI Agent 进行安全评估。

评估标准：OpenClaw安全治理指南 v0.6.3
评估维度：
1. 认证与访问控制 (15%)
2. 数据与隐私保护 (10%)
3. 网络安全 (10%)
4. 应用安全 (10%)
5. 运行时安全 (10%)
6. 审计与合规 (10%)
7. 供应链安全 (10%)
8. 互联网暴露 (10%)
9. 权限控制 (5%)
10. 社会工程学攻击防范 (5%)
11. 场景特定安全 (5%)

请读取配置文件 <配置文件路径>，执行11维度安全检测，输出：
1. 安全评分 (0-100)
2. 风险清单 (P0/P1/P2/P3分级)
3. 加固建议
4. 合规映射 (等保2.0/OWASP/NIST)
```

### 第4步：执行检测工具
如果没有现成的配置文件，请检查项目中是否有 Docker Compose 配置或相关安全文件，然后运行：

```bash
# 运行安全检测
python3 tools/security_detector.py --config <配置文件路径> --json

# 或者使用项目中的检测工具
./openclaw_security_hardening.sh <配置文件路径>
```

## 输出要求

请按以下格式输出完整的检查报告：

### 1. 执行摘要
```markdown
评估对象: [项目名称]
评估时间: [ISO 8601格式时间]
评估标准: OpenClaw安全治理指南 v0.6.3
总体状态: [通过/有条件通过/不通过]
GitHub仓库: [仓库地址]
```

### 2. 安全评分 (0-100)

| 安全维度 | 得分 | 权重 | 加权得分 | 评级 |
|----------|------|------|----------|------|
| 认证与访问控制 | XX/100 | 15% | XX | A/B/C/D |
| 数据与隐私保护 | XX/100 | 10% | XX | A/B/C/D |
| 网络安全 | XX/100 | 10% | XX | A/B/C/D |
| 应用安全 | XX/100 | 10% | XX | A/B/C/D |
| 运行时安全 | XX/100 | 10% | XX | A/B/C/D |
| 审计与合规 | XX/100 | 10% | XX | A/B/C/D |
| 供应链安全 | XX/100 | 10% | XX | A/B/C/D |
| 互联网暴露 | XX/100 | 10% | XX | A/B/C/D |
| 权限控制 | XX/100 | 5% | XX | A/B/C/D |
| 社会工程学攻击防范 | XX/100 | 5% | XX | A/B/C/D |
| 场景特定安全 | XX/100 | 5% | XX | A/B/C/D |
| **综合评分** | **XX/100** | 100% | **XX** | **A/B/C/D** |

**评级说明**:
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

## 使用示例

### 示例 1：评估指定仓库

```
请帮我对 https://github.com/hua1998/openclaw-security-guide 项目进行安全评估。
```

### 示例 2：评估本地配置

```
请对 config/openclaw.json 文件进行安全评估，并生成加固建议。
```

### 示例 3：完整评估流程

```
1. 克隆仓库 https://github.com/hua1998/openclaw-security-guide
2. 查找配置文件
3. 运行python3 security_detector.py 进行安全检测
4. 输出完整的检查报告
```

### 示例 4：批量评估多个仓库

```
请依次评估以下仓库的安全配置：
1. https://github.com/example/repo1
2. https://github.com/example/repo2
3. https://github.com/example/repo3

每个仓库输出完整的检查报告。
```

---

## 注意事项

1. **配置文件路径**：确保正确指定配置文件的路径
2. **依赖安装**：如果项目需要额外依赖，先安装
3. **Token 处理**：评估过程中注意保护敏感 Token
4. **备份建议**：加固前建议备份原配置
5. **网络访问**：确保能够访问 GitHub 仓库
6. **权限要求**：执行某些操作可能需要管理员权限
```

---

## 高级功能

### 自动化脚本

您可以将以下脚本保存为 `github-security-scan.sh`，实现自动化安全评估：

```bash
#!/bin/bash

# GitHub 仓库地址
REPO_URL=$1

# 临时目录
TEMP_DIR=$(mktemp -d)

# 克隆仓库
git clone $REPO_URL $TEMP_DIR

# 查找配置文件
CONFIG_FILE=$(find $TEMP_DIR -name "openclaw.json" -o -name "config.json" | head -1)

if [ -z "$CONFIG_FILE" ]; then
    echo "未找到配置文件"
    exit 1
fi

# 运行安全检测
python3 tools/security_detector.py --config $CONFIG_FILE --json > security-report.json

# 输出报告
cat security-report.json

# 清理临时目录
rm -rf $TEMP_DIR
```

### 使用方法

```bash
# 赋予执行权限
chmod +x github-security-scan.sh

# 执行评估
./github-security-scan.sh https://github.com/hua1998/openclaw-security-guide
```

---

## 报告导出

评估完成后，您可以将报告导出为以下格式：

1. **Markdown 格式**：便于阅读和分享
2. **JSON 格式**：便于程序处理和集成
3. **PDF 格式**：便于打印和归档

---

## 支持的评估场景

本提示词支持以下场景的安全评估：

1. **智能办公场景**：检测供应链攻击风险
2. **开发运维场景**：检测权限控制和网络安全
3. **个人助手场景**：检测社会工程学攻击防范
4. **金融交易场景**：检测合规性和权限控制

---

## 版本信息

- **版本**: v2.1
- **更新日期**: 2026-03-11
- **评估标准**: OpenClaw安全治理指南 v0.6.3
- **检测维度**: 11个安全维度
- **风险分级**: P0/P1/P2/P3 四级

---

## 技术支持

如有问题或建议，请联系：
- GitHub: https://github.com/hua1998/openclaw-security-guide
- Issues: https://github.com/hua1998/openclaw-security-guide/issues
