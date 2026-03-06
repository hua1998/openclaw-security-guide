# OpenClaw Security Tools

> OpenClaw 安全工具集
> 
> 版本: 2.0
> 更新: 2026-03-06

---

## 概述

OpenClaw 安全工具集，提供完整的安全检测、加固和监控能力。

---

## 工具列表

| 工具 | 功能 | 状态 |
|------|------|------|
| security_detector.py | 安全检测器 | ✅ |
| security_hardening.py | 安全加固脚本 | ✅ |
| config_baseline.py | 配置基线检查 | ✅ |
| config_watcher.py | 配置变更监控 | ✅ |
| token_generator.py | Token 生成器 | ✅ |
| multi_platform_scanner.py | 多平台扫描器 | ✅ |

### 研究工具 (tools/research/)

| 工具 | 功能 | 状态 |
|------|------|------|
| prompt_injection_detector.py | 提示词注入检测 | ✅ |
| behavior_baseline.py | 行为基线建模 | ✅ |
| skill_signature.py | Skills 签名验证 | ✅ |
| mcp_security_tester.py | MCP 安全测试 | ✅ |

### 适配器 (tools/adapters/)

| 适配器 | 平台 | 状态 |
|--------|------|------|
| dify_adapter.py | Dify | ✅ |
| autogpt_adapter.py | AutoGPT | ✅ |
| fastgpt_adapter.py | FastGPT | ✅ |

---

## 安装

```bash
# 克隆项目
git clone https://github.com/openclaw-security/agent-security-guide.git
cd agent-security-guide

# 安装依赖
pip install -r requirements.txt
```

---

## 使用方法

### 1. 安全检测 (security_detector.py)

检测当前配置的安全问题。

```bash
# 基本检测
python tools/security_detector.py --config config/openclaw.json

# 详细输出
python tools/security_detector.py --config config/openclaw.json --verbose

# JSON 输出
python tools/security_detector.py --config config/openclaw.json --json

# 修复建议
python tools/security_detector.py --config config/openclaw.json --fix
```

**输出示例**:
```
Risk Level: CRITICAL
Grade: C
Compliance: 53%
Total Issues: 8

Issues:
1. [CRITICAL] tools.exec.security - 未配置
2. [HIGH] sandbox.mode - 未启用
...
```

---

### 2. 安全加固 (security_hardening.py)

一键加固或分步加固配置。

```bash
# 查看加固步骤
python tools/security_hardening.py --list

# 完全加固 (10 步)
python tools/security_hardening.py --full

# 分步加固
python tools/security_hardening.py --step 1
python tools/security_hardening.py --step 2

# 验证加固结果
python tools/security_hardening.py --verify

# 回滚
python tools/security_hardening.py --rollback
```

**加固步骤**:
1. 认证配置 (Token 模式)
2. 会话隔离 (per-channel-peer)
3. 工具 Profile (messaging)
4. 沙箱模式 (container)
5. 网络白名单
6. 审计日志
7. 监控告警
8. 限流配置
9. 审批流程
10. 敏感数据过滤

---

### 3. 配置基线检查 (config_baseline.py)

检查配置是否符合安全基线。

```bash
# 检查当前配置
python tools/config_baseline.py --check

# 对比基线
python tools/config_baseline.py --diff

# 生成报告
python tools/config_baseline.py --report
```

---

### 4. 配置监控 (config_watcher.py)

实时监控配置文件变更。

```bash
# 监控配置目录
python tools/config_watcher.py --path config/

# 监控特定文件
python tools/config_watcher.py --config config/openclaw.json

# 自动修复
python tools/config_watcher.py --auto-fix
```

---

### 5. Token 生成器 (token_generator.py)

生成安全的访问令牌。

```bash
# 生成 Token
python tools/token_generator.py --generate

# 验证 Token
python tools/token_generator.py --verify <token>

# 生成带权限的 Token
python tools/token_generator.py --generate --permissions "read,write"
```

---

### 6. 多平台扫描器 (multi_platform_scanner.py)

支持多种 AI Agent 平台的安全扫描。

```bash
# 自动检测平台
python tools/multi_platform_scanner.py --config /path/to/config

# 指定平台
python tools/multi_platform_scanner.py --platform dify --config .env
python tools/multi_platform_scanner.py --platform autogpt --config .env
python tools/multi_platform_scanner.py --platform fastgpt --config config.json

# JSON 输出
python tools/multi_platform_scanner.py --config .env --json
```

---

## 研究工具使用

### 提示词注入检测

```bash
# 检测单个输入
python tools/research/prompt_injection_detector.py --test "用户输入"

# 批量检测
python tools/research/prompt_injection_detector.py --batch tests/inputs.txt

# 启用语义分析
python tools/research/prompt_injection_detector.py --test "输入" --semantic

# 启用行为分析
python tools/research/prompt_injection_detector.py --test "输入" --behavioral
```

### 行为基线建模

```bash
# 学习正常行为
python tools/research/behavior_baseline.py --learn --data behavior_logs.json

# 检测异常
python tools/research/behavior_baseline.py --detect --session session_data.json

# 生成报告
python tools/research/behavior_baseline.py --report
```

### Skills 签名验证

```bash
# 生成密钥对
python tools/research/skill_signature.py --generate-keys

# 签名 Skill
python tools/research/skill_signature.py --sign /path/to/skill.yaml

# 验证签名
python tools/research/skill_signature.py --verify /path/to/skill.yaml

# 验证技能仓库
python tools/research/skill_signature.py --verify-all /path/to/skills/
```

### MCP 安全测试

```bash
# 全面测试
python tools/research/mcp_security_tester.py --target http://localhost:3000

# SQL 注入测试
python tools/research/mcp_security_tester.py --target http://localhost:3000 --test sql_injection

# 认证绕过测试
python tools/research/mcp_security_tester.py --target http://localhost:3000 --test auth_bypass

# 生成报告
python tools/research/mcp_security_tester.py --target http://localhost:3000 --report mcp_report.json
```

---

## 脚本工具

### 自我评估 (scripts/self_assessment.py)

```bash
python scripts/self_assessment.py
```

### 差距分析 (scripts/gap_analysis.py)

```bash
python scripts/gap_analysis.py
```

---

## 配置说明

### 配置文件位置

```
config/
├── openclaw.json          # 主配置
├── security-config.yaml   # 安全配置
├── approvers.yaml         # 审批人配置
└── monitoring.yaml        # 监控配置
```

### 快速配置

```bash
# 复制示例配置
cp config/openclaw.json ~/.openclaw/
cp config/security-config.yaml ~/.openclaw/

# 修改配置
vim ~/.openclaw/openclaw.json
```

---

## 测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行特定测试
pytest tests/test_security_detector.py -v

# 覆盖率报告
pytest tests/ --cov=tools --cov-report=html
```

---

## CI/CD 集成

### GitHub Actions

```yaml
- name: Security Check
  run: |
    python tools/security_detector.py --json
    
- name: Baseline Check
  run: |
    python tools/config_baseline.py --check
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
python tools/security_detector.py --config config/openclaw.json
if [ $? -ne 0 ]; then
    echo "Security check failed!"
    exit 1
fi
```

---

## 安全等级

| 等级 | 分数 | 说明 |
|------|------|------|
| A | 90-100 | 优秀，符合企业级安全标准 |
| B | 80-89 | 良好，基本安全配置完成 |
| C | 70-79 | 一般，存在一些风险 |
| D | 60-69 | 较差，需要立即修复 |
| F | <60 | 危险，不建议生产使用 |

---

## 故障排除

### 常见问题

**Q: 找不到配置文件?**
```bash
# 复制示例配置
cp config/openclaw.json ./
```

**Q: 权限不足?**
```bash
# 检查文件权限
chmod 600 config/openclaw.json
```

**Q: 依赖缺失?**
```bash
# 安装依赖
pip install -r requirements.txt
```

---

## 更新日志

### v2.0 (2026-03-06)
- ✅ 统一工具路径到 tools/
- ✅ 新增多平台扫描器
- ✅ 新增研究工具套件
- ✅ 完善 CI/CD 集成
- ✅ 更新文档

### v1.0 (2026-02-28)
- 初始版本
- 基础安全检测
- 加固脚本

---

## 参考

- [README.md](../README.md)
- [快速使用指南](../快速使用指南.md)
- [附录A: 工具集使用指南](../附录/A-工具集使用指南.md)
