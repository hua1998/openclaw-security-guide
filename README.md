# OpenClaw 安全治理指南 v0.6.3

> **版本**: v0.6.3 

---

## 🚀 快速评估

直接运行安全检测工具：

```bash
# 1. 克隆仓库
git clone https://github.com/openclaw-security/agent-security-guide.git
cd agent-security-guide

# 2. 运行安全评估
python tools/security_detector.py --config config/openclaw.json

# 3. 查看详细报告（JSON格式）
python tools/security_detector.py --config config/openclaw.json --json

# 4. 一键加固
python tools/security_hardening.py --config config/openclaw.json
```

**评估输出示例：**
```
🔍 OpenClaw 安全检测报告
━━━━━━━━━━━━━━━━━━━━━━━
📊 安全评分: 68/100
🚨 发现 3 个高危风险，2 个中危风险

风险清单:
  [P0] 未启用Token认证
  [P0] Token强度不足
  [P1] 沙箱未启用

加固建议:
  1. 配置gateway.auth.mode为"token"
  2. 生成高强度Token: python tools/token_generator.py
  3. 启用Docker沙箱隔离
```

---

## 📦 工具集

| 工具 | 功能 | 状态 |
|------|------|------|
| `security_detector.py` | 安全检测与评分 | ✅ 可用 |
| `security_hardening.py` | 一键加固与回滚 | ✅ 可用 |
| `config_baseline.py` | 配置基线检查 | ✅ 可用 |
| `config_watcher.py` | 配置变更监控 | ✅ 可用 |
| `token_generator.py` | 高强度Token生成 | ✅ 可用 |

---

## 📚 11大安全模块

| 模块 | 内容 |
|------|------|
| [01-基础安全](01-基础安全/) | 配置安全、身份认证、数据安全 |
| [02-应用安全](02-应用安全/) | Skills供应链、提示词安全、MCP安全 |
| [03-网络运营](03-网络运营/) | 网络安全、监控告警、运维安全 |
| [04-事件响应](04-事件响应/) | 响应流程、合规映射、Playbook |
| [05-容器安全](05-容器安全/) | 镜像安全、运行时安全、K8s安全 |
| [06-办公安全](06-办公安全/) | 终端安全、网络安全、数据保护 |
| [07-行为安全](07-行为安全/) | AI行为分析、监控审计、异常检测 |
| [08-新型风险](08-新型风险/) | 提示词注入、知识库污染、对抗攻击 |
| [09-红蓝对抗](09-红蓝对抗/) | 红队攻击、蓝队防御、对抗演练 |
| [10-实战演练](10-实战演练/) | 场景案例、应急响应、复盘总结 |
| [11-MAESTRO框架](11-MAESTRO框架/) | 7层智能AI威胁模型检测、基础模型层、数据操作层、工具使用层、网络交互层、沙箱逃逸层、持久化层、横向移动层 |

---

## 🔧 安装依赖

```bash
# Python 3.8+
pip install pyyaml cryptography watchdog
```

---

## 📖 快速开始指南

详见 [快速使用指南.md](快速使用指南.md)

---





## 📄 许可证

MIT License
