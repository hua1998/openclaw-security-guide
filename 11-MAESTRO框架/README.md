# MAESTRO 框架安全检测

## 简介

MAESTRO 框架是一个 7 层智能 AI 威胁模型，用于全面评估 AI Agent 的安全风险。本模块基于 MAESTRO 框架，实现了对 AI Agent 各层次的安全检测、评估和加固。

## 7 层威胁模型

| 层次 | 名称 | 检测内容 |
|------|------|----------|
| 1 | 基础模型层 (LM) | 系统提示保护、模型 API 密钥安全存储、会话压缩防止越狱 |
| 2 | 数据操作层 (DO) | 凭证安全存储、状态目录权限限制、数据加密启用 |
| 3 | 工具使用层 (TU) | 工具权限控制、危险工具禁用 |
| 4 | 网络交互层 (NI) | 网络策略模式、外部网络访问控制 |
| 5 | 沙箱逃逸层 (SE) | 沙箱隔离模式、沙箱资源限制 |
| 6 | 持久化层 (PE) | 配置文件权限限制、凭证安全存储 |
| 7 | 横向移动层 (LM2) | 通道隔离、认证模式 |

## 检测方法

### 1. 基础模型层 (LM) 检测

检测系统提示是否受保护，模型 API 密钥是否安全存储，会话是否启用压缩以防止越狱。

### 2. 数据操作层 (DO) 检测

检测凭证是否安全存储，状态目录权限是否受限，数据是否启用加密。

### 3. 工具使用层 (TU) 检测

检测工具权限是否启用控制，危险工具是否禁用。

### 4. 网络交互层 (NI) 检测

检测网络策略模式是否为白名单，外部网络访问是否被控制。

### 5. 沙箱逃逸层 (SE) 检测

检测沙箱是否启用隔离，沙箱资源是否启用限制。

### 6. 持久化层 (PE) 检测

检测配置文件权限是否受限，凭证是否安全存储。

### 7. 横向移动层 (LM2) 检测

检测通道是否启用隔离，认证模式是否为 token。

## 加固建议

### 1. 基础模型层 (LM) 加固

- 启用系统提示保护：`agents.bootstrap.protect_prompts: true`
- 安全存储模型 API 密钥：`model.useKeychain: true`
- 启用会话压缩：`session.compaction.enabled: true`

### 2. 数据操作层 (DO) 加固

- 启用凭证安全存储：`pairing.secureStorage: true`
- 限制状态目录权限：`state.restrictPermissions: true`
- 启用数据加密：`security.dataEncryption.enabled: true`

### 3. 工具使用层 (TU) 加固

- 启用工具权限控制：`tools.permissions.enabled: true`
- 禁用危险工具：`tools.deny: ["exec", "elevated", "file_system", "network"]`

### 4. 网络交互层 (NI) 加固

- 设置网络策略模式为白名单：`network.mode: "whitelist"`
- 禁用外部网络访问：`network.allow_external: false`

### 5. 沙箱逃逸层 (SE) 加固

- 启用沙箱隔离：`agents.defaults.sandbox.mode: "non-main"`
- 启用沙箱资源限制：`agents.defaults.sandbox.resource_limits.enabled: true`

### 6. 持久化层 (PE) 加固

- 限制配置文件权限：`config.restrictPermissions: true`
- 启用凭证安全存储：`credentials.secureStorage: true`

### 7. 横向移动层 (LM2) 加固

- 启用通道隔离：`channels.*.isolate: true`
- 设置认证模式为 token：`gateway.auth.mode: "token"`

## 使用示例

### 运行 MAESTRO 框架检测

```bash
python tools/security_detector.py --config config/openclaw.json
```

### 查看 MAESTRO 框架检测结果

检测结果将包含 MAESTRO 各层次的安全问题，例如：

```
1. [X] [CRITICAL] maestro_do
   Check: pairing.secureStorage
   Expected: True
   Actual: False
   未启用安全存储，凭证可能以明文形式存储

2. [X] [CRITICAL] maestro_se
   Check: agents.defaults.sandbox.mode
   Expected: non-main or all
   Actual: off
   未启用沙箱隔离，存在沙箱逃逸风险

3. [~] [MEDIUM] maestro_lm
   Check: agents.bootstrap.protect_prompts
   Expected: True
   Actual: False
   未启用系统提示保护，可能导致系统提示泄漏
```

### 一键加固

```bash
python tools/security_hardening.py --config config/openclaw.json
```

## 合规映射

| MAESTRO 层次 | 等保2.0 | OWASP Top 10 | NIST CSF |
|-------------|---------|--------------|----------|
| 基础模型层 (LM) | 身份鉴别、访问控制 | A01: Broken Access Control | PR.AC: Access Control |
| 数据操作层 (DO) | 数据保护、密码学应用 | A03: Sensitive Data Exposure | PR.DS: Data Security |
| 工具使用层 (TU) | 访问控制、安全审计 | A01: Broken Access Control | PR.AC: Access Control |
| 网络交互层 (NI) | 网络安全、边界防护 | A05: Security Misconfiguration | PR.IP: Information Protection |
| 沙箱逃逸层 (SE) | 安全区域边界、恶意代码防范 | A08: Software and Data Integrity Failures | PR.IP: Information Protection |
| 持久化层 (PE) | 数据保护、密码学应用 | A03: Sensitive Data Exposure | PR.DS: Data Security |
| 横向移动层 (LM2) | 身份鉴别、访问控制 | A01: Broken Access Control | PR.AC: Access Control |

## 版本历史

| 版本 | 日期 | 更新内容 |
|------|------|----------|
| v1.0 | 2026-03-13 | 初始版：MAESTRO 框架 7 层检测 |
