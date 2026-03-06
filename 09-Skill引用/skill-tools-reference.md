# OpenClaw Skill 工具引用

> 独立 Skill 工具引用章节
> 
> 版本: 1.0
> 更新: 2026-02-28

---

## 概述

本章节引用用户发布的独立 Skill 工具。

**注意**: 以下 Skill 由用户独立发布和维护，本指南仅提供引用。

---

## Skill 工具列表

### 安全类

| Skill | 功能 | 状态 | 引用 |
|-------|------|------|------|
| skill-security-detector | Skill 安全检测 | 待发布 | - |
| security-detector | 配置安全检测 | 已有 | ✅ |
| reply-throttle | 防骚扰控制 | 已有 | ✅ |
| browser-search-reliability | 浏览器搜索可靠性 | 已有 | ✅ |

### 工具类

| Skill | 功能 | 状态 | 引用 |
|-------|------|------|------|
| todo-management | 待办管理 | 已有 | ✅ |
| skill-creator | Skill 创建 | 已有 | ✅ |
| find-skills | 技能发现 | 已有 | ✅ |
| memory-hygiene | 记忆清理 | 已有 | ✅ |
| elite-longterm-memory | 长期记忆 | 已有 | ✅ |
| agent-memory | Agent 记忆 | 已有 | ✅ |

### 网络类

| Skill | 功能 | 状态 | 引用 |
|-------|------|------|------|
| web-fetch | 网页抓取 | 已有 | ✅ |
| web-search | 网络搜索 | 已有 | ✅ |

---

## 使用方法

### 安装 Skill

```bash
# 方式 1: 从 ClawHub 安装
clawhub install @user/skill-name

# 方式 2: 手动安装
cp -r skills/skill-name ~/.openclaw/skills/
```

### 配置 Skill

每个 Skill 都有独立的配置文件，详见各 Skill 的 SKILL.md。

---

## 后续发布

用户将持续发布新的 Skill 工具，本章节将持续更新引用。

### 计划发布

| Skill | 功能 | 预计 |
|-------|------|------|
| skill-security-detector | Skill 安全检测 | 待发布 |
| xxx | xxx | 待发布 |

---

## 引用规范

### 引用格式

```markdown
## X.XX Skill 工具引用

| Skill | 功能 | 版本 |
|-------|------|------|
| xxx | xxx | v1.0 |
```

### 更新机制

当用户发布新 Skill 时:
1. 在对应分类添加引用
2. 注明版本和功能
3. 提供使用说明链接

---

## 示例引用

### 安全类 Skill 引用示例

```markdown
## X.XX 安全类 Skill

### skill-security-detector

功能: 检测 Skill 的安全问题

使用:
```bash
python tools/skill_security_detector.py --path /path/to/skill
```

引用: `tools/skill_security_detector.py`
```

---

## 维护

**注意**: 本章节仅提供引用，Skill 的实际内容和维护由发布者负责。

如有问题，请联系 Skill 发布者。

---

*版本: 1.0*
*更新: 2026-02-28*
