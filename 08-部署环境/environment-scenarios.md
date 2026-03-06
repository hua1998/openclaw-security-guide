# OpenClaw 环境场景方案

> 测试环境 / 开发环境 / 生产环境 + 部署环境 场景方案
> 
> 版本: 2.0
> 更新: 2026-02-28

---

## 一、环境类型定义

### 1.1 用途维度

| 环境类型 | 用途 | 风险承受 | 配置策略 |
|----------|------|----------|----------|
| **测试环境** | 功能测试、安全验证 | 可承受数据丢失 | 宽松配置 |
| **开发环境** | 日常开发调试 | 有限风险 | 中等配置 |
| **生产环境** | 正式运行 | 无风险承受 | 严格配置 |

### 1.2 部署维度

| 部署类型 | 说明 | 适用场景 |
|----------|------|----------|
| **物理宿主机** | 直接安装在物理服务器 | 高性能需求、长期运行 |
| **CVM 云服务器** | 云虚拟机 (阿里云/腾讯云/AWS) | 云端部署、弹性伸缩 |
| **Docker 容器** | 容器化部署 | 快速部署、隔离需求 |
| **Kubernetes** | K8s 集群部署 | 多实例、容器编排 |
| **桌面/笔记本** | 本地开发机 | 个人使用、日常开发 |
| **NAS** | 网络存储设备 | 家庭/小型办公 |

---

## 二、物理宿主机部署

### 2.1 场景描述

**适用场景**:
- 高性能需求
- 长期稳定运行
- 完整控制

**特点**:
- 直接安装操作系统
- 独占资源
- 需要自行管理

### 2.2 配置策略

```json
{
  "environment": "production",
  "deployment": "bare-metal",
  
  "gateway": {
    "mode": "local",
    "bind": "127.0.0.1",
    "auth": {
      "mode": "token",
      "token": "${SECURE_TOKEN}"
    }
  },
  
  "session": {
    "dmScope": "per-channel-peer"
  },
  
  "tools": {
    "profile": "minimal",
    "deny": ["group:automation", "group:runtime", "group:fs"],
    "fs": { "workspaceOnly": true },
    "exec": { "security": "deny", "ask": "always" },
    "elevated": { "enabled": false }
  },
  
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "scope": "session",
        "workspaceAccess": "none",
        "docker": {
          "network": "none"
        }
      }
    }
  }
}
```

### 2.3 安全加固

```bash
# 完全加固
python security_hardening.py --full

# 防火墙配置
sudo ufw enable
sudo ufw allow 18789/tcp

# 只允许本地访问
sudo ufw deny 18789/tcp
```

---

## 三、CVM 云服务器部署

### 3.1 场景描述

**适用场景**:
- 云端部署
- 弹性伸缩
- 无需硬件管理

**特点**:
- 按需付费
- 自动备份
- 安全组控制

### 3.2 配置策略

```json
{
  "environment": "production",
  "deployment": "cvm",
  "cloud_provider": "aliyun|tencent|aws",
  
  "gateway": {
    "mode": "local",
    "bind": "127.0.0.1",
    "auth": {
      "mode": "token",
      "token": "${SECURE_TOKEN}"
    },
    "tailscale": {
      "mode": "serve"
    }
  },
  
  "session": {
    "dmScope": "per-channel-peer"
  },
  
  "tools": {
    "profile": "minimal",
    "deny": ["group:automation", "group:runtime", "group:fs"],
    "fs": { "workspaceOnly": true },
    "exec": { "security": "deny" },
    "elevated": { "enabled": false }
  },
  
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "docker": {
          "network": "bridge"
        }
      }
    }
  }
}
```

### 3.3 云安全组配置

**阿里云安全组**:
```
入站规则:
- 允许 100.100.100.100/32 端口 18789 (内网)
- 允许 Tailscale IP 端口 18789

出站规则:
- 全部拒绝 (沙箱网络隔离)
```

**腾讯云安全组**:
```
- 仅绑定内网网卡
- 禁止公网访问
```

---

## 四、Docker 容器部署

### 4.1 场景描述

**适用场景**:
- 快速部署
- 环境隔离
- 资源受限

**特点**:
- 容器化运行
- 环境一致
- 便于迁移

### 4.2 配置策略

```json
{
  "environment": "production",
  "deployment": "docker",
  
  "gateway": {
    "mode": "local",
    "bind": "127.0.0.1",
    "auth": {
      "mode": "token",
      "token": "${SECURE_TOKEN}"
    }
  },
  
  "session": {
    "dmScope": "per-channel-peer"
  },
  
  "tools": {
    "profile": "messaging",
    "deny": ["group:automation", "group:runtime"]
  },
  
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "scope": "session"
      }
    }
  }
}
```

### 4.3 Docker 启动

```bash
# 启动容器
docker run -d \
  --name openclaw \
  -v ~/.openclaw:/home/node/.openclaw \
  -v openclaw-workspace:/home/node/.openclaw/workspace \
  -p 127.0.0.1:18789:18789 \
  --restart unless-stopped \
  openclai/openclaw:latest

# 查看日志
docker logs -f openclaw

# 停止
docker stop openclaw

# 重启
docker restart openclaw
```

### 4.4 安全加固 (Docker)

```bash
# 只允许本地访问
docker run -d \
  -p 127.0.0.1:18789:18789 \
  ...

# 网络隔离
docker network create --driver bridge openclaw-net
docker run --network openclaw-net ...

# 资源限制
docker run \
  --memory=2g \
  --cpus=1.0 \
  ...
```

---

## 五、Kubernetes 部署

### 5.1 场景描述

**适用场景**:
- 多实例部署
- 高可用需求
- 自动化运维

**特点**:
- 容器编排
- 自动扩缩容
- 滚动更新

### 5.2 K8s 配置

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw
spec:
  replicas: 1
  selector:
    matchLabels:
      app: openclaw
  template:
    metadata:
      labels:
        app: openclaw
    spec:
      containers:
      - name: openclaw
        image: openclai/openclaw:latest
        ports:
        - containerPort: 18789
        env:
        - name: OPENCLAW_AUTH_TOKEN
          valueFrom:
            secretKeyRef:
              name: openclaw-secrets
              key: token
        volumeMounts:
        - name: openclaw-config
          mountPath: /home/node/.openclaw
        resources:
          limits:
            memory: "2Gi"
            cpu: "1000m"
      volumes:
      - name: openclaw-config
        persistentVolumeClaim:
          claimName: openclaw-pvc
---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: openclaw
spec:
  selector:
    app: openclaw
  ports:
  - port: 18789
    targetPort: 18789
  # 仅集群内部访问
  type: ClusterIP
```

### 5.3 K8s 安全加固

```yaml
# 安全上下文
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000

# 网络策略
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: openclaw-network-policy
spec:
  podSelector:
    matchLabels:
      app: openclaw
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          kube-dns: ""
    ports:
    - protocol: UDP
      port: 53
```

---

## 六、桌面/笔记本部署

### 6.1 场景描述

**适用场景**:
- 个人使用
- 日常开发
- 移动办公

**特点**:
- 直接运行
- 资源充足
- 便于调试

### 6.2 配置策略

```json
{
  "environment": "development",
  "deployment": "desktop",
  
  "gateway": {
    "mode": "local",
    "bind": "127.0.0.1",
    "auth": {
      "mode": "token",
      "token": "dev-token-32chars-minimum-xxxx"
    }
  },
  
  "session": {
    "dmScope": "per-peer"
  },
  
  "tools": {
    "profile": "standard",
    "deny": ["group:automation"],
    "fs": { "workspaceOnly": true },
    "exec": { "ask": "always" }
  },
  
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main",
        "scope": "session"
      }
    }
  }
}
```

### 6.3 开发调试

```bash
# 启动开发模式
openclaw gateway --verbose

# 查看日志
openclaw logs --follow

# 调试模式
openclaw doctor
```

---

## 七、NAS 部署

### 7.1 场景描述

**适用场景**:
- 家庭使用
- 小型办公
- 7x24 运行

**特点**:
- 低功耗
- 大存储
- 长期运行

### 7.2 支持的 NAS

| NAS 类型 | 支持情况 |
|----------|----------|
| Synology | ✅ Docker 支持 |
| QNAP | ✅ Docker 支持 |
| 华硕 NAS | ✅ Docker 支持 |
| 绿联 NAS | ✅ Docker 支持 |
| 自建 NAS | ✅ 通用 |

### 7.3 配置策略

```json
{
  "environment": "production",
  "deployment": "nas",
  
  "gateway": {
    "mode": "local",
    "bind": "127.0.0.1",
    "auth": {
      "mode": "token",
      "token": "${SECURE_TOKEN}"
    }
  },
  
  "session": {
    "dmScope": "per-channel-peer"
  },
  
  "tools": {
    "profile": "messaging",
    "deny": ["group:automation", "group:runtime", "group:fs"]
  },
  
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "docker": {
          "network": "bridge"
        }
      }
    }
  }
}
```

### 7.4 NAS Docker 配置

```bash
# Synology DSM Docker
# 1. 打开 Docker 套件
# 2. 创建容器
# 3. 配置:
#    - 镜像: openclai/openclaw:latest
#    - 端口映射: 127.0.0.1:18789:18789
#    - 卷: /volume1/docker/openclaw:/home/node/.openclaw
#    - 重启策略: 除了停止
```

---

## 八、部署环境对比

### 8.1 对比表

| 部署类型 | 性能 | 隔离性 | 易用性 | 推荐场景 |
|----------|------|--------|--------|----------|
| 物理宿主机 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | 高性能生产 |
| CVM | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 云端生产 |
| Docker | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 快速部署 |
| Kubernetes | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | 多实例生产 |
| 桌面 | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ | 个人开发 |
| NAS | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | 家庭/小型 |

### 8.2 安全对比

| 部署类型 | 网络隔离 | 资源隔离 | 数据安全 |
|----------|----------|----------|----------|
| 物理宿主机 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 自行保障 |
| CVM | ⭐⭐⭐⭐ | ⭐⭐⭐ | 云盘加密 |
| Docker | ⭐⭐⭐ | ⭐⭐⭐ | 卷管理 |
| Kubernetes | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | PVC 加密 |
| 桌面 | ⭐⭐ | ⭐⭐ | 本地加密 |
| NAS | ⭐⭐ | ⭐⭐ | RAID/加密 |

---

## 九、完整环境矩阵

### 9.1 用途 × 部署

| | 测试 | 开发 | 生产 |
|---|------|------|------|
| **物理宿主机** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **CVM** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Docker** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Kubernetes** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **桌面** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐ |
| **NAS** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |

---

## 十、快速部署模板

### 10.1 Docker 通用

```bash
# 通用 Docker 启动
docker run -d \
  --name openclaw \
  -v ~/.openclaw:/home/node/.openclaw \
  -p 127.0.0.1:18789:18789 \
  --restart unless-stopped \
  openclai/openclaw:latest
```

### 10.2 生产环境 (CVM)

```bash
# 生产环境启动
docker run -d \
  --name openclaw-prod \
  -v /data/openclaw:/home/node/.openclaw \
  -p 127.0.0.1:18789:18789 \
  --memory=2g \
  --cpus=1 \
  --restart unless-stopped \
  openclai/openclaw:latest
```

### 10.3 开发环境 (桌面)

```bash
# 开发环境启动
docker run -d \
  --name openclaw-dev \
  -v ~/openclaw:/home/node/.openclaw \
  -p 127.0.0.1:18789:18789 \
  --restart on-failure \
  openclai/openclaw:latest
```

---

## 十一、配置模板

### 11.1 配置文件结构

```
~/.openclaw/
├── openclaw.json           # 当前配置
├── config/
│   ├── test-dev.json      # 测试开发
│   ├── test-prod.json     # 测试生产
│   ├── dev-desktop.json   # 桌面开发
│   ├── dev-nas.json       # NAS 开发
│   ├── prod-cvm.json      # CVM 生产
│   ├── prod-baremetal.json # 物理机生产
│   └── prod-k8s.json      # K8s 生产
└── backups/
```

### 11.2 环境切换

```bash
# 切换到 CVM 生产环境
cp config/prod-cvm.json ~/.openclaw/openclaw.json

# 切换到桌面开发环境
cp config/dev-desktop.json ~/.openclaw/openclaw.json

# 切换到 NAS 生产环境
cp config/prod-nas.json ~/.openclaw/openclaw.json
```

---

*文档版本: 2.0*
*更新: 2026-02-28*
