# OpenClaw Security Tools

> OpenClaw 安全治理工具集
> 
> 版本: v1.0.0
> 状态: 可用

---

## 工具列表

### 1. security_audit.py

安全审计工具 - 检查 OpenClaw 配置安全性

```bash
python security_audit.py --config ~/.openclaw/openclaw.json
```

### 2. token_generator.py

Token 生成器 - 生成符合规范的随机 Token

```bash
python token_generator.py --length 32
```

### 3. config_baseline.py

配置基线检查 - 对比当前配置与安全基线

```bash
python config_baseline.py --config ~/.openclaw/openclaw.json
```

### 4. config_watcher.py

配置变更监控 - 监控配置文件变更

```bash
python config_watcher.py --config ~/.openclaw/openclaw.json
```

---

## 安装

```bash
pip install -r requirements.txt
```

## 使用

详见各工具的 --help 输出
