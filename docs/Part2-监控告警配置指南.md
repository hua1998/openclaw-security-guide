# Part 2 监控告警配置指南

> **版本**: v3.0  
> **创建日期**: 2026-02-26  
> **用**: 监控告警配置完整指南，复制粘贴即可用  

---

## 一、快速开*(1 小时完成)

### 步骤 1: 配置监控指标 (10 分钟)

创建文件：`config/monitoring.yaml`

```yaml
metrics:
  # 安全指标
  security_incidents:
    enabled: true
    target: 0
    alert_threshold: 1
  
  audit_log_completeness:
    enabled: true
    target: 100%
    alert_threshold: 95%
  
  # 效率指标
  auto_approval_rate:
    enabled: true
    target: 70%
    alert_threshold: 50%
  
  # 响应指标
  avg_response_time:
    enabled: true
    target: 10m
    alert_threshold: 30m
```

### 步骤 2: 配置告警通知 (10 分钟)

创建文件：`config/alerts.yaml`

```yaml
notifications:
  feishu:
    enabled: true
    webhook: "https://open.feishu.cn/open-apis/bot/v2/hook/YOUR_WEBHOOK"
  
  email:
    enabled: true
    smtp_server: "smtp.example.com"
    recipients:
      - "security@example.com"

alerts:
  - name: 安全事件
    condition: security_incidents > 0
    notify: [feishu, email]
    severity: P0
```

### 步骤 3: 启动监控 (30 分钟)

```bash
# 启动监控服务
openclaw monitoring start

# 验证监控状*openclaw monitoring status

# 访问监控仪表*openclaw dashboard open
# http://localhost:8080/dashboard
```

### 步骤 4: 测试告警 (10 分钟)

```bash
# 发送测试告*openclaw alert test

# 验证：飞书收到告警消*```

---

## 二、监控指标详*
### 2.1 核心指标

| 指标 | 说明 | 目标*| 告警阈*|
|------|------|--------|----------|
| security_incidents | 安全事件*| 0 | >0 |
| auto_approval_rate | 自动审批*| >70% | <50% |
| avg_response_time | 平均响应时间 | <10m | >30m |
| audit_log_completeness | 审计日志完整*| 100% | <95% |

### 2.2 指标采集

```yaml
collection:
  interval: 1m  # 采集频率
  retention: 90d  # 数据保留
  aggregation:
    - avg
    - max
    - min
    - sum
```

---

## 三、告警配置详*
### 3.1 告警级别

| 级别 | 说明 | 通知方式 | 响应时间 |
|------|------|----------|----------|
| **P0** | 紧*| 飞书 + 短信 + 电话 | <5 分钟 |
| **P1** | *| 飞书 + 邮件 | <30 分钟 |
| **P2** | *| 飞书 | <2 小时 |
| **P3** | *| 邮件 | <24 小时 |

### 3.2 告警规则

```yaml
alert_rules:
  # P0 规则
  p0_rules:
    - name: 安全事件
      condition: security_incidents > 0
      severity: P0
    
    - name: 系统不可*      condition: system_availability < 99%
      severity: P0
  
  # P1 规则
  p1_rules:
    - name: 审批超时
      condition: pending_approval > 30m
      severity: P1
    
    - name: 自动审批率低
      condition: auto_approval_rate < 50%
      severity: P1
```

---

## 四、监控仪表板

### 4.1 预置仪表*
**访问**: http://localhost:8080/dashboard

**包含页面**:
1. **概览**: 核心指标总览
2. **审批**: 审批统计和趋*3. **安全**: 安全事件和告*4. **系统**: 资源使用和性能

### 4.2 自定义仪表板

```yaml
dashboard:
  title: "OpenClaw 监控"
  refresh: 1m
  panels:
    - title: "安全事件趋势"
      type: line
      metrics: [security_incidents]
      time_range: 24h
    
    - title: "审批统计"
      type: pie
      metrics: [approval_status]
    
    - title: "核心指标"
      type: stat
      metrics: [auto_approval_rate, avg_response_time]
```

---

## 五、故障排*
### 5.1 监控不工*
```bash
# 检查监控服务状*openclaw monitoring status

# 查看监控日志
openclaw logs monitoring

# 重启监控服务
openclaw monitoring restart
```

### 5.2 告警不发*
```bash
# 检查告警配*openclaw config check alerts

# 测试告警
openclaw alert test

# 查看告警历史
openclaw alert history
```

---

*Part 2 监控告警配置指南 v1.0*  
*创建*026-02-26*
