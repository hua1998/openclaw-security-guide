#!/usr/bin/env python3
"""
OpenClaw 配置变更监控脚本
实时监控配置文件变化

功能:
- 监控配置文件变更
- 检测危险配置
- 记录变更历史
- 告警通知

用法:
    python config_watcher.py              # 启动监控
    python config_watcher.py --check      # 单次检查
    python config_watcher.py --history   # 查看历史
    python config_watcher.py --watch      # 持续监控
"""

import json
import os
import sys
import time
import hashlib
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 颜色定义
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

def log_info(msg):
    print(f"{GREEN}[INFO]{RESET} {msg}")

def log_warn(msg):
    print(f"{YELLOW}[WARN]{RESET} {msg}")

def log_error(msg):
    print(f"{RED}[ERROR]{RESET} {msg}")

def log_alert(msg):
    print(f"{RED}[ALERT]{RESET} {msg}")

def get_config_path():
    """获取配置文件路径"""
    home = os.path.expanduser("~")
    return os.path.join(home, ".openclaw", "openclaw.json")

def get_history_path():
    """获取历史记录路径"""
    home = os.path.expanduser("~")
    return os.path.join(home, ".openclaw", "config_history")

# 危险配置规则
DANGEROUS_RULES = [
    {
        "path": "gateway.bind",
        "dangerous_value": "0.0.0.0",
        "severity": "critical",
        "message": "Gateway 绑定到所有地址，存在安全风险"
    },
    {
        "path": "gateway.tailscale.mode",
        "dangerous_value": "funnel",
        "severity": "critical",
        "message": "Tailscale Funnel 暴露公网"
    },
    {
        "path": "tools.exec.security",
        "dangerous_value": "allow",
        "severity": "critical",
        "message": "允许执行任意命令"
    },
    {
        "path": "tools.elevated.enabled",
        "dangerous_value": True,
        "severity": "high",
        "message": "启用 Elevated 工具"
    },
    {
        "path": "tools.fs.workspaceOnly",
        "dangerous_value": False,
        "severity": "high",
        "message": "文件系统未限制工作区"
    },
    {
        "path": "agents.defaults.sandbox.mode",
        "dangerous_value": "off",
        "severity": "high",
        "message": "未启用沙箱隔离"
    },
    {
        "path": "agents.defaults.sandbox.docker.network",
        "dangerous_value": "host",
        "severity": "critical",
        "message": "沙箱使用主机网络"
    },
    {
        "path": "gateway.auth.mode",
        "dangerous_value": "none",
        "severity": "critical",
        "message": "未启用认证"
    }
]

def compute_hash(content):
    """计算文件哈希"""
    return hashlib.sha256(content.encode()).hexdigest()[:16]

def load_config():
    """加载配置文件"""
    config_path = get_config_path()
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log_error(f"加载配置失败: {e}")
        return None

def get_nested_value(d, path, default=None):
    """获取嵌套值"""
    keys = path.split('.')
    value = d
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key, default)
        else:
            return default
    return value

def check_dangerous_config(config):
    """检查危险配置"""
    alerts = []
    
    for rule in DANGEROUS_RULES:
        value = get_nested_value(config, rule["path"])
        
        # 检查精确匹配或存在性
        if rule.get("dangerous_value") is not None:
            if value == rule["dangerous_value"]:
                alerts.append({
                    "path": rule["path"],
                    "value": value,
                    "severity": rule["severity"],
                    "message": rule["message"]
                })
        elif rule.get("check_exists"):
            # 只检查是否存在
            if value is not None:
                alerts.append({
                    "path": rule["path"],
                    "value": value,
                    "severity": rule["severity"],
                    "message": rule["message"]
                })
    
    return alerts

def save_history(action, config_hash, details=None):
    """保存历史记录"""
    history_path = get_history_path()
    os.makedirs(history_path, exist_ok=True)
    
    history_file = os.path.join(history_path, "history.json")
    
    # 读取现有历史
    try:
        with open(history_file, 'r', encoding='utf-8') as f:
            history = json.load(f)
    except:
        history = []
    
    # 添加新记录
    record = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "config_hash": config_hash,
        "details": details or {}
    }
    
    history.append(record)
    
    # 只保留最近 100 条
    history = history[-100:]
    
    # 保存
    with open(history_file, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2, ensure_ascii=False)

def show_history():
    """显示历史记录"""
    history_file = os.path.join(get_history_path(), "history.json")
    
    try:
        with open(history_file, 'r', encoding='utf-8') as f:
            history = json.load(f)
    except:
        log_error("没有历史记录")
        return
    
    print("\n" + "="*70)
    print(f"{'时间':<25} {'操作':<15} {'哈希':<20}")
    print("="*70)
    
    for record in reversed(history[-20:]):
        print(f"{record['timestamp']:<25} {record['action']:<15} {record['config_hash']:<20}")
    
    print("="*70)

def single_check():
    """单次检查"""
    config_path = get_config_path()
    
    if not os.path.exists(config_path):
        log_error(f"配置文件不存在: {config_path}")
        return
    
    log_info(f"检查配置: {config_path}")
    
    # 读取配置
    with open(config_path, 'r', encoding='utf-8') as f:
        config_content = f.read()
        config = json.loads(config_content)
    
    config_hash = compute_hash(config_content)
    log_info(f"配置哈希: {config_hash}")
    
    # 检查危险配置
    alerts = check_dangerous_config(config)
    
    if alerts:
        log_warn(f"发现 {len(alerts)} 个危险配置:")
        print()
        
        for alert in alerts:
            severity_color = RED if alert["severity"] == "critical" else YELLOW
            print(f"  {severity_color}[{alert['severity'].upper()}]{RESET} {alert['path']}")
            print(f"    当前值: {alert['value']}")
            print(f"    {alert['message']}")
            print()
    else:
        log_info("未发现危险配置")
    
    # 保存历史
    save_history("check", config_hash, {"alerts": len(alerts)})
    
    return len(alerts) == 0

class ConfigFileHandler(FileSystemEventHandler):
    """配置文件变更处理器"""
    
    def __init__(self, callback=None):
        self.callback = callback
        self.last_modified = None
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        if event.src_path.endswith("openclaw.json"):
            log_info(f"配置文件变更: {event.src_path}")
            self.handle_change()
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        if event.src_path.endswith("openclaw.json"):
            log_info(f"配置文件创建: {event.src_path}")
            self.handle_change()
    
    def handle_change(self):
        """处理变更"""
        time.sleep(0.5)  # 等待文件稳定
        
        config_path = get_config_path()
        
        if not os.path.exists(config_path):
            return
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_content = f.read()
                config = json.loads(config_content)
            
            config_hash = compute_hash(config_content)
            
            # 检查危险配置
            alerts = check_dangerous_config(config)
            
            if alerts:
                log_alert("警告: 检测到危险配置!")
                for alert in alerts:
                    print(f"  {RED}[{alert['severity'].upper()}]{RESET} {alert['message']}")
            
            # 保存历史
            save_history("modified", config_hash, {"alerts": len(alerts)})
            
            # 回调
            if self.callback:
                self.callback(config, alerts)
                
        except Exception as e:
            log_error(f"处理变更失败: {e}")

def start_watching(callback=None):
    """启动监控"""
    config_path = get_config_path()
    config_dir = os.path.dirname(config_path)
    
    log_info(f"启动配置监控: {config_dir}")
    
    # 确保目录存在
    os.makedirs(config_dir, exist_ok=True)
    
    # 创建观察者
    event_handler = ConfigFileHandler(callback)
    observer = Observer()
    observer.schedule(event_handler, config_dir, recursive=False)
    observer.start()
    
    log_info("监控中... (按 Ctrl+C 停止)")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_info("停止监控")
        observer.stop()
    
    observer.join()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="OpenClaw 配置变更监控",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python config_watcher.py --check      # 单次检查
    python config_watcher.py --watch      # 持续监控
    python config_watcher.py --history     # 查看历史
        """
    )
    
    parser.add_argument("--check", action="store_true", help="单次检查配置")
    parser.add_argument("--watch", action="store_true", help="持续监控配置")
    parser.add_argument("--history", action="store_true", help="查看变更历史")
    
    args = parser.parse_args()
    
    if args.check:
        single_check()
    elif args.watch:
        start_watching()
    elif args.history:
        show_history()
    else:
        # 默认单次检查
        single_check()

if __name__ == "__main__":
    main()
