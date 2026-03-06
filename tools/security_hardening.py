#!/usr/bin/env python3
"""
OpenClaw 安全加固脚本
自动执行安全加固配置

功能:
- 一键加固配置
- 分步加固
- 验证加固结果
- 回滚支持

用法:
    python security_hardening.py              # 交互模式
    python security_hardening.py --full       # 完全加固
    python security_hardening.py --step 1     # 第一步
    python security_hardening.py --verify     # 验证
    python security_hardening.py --rollback   # 回滚
"""

import json
import os
import sys
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

# 颜色定义
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'

def log_info(msg):
    print(f"{GREEN}[INFO]{RESET} {msg}")

def log_warn(msg):
    print(f"{YELLOW}[WARN]{RESET} {msg}")

def log_error(msg):
    print(f"{RED}[ERROR]{RESET} {msg}")

def log_step(msg):
    print(f"{BLUE}[STEP]{RESET} {msg}")

def get_config_path():
    """获取配置文件路径"""
    home = os.path.expanduser("~")
    return os.path.join(home, ".openclaw", "openclaw.json")

def backup_config():
    """备份当前配置"""
    config_path = get_config_path()
    if not os.path.exists(config_path):
        log_error(f"配置文件不存在: {config_path}")
        return False
    
    backup_path = f"{config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(config_path, backup_path)
    log_info(f"配置已备份: {backup_path}")
    return True

def load_config():
    """加载配置文件"""
    config_path = get_config_path()
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log_error(f"加载配置失败: {e}")
        return {}

def save_config(config):
    """保存配置文件"""
    config_path = get_config_path()
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        log_info(f"配置已保存")
        return True
    except Exception as e:
        log_error(f"保存配置失败: {e}")
        return False

def run_openclaw_command(cmd):
    """运行 OpenClaw 命令"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=30
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

# 加固步骤定义
HARDENING_STEPS = [
    {
        "id": 1,
        "name": "认证配置",
        "config": {
            "gateway": {
                "auth": {
                    "mode": "token"
                }
            }
        },
        "description": "启用 Token 认证模式",
        "impact": "无实际影响"
    },
    {
        "id": 2,
        "name": "会话隔离",
        "config": {
            "session": {
                "dmScope": "per-channel-peer"
            }
        },
        "description": "配置会话按频道和用户隔离",
        "impact": "多用户场景下会话分离"
    },
    {
        "id": 3,
        "name": "工具 Profile",
        "config": {
            "tools": {
                "profile": "messaging"
            }
        },
        "description": "设置最小工具集",
        "impact": "部分工具被禁用"
    },
    {
        "id": 4,
        "name": "工具禁用规则",
        "config": {
            "tools": {
                "deny": [
                    "group:automation",
                    "group:runtime",
                    "group:fs"
                ]
            }
        },
        "description": "禁用危险工具组",
        "impact": "自动化和运行时工具被禁用"
    },
    {
        "id": 5,
        "name": "文件系统限制",
        "config": {
            "tools": {
                "fs": {
                    "workspaceOnly": True
                }
            }
        },
        "description": "限制文件访问在工作区",
        "impact": "无法访问系统文件"
    },
    {
        "id": 6,
        "name": "执行确认",
        "config": {
            "tools": {
                "exec": {
                    "ask": "always"
                }
            }
        },
        "description": "执行前需要确认",
        "impact": "命令执行需要确认"
    },
    {
        "id": 7,
        "name": "沙箱模式",
        "config": {
            "agents": {
                "defaults": {
                    "sandbox": {
                        "mode": "non-main"
                    }
                }
            }
        },
        "description": "启用沙箱隔离",
        "impact": "需要 Docker 支持"
    },
    {
        "id": 8,
        "name": "沙箱网络",
        "config": {
            "agents": {
                "defaults": {
                    "sandbox": {
                        "docker": {
                            "network": "none"
                        }
                    }
                }
            }
        },
        "description": "隔离沙箱网络",
        "impact": "沙箱无法访问网络"
    },
    {
        "id": 9,
        "name": "网络绑定",
        "config": {
            "gateway": {
                "bind": "loopback"
            }
        },
        "description": "绑定到本地",
        "impact": "远程访问需要 Tailscale"
    },
    {
        "id": 10,
        "name": "禁用 Elevated",
        "config": {
            "tools": {
                "elevated": {
                    "enabled": False
                }
            }
        },
        "description": "禁用提权工具",
        "impact": "无法使用提权功能"
    }
]

def apply_step(step):
    """应用单个加固步骤"""
    config = load_config()
    
    # 深度合并配置
    def deep_merge(base, updates):
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                deep_merge(base[key], value)
            else:
                base[key] = value
        return base
    
    config = deep_merge(config, step["config"])
    
    if save_config(config):
        log_step(f"步骤 {step['id']}: {step['name']} - 已应用")
        return True
    return False

def apply_full_hardening():
    """执行完全加固"""
    log_info("开始完全加固...")
    
    # 备份
    if not backup_config():
        return False
    
    # 应用所有步骤
    for i, step in enumerate(HARDENING_STEPS):
        log_step(f"应用步骤 {i+1}/{len(HARDENING_STEPS)}: {step['name']}")
        apply_step(step)
    
    log_info("加固完成!")
    log_info("请运行 --verify 验证结果")
    return True

def apply_step_by_step(step_num):
    """分步加固"""
    if step_num < 1 or step_num > len(HARDENING_STEPS):
        log_error(f"步骤编号无效: 1-{len(HARDENING_STEPS)}")
        return False
    
    # 备份
    backup_config()
    
    step = HARDENING_STEPS[step_num - 1]
    log_step(f"步骤 {step['id']}: {step['name']}")
    log_info(f"描述: {step['description']}")
    log_warn(f"影响: {step['impact']}")
    
    confirm = input(f"\n确认应用此步骤? (y/n): ")
    if confirm.lower() != 'y':
        log_info("已取消")
        return False
    
    return apply_step(step)

def verify_hardening():
    """验证加固结果"""
    log_info("验证加固结果...")
    
    config = load_config()
    results = []
    
    # 检查项
    checks = [
        ("gateway.auth.mode", "token", "认证模式"),
        ("session.dmScope", "per-channel-peer", "会话隔离"),
        ("tools.profile", "messaging", "工具 Profile"),
        ("tools.fs.workspaceOnly", True, "文件系统限制"),
        ("tools.exec.ask", "always", "执行确认"),
        ("agents.defaults.sandbox.mode", "non-main", "沙箱模式"),
        ("gateway.bind", "loopback", "网络绑定"),
        ("tools.elevated.enabled", False, "禁用 Elevated"),
    ]
    
    def get_nested_value(d, path):
        keys = path.split('.')
        value = d
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    for path, expected, name in checks:
        actual = get_nested_value(config, path)
        status = "OK" if actual == expected else "FAIL"
        results.append((name, status, expected, actual))
    
    # 显示结果
    print("\n" + "="*60)
    print(f"{'检查项':<20} {'状态':<10} {'期望':<15} {'实际':<15}")
    print("="*60)
    
    for name, status, expected, actual in results:
        color = GREEN if status == "OK" else RED
        print(f"{name:<20} {color}{status:<10}{RESET} {str(expected):<15} {str(actual):<15}")
    
    print("="*60)
    
    ok_count = sum(1 for _, s, _, _ in results if s == "OK")
    total = len(results)
    score = int(ok_count / total * 100)
    
    log_info(f"合规评分: {score}%")
    
    return score

def rollback():
    """回滚到备份"""
    config_path = get_config_path()
    backup_dir = os.path.dirname(config_path)
    
    # 查找最新备份
    backups = sorted(Path(backup_dir).glob("openclaw.json.backup.*"))
    if not backups:
        log_error("没有找到备份文件")
        return False
    
    latest = backups[-1]
    log_info(f"使用备份: {latest}")
    
    confirm = input(f"确认回滚? (y/n): ")
    if confirm.lower() != 'y':
        log_info("已取消")
        return False
    
    shutil.copy2(latest, config_path)
    log_info("已回滚")
    return True

def show_steps():
    """显示所有加固步骤"""
    print("\n" + "="*60)
    print("加固步骤列表")
    print("="*60)
    
    for step in HARDENING_STEPS:
        print(f"\n步骤 {step['id']}: {step['name']}")
        print(f"  描述: {step['description']}")
        print(f"  影响: {step['impact']}")
    
    print("\n" + "="*60)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="OpenClaw 安全加固脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python security_hardening.py              # 交互模式
    python security_hardening.py --full       # 完全加固
    python security_hardening.py --step 1     # 第一步
    python security_hardening.py --verify     # 验证
    python security_hardening.py --rollback   # 回滚
    python security_hardening.py --list       # 显示步骤
        """
    )
    
    parser.add_argument("--full", action="store_true", help="执行完全加固")
    parser.add_argument("--step", type=int, help="执行指定步骤")
    parser.add_argument("--verify", action="store_true", help="验证加固结果")
    parser.add_argument("--rollback", action="store_true", help="回滚配置")
    parser.add_argument("--list", action="store_true", help="显示加固步骤")
    
    args = parser.parse_args()
    
    if args.list:
        show_steps()
    elif args.full:
        apply_full_hardening()
    elif args.step:
        apply_step_by_step(args.step)
    elif args.verify:
        verify_hardening()
    elif args.rollback:
        rollback()
    else:
        # 交互模式
        print("""
OpenClaw 安全加固脚本
======================

请选择操作:
1. 完全加固
2. 分步加固
3. 验证结果
4. 回滚
5. 显示步骤
0. 退出
""")
        choice = input("选择: ")
        
        if choice == "1":
            apply_full_hardening()
        elif choice == "2":
            show_steps()
            step = input("选择步骤编号: ")
            try:
                apply_step_by_step(int(step))
            except:
                log_error("无效步骤")
        elif choice == "3":
            verify_hardening()
        elif choice == "4":
            rollback()
        elif choice == "5":
            show_steps()

if __name__ == "__main__":
    main()
