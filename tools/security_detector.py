#!/usr/bin/env python3
"""
OpenClaw 安全检测器 - 完整版
整合 v2.0 研究检测逻辑

用法:
    python security_detector.py --config ~/.openclaw/openclaw.json
    python security_detector.py --config ~/.openclaw/openclaw.json --json
    python security_detector.py --config ~/.openclaw/openclaw.json --baseline
"""

import json
import sys
import argparse
from pathlib import Path


def load_config(config_path):
    """加载配置文件"""
    path = Path(config_path).expanduser()
    if not path.exists():
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}")
        sys.exit(1)


def check_auth(config):
    """认证检测"""
    issues = []
    
    # Token 认证
    auth = config.get("gateway", {}).get("auth", {})
    if auth.get("mode") != "token":
        issues.append({
            "risk": "critical",
            "category": "authentication",
            "check": "gateway.auth.mode",
            "expected": "token",
            "actual": auth.get("mode", "not set"),
            "description": "未启用 Token 认证"
        })
    
    # Token 强度
    token = auth.get("token", "")
    if len(token) < 32:
        issues.append({
            "risk": "high",
            "category": "authentication",
            "check": "gateway.auth.token.length",
            "expected": ">=32",
            "actual": len(token),
            "description": "Token 长度不足"
        })
    
    return issues


def check_session(config):
    """会话检测"""
    issues = []
    
    dm_scope = config.get("session", {}).get("dmScope", "global")
    if dm_scope == "global":
        issues.append({
            "risk": "high",
            "category": "session",
            "check": "session.dmScope",
            "expected": "per-channel-peer or per-account-channel-peer",
            "actual": dm_scope,
            "description": "DM 会话未隔离"
        })
    
    return issues


def check_tools(config):
    """工具检测"""
    issues = []
    tools = config.get("tools", {})
    
    # profile
    if tools.get("profile") not in ["minimal", "messaging"]:
        issues.append({
            "risk": "medium",
            "category": "tools",
            "check": "tools.profile",
            "expected": "minimal or messaging",
            "actual": tools.get("profile", "not set"),
            "description": "工具 profile 过于宽松"
        })
    
    # deny 规则
    deny = tools.get("deny", [])
    required_deny = ["group:automation", "group:runtime"]
    for item in required_deny:
        if item not in deny:
            issues.append({
                "risk": "high",
                "category": "tools",
                "check": "tools.deny",
                "expected": f"包含 {item}",
                "actual": deny,
                "description": f"未禁用 {item}"
            })
    
    # fs 限制
    fs = tools.get("fs", {})
    if not fs.get("workspaceOnly"):
        issues.append({
            "risk": "high",
            "category": "tools",
            "check": "tools.fs.workspaceOnly",
            "expected": True,
            "actual": False,
            "description": "文件系统工具未限制工作区"
        })
    
    # exec 控制
    exec = tools.get("exec", {})
    if exec.get("security") != "deny":
        issues.append({
            "risk": "critical",
            "category": "tools",
            "check": "tools.exec.security",
            "expected": "deny",
            "actual": exec.get("security", "not set"),
            "description": "未禁用 exec 直接执行"
        })
    
    if exec.get("ask") != "always":
        issues.append({
            "risk": "high",
            "category": "tools",
            "check": "tools.exec.ask",
            "expected": "always",
            "actual": exec.get("ask", "not set"),
            "description": "exec 未设置始终询问"
        })
    
    # elevated
    elevated = tools.get("elevated", {})
    if elevated.get("enabled") != False:
        issues.append({
            "risk": "critical",
            "category": "tools",
            "check": "tools.elevated.enabled",
            "expected": False,
            "actual": elevated.get("enabled"),
            "description": "未禁用 elevated 工具"
        })
    
    return issues


def check_network(config):
    """网络检测"""
    issues = []
    
    gateway = config.get("gateway", {})
    
    # bind
    if gateway.get("bind") != "loopback":
        issues.append({
            "risk": "critical",
            "category": "network",
            "check": "gateway.bind",
            "expected": "loopback",
            "actual": gateway.get("bind", "not set"),
            "description": "Gateway 未绑定本地"
        })
    
    return issues


def check_sandbox(config):
    """沙箱检测"""
    issues = []
    
    sandbox = config.get("agents", {}).get("defaults", {}).get("sandbox", {})
    mode = sandbox.get("mode", "off")
    
    if mode == "off":
        issues.append({
            "risk": "high",
            "category": "sandbox",
            "check": "agents.defaults.sandbox.mode",
            "expected": "non-main or all",
            "actual": mode,
            "description": "未启用沙箱隔离"
        })
    
    # scope 检测
    scope = sandbox.get("scope", "session")
    if scope not in ["session", "agent"]:
        issues.append({
            "risk": "medium",
            "category": "sandbox",
            "check": "agents.defaults.sandbox.scope",
            "expected": "session or agent",
            "actual": scope,
            "description": "沙箱 scope 建议使用 session 或 agent"
        })
    
    # workspaceAccess 检测
    workspace_access = sandbox.get("workspaceAccess", "none")
    if workspace_access == "rw":
        issues.append({
            "risk": "medium",
            "category": "sandbox",
            "check": "agents.defaults.sandbox.workspaceAccess",
            "expected": "none or ro",
            "actual": workspace_access,
            "description": "沙箱工作区建议设置为只读"
        })
    
    # network 检测
    network = sandbox.get("docker", {}).get("network", "none")
    if network == "host":
        issues.append({
            "risk": "critical",
            "category": "sandbox",
            "check": "agents.defaults.sandbox.docker.network",
            "expected": "none or bridge",
            "actual": network,
            "description": "禁止使用 host 网络模式"
        })
    
    return issues


def check_channels(config):
    """频道检测"""
    issues = []
    
    channels = config.get("channels", {})
    
    for channel_name, channel_config in channels.items():
        # DM policy
        dm_policy = channel_config.get("dmPolicy", "pairing")
        if dm_policy == "open":
            issues.append({
                "risk": "high",
                "category": "channels",
                "check": f"channels.{channel_name}.dmPolicy",
                "expected": "pairing or allowlist",
                "actual": dm_policy,
                "description": f"{channel_name} DM 策略过于宽松"
            })
        
        # Group policy
        groups = channel_config.get("groups", {})
        for group_name, group_config in groups.items():
            if not group_config.get("requireMention", False):
                issues.append({
                    "risk": "medium",
                    "category": "channels",
                    "check": f"channels.{channel_name}.groups.{group_name}.requireMention",
                    "expected": True,
                    "actual": False,
                    "description": f"{channel_name} 群组未设置 requireMention"
                })
    
    return issues


def calculate_risk_score(issues):
    """计算风险评分"""
    risk_weights = {
        "critical": 10,
        "high": 5,
        "medium": 2,
        "low": 1
    }
    
    total = sum(risk_weights.get(i["risk"], 2) for i in issues)
    compliance = max(0, 100 - total)
    
    return {
        "total_issues": len(issues),
        "risk_score": total,
        "compliance_percentage": round(compliance, 1),
        "risk_level": "critical" if total >= 30 else "high" if total >= 15 else "medium" if total >= 5 else "low",
        "grade": "A" if compliance >= 90 else "B" if compliance >= 70 else "C" if compliance >= 50 else "D"
    }


def check_all(config):
    """执行所有检查"""
    all_issues = []
    all_issues.extend(check_auth(config))
    all_issues.extend(check_session(config))
    all_issues.extend(check_tools(config))
    all_issues.extend(check_network(config))
    all_issues.extend(check_sandbox(config))
    all_issues.extend(check_channels(config))
    return all_issues


def print_results(issues, risk_info, json_output=False):
    """输出结果"""
    if json_output:
        print(json.dumps({
            "results": issues,
            "risk_info": risk_info
        }, indent=2, ensure_ascii=False))
        return
    
    print("=" * 60)
    print("OpenClaw Security Detector")
    print("=" * 60)
    
    print(f"\nRisk Level: {risk_info['risk_level'].upper()}")
    print(f"Grade: {risk_info['grade']}")
    print(f"Compliance: {risk_info['compliance_percentage']}%")
    print(f"Total Issues: {risk_info['total_issues']}")
    
    if not issues:
        print("\n[PASS] No security issues found!")
        return
    
    print("\n" + "=" * 60)
    print("Issues")
    print("=" * 60)
    
    # Sort by risk
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    issues.sort(key=lambda x: order.get(x.get("risk", "medium"), 4))
    
    for i, issue in enumerate(issues, 1):
        risk = issue.get("risk", "medium")
        icon = {"critical": "[X]", "high": "[!]", "medium": "[~]", "low": "[o]"}.get(risk, "[?]")
        
        print(f"\n{i}. {icon} [{risk.upper()}] {issue['category']}")
        print(f"   Check: {issue['check']}")
        print(f"   Expected: {issue['expected']}")
        print(f"   Actual: {issue['actual']}")
        print(f"   {issue['description']}")


def main():
    parser = argparse.ArgumentParser(description="OpenClaw Security Detector")
    parser.add_argument("--config", "-c", default="~/.openclaw/openclaw.json", help="Config file path")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    parser.add_argument("--baseline", "-b", action="store_true", help="Show baseline config")
    
    args = parser.parse_args()
    
    if args.baseline:
        baseline = {
            "gateway": {
                "mode": "local",
                "bind": "loopback",
                "auth": {"mode": "token", "token": "YOUR_TOKEN_HERE"}
            },
            "session": {"dmScope": "per-channel-peer"},
            "tools": {
                "profile": "messaging",
                "deny": ["group:automation", "group:runtime"],
                "fs": {"workspaceOnly": True},
                "exec": {"security": "deny", "ask": "always"},
                "elevated": {"enabled": False}
            },
            "agents": {
                "defaults": {
                    "sandbox": {"mode": "non-main", "scope": "agent"}
                }
            }
        }
        print(json.dumps(baseline, indent=2))
        return
    
    config = load_config(args.config)
    issues = check_all(config)
    risk_info = calculate_risk_score(issues)
    print_results(issues, risk_info, args.json)


if __name__ == "__main__":
    main()
