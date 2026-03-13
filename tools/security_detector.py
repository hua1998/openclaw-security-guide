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


def check_supply_chain(config):
    """供应链安全检测（针对智能办公场景）"""
    issues = []
    
    # 插件管理
    plugins = config.get("plugins", {})
    entries = plugins.get("entries", {})
    
    # 检查插件来源
    for plugin_name, plugin_config in entries.items():
        if isinstance(plugin_config, dict):
            source = plugin_config.get("source", "")
            if "github.com" in source and not source.startswith("https://github.com/openclaw-security/"):
                issues.append({
                    "risk": "medium",
                    "category": "supply_chain",
                    "check": f"plugins.entries.{plugin_name}.source",
                    "expected": "官方插件或可信来源",
                    "actual": source,
                    "description": f"插件 {plugin_name} 来源非官方，存在供应链风险"
                })
    
    # 技能包检查
    skills = config.get("skills", {})
    allow = skills.get("allow", [])
    if not allow:
        issues.append({
            "risk": "high",
            "category": "supply_chain",
            "check": "skills.allow",
            "expected": "明确允许的技能包列表",
            "actual": "空",
            "description": "未设置技能包白名单，可能引入恶意技能包"
        })
    
    return issues


def check_internet_exposure(config):
    """互联网暴露检测"""
    issues = []
    
    # 网络配置
    network = config.get("network", {})
    allow_external = network.get("allow_external", False)
    
    if allow_external:
        issues.append({
            "risk": "critical",
            "category": "network",
            "check": "network.allow_external",
            "expected": False,
            "actual": True,
            "description": "允许外部网络访问，存在互联网暴露风险"
        })
    
    # 网关绑定
    gateway = config.get("gateway", {})
    bind = gateway.get("bind", "")
    if bind and bind not in ["loopback", "127.0.0.1"]:
        issues.append({
            "risk": "critical",
            "category": "network",
            "check": "gateway.bind",
            "expected": "loopback 或 127.0.0.1",
            "actual": bind,
            "description": "网关绑定到非本地地址，存在互联网暴露风险"
        })
    
    return issues


def check_privilege(config):
    """权限控制检测（最小权限原则）"""
    issues = []
    
    # 执行权限
    exec_config = config.get("tools", {}).get("exec", {})
    if exec_config.get("security") != "deny":
        issues.append({
            "risk": "critical",
            "category": "privilege",
            "check": "tools.exec.security",
            "expected": "deny",
            "actual": exec_config.get("security", "not set"),
            "description": "未禁用直接执行命令，权限过大"
        })
    
    # 工作区访问
    sandbox = config.get("agents", {}).get("defaults", {}).get("sandbox", {})
    workspace_access = sandbox.get("workspaceAccess", "none")
    if workspace_access == "rw":
        issues.append({
            "risk": "medium",
            "category": "privilege",
            "check": "agents.defaults.sandbox.workspaceAccess",
            "expected": "none or ro",
            "actual": workspace_access,
            "description": "沙箱工作区权限过大，建议只读"
        })
    
    return issues


def check_social_engineering(config):
    """社会工程学攻击防范检测"""
    issues = []
    
    # 提示词安全
    prompt_security = config.get("security", {}).get("prompt_security", {})
    injection_detection = prompt_security.get("injection_detection", False)
    
    if not injection_detection:
        issues.append({
            "risk": "high",
            "category": "social_engineering",
            "check": "security.prompt_security.injection_detection",
            "expected": True,
            "actual": False,
            "description": "未启用提示词注入检测，易受社会工程学攻击"
        })
    
    # 浏览器安全
    browser = config.get("browser", {})
    sandbox_enabled = browser.get("sandbox", False)
    
    if not sandbox_enabled:
        issues.append({
            "risk": "medium",
            "category": "social_engineering",
            "check": "browser.sandbox",
            "expected": True,
            "actual": False,
            "description": "未启用浏览器沙箱，易受浏览器劫持"
        })
    
    return issues


def check_maestro_lm(config):
    """MAESTRO 基础模型层检测"""
    issues = []
    
    # 系统提示泄漏检测
    bootstrap = config.get("agents", {}).get("bootstrap", {})
    if not bootstrap.get("protect_prompts", False):
        issues.append({
            "risk": "medium",
            "category": "maestro_lm",
            "check": "agents.bootstrap.protect_prompts",
            "expected": True,
            "actual": False,
            "description": "未启用系统提示保护，可能导致系统提示泄漏"
        })
    
    # 模型 API 密钥泄露检测
    model = config.get("model", {})
    api_key = model.get("apiKey", "")
    if api_key and not model.get("useKeychain", False):
        issues.append({
            "risk": "critical",
            "category": "maestro_lm",
            "check": "model.useKeychain",
            "expected": True,
            "actual": False,
            "description": "模型 API 密钥直接存储在配置中，存在泄露风险"
        })
    
    # 多回合上下文越狱检测
    session = config.get("session", {})
    if not session.get("compaction", {}).get("enabled", False):
        issues.append({
            "risk": "high",
            "category": "maestro_lm",
            "check": "session.compaction.enabled",
            "expected": True,
            "actual": False,
            "description": "未启用会话压缩，可能导致多回合上下文越狱"
        })
    
    return issues


def check_maestro_do(config):
    """MAESTRO 数据操作层检测"""
    issues = []
    
    # 凭证存储安全检测
    pairing = config.get("pairing", {})
    if not pairing.get("secureStorage", False):
        issues.append({
            "risk": "critical",
            "category": "maestro_do",
            "check": "pairing.secureStorage",
            "expected": True,
            "actual": False,
            "description": "未启用安全存储，凭证可能以明文形式存储"
        })
    
    # 状态目录权限检测
    state = config.get("state", {})
    directory = state.get("directory", "~/.openclaw")
    if not state.get("restrictPermissions", False):
        issues.append({
            "risk": "high",
            "category": "maestro_do",
            "check": "state.restrictPermissions",
            "expected": True,
            "actual": False,
            "description": "未限制状态目录权限，可能导致全局可读"
        })
    
    # 数据加密检测
    security = config.get("security", {})
    if not security.get("dataEncryption", {}).get("enabled", False):
        issues.append({
            "risk": "medium",
            "category": "maestro_do",
            "check": "security.dataEncryption.enabled",
            "expected": True,
            "actual": False,
            "description": "未启用数据加密，敏感数据可能未加密存储"
        })
    
    return issues


def check_maestro_tu(config):
    """MAESTRO 工具使用层检测"""
    issues = []
    
    # 工具权限检测
    tools = config.get("tools", {})
    if not tools.get("permissions", {}).get("enabled", False):
        issues.append({
            "risk": "high",
            "category": "maestro_tu",
            "check": "tools.permissions.enabled",
            "expected": True,
            "actual": False,
            "description": "未启用工具权限控制，可能导致权限滥用"
        })
    
    # 危险工具使用检测
    deny = tools.get("deny", [])
    dangerous_tools = ["exec", "elevated", "file_system", "network"]
    for tool in dangerous_tools:
        if tool not in deny:
            issues.append({
                "risk": "medium",
                "category": "maestro_tu",
                "check": f"tools.deny",
                "expected": f"包含 {tool}",
                "actual": deny,
                "description": f"未禁用危险工具 {tool}"
            })
    
    return issues


def check_maestro_ni(config):
    """MAESTRO 网络交互层检测"""
    issues = []
    
    # 网络策略检测
    network = config.get("network", {})
    if network.get("mode", "whitelist") != "whitelist":
        issues.append({
            "risk": "high",
            "category": "maestro_ni",
            "check": "network.mode",
            "expected": "whitelist",
            "actual": network.get("mode"),
            "description": "网络策略未设置为白名单模式，可能导致未授权网络访问"
        })
    
    # 外部网络访问检测
    if network.get("allow_external", False):
        issues.append({
            "risk": "critical",
            "category": "maestro_ni",
            "check": "network.allow_external",
            "expected": False,
            "actual": True,
            "description": "允许外部网络访问，存在安全风险"
        })
    
    return issues


def check_maestro_se(config):
    """MAESTRO 沙箱逃逸层检测"""
    issues = []
    
    # 沙箱配置检测
    sandbox = config.get("agents", {}).get("defaults", {}).get("sandbox", {})
    if sandbox.get("mode", "off") == "off":
        issues.append({
            "risk": "critical",
            "category": "maestro_se",
            "check": "agents.defaults.sandbox.mode",
            "expected": "non-main or all",
            "actual": "off",
            "description": "未启用沙箱隔离，存在沙箱逃逸风险"
        })
    
    # 沙箱资源限制检测
    resource_limits = sandbox.get("resource_limits", {})
    if not resource_limits.get("enabled", False):
        issues.append({
            "risk": "medium",
            "category": "maestro_se",
            "check": "agents.defaults.sandbox.resource_limits.enabled",
            "expected": True,
            "actual": False,
            "description": "未启用沙箱资源限制，可能导致资源耗尽攻击"
        })
    
    return issues


def check_maestro_pe(config):
    """MAESTRO 持久化层检测"""
    issues = []
    
    # 配置文件权限检测
    config_file = config.get("config", {})
    if not config_file.get("restrictPermissions", False):
        issues.append({
            "risk": "high",
            "category": "maestro_pe",
            "check": "config.restrictPermissions",
            "expected": True,
            "actual": False,
            "description": "未限制配置文件权限，可能导致配置泄露"
        })
    
    # 持久化凭证检测
    credentials = config.get("credentials", {})
    if not credentials.get("secureStorage", False):
        issues.append({
            "risk": "critical",
            "category": "maestro_pe",
            "check": "credentials.secureStorage",
            "expected": True,
            "actual": False,
            "description": "未启用凭证安全存储，可能导致凭证持久化泄露"
        })
    
    return issues


def check_maestro_lm2(config):
    """MAESTRO 横向移动层检测"""
    issues = []
    
    # 跨通道攻击检测
    channels = config.get("channels", {})
    for channel_name, channel_config in channels.items():
        if not channel_config.get("isolate", False):
            issues.append({
                "risk": "medium",
                "category": "maestro_lm2",
                "check": f"channels.{channel_name}.isolate",
                "expected": True,
                "actual": False,
                "description": f"{channel_name} 通道未启用隔离，可能导致跨通道攻击"
            })
    
    # 权限提升检测
    auth = config.get("gateway", {}).get("auth", {})
    if auth.get("mode") != "token":
        issues.append({
            "risk": "critical",
            "category": "maestro_lm2",
            "check": "gateway.auth.mode",
            "expected": "token",
            "actual": auth.get("mode"),
            "description": "未启用 token 认证，可能导致权限提升攻击"
        })
    
    return issues


def check_compliance(config):
    """合规性检测"""
    issues = []
    
    # 审计日志
    audit_logging = config.get("security", {}).get("audit_logging", {})
    enabled = audit_logging.get("enabled", False)
    retention_days = audit_logging.get("retention_days", 0)
    
    if not enabled:
        issues.append({
            "risk": "high",
            "category": "compliance",
            "check": "security.audit_logging.enabled",
            "expected": True,
            "actual": False,
            "description": "未启用审计日志，不符合合规要求"
        })
    
    if retention_days < 90:
        issues.append({
            "risk": "medium",
            "category": "compliance",
            "check": "security.audit_logging.retention_days",
            "expected": ">= 90",
            "actual": retention_days,
            "description": "审计日志保留期限不足，不符合合规要求"
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
    all_issues.extend(check_internet_exposure(config))  # 新增：互联网暴露检测
    all_issues.extend(check_sandbox(config))
    all_issues.extend(check_channels(config))
    all_issues.extend(check_supply_chain(config))  # 新增：供应链安全检测
    all_issues.extend(check_privilege(config))  # 新增：权限控制检测
    all_issues.extend(check_social_engineering(config))  # 新增：社会工程学攻击防范检测
    all_issues.extend(check_compliance(config))  # 新增：合规性检测
    # MAESTRO 框架检测
    all_issues.extend(check_maestro_lm(config))  # MAESTRO 基础模型层检测
    all_issues.extend(check_maestro_do(config))  # MAESTRO 数据操作层检测
    all_issues.extend(check_maestro_tu(config))  # MAESTRO 工具使用层检测
    all_issues.extend(check_maestro_ni(config))  # MAESTRO 网络交互层检测
    all_issues.extend(check_maestro_se(config))  # MAESTRO 沙箱逃逸层检测
    all_issues.extend(check_maestro_pe(config))  # MAESTRO 持久化层检测
    all_issues.extend(check_maestro_lm2(config))  # MAESTRO 横向移动层检测
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
            "session": {
                "dmScope": "per-channel-peer",
                "compaction": {
                    "enabled": True
                }
            },
            "tools": {
                "profile": "messaging",
                "deny": ["group:automation", "group:runtime", "exec", "elevated", "file_system", "network"],
                "fs": {"workspaceOnly": True},
                "exec": {"security": "deny", "ask": "always"},
                "elevated": {"enabled": False},
                "permissions": {
                    "enabled": True
                }
            },
            "agents": {
                "defaults": {
                    "sandbox": {
                        "mode": "non-main", 
                        "scope": "agent",
                        "workspaceAccess": "ro",
                        "docker": {"network": "bridge"},
                        "resource_limits": {
                            "enabled": True
                        }
                    }
                },
                "bootstrap": {
                    "protect_prompts": True
                }
            },
            "network": {
                "allow_external": False,
                "mode": "whitelist"
            },
            "security": {
                "prompt_security": {
                    "injection_detection": True
                },
                "audit_logging": {
                    "enabled": True,
                    "retention_days": 90
                },
                "dataEncryption": {
                    "enabled": True
                }
            },
            "browser": {
                "sandbox": True
            },
            "skills": {
                "allow": []  # 建议填写具体的可信技能包
            },
            "model": {
                "useKeychain": True
            },
            "pairing": {
                "secureStorage": True
            },
            "state": {
                "restrictPermissions": True
            },
            "config": {
                "restrictPermissions": True
            },
            "credentials": {
                "secureStorage": True
            },
            "channels": {
                "discord": {
                    "isolate": True
                },
                "telegram": {
                    "isolate": True
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
