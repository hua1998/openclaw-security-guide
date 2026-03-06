#!/usr/bin/env python3
"""
OpenClaw 安全配置基线检查工具
对比当前配置与安全基线，输出差异和风险评分

用法:
    python config_baseline.py --config ~/.openclaw/openclaw.json
    python config_baseline.py --config ~/.openclaw/openclaw.json --json
"""

import json
import sys
import argparse
from pathlib import Path


# 安全基线配置
SECURITY_BASELINE = {
    "gateway": {
        "mode": "local",
        "bind": "loopback",
        "auth": {
            "mode": "token"
        }
    },
    "session": {
        "dmScope": "per-channel-peer"
    },
    "tools": {
        "profile": "messaging",
        "deny": ["group:automation", "group:runtime"],
        "fs": {"workspaceOnly": True},
        "exec": {"security": "deny", "ask": "always"},
        "elevated": {"enabled": False}
    }
}

# 基线规则说明
BASELINE_RULES = {
    "gateway.mode": {
        "expected": "local",
        "risk": "high",
        "description": "Gateway 应仅在本地运行，避免暴露到公网"
    },
    "gateway.bind": {
        "expected": "loopback",
        "risk": "high", 
        "description": "Gateway 应仅绑定本地回环地址"
    },
    "gateway.auth.mode": {
        "expected": "token",
        "risk": "critical",
        "description": "应启用 Token 认证"
    },
    "session.dmScope": {
        "expected": "per-channel-peer",
        "risk": "medium",
        "description": "DM 应按用户隔离"
    },
    "tools.profile": {
        "expected": "messaging",
        "risk": "medium",
        "description": "应使用 messaging 工具配置"
    },
    "tools.deny": {
        "expected": ["group:automation", "group:runtime"],
        "risk": "high",
        "description": "应禁用 automation 和 runtime 工具组"
    },
    "tools.fs.workspaceOnly": {
        "expected": True,
        "risk": "high",
        "description": "文件系统工具应限制在工作区"
    },
    "tools.exec.security": {
        "expected": "deny",
        "risk": "critical",
        "description": "应禁用 exec 直接执行"
    },
    "tools.exec.ask": {
        "expected": "always",
        "risk": "high",
        "description": "exec 应始终询问用户"
    },
    "tools.elevated.enabled": {
        "expected": False,
        "risk": "critical",
        "description": "应禁用 elevated 工具"
    }
}


def load_config(config_path):
    """加载配置文件"""
    path = Path(config_path).expanduser()
    if not path.exists():
        print(f"错误: 配置文件不存在: {config_path}")
        sys.exit(1)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"错误: 配置文件格式错误: {e}")
        sys.exit(1)


def check_baseline(config, baseline, path=""):
    """递归检查配置与基线的差异"""
    results = []
    
    # 检查当前基线中的所有键
    for key, baseline_value in baseline.items():
        current_path = f"{path}.{key}" if path else key
        
        if key not in config:
            # 配置项缺失
            rule = BASELINE_RULES.get(current_path, {})
            results.append({
                "path": current_path,
                "status": "missing",
                "expected": baseline_value,
                "actual": None,
                "risk": rule.get("risk", "high"),
                "description": rule.get("description", f"缺少配置项: {current_path}")
            })
        else:
            current_value = config[key]
            
            if isinstance(baseline_value, dict):
                # 递归检查嵌套对象
                results.extend(check_baseline(current_value, baseline_value, current_path))
            else:
                # 检查值是否匹配
                if current_value != baseline_value:
                    rule = BASELINE_RULES.get(current_path, {})
                    results.append({
                        "path": current_path,
                        "status": "mismatch",
                        "expected": baseline_value,
                        "actual": current_value,
                        "risk": rule.get("risk", "medium"),
                        "description": rule.get("description", f"{current_path} 值不符合基线")
                    })
    
    return results


def calculate_risk_score(results):
    """计算风险评分"""
    risk_weights = {
        "critical": 10,
        "high": 5,
        "medium": 2,
        "low": 1
    }
    
    total_score = 0
    max_score = 100
    
    for result in results:
        risk = result.get("risk", "medium")
        weight = risk_weights.get(risk, 2)
        total_score += weight
    
    # 计算合规百分比
    compliance = max(0, 100 - (total_score / max_score * 100))
    
    return {
        "total_issues": len(results),
        "risk_score": total_score,
        "compliance_percentage": round(compliance, 1),
        "risk_level": "critical" if total_score >= 30 else "high" if total_score >= 15 else "medium" if total_score >= 5 else "low"
    }


def print_results(results, risk_info, json_output=False):
    """输出检查结果"""
    if json_output:
        output = {
            "results": results,
            "risk_info": risk_info
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return
    
    # 文本输出
    print("=" * 60)
    print("OpenClaw 安全配置基线检查")
    print("=" * 60)
    
    print(f"\n风险等级: {risk_info['risk_level'].upper()}")
    print(f"合规评分: {risk_info['compliance_percentage']}%")
    print(f"问题数量: {risk_info['total_issues']}")
    print(f"风险分数: {risk_info['risk_score']}")
    
    if not results:
        print("\n✅ 配置符合安全基线！")
        return
    
    print("\n" + "=" * 60)
    print("问题列表")
    print("=" * 60)
    
    # 按风险等级排序
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda x: risk_order.get(x.get("risk", "medium"), 4))
    
    for i, result in enumerate(results, 1):
        risk = result.get("risk", "medium")
        risk_icon = {"critical": "[X]", "high": "[!]", "medium": "[~]", "low": "[o]"}
        
        print(f"\n{i}. {risk_icon} [{risk.upper()}] {result['path']}")
        print(f"   说明: {result['description']}")
        print(f"   期望: {result['expected']}")
        print(f"   实际: {result['actual']}")
    
    print("\n" + "=" * 60)
    print("修复建议")
    print("=" * 60)
    
    for result in results:
        if result['risk'] in ["critical", "high"]:
            print(f"\n• {result['path']}:")
            print(f"  {result['description']}")


def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw 安全配置基线检查工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python config_baseline.py --config ~/.openclaw/openclaw.json
  python config_baseline.py --config ~/.openclaw/openclaw.json --json
  python config_baseline.py --config ~/.openclaw/openclaw.json --fix
        """
    )
    
    parser.add_argument(
        "--config", "-c",
        default="~/.openclaw/openclaw.json",
        help="OpenClaw 配置文件路径 (默认: ~/.openclaw/openclaw.json)"
    )
    
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="JSON 格式输出"
    )
    
    parser.add_argument(
        "--fix",
        action="store_true",
        help="生成修复配置"
    )
    
    args = parser.parse_args()
    
    # 加载配置
    config = load_config(args.config)
    
    # 检查基线
    results = check_baseline(config, SECURITY_BASELINE)
    
    # 计算风险
    risk_info = calculate_risk_score(results)
    
    # 输出结果
    print_results(results, risk_info, args.json)
    
    # 生成修复配置
    if args.fix and results:
        print("\n" + "=" * 60)
        print("建议修复配置")
        print("=" * 60)
        
        # 合并基线到当前配置
        fixed_config = config.copy()
        for key, value in SECURITY_BASELINE.items():
            if key not in fixed_config:
                fixed_config[key] = value
            elif isinstance(value, dict):
                if key not in fixed_config:
                    fixed_config[key] = {}
                for k, v in value.items():
                    if isinstance(v, dict):
                        fixed_config[key].setdefault(k, v)
                    else:
                        fixed_config[key][k] = v
        
        print("\n建议添加到配置:")
        print(json.dumps(fixed_config, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
