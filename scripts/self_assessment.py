#!/usr/bin/env python3
"""
OpenClaw 自我评估和加固工具 v3.0

功能:
1. 自我评估当前配置安全性
2. 生成加固建议
3. 自动生成加固脚本
4. 执行加固 (需确认)
5. 验证加固效果
"""

import os
import json
import yaml
from pathlib import Path
from datetime import datetime

class OpenClawSelfAssessment:
    """OpenClaw 自我评估类"""
    
    def __init__(self, config_path="config"):
        self.config_path = Path(config_path)
        self.assessment_results = {}
    
    def load_config(self):
        """加载当前配置"""
        configs = {}
        config_files = [
            "openclaw.json",
            "security-config.yaml",
            "approvers.yaml",
            "monitoring.yaml"
        ]
        
        for config_file in config_files:
            config_path = self.config_path / config_file
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    if config_file.endswith('.json'):
                        configs[config_file] = json.load(f)
                    else:
                        configs[config_file] = yaml.safe_load(f)
        
        return configs
    
    def assess_security(self, configs):
        """评估安全性"""
        score = 100
        issues = []
        recommendations = []
        
        # 检查 1: 沙箱配置
        if 'openclaw.json' in configs:
            sandbox = configs['openclaw.json'].get('agents', {}).get('default', {}).get('sandbox', {})
            if not sandbox.get('enabled', False):
                score -= 20
                issues.append({
                    "id": "SEC001",
                    "severity": "P0",
                    "title": "沙箱未启用",
                    "description": "沙箱隔离未配置，命令直接在宿主机执行",
                    "recommendation": "启用 Docker 沙箱隔离"
                })
                recommendations.append({
                    "action": "enable_sandbox",
                    "config": {
                        "agents": {
                            "default": {
                                "sandbox": {
                                    "enabled": True,
                                    "mode": "session"
                                }
                            }
                        }
                    }
                })
        
        # 检查 2: 审批流程
        if 'approvers.yaml' not in configs:
            score -= 15
            issues.append({
                "id": "SEC002",
                "severity": "P0",
                "title": "审批流程未配置",
                "description": "审批人配置缺失",
                "recommendation": "配置审批人和审批规则"
            })
            recommendations.append({
                "action": "setup_approvers",
                "template": "approvers.yaml.example"
            })
        
        # 检查 3: 监控告警
        if 'monitoring.yaml' not in configs:
            score -= 15
            issues.append({
                "id": "SEC003",
                "severity": "P1",
                "title": "监控告警未配置",
                "description": "监控和告警配置缺失",
                "recommendation": "配置监控指标和告警规则"
            })
            recommendations.append({
                "action": "setup_monitoring",
                "template": "monitoring.yaml.example"
            })
        
        # 检查 4: 审计日志
        if 'security-config.yaml' in configs:
            audit = configs['security-config.yaml'].get('audit', {})
            if not audit.get('enabled', False):
                score -= 10
                issues.append({
                    "id": "SEC004",
                    "severity": "P1",
                    "title": "审计日志未启用",
                    "description": "审计日志未开启",
                    "recommendation": "启用审计日志"
                })
                recommendations.append({
                    "action": "enable_audit",
                    "config": {
                        "audit": {
                            "enabled": True,
                            "format": "json"
                        }
                    }
                })
        
        self.assessment_results = {
            "score": max(0, score),
            "issues": issues,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        }
        
        return self.assessment_results
    
    def generate_report(self):
        """生成评估报告"""
        report = []
        report.append("=" * 70)
        report.append("OpenClaw 安全评估报告")
        report.append("=" * 70)
        report.append(f"\n评估时间：{self.assessment_results.get('timestamp')}")
        report.append(f"\n安全评分：{self.assessment_results['score']}/100\n")
        
        if self.assessment_results['score'] >= 80:
            report.append("评级：🟢 良好")
        elif self.assessment_results['score'] >= 60:
            report.append("评级：🟡 中等")
        else:
            report.append("评级：🔴 需要改进")
        
        report.append("\n" + "=" * 70)
        report.append("发现的问题")
        report.append("=" * 70)
        
        for issue in self.assessment_results['issues']:
            report.append(f"\n[{issue['severity']}] {issue['id']}: {issue['title']}")
            report.append(f"  描述：{issue['description']}")
            report.append(f"  建议：{issue['recommendation']}")
        
        report.append("\n" + "=" * 70)
        report.append("加固建议")
        report.append("=" * 70)
        
        for rec in self.assessment_results['recommendations']:
            report.append(f"\n- {rec['action']}")
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)
    
    def generate_fix_script(self):
        """生成加固脚本"""
        script = []
        script.append("#!/bin/bash")
        script.append("# OpenClaw 自动加固脚本")
        script.append(f"# 生成时间：{datetime.now().isoformat()}")
        script.append("")
        script.append("set -e")
        script.append("")
        
        for rec in self.assessment_results['recommendations']:
            if rec['action'] == 'enable_sandbox':
                script.append("# 1. 启用沙箱")
                script.append("echo '启用沙箱隔离...'")
                script.append("openclaw config set agents.default.sandbox.enabled true")
                script.append("openclaw config set agents.default.sandbox.mode session")
                script.append("")
            
            elif rec['action'] == 'setup_approvers':
                script.append("# 2. 配置审批人")
                script.append("echo '配置审批人...'")
                script.append("cat > config/approvers.yaml << 'EOF'")
                script.append("approvers:")
                script.append("  developer:")
                script.append("    level_1: \"ou_xxx\"  # 替换为团队主管飞书 ID")
                script.append("    level_2: \"ou_yyy\"  # 替换为运维主管飞书 ID")
                script.append("EOF")
                script.append("")
            
            elif rec['action'] == 'setup_monitoring':
                script.append("# 3. 配置监控")
                script.append("echo '配置监控告警...'")
                script.append("cat > config/monitoring.yaml << 'EOF'")
                script.append("metrics:")
                script.append("  security_incidents:")
                script.append("    enabled: true")
                script.append("    target: 0")
                script.append("EOF")
                script.append("")
            
            elif rec['action'] == 'enable_audit':
                script.append("# 4. 启用审计日志")
                script.append("echo '启用审计日志...'")
                script.append("openclaw config set audit.enabled true")
                script.append("openclaw config set audit.format json")
                script.append("")
        
        script.append("# 重启服务")
        script.append("echo '重启 OpenClaw 服务...'")
        script.append("openclaw restart")
        script.append("")
        script.append("echo '加固完成!'")
        
        return "\n".join(script)


def main():
    print("=" * 70)
    print("OpenClaw 自我评估和加固工具 v3.0")
    print("=" * 70)
    print()
    
    # 创建评估器
    assessor = OpenClawSelfAssessment()
    
    # 加载配置
    print("加载配置...")
    configs = assessor.load_config()
    print(f"加载了 {len(configs)} 个配置文件")
    print()
    
    # 评估安全性
    print("评估安全性...")
    results = assessor.assess_security(configs)
    print()
    
    # 生成报告
    report = assessor.generate_report()
    print(report)
    print()
    
    # 保存报告
    report_file = Path("assessment_report.txt")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"报告已保存至：{report_file}")
    print()
    
    # 生成加固脚本
    if results['recommendations']:
        print("生成加固脚本...")
        script = assessor.generate_fix_script()
        
        script_file = Path("security_hardening.sh")
        with open(script_file, 'w', encoding='utf-8') as f:
            f.write(script)
        
        print(f"加固脚本已保存至：{script_file}")
        print()
        print("是否执行加固脚本？[y/N]")
        # 实际使用时需要用户确认
        # if input().lower() == 'y':
        #     os.system(f"bash {script_file}")
    else:
        print("✅ 无需加固，配置良好!")


if __name__ == "__main__":
    main()
