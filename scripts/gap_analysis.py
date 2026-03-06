#!/usr/bin/env python3
"""
安全差距分析工具 - 简化版
自动分析文档并生成加固建议
"""

import os
import json
from pathlib import Path
from datetime import datetime

# OWASP Top 10 for LLM 检查项
OWASP_CHECKS = {
    "LLM01": {
        "name": "Prompt Injection",
        "keywords": ["提示词注入", "注入检测", "输入过滤", "prompt", "injection"],
        "controls": ["输入验证", "指令分离", "提示词加固", "注入检测"]
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "keywords": ["输出处理", "输出验证", "沙箱", "output"],
        "controls": ["输出编码", "沙箱执行", "输出验证"]
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "keywords": ["训练数据", "供应链", "skills 扫描", "dependency"],
        "controls": ["数据源验证", "Skills 扫描", "依赖检查"]
    },
    "LLM04": {
        "name": "Model DoS",
        "keywords": ["限流", "速率", "资源", "rate limit", "quota"],
        "controls": ["速率限制", "资源配额", "超时控制"]
    },
    "LLM05": {
        "name": "Supply Chain",
        "keywords": ["供应链", "白名单", "supply chain", "whitelist"],
        "controls": ["供应商评估", "白名单", "版本锁定"]
    },
    "LLM06": {
        "name": "Sensitive Disclosure",
        "keywords": ["脱敏", "敏感信息", "masking", "sensitive"],
        "controls": ["数据脱敏", "访问控制", "输出过滤"]
    },
    "LLM07": {
        "name": "Insecure Plugin",
        "keywords": ["插件", "工具", "权限", "plugin", "tool"],
        "controls": ["插件沙箱", "最小权限", "输入验证"]
    },
    "LLM08": {
        "name": "Excessive Agency",
        "keywords": ["审批", "人工在环", "approval", "human-in-the-loop"],
        "controls": ["人工在环", "操作审批", "权限分级"]
    },
    "LLM09": {
        "name": "Overreliance",
        "keywords": ["审计", "日志", "复核", "audit", "review"],
        "controls": ["审计日志", "人工复核", "定期评估"]
    },
    "LLM10": {
        "name": "Model Theft",
        "keywords": ["访问控制", "认证", "授权", "access control", "auth"],
        "controls": ["访问控制", "模型加密", "API 限流"]
    }
}

def analyze_document(doc_path):
    """分析单个文档"""
    try:
        content = doc_path.read_text(encoding='utf-8').lower()
    except Exception as e:
        print(f"  ⚠️  读取失败：{e}")
        return None
    
    results = {
        "document": doc_path.name,
        "owasp_coverage": {}
    }
    
    # 检查 OWASP 覆盖
    for owasp_id, check_info in OWASP_CHECKS.items():
        found_controls = []
        keyword_found = any(kw.lower() in content for kw in check_info["keywords"])
        
        if keyword_found:
            for control in check_info["controls"]:
                if control.lower() in content:
                    found_controls.append(control)
        
        results["owasp_coverage"][owasp_id] = {
            "name": check_info["name"],
            "mentioned": keyword_found,
            "controls_found": found_controls,
            "coverage_rate": len(found_controls) / len(check_info["controls"]) if found_controls else 0
        }
    
    return results

def main():
    reports_dir = Path("D:\\ai-security\\reports")
    docs_dir = Path("D:\\ai-security\\docs")
    
    print("=" * 70)
    print("OpenClaw 安全差距分析工具 v1.0")
    print("=" * 70)
    print()
    
    # 收集所有文档
    all_docs = list(reports_dir.glob("*.md")) + list(docs_dir.glob("*.md"))
    print(f"找到 {len(all_docs)} 个文档")
    print()
    
    # 分析文档
    analysis_results = []
    for doc in all_docs:
        print(f"分析：{doc.name}")
        result = analyze_document(doc)
        if result:
            analysis_results.append(result)
    
    print()
    print(f"成功分析 {len(analysis_results)} 个文档")
    print()
    
    # 汇总 OWASP 覆盖
    owasp_summary = {}
    for owasp_id in OWASP_CHECKS:
        owasp_summary[owasp_id] = {
            "name": OWASP_CHECKS[owasp_id]["name"],
            "docs_mentioned": 0,
            "total_controls": 0,
            "avg_coverage": 0
        }
    
    for result in analysis_results:
        for owasp_id, coverage in result["owasp_coverage"].items():
            if coverage["mentioned"]:
                owasp_summary[owasp_id]["docs_mentioned"] += 1
            owasp_summary[owasp_id]["total_controls"] += coverage["coverage_rate"]
    
    # 计算平均覆盖率
    for owasp_id in owasp_summary:
        if analysis_results:
            owasp_summary[owasp_id]["avg_coverage"] = (
                owasp_summary[owasp_id]["total_controls"] / len(analysis_results)
            )
    
    # 输出报告
    print("=" * 70)
    print("OWASP Top 10 for LLM 覆盖分析")
    print("=" * 70)
    print()
    print(f"{'ID':<8} {'名称':<30} {'文档数':<8} {'覆盖率':<10} {'状态'}")
    print("-" * 70)
    
    gaps = []
    for owasp_id, summary in owasp_summary.items():
        coverage = summary["avg_coverage"]
        docs_count = summary["docs_mentioned"]
        
        if coverage >= 0.8:
            status = "[OK]"
        elif coverage >= 0.5:
            status = "[WARN]"
        else:
            status = "[GAP]"
            gaps.append({
                "id": owasp_id,
                "name": summary["name"],
                "coverage": coverage,
                "priority": "P0" if coverage < 0.3 else "P1"
            })
        
        print(f"{owasp_id:<8} {summary['name']:<30} {docs_count:<8} {coverage:>6.0%}      {status}")
    
    print()
    print("=" * 70)
    print("识别的安全差距")
    print("=" * 70)
    
    if not gaps:
        print("[OK] No significant gaps found")
    else:
        for gap in sorted(gaps, key=lambda x: x["coverage"]):
            print(f"\n{gap['id']}: {gap['name']}")
            print(f"  Coverage: {gap['coverage']:.0%}")
            print(f"  Priority: {gap['priority']}")
            print(f"  Action: Strengthen related controls")
    
    # 生成加固建议
    print()
    print("=" * 70)
    print("加固建议")
    print("=" * 70)
    
    recommendations = []
    for gap in sorted(gaps, key=lambda x: x["coverage"])[:5]:  # Top 5
        rec = {
            "id": gap["id"],
            "name": gap["name"],
            "priority": gap["priority"],
            "recommendation": f"完善{gap['name']}相关控制",
            "actions": []
        }
        
        # 根据 OWASP 项生成具体建议
        if gap["id"] == "LLM03":
            rec["actions"] = [
                "添加 Skills 安全扫描流程",
                "实施依赖项漏洞检查",
                "建立供应商评估机制"
            ]
            rec["effort"] = "8h"
        elif gap["id"] == "LLM10":
            rec["actions"] = [
                "实施模型访问控制",
                "添加 API 调用限流",
                "建立模型使用审计"
            ]
            rec["effort"] = "6h"
        else:
            rec["actions"] = [
                f"审查{gap['name']}相关控制",
                "识别缺失的控制措施",
                "制定实施方案"
            ]
            rec["effort"] = "4h"
        
        recommendations.append(rec)
        print(f"\n{gap['id']} ({gap['priority']}): {gap['name']}")
        print(f"  Recommendation: {rec['recommendation']}")
        print(f"  Actions:")
        for action in rec["actions"]:
            print(f"    - {action}")
        print(f"  Effort: {rec['effort']}")
    
    # 保存报告
    report = {
        "generated_at": datetime.now().isoformat(),
        "documents_analyzed": len(analysis_results),
        "owasp_summary": owasp_summary,
        "gaps": gaps,
        "recommendations": recommendations
    }
    
    output_file = Path("D:\\ai-security\\gap_analysis_report.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    print()
    print("=" * 70)
    print(f"详细报告已保存：{output_file}")
    print("=" * 70)

if __name__ == "__main__":
    main()
