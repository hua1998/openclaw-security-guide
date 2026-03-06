#!/usr/bin/env python3
"""
OpenClaw Token 生成器
生成符合安全规范的随机 Token

用法:
    python token_generator.py
    python token_generator.py --length 32
    python token_generator.py --format hex
    python token_generator.py --count 5
"""

import secrets
import argparse
import string
import json


def generate_token(length=32, format="random"):
    """生成随机 Token"""
    if format == "hex":
        return secrets.token_hex(length // 2)
    elif format == "base64":
        return secrets.token_urlsafe(length)
    else:
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_token_batch(count=1, length=32, format="random"):
    """批量生成 Token"""
    return [generate_token(length, format) for _ in range(count)]


def evaluate_token_strength(token):
    """评估 Token 强度"""
    score = 0
    feedback = []
    
    # 长度检查
    if len(token) >= 32:
        score += 30
    elif len(token) >= 24:
        score += 20
    elif len(token) >= 16:
        score += 10
    else:
        feedback.append("Token 长度不足，建议 32 位以上")
    
    # 字符类型检查
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    has_special = any(not c.isalnum() for c in token)
    
    type_count = sum([has_upper, has_lower, has_digit, has_special])
    
    if type_count >= 3:
        score += 30
    elif type_count >= 2:
        score += 20
    else:
        feedback.append("建议使用混合字符类型")
    
    # 强度判断
    if len(token) >= 32 and type_count >= 3:
        strength = "strong"
    elif len(token) >= 24 and type_count >= 2:
        strength = "medium"
    else:
        strength = "weak"
    
    return {
        "score": min(score, 100),
        "strength": strength,
        "length": len(token),
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "feedback": feedback
    }


def main():
    parser = argparse.ArgumentParser(description="OpenClaw Token 生成器")
    parser.add_argument("--length", "-l", type=int, default=32, help="Token 长度")
    parser.add_argument("--format", "-f", choices=["random", "hex", "base64"], default="random", help="Token 格式")
    parser.add_argument("--count", "-c", type=int, default=1, help="生成数量")
    parser.add_argument("--json", "-j", action="store_true", help="JSON 格式输出")
    parser.add_argument("--evaluate", "-e", action="store_true", help="评估 Token 强度")
    
    args = parser.parse_args()
    
    tokens = generate_token_batch(args.count, args.length, args.format)
    
    if args.json:
        if args.evaluate and args.count == 1:
            result = {"token": tokens[0], "evaluation": evaluate_token_strength(tokens[0])}
        else:
            result = {"tokens": tokens, "count": len(tokens), "length": args.length, "format": args.format}
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("=" * 60)
        print("OpenClaw Token 生成器")
        print("=" * 60)
        print(f"\n长度: {args.length}")
        print(f"格式: {args.format}")
        print(f"数量: {args.count}")
        
        for i, token in enumerate(tokens, 1):
            print(f"\nToken {i}: {token}")
            
            if args.evaluate and args.count == 1:
                eval_result = evaluate_token_strength(token)
                strength_icon = {"weak": "🔴", "medium": "🟡", "strong": "🟢"}
                print(f"  强度: {strength_icon.get(eval_result['strength'], '⚪')} {eval_result['strength'].upper()}")
                print(f"  评分: {eval_result['score']}/100")
                if eval_result['feedback']:
                    print(f"  建议: {', '.join(eval_result['feedback'])}")
        
        print("\n" + "-" * 60)
        print("安全建议:")
        print("  • 使用 32 位以上 Token")
        print("  • 使用混合字符类型")
        print("  • 存储在环境变量中")
        print("  • 定期轮换")


if __name__ == "__main__":
    main()
