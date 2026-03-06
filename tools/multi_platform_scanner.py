#!/usr/bin/env python3
"""
多平台安全扫描器入口
支持 OpenClaw, Dify, AutoGPT, FastGPT 等平台
"""
import argparse
import json
import sys
from pathlib import Path

# 导入适配器
sys.path.insert(0, str(Path(__file__).parent))

try:
    from adapters.dify_adapter import DifyAdapter
    from adapters.autogpt_adapter import AutoGPTAdapter
    from adapters.fastgpt_adapter import FastGPTAdapter
    ADAPTERS_AVAILABLE = True
except ImportError:
    ADAPTERS_AVAILABLE = False

ADAPTERS = {
    'openclaw': None,  # 原生支持
    'dify': DifyAdapter if ADAPTERS_AVAILABLE else None,
    'autogpt': AutoGPTAdapter if ADAPTERS_AVAILABLE else None,
    'fastgpt': FastGPTAdapter if ADAPTERS_AVAILABLE else None,
}

def detect_platform(config_path: str) -> str:
    """自动检测平台类型"""
    path = Path(config_path)
    path_str = str(path).lower()
    name = path.name.lower()
    
    # Dify检测
    if 'dify' in path_str:
        return 'dify'
    
    # FastGPT检测
    if 'fastgpt' in path_str:
        return 'fastgpt'
    
    # AutoGPT检测
    if 'autogpt' in path_str or name in ['.env', 'ai_settings.yaml']:
        # 进一步检查文件内容
        try:
            with open(path, 'r') as f:
                content = f.read().lower()
                if 'autogpt' in content or 'ai_name' in content:
                    return 'autogpt'
        except:
            pass
    
    # 通用.env文件检测 - 尝试识别内容
    if name == '.env':
        try:
            with open(path, 'r') as f:
                content = f.read().lower()
                if 'fastgpt' in content:
                    return 'fastgpt'
                elif 'autogpt' in content or 'ai_name' in content:
                    return 'autogpt'
                elif 'dify' in content:
                    return 'dify'
        except:
            pass
    
    # FastGPT JSON配置检测
    if path.suffix == '.json' and 'fastgpt' in path_str:
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                if 'SystemParams' in data or 'LLMModels' in data:
                    return 'fastgpt'
        except:
            pass
    
    # OpenClaw检测 (JSON格式)
    if path.suffix == '.json':
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                if 'gateway' in data and 'session' in data:
                    return 'openclaw'
        except:
            pass
    
    return 'unknown'

def scan_config(platform: str, config_path: str, output_format: str = 'text') -> dict:
    """扫描配置安全性"""
    result = {
        'platform': platform,
        'config_path': config_path,
        'timestamp': None,
        'score': 0,
        'issues': [],
        'recommendations': []
    }
    
    from datetime import datetime
    result['timestamp'] = datetime.now().isoformat()
    
    # 原生OpenClaw直接检测
    if platform == 'openclaw':
        return scan_openclaw(config_path, output_format)
    
    # 其他平台使用适配器
    adapter_class = ADAPTERS.get(platform)
    if adapter_class is None:
        result['error'] = f'暂不支持平台: {platform}'
        return result
    
    try:
        adapter = adapter_class(config_path)
        openclaw_config = adapter.to_openclaw_format()
        
        # 保存临时配置文件
        temp_dir = Path('/tmp/openclaw_scan')
        temp_dir.mkdir(exist_ok=True)
        temp_config = temp_dir / f'{platform}_temp_config.json'
        
        with open(temp_config, 'w') as f:
            json.dump(openclaw_config, f, indent=2)
        
        # 调用原生检测器
        result = scan_openclaw(str(temp_config), output_format)
        
        # 添加平台特定建议
        if hasattr(adapter, 'get_security_recommendations'):
            platform_recs = adapter.get_security_recommendations()
            result['platform_recommendations'] = platform_recs
        
        # 清理临时文件
        temp_config.unlink(missing_ok=True)
        
        result['platform'] = platform
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def scan_openclaw(config_path: str, output_format: str = 'text') -> dict:
    """扫描OpenClaw配置"""
    import subprocess
    
    cmd = ['python', str(Path(__file__).parent / 'security_detector.py'), 
           '--config', config_path]
    
    if output_format == 'json':
        cmd.append('--json')
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if output_format == 'json':
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {'error': '无法解析JSON输出', 'raw': result.stdout}
        else:
            return {
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
    except Exception as e:
        return {'error': str(e)}

def main():
    parser = argparse.ArgumentParser(
        description='多平台AI Agent安全扫描器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 自动检测平台
  python multi_platform_scanner.py --config .env
  
  # 指定平台
  python multi_platform_scanner.py --config .env --platform dify
  
  # JSON输出
  python multi_platform_scanner.py --config openclaw.json --json
  
支持的平台:
  - openclaw: OpenClaw原生JSON配置
  - dify: Dify的.env或docker-compose.yaml
  - autogpt: AutoGPT的.env配置
  - fastgpt: FastGPT配置 (开发中)
        """
    )
    
    parser.add_argument('--config', required=True, help='配置文件路径')
    parser.add_argument('--platform', choices=list(ADAPTERS.keys()), 
                       help='指定平台类型（自动检测）')
    parser.add_argument('--json', action='store_true', help='JSON格式输出')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    # 验证配置文件存在
    if not Path(args.config).exists():
        print(f"错误: 配置文件不存在: {args.config}", file=sys.stderr)
        sys.exit(1)
    
    # 自动检测平台
    platform = args.platform or detect_platform(args.config)
    if platform == 'unknown':
        print("错误: 无法自动检测平台类型，请使用 --platform 指定", file=sys.stderr)
        print(f"支持的平台: {', '.join(ADAPTERS.keys())}", file=sys.stderr)
        sys.exit(1)
    
    if args.verbose:
        print(f"检测到平台: {platform}")
        print(f"配置文件: {args.config}")
    
    # 执行扫描
    result = scan_config(platform, args.config, 'json' if args.json else 'text')
    
    # 输出结果
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        if 'output' in result:
            print(result['output'])
        elif 'error' in result:
            print(f"错误: {result['error']}", file=sys.stderr)
            sys.exit(1)
        
        # 输出平台特定建议
        if 'platform_recommendations' in result and result['platform_recommendations']:
            print("\n" + "="*50)
            print(f"平台特定安全建议 ({platform}):")
            print("="*50)
            for rec in result['platform_recommendations']:
                severity = rec.get('severity', 'info').upper()
                print(f"\n[{severity}] {rec['message']}")
                if 'fix' in rec:
                    print(f"  修复建议: {rec['fix']}")
                if 'warning' in rec:
                    print(f"  警告: {rec['warning']}")

if __name__ == '__main__':
    main()
