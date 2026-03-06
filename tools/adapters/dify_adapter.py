"""
Dify 平台配置适配器
支持 .env 和 docker-compose.yaml 配置格式
"""
import os
import re
from pathlib import Path
from typing import Dict, Any
import yaml

from .base_adapter import BaseAdapter


class DifyAdapter(BaseAdapter):
    """Dify 配置适配器"""
    
    PLATFORM_NAME = "dify"
    
    # 安全配置映射
    SECURITY_MAPPINGS = {
        'CONSOLE_API_URL': {'category': 'network', 'key': 'api_endpoint'},
        'APP_API_KEY': {'category': 'auth', 'key': 'api_key'},
        'CODE_EXECUTION_ENABLED': {'category': 'sandbox', 'key': 'code_execution'},
        'CODE_EXECUTION_TIMEOUT': {'category': 'sandbox', 'key': 'execution_timeout'},
        'LOG_LEVEL': {'category': 'audit', 'key': 'log_level'},
        'LOG_FILE': {'category': 'audit', 'key': 'log_path'},
    }
    
    def _load_config(self) -> Dict[str, Any]:
        """加载Dify配置"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        # 支持 .env 和 docker-compose.yaml
        if self.config_path.suffix == '.env':
            return self._parse_env()
        elif self.config_path.name == 'docker-compose.yaml':
            return self._parse_compose()
        elif self.config_path.suffix in ['.yaml', '.yml']:
            return self._parse_yaml()
        else:
            raise ValueError(f"Unsupported config format: {self.config_path}")
    
    def _parse_env(self) -> Dict[str, Any]:
        """解析.env文件"""
        config = {}
        with open(self.config_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    # 处理带引号的值
                    match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=[\'"]?(.*?)[\'"]?$', line)
                    if match:
                        key, value = match.groups()
                        config[key] = value
        
        return self._transform_env_config(config)
    
    def _parse_compose(self) -> Dict[str, Any]:
        """解析docker-compose.yaml"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            compose = yaml.safe_load(f)
        
        # 提取服务配置
        services = compose.get('services', {})
        api_service = services.get('api', {})
        environment = api_service.get('environment', {})
        
        # 处理环境变量格式
        env_config = {}
        if isinstance(environment, list):
            for item in environment:
                if '=' in item:
                    key, value = item.split('=', 1)
                    env_config[key] = value
        elif isinstance(environment, dict):
            env_config = environment
        
        return self._transform_env_config(env_config)
    
    def _parse_yaml(self) -> Dict[str, Any]:
        """解析YAML配置文件"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def _transform_env_config(self, env_config: Dict[str, str]) -> Dict[str, Any]:
        """将环境变量转换为OpenClaw格式"""
        openclaw_config = {
            "version": "3.0",
            "platform": "dify",
            "gateway": {
                "auth": {
                    "mode": "api_key" if env_config.get('APP_API_KEY') else "none",
                    "token": env_config.get('APP_API_KEY', ''),
                    "api_key_length": len(env_config.get('APP_API_KEY', ''))
                },
                "endpoints": {
                    "console": env_config.get('CONSOLE_API_URL', ''),
                    "app": env_config.get('APP_API_URL', '')
                }
            },
            "sandbox": {
                "enabled": env_config.get('CODE_EXECUTION_ENABLED', 'false').lower() == 'true',
                "runtime": "docker",
                "timeout": int(env_config.get('CODE_EXECUTION_TIMEOUT', '60')),
                "resource_limits": {
                    "memory": env_config.get('CODE_MAX_MEMORY', '1G'),
                    "cpu": env_config.get('CODE_MAX_CPU', '1')
                }
            },
            "audit": {
                "enabled": True,
                "level": env_config.get('LOG_LEVEL', 'INFO'),
                "destination": [{
                    "type": "file",
                    "path": env_config.get('LOG_FILE', '/var/log/dify/app.log')
                }]
            },
            "database": {
                "host": env_config.get('DB_HOST', 'localhost'),
                "port": int(env_config.get('DB_PORT', '5432')),
                "ssl_enabled": env_config.get('DB_SSL', 'false').lower() == 'true'
            },
            "security_settings": {
                "file_upload": {
                    "enabled": env_config.get('FILES_UPLOAD_ENABLED', 'true').lower() == 'true',
                    "max_size": env_config.get('FILES_UPLOAD_MAX_SIZE', '15'),
                    "allowed_extensions": env_config.get('FILES_UPLOAD_EXTENSIONS', '*').split(',')
                },
                "cors": {
                    "enabled": bool(env_config.get('CORS_ALLOW_ORIGINS')),
                    "allow_origins": env_config.get('CORS_ALLOW_ORIGINS', '').split(',')
                }
            },
            "raw_env": env_config  # 保留原始配置
        }
        
        return openclaw_config
    
    def to_openclaw_format(self) -> Dict[str, Any]:
        """导出为OpenClaw标准格式"""
        return self.raw_config
    
    def get_security_recommendations(self) -> list:
        """获取Dify特定安全建议"""
        recommendations = []
        config = self.raw_config
        
        # 认证检查
        auth = config.get('gateway', {}).get('auth', {})
        if auth.get('mode') == 'none':
            recommendations.append({
                'severity': 'critical',
                'category': 'authentication',
                'message': '未启用API Key认证，建议设置 APP_API_KEY',
                'fix': '在.env文件中设置 APP_API_KEY=your-secure-key'
            })
        elif auth.get('api_key_length', 0) < 32:
            recommendations.append({
                'severity': 'high',
                'category': 'authentication',
                'message': 'API Key长度过短，建议使用至少32位随机字符串',
                'fix': '重新生成高强度API Key'
            })
        
        # 沙箱检查
        sandbox = config.get('sandbox', {})
        if sandbox.get('enabled'):
            if sandbox.get('timeout', 0) > 300:
                recommendations.append({
                    'severity': 'medium',
                    'category': 'sandbox',
                    'message': '代码执行超时时间过长，建议限制在300秒以内',
                    'fix': '设置 CODE_EXECUTION_TIMEOUT=120'
                })
        else:
            recommendations.append({
                'severity': 'low',
                'category': 'sandbox',
                'message': '代码执行已禁用，如需启用请确保资源配置合理',
                'info': '当前配置: CODE_EXECUTION_ENABLED=false'
            })
        
        # 数据库检查
        db = config.get('database', {})
        if not db.get('ssl_enabled'):
            recommendations.append({
                'severity': 'high',
                'category': 'database',
                'message': '数据库连接未启用SSL，生产环境建议启用',
                'fix': '设置 DB_SSL=true 并配置SSL证书'
            })
        
        # CORS检查
        cors = config.get('security_settings', {}).get('cors', {})
        if cors.get('enabled'):
            origins = cors.get('allow_origins', [])
            if '*' in origins:
                recommendations.append({
                    'severity': 'medium',
                    'category': 'cors',
                    'message': 'CORS允许所有来源(*)，建议限制为特定域名',
                    'fix': '设置 CORS_ALLOW_ORIGINS=https://your-domain.com'
                })
        
        return recommendations


# 使用示例
if __name__ == '__main__':
    import json
    
    # 示例用法
    try:
        adapter = DifyAdapter('config/dify.env')
        openclaw_config = adapter.to_openclaw_format()
        
        print("Dify配置转换成功")
        print(f"平台: {adapter.get_platform_info()}")
        print(f"OpenClaw格式:\n{json.dumps(openclaw_config, indent=2, ensure_ascii=False)}")
        
        # 获取安全建议
        recommendations = adapter.get_security_recommendations()
        if recommendations:
            print(f"\n发现 {len(recommendations)} 个安全建议:")
            for rec in recommendations:
                print(f"  [{rec['severity'].upper()}] {rec['message']}")
    
    except FileNotFoundError:
        print("示例文件不存在，这是正常的演示代码")
