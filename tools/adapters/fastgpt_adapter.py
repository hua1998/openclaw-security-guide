"""
FastGPT 平台配置适配器
支持 config.json 和 docker-compose 配置格式
"""
import json
import re
from pathlib import Path
from typing import Dict, Any, List

from .base_adapter import BaseAdapter


class FastGPTAdapter(BaseAdapter):
    """FastGPT 配置适配器"""
    
    PLATFORM_NAME = "fastgpt"
    
    def _load_config(self) -> Dict[str, Any]:
        """加载FastGPT配置"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        # 支持 config.json
        if self.config_path.suffix == '.json':
            return self._parse_json()
        elif self.config_path.name == 'docker-compose.yaml':
            return self._parse_compose()
        else:
            raise ValueError(f"Unsupported config format: {self.config_path}")
    
    def _parse_json(self) -> Dict[str, Any]:
        """解析config.json"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        return self._transform_config(config)
    
    def _parse_compose(self) -> Dict[str, Any]:
        """解析docker-compose.yaml"""
        import yaml
        with open(self.config_path, 'r', encoding='utf-8') as f:
            compose = yaml.safe_load(f)
        
        # 提取FastGPT服务配置
        services = compose.get('services', {})
        fastgpt_service = services.get('fastgpt', {})
        environment = fastgpt_service.get('environment', {})
        
        # 转换为标准格式
        config = {}
        if isinstance(environment, dict):
            config = environment
        elif isinstance(environment, list):
            for item in environment:
                if '=' in item:
                    key, value = item.split('=', 1)
                    config[key] = value
        
        return self._transform_env_config(config)
    
    def _transform_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """将FastGPT配置转换为OpenClaw格式"""
        
        # 系统配置
        system_config = config.get('SystemParams', {})
        
        # 权限配置
        auth_config = config.get('Auth', {})
        
        # 模型配置
        model_config = config.get('LLMModels', [])
        
        # 文件上传配置
        upload_config = config.get('UploadFile', {})
        
        openclaw_config = {
            "version": "3.0",
            "platform": "fastgpt",
            "system": {
                "welcome_text": system_config.get('welcomeText', ''),
                "timeout": system_config.get('timeout', 30),
                "open_sign_up": system_config.get('openSignUp', False),
                "limit": {
                    "qa_max_context": system_config.get('limit', {}).get('qaMaxContext', 10),
                    "qa_max_history": system_config.get('limit', {}).get('qaMaxHistory', 10),
                    "max_tokens": system_config.get('limit', {}).get('maxTokens', 4000)
                }
            },
            "gateway": {
                "auth": {
                    "mode": "token" if auth_config.get('token') else "none",
                    "token": auth_config.get('token', ''),
                    "token_length": len(auth_config.get('token', ''))
                },
                "root_key": self._mask_key(auth_config.get('rootKey', ''))
            },
            "llm_models": [
                {
                    "model": model.get('model', ''),
                    "name": model.get('name', ''),
                    "max_context": model.get('maxContext', 4096),
                    "max_response": model.get('maxResponse', 4096),
                    "quote_max_tokens": model.get('quoteMaxToken', 2000)
                }
                for model in model_config
            ],
            "sandbox": {
                "enabled": False,  # FastGPT默认无代码执行
                "code_interpreter": system_config.get('plugin', {}).get('codeInterpreter', False)
            },
            "file_upload": {
                "enabled": upload_config.get('open', False),
                "max_size": upload_config.get('maxSize', 2),  # MB
                "allowed_extensions": upload_config.get('suffix', '.pdf,.docx,.txt').split(','),
                "auto_process": upload_config.get('autoProcess', True)
            },
            "feishu": {
                "enabled": bool(config.get('Feishu', {}).get('appId')),
                "app_id_mask": self._mask_key(config.get('Feishu', {}).get('appId', '')),
                "encrypt_key_set": bool(config.get('Feishu', {}).get('encryptKey'))
            },
            "oneapi": {
                "base_url": config.get('OneAPI', {}).get('baseUrl', ''),
                "api_key_mask": self._mask_key(config.get('OneAPI', {}).get('apiKey', ''))
            },
            "raw_config": config
        }
        
        return openclaw_config
    
    def _transform_env_config(self, env_config: Dict[str, str]) -> Dict[str, Any]:
        """从环境变量转换"""
        return {
            "version": "3.0",
            "platform": "fastgpt",
            "gateway": {
                "auth": {
                    "mode": "token" if env_config.get('TOKEN') else "none",
                    "token": env_config.get('TOKEN', '')
                },
                "root_key": self._mask_key(env_config.get('ROOT_KEY', ''))
            },
            "oneapi": {
                "base_url": env_config.get('ONEAPI_URL', ''),
                "api_key_mask": self._mask_key(env_config.get('ONEAPI_KEY', ''))
            },
            "mongodb": {
                "uri_mask": self._mask_mongo_uri(env_config.get('MONGODB_URI', ''))
            },
            "redis": {
                "host": env_config.get('REDIS_HOST', 'localhost'),
                "port": int(env_config.get('REDIS_PORT', '6379'))
            },
            "raw_env": env_config
        }
    
    def _mask_key(self, key: str) -> str:
        """隐藏API Key中间部分"""
        if not key or len(key) < 8:
            return '*' * len(key) if key else ''
        return key[:4] + '*' * (len(key) - 8) + key[-4:]
    
    def _mask_mongo_uri(self, uri: str) -> str:
        """隐藏MongoDB URI中的密码"""
        if not uri:
            return ''
        # mongodb://username:password@host:port/db
        pattern = r'(mongodb://[^:]+:)([^@]+)(@.+)'  # noqa: W605
        return re.sub(pattern, r'\1****\3', uri)
    
    def to_openclaw_format(self) -> Dict[str, Any]:
        """导出为OpenClaw标准格式"""
        return self.raw_config
    
    def get_security_recommendations(self) -> List[Dict]:
        """获取FastGPT特定安全建议"""
        recommendations = []
        config = self.raw_config
        
        # Token检查
        gateway = config.get('gateway', {})
        auth = gateway.get('auth', {})
        
        if auth.get('mode') == 'none':
            recommendations.append({
                'severity': 'high',
                'category': 'authentication',
                'message': '未配置访问Token，任何人都可以访问FastGPT API',
                'fix': '在配置文件中设置 Auth.token'
            })
        elif auth.get('token_length', 0) < 16:
            recommendations.append({
                'severity': 'medium',
                'category': 'authentication',
                'message': 'Token长度较短，建议使用至少16位随机字符串',
                'fix': '使用 openssl rand -base64 24 生成高强度Token'
            })
        
        # Root Key检查
        if gateway.get('rootKey'):
            recommendations.append({
                'severity': 'high',
                'category': 'authorization',
                'message': 'Root Key具有最高权限，请确保其安全性',
                'warning': 'Root Key泄露可能导致系统完全失控',
                'fix': '定期轮换Root Key，不要在日志中记录'
            })
        
        # 开放注册检查
        system = config.get('system', {})
        if system.get('open_sign_up'):
            recommendations.append({
                'severity': 'medium',
                'category': 'access_control',
                'message': '已开放用户注册，建议配置邮箱验证或审核机制',
                'fix': '在SystemParams中配置注册限制或关闭注册'
            })
        
        # 文件上传检查
        file_upload = config.get('file_upload', {})
        if file_upload.get('enabled'):
            max_size = file_upload.get('max_size', 0)
            if max_size > 10:
                recommendations.append({
                    'severity': 'low',
                    'category': 'file_upload',
                    'message': f'文件上传限制较大 ({max_size}MB)，可能导致存储压力',
                    'fix': '根据实际需求调整 maxSize'
                })
            
            allowed = file_upload.get('allowed_extensions', [])
            dangerous = ['.exe', '.sh', '.bat', '.cmd', '.scr']
            for ext in dangerous:
                if ext in allowed:
                    recommendations.append({
                        'severity': 'critical',
                        'category': 'file_upload',
                        'message': f'允许上传危险文件类型: {ext}',
                        'fix': f'从 allowed_extensions 中移除 {ext}'
                    })
        
        # OneAPI配置检查
        oneapi = config.get('oneapi', {})
        if oneapi.get('api_key_mask'):
            recommendations.append({
                'severity': 'info',
                'category': 'llm_api',
                'message': '已配置OneAPI，请确保API Key安全',
                'fix': '定期轮换API Key，监控API使用情况'
            })
        
        # 飞书集成检查
        feishu = config.get('feishu', {})
        if feishu.get('enabled'):
            if not feishu.get('encrypt_key_set'):
                recommendations.append({
                    'severity': 'high',
                    'category': 'integration',
                    'message': '飞书集成未配置加密密钥，消息传输不安全',
                    'fix': '在Feishu配置中设置 encryptKey'
                })
        
        # MongoDB URI检查
        mongodb = config.get('mongodb', {})
        uri_mask = mongodb.get('uri_mask', '')
        if uri_mask and '****' not in uri_mask:
            recommendations.append({
                'severity': 'critical',
                'category': 'database',
                'message': 'MongoDB URI中可能包含明文密码',
                'warning': '建议使用环境变量或密钥管理服务',
                'fix': '将密码存储在环境变量中，不要在配置文件中使用明文'
            })
        
        # 代码解释器检查
        sandbox = config.get('sandbox', {})
        if sandbox.get('code_interpreter'):
            recommendations.append({
                'severity': 'high',
                'category': 'sandbox',
                'message': '已启用代码解释器功能，存在代码执行风险',
                'warning': '确保代码在隔离环境中运行',
                'fix': '配置资源限制和超时控制，监控代码执行'
            })
        
        # Redis配置检查
        redis = config.get('redis', {})
        if redis.get('host') == 'localhost' or redis.get('host') == '127.0.0.1':
            pass  # 本地Redis是正常的
        elif not redis.get('password'):
            recommendations.append({
                'severity': 'medium',
                'category': 'cache',
                'message': '使用远程Redis但未配置密码',
                'fix': '配置Redis密码，使用TLS连接'
            })
        
        return recommendations


# 使用示例
if __name__ == '__main__':
    try:
        adapter = FastGPTAdapter('config.json')
        openclaw_config = adapter.to_openclaw_format()
        
        print("FastGPT配置转换成功")
        print(f"模型数量: {len(openclaw_config.get('llm_models', []))}")
        
        # 获取安全建议
        recommendations = adapter.get_security_recommendations()
        if recommendations:
            print(f"\n发现 {len(recommendations)} 个安全建议:")
            for rec in recommendations:
                print(f"  [{rec['severity'].upper()}] {rec['message']}")
        else:
            print("\n未发现问题，配置安全")
    
    except FileNotFoundError:
        print("示例文件不存在，这是正常的演示代码")
