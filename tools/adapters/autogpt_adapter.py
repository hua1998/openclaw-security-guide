"""
AutoGPT 平台配置适配器
支持 .env 和 ai_settings.yaml 配置格式
"""
import json
import re
from pathlib import Path
from typing import Dict, Any

from .base_adapter import BaseAdapter


class AutoGPTAdapter(BaseAdapter):
    """AutoGPT 配置适配器"""
    
    PLATFORM_NAME = "autogpt"
    
    def _load_config(self) -> Dict[str, Any]:
        """加载AutoGPT配置"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        # 支持 .env 和 ai_settings.yaml
        if self.config_path.suffix == '.env':
            return self._parse_env()
        elif self.config_path.suffix in ['.yaml', '.yml']:
            return self._parse_yaml()
        elif self.config_path.suffix == '.json':
            return self._parse_json()
        else:
            raise ValueError(f"Unsupported config format: {self.config_path}")
    
    def _parse_env(self) -> Dict[str, Any]:
        """解析.env文件"""
        config = {}
        with open(self.config_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    config[key] = value.strip('"\'')
        
        return self._transform_env_config(config)
    
    def _parse_yaml(self) -> Dict[str, Any]:
        """解析YAML配置文件"""
        import yaml
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def _parse_json(self) -> Dict[str, Any]:
        """解析JSON配置文件"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _transform_env_config(self, env_config: Dict[str, str]) -> Dict[str, Any]:
        """将环境变量转换为OpenClaw格式"""
        openclaw_config = {
            "version": "3.0",
            "platform": "autogpt",
            "ai_settings": {
                "ai_name": env_config.get('AI_NAME', 'AutoGPT'),
                "ai_role": env_config.get('AI_ROLE', ''),
                "ai_goals": env_config.get('AI_GOALS', '').split(',') if env_config.get('AI_GOALS') else []
            },
            "gateway": {
                "auth": {
                    "mode": "api_key" if env_config.get('OPENAI_API_KEY') else "none",
                    "openai_api_key": self._mask_key(env_config.get('OPENAI_API_KEY', '')),
                    "openai_api_key_length": len(env_config.get('OPENAI_API_KEY', ''))
                },
                "model": {
                    "name": env_config.get('SMART_LLM_MODEL', 'gpt-4'),
                    "fast_model": env_config.get('FAST_LLM_MODEL', 'gpt-3.5-turbo')
                }
            },
            "sandbox": {
                "enabled": env_config.get('EXECUTE_LOCAL_COMMANDS', 'false').lower() == 'true',
                "allow_local_commands": env_config.get('EXECUTE_LOCAL_COMMANDS', 'false').lower() == 'true',
                "shell": env_config.get('SHELL', '/bin/bash'),
                "blocked_commands": env_config.get('BLOCKED_COMMANDS', '').split(',') if env_config.get('BLOCKED_COMMANDS') else [],
                "allowed_commands": env_config.get('ALLOWED_COMMANDS', '').split(',') if env_config.get('ALLOWED_COMMANDS') else []
            },
            "browser": {
                "headless": env_config.get('HEADLESS_BROWSER', 'true').lower() == 'true',
                "user_agent": env_config.get('USER_AGENT', ''),
                "safe_search": env_config.get('SAFE_SEARCH', 'off')
            },
            "memory": {
                "backend": env_config.get('MEMORY_BACKEND', 'local'),
                "redis_host": env_config.get('REDIS_HOST', ''),
                "redis_port": int(env_config.get('REDIS_PORT', '6379')) if env_config.get('REDIS_PORT') else None
            },
            "plugins": {
                "allowlist": env_config.get('ALLOWLISTED_PLUGINS', '').split(',') if env_config.get('ALLOWLISTED_PLUGINS') else [],
                "denylist": env_config.get('DENYLISTED_PLUGINS', '').split(',') if env_config.get('DENYLISTED_PLUGINS') else []
            },
            "rate_limits": {
                "openai_requests_per_minute": int(env_config.get('OPENAI_API_RPM', '10')),
                "openai_tokens_per_minute": int(env_config.get('OPENAI_API_TPM', '10000'))
            },
            "image_generation": {
                "provider": env_config.get('IMAGE_PROVIDER', 'dalle'),
                "size": env_config.get('IMAGE_SIZE', '256x256')
            },
            "tts": {
                "enabled": env_config.get('USE_TTS', 'false').lower() == 'true',
                "voice": env_config.get('TTS_VOICE', 'alloy')
            },
            "raw_env": env_config
        }
        
        return openclaw_config
    
    def _mask_key(self, key: str) -> str:
        """隐藏API Key中间部分"""
        if len(key) < 8:
            return '*' * len(key)
        return key[:4] + '*' * (len(key) - 8) + key[-4:]
    
    def to_openclaw_format(self) -> Dict[str, Any]:
        """导出为OpenClaw标准格式"""
        return self.raw_config
    
    def get_security_recommendations(self) -> list:
        """获取AutoGPT特定安全建议"""
        recommendations = []
        config = self.raw_config
        
        # API Key检查
        auth = config.get('gateway', {}).get('auth', {})
        if auth.get('mode') == 'none':
            recommendations.append({
                'severity': 'critical',
                'category': 'authentication',
                'message': '未配置OpenAI API Key，AutoGPT无法运行',
                'fix': '在.env文件中设置 OPENAI_API_KEY=sk-...'
            })
        elif auth.get('openai_api_key_length', 0) < 40:
            recommendations.append({
                'severity': 'high',
                'category': 'authentication',
                'message': 'OpenAI API Key格式不正确',
                'fix': '检查API Key是否完整，应以 sk- 开头'
            })
        
        # 本地命令执行检查
        sandbox = config.get('sandbox', {})
        if sandbox.get('allow_local_commands'):
            recommendations.append({
                'severity': 'critical',
                'category': 'sandbox',
                'message': '已启用本地命令执行，存在严重安全风险',
                'warning': '确保BLOCKED_COMMANDS包含所有危险命令',
                'fix': '设置 EXECUTE_LOCAL_COMMANDS=false 或配置严格的ALLOWED_COMMANDS'
            })
            
            # 检查是否有命令白名单
            allowed = sandbox.get('allowed_commands', [])
            if not allowed:
                recommendations.append({
                    'severity': 'critical',
                    'category': 'sandbox',
                    'message': '未配置允许的命令列表，所有命令都可能被执行',
                    'fix': '设置 ALLOWED_COMMANDS=ls,cat,echo,git 等必要命令'
                })
            
            # 检查危险命令是否在阻止列表
            blocked = sandbox.get('blocked_commands', [])
            dangerous_commands = ['rm', 'dd', 'mkfs', 'format', 'del', 'rd', 'reg']
            for cmd in dangerous_commands:
                if cmd not in blocked:
                    recommendations.append({
                        'severity': 'high',
                        'category': 'sandbox',
                        'message': f'危险命令 "{cmd}" 未在阻止列表中',
                        'fix': f'添加到 BLOCKED_COMMANDS: {cmd}'
                    })
        
        # 浏览器安全检查
        browser = config.get('browser', {})
        if not browser.get('safe_search') == 'on':
            recommendations.append({
                'severity': 'low',
                'category': 'browser',
                'message': '未启用安全搜索，可能访问不安全内容',
                'fix': '设置 SAFE_SEARCH=on'
            })
        
        # 插件安全检查
        plugins = config.get('plugins', {})
        allowlist = plugins.get('allowlist', [])
        denylist = plugins.get('denylist', [])
        
        if not allowlist and not denylist:
            recommendations.append({
                'severity': 'medium',
                'category': 'plugins',
                'message': '未配置插件白名单或黑名单，所有插件都可能被加载',
                'fix': '设置 ALLOWLISTED_PLUGINS=plugin1,plugin2 指定允许的插件'
            })
        
        # 速率限制检查
        rate_limits = config.get('rate_limits', {})
        rpm = rate_limits.get('openai_requests_per_minute', 10)
        if rpm > 60:
            recommendations.append({
                'severity': 'low',
                'category': 'rate_limiting',
                'message': f'OpenAI请求速率限制较高 ({rpm} RPM)，可能导致API费用过高',
                'info': '当前配置可能在意外情况下产生大量API调用'
            })
        
        # Redis配置检查
        memory = config.get('memory', {})
        if memory.get('backend') == 'redis':
            if not memory.get('redis_host'):
                recommendations.append({
                    'severity': 'medium',
                    'category': 'memory',
                    'message': 'Redis后端已启用但未配置主机地址',
                    'fix': '设置 REDIS_HOST=localhost 或 Redis服务器地址'
                })
        
        return recommendations


# 使用示例
if __name__ == '__main__':
    import json
    
    try:
        adapter = AutoGPTAdapter('.env')
        openclaw_config = adapter.to_openclaw_format()
        
        print("AutoGPT配置转换成功")
        print(f"AI名称: {openclaw_config.get('ai_settings', {}).get('ai_name')}")
        print(f"OpenClaw格式:\n{json.dumps(openclaw_config, indent=2, ensure_ascii=False)}")
        
        # 获取安全建议
        recommendations = adapter.get_security_recommendations()
        if recommendations:
            print(f"\n发现 {len(recommendations)} 个安全建议:")
            for rec in recommendations:
                print(f"  [{rec['severity'].upper()}] {rec['message']}")
    
    except FileNotFoundError:
        print("示例文件不存在，这是正常的演示代码")
