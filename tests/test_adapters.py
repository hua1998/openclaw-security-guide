#!/usr/bin/env python3
"""
适配器测试套件
测试多平台适配器的功能
"""

import pytest
import tempfile
import os
from pathlib import Path

# 测试 Dify 适配器
def test_dify_adapter_env_parsing():
    """测试 Dify 适配器解析 .env 文件"""
    from tools.adapters.dify_adapter import DifyAdapter
    
    adapter = DifyAdapter()
    
    # 创建临时 .env 文件
    env_content = """
CONSOLE_API_URL=http://localhost:5001
CONSOLE_WEB_URL=http://localhost:3000
PORT=5001
SECRET_KEY=test-secret-key-123
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
        f.write(env_content)
        temp_path = f.name
    
    try:
        config = adapter.parse_config(temp_path)
        
        assert config['gateway']['host'] == 'localhost'
        assert config['gateway']['port'] == 5001
        assert config['gateway']['auth']['mode'] == 'api_key'
        assert 'SECRET_KEY' in config['security']['audit_logging']['custom_fields']
        
    finally:
        os.unlink(temp_path)

def test_dify_adapter_security_recommendations():
    """测试 Dify 适配器安全建议"""
    from tools.adapters.dify_adapter import DifyAdapter
    
    adapter = DifyAdapter()
    
    # 不安全的配置
    insecure_config = {
        'gateway': {'auth': {'mode': 'none'}},
        'security': {'sandbox': {'enabled': False}},
        'tools': {'exec': {'security': 'allow'}}
    }
    
    issues = adapter.check_security_issues(insecure_config)
    
    assert len(issues) >= 3
    issue_ids = [i['id'] for i in issues]
    assert 'DIFY001' in issue_ids  # 无认证
    assert 'DIFY002' in issue_ids  # 无沙箱
    assert 'DIFY003' in issue_ids  # 允许执行

def test_autogpt_adapter_parsing():
    """测试 AutoGPT 适配器解析"""
    from tools.adapters.autogpt_adapter import AutoGPTAdapter
    
    adapter = AutoGPTAdapter()
    
    env_content = """
OPENAI_API_KEY=sk-test123
EXECUTE_LOCAL_COMMANDS=True
SHELL_ALLOWLIST=ls,cat,grep
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
        f.write(env_content)
        temp_path = f.name
    
    try:
        config = adapter.parse_config(temp_path)
        
        assert config['tools']['exec']['enabled'] == True
        assert 'ls' in config['tools']['exec']['allowlist']
        assert 'rm' not in config['tools']['exec']['allowlist']
        
    finally:
        os.unlink(temp_path)

def test_autogpt_adapter_dangerous_exec():
    """测试 AutoGPT 适配器检测危险执行权限"""
    from tools.adapters.autogpt_adapter import AutoGPTAdapter
    
    adapter = AutoGPTAdapter()
    
    dangerous_config = {
        'tools': {
            'exec': {
                'enabled': True,
                'allowlist': ['rm', 'sudo', 'curl']
            }
        }
    }
    
    issues = adapter.check_security_issues(dangerous_config)
    
    dangerous_issues = [i for i in issues if i['severity'] == 'critical']
    assert len(dangerous_issues) > 0

def test_fastgpt_adapter_json_parsing():
    """测试 FastGPT 适配器 JSON 解析"""
    from tools.adapters.fastgpt_adapter import FastGPTAdapter
    
    adapter = FastGPTAdapter()
    
    json_content = """{
        "SystemParams": {
            "rootKey": "sk-test-key",
            "openapiPrefix": "fastgpt"
        },
        "UploadLimit": 10
    }"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write(json_content)
        temp_path = f.name
    
    try:
        config = adapter.parse_config(temp_path)
        
        assert config['gateway']['auth']['mode'] == 'api_key'
        assert config['upload']['max_size_mb'] == 10
        
    finally:
        os.unlink(temp_path)

def test_fastgpt_adapter_root_key_exposure():
    """测试 FastGPT 适配器检测 rootKey 暴露"""
    from tools.adapters.fastgpt_adapter import FastGPTAdapter
    
    adapter = FastGPTAdapter()
    
    config = {
        'gateway': {
            'auth': {
                'root_key': 'sk-test-exposed-key',
                'mode': 'api_key'
            }
        }
    }
    
    issues = adapter.check_security_issues(config)
    
    root_key_issues = [i for i in issues if 'rootKey' in i['description']]
    assert len(root_key_issues) > 0

def test_adapter_base_class():
    """测试适配器基类"""
    from tools.adapters.base_adapter import BaseAdapter, ConfigIssue
    
    # 测试 ConfigIssue 数据类
    issue = ConfigIssue(
        id="TEST001",
        title="Test Issue",
        description="Test description",
        severity="high",
        recommendation="Fix it"
    )
    
    assert issue.id == "TEST001"
    assert issue.severity == "high"
    
    # 测试抽象基类不能被实例化
    with pytest.raises(TypeError):
        BaseAdapter()

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
