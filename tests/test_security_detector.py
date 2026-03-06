"""security_detector.py 单元测试"""
import unittest
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from security_detector import load_config, check_auth, check_session, check_tools, calculate_score


class TestSecurityDetector(unittest.TestCase):
    """安全检测器测试套件"""
    
    def setUp(self):
        """设置测试数据"""
        self.test_config = {
            "gateway": {
                "auth": {
                    "mode": "token",
                    "token": "a" * 32
                }
            },
            "session": {
                "dmScope": "per-channel-peer"
            },
            "tools": {
                "profile": "minimal",
                "deny": ["group:automation", "group:runtime"]
            },
            "sandbox": {
                "enabled": True,
                "image": "docker.io/openclaw/sandbox:latest"
            },
            "audit": {
                "enabled": True
            }
        }
    
    def test_check_auth_with_valid_token(self):
        """测试有效Token认证"""
        issues = check_auth(self.test_config)
        auth_issues = [i for i in issues if i['category'] == 'authentication']
        self.assertEqual(len(auth_issues), 0, "有效Token不应产生认证问题")
    
    def test_check_auth_without_token(self):
        """测试缺少Token认证"""
        self.test_config['gateway']['auth']['mode'] = 'none'
        issues = check_auth(self.test_config)
        critical_issues = [i for i in issues if i['risk'] == 'critical']
        self.assertTrue(len(critical_issues) > 0, "缺少Token应产生严重问题")
    
    def test_check_auth_weak_token(self):
        """测试弱Token"""
        self.test_config['gateway']['auth']['token'] = 'short'
        issues = check_auth(self.test_config)
        length_issues = [i for i in issues if 'length' in i.get('check', '')]
        self.assertTrue(len(length_issues) > 0, "短Token应产生长度警告")
    
    def test_check_session_isolation(self):
        """测试会话隔离"""
        # 测试全局会话（不安全）
        self.test_config['session']['dmScope'] = 'global'
        issues = check_session(self.test_config)
        self.assertTrue(len(issues) > 0, "全局会话应产生问题")
        
        # 测试隔离会话（安全）
        self.test_config['session']['dmScope'] = 'per-channel-peer'
        issues = check_session(self.test_config)
        self.assertEqual(len(issues), 0, "隔离会话不应产生问题")
    
    def test_check_tools_profile(self):
        """测试工具配置"""
        # 测试宽松profile
        self.test_config['tools']['profile'] = 'full'
        issues = check_tools(self.test_config)
        self.assertTrue(len(issues) > 0, "宽松profile应产生警告")
        
        # 测试最小profile
        self.test_config['tools']['profile'] = 'minimal'
        issues = check_tools(self.test_config)
        profile_issues = [i for i in issues if i['check'] == 'tools.profile']
        self.assertEqual(len(profile_issues), 0, "最小profile不应产生profile警告")
    
    def test_calculate_score(self):
        """测试评分计算"""
        # 无问题时应得满分
        no_issues = []
        score = calculate_score(no_issues)
        self.assertEqual(score, 100, "无问题时应为满分")
        
        # 有严重问题时应扣分
        critical_issues = [{'risk': 'critical'}]
        score = calculate_score(critical_issues)
        self.assertLess(score, 100, "有问题时应扣分")


class TestConfigLoading(unittest.TestCase):
    """配置加载测试"""
    
    def test_load_valid_config(self):
        """测试加载有效配置"""
        # 创建临时测试文件
        test_config = {
            "gateway": {"auth": {"mode": "token", "token": "test" * 8}}
        }
        temp_path = Path('/tmp/test_config.json')
        with open(temp_path, 'w') as f:
            json.dump(test_config, f)
        
        loaded = load_config(str(temp_path))
        self.assertEqual(loaded['gateway']['auth']['mode'], 'token')
        
        # 清理
        temp_path.unlink()


if __name__ == '__main__':
    unittest.main()
