"""
MCP (Model Context Protocol) 安全测试框架
用于测试MCP服务器和客户端的安全漏洞
"""
import json
import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import re


class Severity(Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TestCategory(Enum):
    """测试类别"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    INJECTION = "injection"
    TRANSPORT = "transport"


@dataclass
class Vulnerability:
    """漏洞信息"""
    id: str
    name: str
    description: str
    severity: Severity
    category: TestCategory
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class TestResult:
    """测试结果"""
    test_name: str
    passed: bool
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


class MCPSecurityTestCase:
    """MCP安全测试用例基类"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    async def run(self, target: str, session: aiohttp.ClientSession) -> TestResult:
        """执行测试"""
        raise NotImplementedError


# ==================== 具体测试用例 ====================

class AuthenticationBypassTest(MCPSecurityTestCase):
    """认证绕过测试"""
    
    def __init__(self):
        super().__init__(
            "Authentication Bypass",
            "测试MCP端点是否存在认证绕过漏洞"
        )
    
    async def run(self, target: str, session: aiohttp.ClientSession) -> TestResult:
        vulnerabilities = []
        start_time = datetime.now()
        
        # 测试1: 无认证访问
        try:
            async with session.post(
                f"{target}/mcp/v1/initialize",
                json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
                timeout=5
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'result' in data:
                        vulnerabilities.append(Vulnerability(
                            id="MCP-AUTH-001",
                            name="Missing Authentication",
                            description="MCP端点允许无认证访问",
                            severity=Severity.CRITICAL,
                            category=TestCategory.AUTHENTICATION,
                            evidence=f"Endpoint {target}/mcp/v1/initialize accessible without auth",
                            remediation="Implement authentication mechanism (API key, OAuth, etc.)",
                            cwe_id="CWE-306"
                        ))
        except Exception as e:
            pass
        
        # 测试2: 弱认证绕过
        weak_tokens = ["", "null", "undefined", "admin", "test", "123456"]
        for token in weak_tokens:
            try:
                async with session.post(
                    f"{target}/mcp/v1/initialize",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
                    timeout=5
                ) as response:
                    if response.status == 200:
                        vulnerabilities.append(Vulnerability(
                            id="MCP-AUTH-002",
                            name="Weak Token Acceptance",
                            description=f"系统接受弱Token: {token}",
                            severity=Severity.HIGH,
                            category=TestCategory.AUTHENTICATION,
                            evidence=f"Token '{token}' was accepted",
                            remediation="Implement strong token validation and rejection of weak tokens"
                        ))
                        break
            except:
                continue
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return TestResult(
            test_name=self.name,
            passed=len(vulnerabilities) == 0,
            vulnerabilities=vulnerabilities,
            duration_ms=duration
        )


class SQLInjectionTest(MCPSecurityTestCase):
    """SQL注入测试"""
    
    def __init__(self):
        super().__init__(
            "SQL Injection",
            "测试MCP工具参数是否存在SQL注入漏洞"
        )
        
        self.sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "1 AND 1=1",
            "1' AND 1=1 --",
            "admin'--",
            "' OR '1'='1' --",
            "'; exec('xp_cmdshell \"dir\"') --",
        ]
    
    async def run(self, target: str, session: aiohttp.ClientSession) -> TestResult:
        vulnerabilities = []
        start_time = datetime.now()
        
        # 首先获取可用工具列表
        tools = []
        try:
            async with session.post(
                f"{target}/mcp/v1/tools/list",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                timeout=5
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    tools = data.get('result', {}).get('tools', [])
        except:
            pass
        
        # 对每个工具进行注入测试
        for tool in tools:
            tool_name = tool.get('name')
            
            for payload in self.sql_payloads:
                try:
                    # 构造包含注入的调用
                    params = {param: payload for param in tool.get('parameters', {}).get('properties', {}).keys()}
                    
                    async with session.post(
                        f"{target}/mcp/v1/tools/call",
                        json={
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {
                                "name": tool_name,
                                "arguments": params
                            },
                            "id": 1
                        },
                        timeout=10
                    ) as response:
                        response_text = await response.text()
                        
                        # 检测SQL错误信息
                        sql_errors = [
                            "sql syntax",
                            "syntax error",
                            "unexpected token",
                            "invalid query",
                            "pg_query",
                            "mysql_error",
                            "sqlite_error",
                            "ORA-",
                            "SQL Server",
                            "PostgreSQL"
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response_text.lower():
                                vulnerabilities.append(Vulnerability(
                                    id="MCP-INJ-001",
                                    name="SQL Injection",
                                    description=f"Tool '{tool_name}' appears vulnerable to SQL injection",
                                    severity=Severity.CRITICAL,
                                    category=TestCategory.INJECTION,
                                    evidence=f"Payload: {payload[:30]}... Response contains: {error}",
                                    remediation="Use parameterized queries and input validation",
                                    cwe_id="CWE-89"
                                ))
                                break
                        
                        if vulnerabilities:
                            break
                            
                except Exception as e:
                    continue
            
            if vulnerabilities:
                break
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return TestResult(
            test_name=self.name,
            passed=len(vulnerabilities) == 0,
            vulnerabilities=vulnerabilities,
            details={"tools_tested": len(tools)},
            duration_ms=duration
        )


class CommandInjectionTest(MCPSecurityTestCase):
    """命令注入测试"""
    
    def __init__(self):
        super().__init__(
            "Command Injection",
            "测试MCP工具是否存在命令注入漏洞"
        )
        
        self.cmd_payloads = [
            "; id",
            "; whoami",
            "| ls",
            "`whoami`",
            "$(id)",
            "; cat /etc/passwd",
            "&& echo vulnerable",
            "; ping -c 1 127.0.0.1",
        ]
    
    async def run(self, target: str, session: aiohttp.ClientSession) -> TestResult:
        vulnerabilities = []
        start_time = datetime.now()
        
        # 获取工具列表
        tools = []
        try:
            async with session.post(
                f"{target}/mcp/v1/tools/list",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                timeout=5
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    tools = data.get('result', {}).get('tools', [])
        except:
            pass
        
        # 测试每个工具
        for tool in tools:
            tool_name = tool.get('name')
            
            for payload in self.cmd_payloads:
                try:
                    params = {param: payload for param in tool.get('parameters', {}).get('properties', {}).keys()}
                    
                    async with session.post(
                        f"{target}/mcp/v1/tools/call",
                        json={
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {
                                "name": tool_name,
                                "arguments": params
                            },
                            "id": 1
                        },
                        timeout=15
                    ) as response:
                        response_text = await response.text()
                        
                        # 检测命令执行证据
                        cmd_indicators = [
                            "uid=",
                            "gid=",
                            "root:",
                            "bin/bash",
                            "usr/bin",
                            "vulnerable",
                            "PING",
                            "64 bytes from"
                        ]
                        
                        for indicator in cmd_indicators:
                            if indicator.lower() in response_text.lower():
                                vulnerabilities.append(Vulnerability(
                                    id="MCP-INJ-002",
                                    name="Command Injection",
                                    description=f"Tool '{tool_name}' is vulnerable to command injection",
                                    severity=Severity.CRITICAL,
                                    category=TestCategory.INJECTION,
                                    evidence=f"Command output detected: {indicator}",
                                    remediation="Never pass user input directly to system calls. Use allowlists and parameterization.",
                                    cwe_id="CWE-78"
                                ))
                                break
                        
                        if vulnerabilities:
                            break
                            
                except:
                    continue
            
            if vulnerabilities:
                break
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return TestResult(
            test_name=self.name,
            passed=len(vulnerabilities) == 0,
            vulnerabilities=vulnerabilities,
            duration_ms=duration
        )


class InformationDisclosureTest(MCPSecurityTestCase):
    """信息泄露测试"""
    
    def __init__(self):
        super().__init__(
            "Information Disclosure",
            "测试是否存在敏感信息泄露"
        )
    
    async def run(self, target: str, session: aiohttp.ClientSession) -> TestResult:
        vulnerabilities = []
        start_time = datetime.now()
        
        # 测试1: 错误信息泄露
        try:
            async with session.post(
                f"{target}/mcp/v1/tools/call",
                json={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "nonexistent_tool",
                        "arguments": {}
                    },
                    "id": 1
                },
                timeout=5
            ) as response:
                response_text = await response.text()
                
                # 检测敏感信息泄露模式
                sensitive_patterns = [
                    (r'[\"\']?password[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\']', "Password in response"),
                    (r'secret[_-]?key\s*[:=]\s*\S+', "Secret key in response"),
                    (r'api[_-]?key\s*[:=]\s*\S+', "API key in response"),
                    (r'token\s*[:=]\s*[\"\'][^\"\']+[\"\']', "Token in response"),
                    (r'/[a-zA-Z]:/[\w/]+', "Windows file path"),
                    (r'/home/[\w]+', "Linux home path"),
                    (r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', "IP address"),
                ]
                
                for pattern, description in sensitive_patterns:
                    matches = re.findall(pattern, response_text, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append(Vulnerability(
                            id="MCP-INFO-001",
                            name="Sensitive Information Disclosure",
                            description=f"Error response contains {description}",
                            severity=Severity.HIGH,
                            category=TestCategory.INFORMATION_DISCLOSURE,
                            evidence=f"Pattern found: {matches[0][:50]}...",
                            remediation="Remove sensitive data from error messages",
                            cwe_id="CWE-209"
                        ))
        except:
            pass
        
        # 测试2: 系统信息泄露
        try:
            async with session.get(f"{target}/", timeout=5) as response:
                headers = dict(response.headers)
                server_header = headers.get('Server', '')
                powered_by = headers.get('X-Powered-By', '')
                
                if server_header or powered_by:
                    vulnerabilities.append(Vulnerability(
                        id="MCP-INFO-002",
                        name="Server Information Disclosure",
                        description="Server headers reveal implementation details",
                        severity=Severity.LOW,
                        category=TestCategory.INFORMATION_DISCLOSURE,
                        evidence=f"Server: {server_header}, X-Powered-By: {powered_by}",
                        remediation="Remove or obfuscate Server and X-Powered-By headers"
                    ))
        except:
            pass
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return TestResult(
            test_name=self.name,
            passed=len(vulnerabilities) == 0,
            vulnerabilities=vulnerabilities,
            duration_ms=duration
        )


class TransportSecurityTest(MCPSecurityTestCase):
    """传输安全测试"""
    
    def __init__(self):
        super().__init__(
            "Transport Security",
            "测试传输层安全配置"
        )
    
    async def run(self, target: str, session: aiohttp.ClientSession) -> TestResult:
        vulnerabilities = []
        start_time = datetime.now()
        
        # 检查是否使用HTTPS
        if target.startswith('http://'):
            vulnerabilities.append(Vulnerability(
                id="MCP-TRANS-001",
                name="Unencrypted Communication",
                description="MCP endpoint uses HTTP instead of HTTPS",
                severity=Severity.HIGH,
                category=TestCategory.TRANSPORT,
                evidence=f"Endpoint URL: {target}",
                remediation="Enable HTTPS and redirect HTTP to HTTPS"
            ))
        
        # 检查HSTS头
        try:
            async with session.head(target, timeout=5, allow_redirects=True) as response:
                headers = dict(response.headers)
                
                if 'Strict-Transport-Security' not in headers:
                    vulnerabilities.append(Vulnerability(
                        id="MCP-TRANS-002",
                        name="Missing HSTS Header",
                        description="HTTP Strict Transport Security header is missing",
                        severity=Severity.MEDIUM,
                        category=TestCategory.TRANSPORT,
                        evidence="HSTS header not present",
                        remediation="Add Strict-Transport-Security header with appropriate max-age"
                    ))
        except:
            pass
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return TestResult(
            test_name=self.name,
            passed=len(vulnerabilities) == 0,
            vulnerabilities=vulnerabilities,
            duration_ms=duration
        )


# ==================== 测试框架主类 ====================

class MCPSecurityTestSuite:
    """MCP安全测试套件"""
    
    def __init__(self, target: str):
        self.target = target
        self.test_cases: List[MCPSecurityTestCase] = [
            AuthenticationBypassTest(),
            SQLInjectionTest(),
            CommandInjectionTest(),
            InformationDisclosureTest(),
            TransportSecurityTest(),
        ]
        self.results: List[TestResult] = []
    
    async def run_all(self, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """运行所有测试"""
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers or {}
        ) as session:
            for test_case in self.test_cases:
                print(f"Running test: {test_case.name}...")
                result = await test_case.run(self.target, session)
                self.results.append(result)
                
                if not result.passed:
                    print(f"  ⚠️  Found {len(result.vulnerabilities)} vulnerabilities")
                else:
                    print(f"  ✅ Passed")
        
        return self.generate_report()
    
    def generate_report(self) -> Dict[str, Any]:
        """生成测试报告"""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_tests = total_tests - passed_tests
        
        all_vulnerabilities = []
        for result in self.results:
            all_vulnerabilities.extend(result.vulnerabilities)
        
        # 按严重程度分组
        severity_counts = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0
        }
        
        for vuln in all_vulnerabilities:
            severity_counts[vuln.severity.value] += 1
        
        return {
            "summary": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "total_vulnerabilities": len(all_vulnerabilities),
                "severity_counts": severity_counts
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "name": v.name,
                    "severity": v.severity.value,
                    "category": v.category.value,
                    "description": v.description,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                    "cwe_id": v.cwe_id
                }
                for v in all_vulnerabilities
            ],
            "test_results": [
                {
                    "name": r.test_name,
                    "passed": r.passed,
                    "vulnerability_count": len(r.vulnerabilities),
                    "duration_ms": r.duration_ms
                }
                for r in self.results
            ]
        }


# 使用示例
async def main():
    """示例用法"""
    target = "http://localhost:3000"  # MCP服务器地址
    
    print("=" * 60)
    print("MCP Security Test Framework")
    print("=" * 60)
    print(f"Target: {target}\n")
    
    suite = MCPSecurityTestSuite(target)
    report = await suite.run_all()
    
    # 输出报告
    print("\n" + "=" * 60)
    print("Test Report Summary")
    print("=" * 60)
    
    summary = report["summary"]
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
    
    print("\nVulnerability Severity Distribution:")
    for severity, count in summary['severity_counts'].items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")
    
    if report["vulnerabilities"]:
        print("\nDetailed Vulnerabilities:")
        for vuln in report["vulnerabilities"]:
            print(f"\n[{vuln['severity'].upper()}] {vuln['id']}: {vuln['name']}")
            print(f"  Description: {vuln['description']}")
            print(f"  Evidence: {vuln['evidence']}")
            print(f"  Remediation: {vuln['remediation']}")
    
    # 保存报告
    report_file = f"mcp_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: {report_file}")


if __name__ == '__main__':
    asyncio.run(main())
