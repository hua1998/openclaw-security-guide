"""
Skills 供应链签名验证系统
提供技能代码的数字签名和验证机制
"""
import os
import json
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


@dataclass
class SkillManifest:
    """技能清单"""
    name: str
    version: str
    author: str
    description: str
    entry_point: str
    dependencies: List[str]
    permissions: List[str]
    created_at: str
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SkillManifest':
        return cls(**data)


@dataclass
class SkillSignature:
    """技能签名"""
    skill_name: str
    version: str
    hash_algorithm: str
    content_hash: str
    signature: str
    public_key_fingerprint: str
    timestamp: str
    signer: str


class KeyManager:
    """密钥管理器"""
    
    def __init__(self, key_dir: str = "~/.openclaw/keys"):
        self.key_dir = Path(key_dir).expanduser()
        self.key_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_keypair(self, name: str, password: Optional[str] = None) -> Tuple[str, str]:
        """
        生成RSA密钥对
        
        Returns:
            (public_key_path, private_key_path)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # 序列化私钥
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password.encode())
            if password else serialization.NoEncryption()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        # 序列化公钥
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 保存密钥
        private_path = self.key_dir / f"{name}_private.pem"
        public_path = self.key_dir / f"{name}_public.pem"
        
        with open(private_path, 'wb') as f:
            f.write(private_pem)
        
        with open(public_path, 'wb') as f:
            f.write(public_pem)
        
        # 设置权限
        os.chmod(private_path, 0o600)
        os.chmod(public_path, 0o644)
        
        return str(public_path), str(private_path)
    
    def load_private_key(self, name: str, password: Optional[str] = None):
        """加载私钥"""
        private_path = self.key_dir / f"{name}_private.pem"
        
        with open(private_path, 'rb') as f:
            private_pem = f.read()
        
        return serialization.load_pem_private_key(
            private_pem,
            password=password.encode() if password else None,
            backend=default_backend()
        )
    
    def load_public_key(self, name: str):
        """加载公钥"""
        public_path = self.key_dir / f"{name}_public.pem"
        
        with open(public_path, 'rb') as f:
            public_pem = f.read()
        
        return serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
    
    def get_key_fingerprint(self, name: str) -> str:
        """获取公钥指纹"""
        public_key = self.load_public_key(name)
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_bytes).hexdigest()[:16]


class SkillSigner:
    """技能签名器"""
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
    
    def sign_skill(self, skill_path: str, signer_name: str, 
                   password: Optional[str] = None) -> SkillSignature:
        """
        对技能进行签名
        
        Args:
            skill_path: 技能目录路径
            signer_name: 签名者密钥名称
            password: 私钥密码
        
        Returns:
            SkillSignature: 签名信息
        """
        skill_dir = Path(skill_path)
        
        # 读取清单文件
        manifest_path = skill_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found: {manifest_path}")
        
        with open(manifest_path, 'r') as f:
            manifest = SkillManifest.from_dict(json.load(f))
        
        # 计算内容哈希
        content_hash = self._calculate_skill_hash(skill_dir)
        
        # 加载私钥
        private_key = self.key_manager.load_private_key(signer_name, password)
        
        # 创建签名数据
        sign_data = f"{manifest.name}:{manifest.version}:{content_hash}"
        
        # 签名
        signature = private_key.sign(
            sign_data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # 获取公钥指纹
        fingerprint = self.key_manager.get_key_fingerprint(signer_name)
        
        return SkillSignature(
            skill_name=manifest.name,
            version=manifest.version,
            hash_algorithm="SHA256",
            content_hash=content_hash,
            signature=base64.b64encode(signature).decode(),
            public_key_fingerprint=fingerprint,
            timestamp=datetime.now().isoformat(),
            signer=signer_name
        )
    
    def _calculate_skill_hash(self, skill_dir: Path) -> str:
        """计算技能目录的哈希值"""
        hasher = hashlib.sha256()
        
        # 遍历目录中的所有文件
        for file_path in sorted(skill_dir.rglob("*")):
            if file_path.is_file():
                # 计算相对路径
                rel_path = file_path.relative_to(skill_dir)
                
                # 跳过签名文件
                if rel_path.name == "signature.json":
                    continue
                
                # 添加文件路径
                hasher.update(str(rel_path).encode())
                
                # 添加文件内容
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def save_signature(self, skill_path: str, signature: SkillSignature):
        """保存签名到技能目录"""
        signature_path = Path(skill_path) / "signature.json"
        
        with open(signature_path, 'w') as f:
            json.dump({
                'skill_name': signature.skill_name,
                'version': signature.version,
                'hash_algorithm': signature.hash_algorithm,
                'content_hash': signature.content_hash,
                'signature': signature.signature,
                'public_key_fingerprint': signature.public_key_fingerprint,
                'timestamp': signature.timestamp,
                'signer': signature.signer
            }, f, indent=2)


class SkillVerifier:
    """技能验证器"""
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.trusted_signers: Dict[str, str] = {}  # fingerprint -> signer_name
    
    def add_trusted_signer(self, signer_name: str):
        """添加可信签名者"""
        fingerprint = self.key_manager.get_key_fingerprint(signer_name)
        self.trusted_signers[fingerprint] = signer_name
    
    def verify_skill(self, skill_path: str) -> Dict[str, any]:
        """
        验证技能签名
        
        Returns:
            {
                'valid': bool,
                'trusted': bool,
                'skill_name': str,
                'version': str,
                'signer': str,
                'issues': List[str]
            }
        """
        skill_dir = Path(skill_path)
        issues = []
        
        # 检查签名文件
        signature_path = skill_dir / "signature.json"
        if not signature_path.exists():
            return {
                'valid': False,
                'trusted': False,
                'skill_name': '',
                'version': '',
                'signer': '',
                'issues': ['Signature file not found']
            }
        
        # 读取签名
        with open(signature_path, 'r') as f:
            sig_data = json.load(f)
        
        signature = SkillSignature(**sig_data)
        
        # 检查签名者是否可信
        trusted = signature.public_key_fingerprint in self.trusted_signers
        if not trusted:
            issues.append(f"Unknown signer: {signature.signer}")
        
        # 计算当前内容哈希
        signer = SkillSigner(self.key_manager)
        current_hash = signer._calculate_skill_hash(skill_dir)
        
        # 检查哈希是否匹配
        if current_hash != signature.content_hash:
            issues.append("Content hash mismatch - skill may have been modified")
        
        # 验证签名
        try:
            # 加载签名者公钥
            signer_key_name = self.trusted_signers.get(
                signature.public_key_fingerprint, 
                signature.signer
            )
            public_key = self.key_manager.load_public_key(signer_key_name)
            
            # 重建签名数据
            sign_data = f"{signature.skill_name}:{signature.version}:{signature.content_hash}"
            
            # 验证签名
            public_key.verify(
                base64.b64decode(signature.signature),
                sign_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signature_valid = True
            
        except Exception as e:
            signature_valid = False
            issues.append(f"Signature verification failed: {str(e)}")
        
        return {
            'valid': signature_valid and len(issues) == 0,
            'trusted': trusted,
            'skill_name': signature.skill_name,
            'version': signature.version,
            'signer': signature.signer,
            'issues': issues
        }
    
    def verify_skill_directory(self, skills_dir: str) -> List[Dict]:
        """验证目录中的所有技能"""
        results = []
        skills_path = Path(skills_dir)
        
        for skill_dir in skills_path.iterdir():
            if skill_dir.is_dir() and (skill_dir / "manifest.json").exists():
                result = self.verify_skill(str(skill_dir))
                result['path'] = str(skill_dir)
                results.append(result)
        
        return results


class SkillTrustManager:
    """技能信任管理器"""
    
    def __init__(self, trust_db_path: str = "~/.openclaw/trust_db.json"):
        self.trust_db_path = Path(trust_db_path).expanduser()
        self.trust_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.trusted_skills: Dict[str, Dict] = {}
        self._load_trust_db()
    
    def _load_trust_db(self):
        """加载信任数据库"""
        if self.trust_db_path.exists():
            with open(self.trust_db_path, 'r') as f:
                self.trusted_skills = json.load(f)
    
    def _save_trust_db(self):
        """保存信任数据库"""
        with open(self.trust_db_path, 'w') as f:
            json.dump(self.trusted_skills, f, indent=2)
    
    def add_trusted_skill(self, skill_name: str, signature: SkillSignature,
                          trust_level: str = "medium"):
        """添加可信技能"""
        self.trusted_skills[skill_name] = {
            'versions': [signature.version],
            'trusted_signers': [signature.signer],
            'trust_level': trust_level,
            'added_at': datetime.now().isoformat()
        }
        self._save_trust_db()
    
    def is_trusted(self, skill_name: str, version: str, 
                   signer: str) -> bool:
        """检查技能是否可信"""
        if skill_name not in self.trusted_skills:
            return False
        
        skill_trust = self.trusted_skills[skill_name]
        
        return (
            version in skill_trust['versions'] and
            signer in skill_trust['trusted_signers']
        )
    
    def get_trust_level(self, skill_name: str) -> str:
        """获取技能信任级别"""
        if skill_name not in self.trusted_skills:
            return "untrusted"
        
        return self.trusted_skills[skill_name].get('trust_level', 'low')


# 使用示例
if __name__ == '__main__':
    # 初始化密钥管理
    key_manager = KeyManager()
    
    # 生成签名密钥对
    print("Generating signing keys...")
    pub_path, priv_path = key_manager.generate_keypair("openclaw_official")
    print(f"Keys generated: {pub_path}, {priv_path}")
    
    # 创建示例技能
    skill_dir = "/tmp/test_skill"
    os.makedirs(skill_dir, exist_ok=True)
    
    # 创建清单文件
    manifest = SkillManifest(
        name="test_skill",
        version="1.0.0",
        author="OpenClaw Team",
        description="A test skill for demonstration",
        entry_point="main.py",
        dependencies=["requests", "pydantic"],
        permissions=["file:read", "network:http"],
        created_at=datetime.now().isoformat()
    )
    
    with open(f"{skill_dir}/manifest.json", 'w') as f:
        json.dump(manifest.to_dict(), f, indent=2)
    
    # 创建示例代码
    with open(f"{skill_dir}/main.py", 'w') as f:
        f.write("# Test skill main file\n")
    
    # 签名技能
    print("\nSigning skill...")
    signer = SkillSigner(key_manager)
    signature = signer.sign_skill(skill_dir, "openclaw_official")
    signer.save_signature(skill_dir, signature)
    print(f"Signature saved: {signature.content_hash[:16]}...")
    
    # 验证技能
    print("\nVerifying skill...")
    verifier = SkillVerifier(key_manager)
    verifier.add_trusted_signer("openclaw_official")
    
    result = verifier.verify_skill(skill_dir)
    print(f"Verification result:")
    print(f"  Valid: {result['valid']}")
    print(f"  Trusted: {result['trusted']}")
    print(f"  Skill: {result['skill_name']}@{result['version']}")
    print(f"  Signer: {result['signer']}")
    if result['issues']:
        print(f"  Issues: {result['issues']}")
    
    # 信任管理
    print("\nManaging trust...")
    trust_manager = SkillTrustManager()
    trust_manager.add_trusted_skill("test_skill", signature, "high")
    
    is_trusted = trust_manager.is_trusted("test_skill", "1.0.0", "openclaw_official")
    print(f"Skill trusted: {is_trusted}")
