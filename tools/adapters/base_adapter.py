"""
多平台配置适配器基类
提供统一的配置转换接口
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any


class BaseAdapter(ABC):
    """配置适配器基类"""
    
    PLATFORM_NAME = "base"
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.raw_config = self._load_config()
    
    @abstractmethod
    def _load_config(self) -> Dict[str, Any]:
        """加载平台特定配置"""
        pass
    
    @abstractmethod
    def to_openclaw_format(self) -> Dict[str, Any]:
        """转换为OpenClaw标准格式"""
        pass
    
    def validate(self) -> bool:
        """验证配置有效性"""
        return self.config_path.exists()
    
    def get_platform_info(self) -> Dict[str, str]:
        """获取平台信息"""
        return {
            'platform': self.PLATFORM_NAME,
            'config_path': str(self.config_path),
            'status': 'loaded' if self.raw_config else 'error'
        }
