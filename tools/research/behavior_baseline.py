"""
Agent 行为异常基线建模系统
用于建立用户和Agent的行为基线，检测异常行为模式
"""
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import statistics


@dataclass
class BehaviorEvent:
    """行为事件"""
    timestamp: datetime
    event_type: str  # command, file_access, network, api_call
    user_id: str
    session_id: str
    action: str
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    result: str = ""
    duration_ms: int = 0


@dataclass
class BehaviorProfile:
    """行为画像"""
    user_id: str
    created_at: datetime
    updated_at: datetime
    
    # 时间模式
    active_hours: Dict[int, int] = field(default_factory=dict)  # 小时 -> 活动次数
    active_days: Dict[int, int] = field(default_factory=dict)   # 星期 -> 活动次数
    
    # 操作频率
    command_frequency: Dict[str, int] = field(default_factory=dict)
    file_access_pattern: Dict[str, int] = field(default_factory=dict)
    network_target_pattern: Dict[str, int] = field(default_factory=dict)
    
    # 统计指标
    avg_session_duration: float = 0.0
    avg_commands_per_session: float = 0.0
    avg_response_time: float = 0.0
    
    # 异常历史
    anomaly_history: List[Dict] = field(default_factory=list)


class BehaviorCollector:
    """行为数据采集器"""
    
    def __init__(self, storage_path: str = "/tmp/behavior_logs"):
        self.storage_path = storage_path
        self.event_buffer: List[BehaviorEvent] = []
        self.buffer_size = 100
    
    def record_event(self, event: BehaviorEvent):
        """记录行为事件"""
        self.event_buffer.append(event)
        
        # 缓冲区满时持久化
        if len(self.event_buffer) >= self.buffer_size:
            self._flush_buffer()
    
    def _flush_buffer(self):
        """将缓冲区数据写入存储"""
        import os
        os.makedirs(self.storage_path, exist_ok=True)
        
        date_str = datetime.now().strftime("%Y%m%d")
        file_path = f"{self.storage_path}/events_{date_str}.jsonl"
        
        with open(file_path, 'a') as f:
            for event in self.event_buffer:
                event_dict = {
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type,
                    'user_id': event.user_id,
                    'session_id': event.session_id,
                    'action': event.action,
                    'target': event.target,
                    'parameters': event.parameters,
                    'result': event.result,
                    'duration_ms': event.duration_ms
                }
                f.write(json.dumps(event_dict) + '\n')
        
        self.event_buffer = []
    
    def load_events(self, user_id: Optional[str] = None, 
                    days: int = 30) -> List[BehaviorEvent]:
        """加载历史事件"""
        events = []
        
        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            date_str = date.strftime("%Y%m%d")
            file_path = f"{self.storage_path}/events_{date_str}.jsonl"
            
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        data = json.loads(line.strip())
                        if user_id and data['user_id'] != user_id:
                            continue
                        
                        events.append(BehaviorEvent(
                            timestamp=datetime.fromisoformat(data['timestamp']),
                            event_type=data['event_type'],
                            user_id=data['user_id'],
                            session_id=data['session_id'],
                            action=data['action'],
                            target=data['target'],
                            parameters=data.get('parameters', {}),
                            result=data.get('result', ''),
                            duration_ms=data.get('duration_ms', 0)
                        ))
            except FileNotFoundError:
                continue
        
        return events


class BaselineBuilder:
    """基线建立器"""
    
    def __init__(self, collector: BehaviorCollector):
        self.collector = collector
    
    def build_baseline(self, user_id: str, days: int = 14) -> BehaviorProfile:
        """
        为用户建立行为基线
        
        Args:
            user_id: 用户ID
            days: 历史数据天数
        
        Returns:
            BehaviorProfile: 行为画像
        """
        events = self.collector.load_events(user_id, days)
        
        if not events:
            return BehaviorProfile(
                user_id=user_id,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        
        profile = BehaviorProfile(
            user_id=user_id,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # 分析时间模式
        self._analyze_temporal_patterns(events, profile)
        
        # 分析操作频率
        self._analyze_operation_frequency(events, profile)
        
        # 分析会话模式
        self._analyze_session_patterns(events, profile)
        
        return profile
    
    def _analyze_temporal_patterns(self, events: List[BehaviorEvent], 
                                   profile: BehaviorProfile):
        """分析时间模式"""
        for event in events:
            hour = event.timestamp.hour
            weekday = event.timestamp.weekday()
            
            profile.active_hours[hour] = profile.active_hours.get(hour, 0) + 1
            profile.active_days[weekday] = profile.active_days.get(weekday, 0) + 1
    
    def _analyze_operation_frequency(self, events: List[BehaviorEvent],
                                     profile: BehaviorProfile):
        """分析操作频率"""
        for event in events:
            # 命令频率
            if event.event_type == 'command':
                cmd_key = f"{event.action}:{event.target}"
                profile.command_frequency[cmd_key] = \
                    profile.command_frequency.get(cmd_key, 0) + 1
            
            # 文件访问模式
            elif event.event_type == 'file_access':
                ext = event.target.split('.')[-1] if '.' in event.target else 'unknown'
                profile.file_access_pattern[ext] = \
                    profile.file_access_pattern.get(ext, 0) + 1
            
            # 网络目标模式
            elif event.event_type == 'network':
                domain = event.target.split('/')[2] if '//' in event.target else event.target
                profile.network_target_pattern[domain] = \
                    profile.network_target_pattern.get(domain, 0) + 1
    
    def _analyze_session_patterns(self, events: List[BehaviorEvent],
                                  profile: BehaviorProfile):
        """分析会话模式"""
        # 按会话分组
        sessions: Dict[str, List[BehaviorEvent]] = defaultdict(list)
        for event in events:
            sessions[event.session_id].append(event)
        
        if not sessions:
            return
        
        # 计算会话时长
        session_durations = []
        commands_per_session = []
        
        for session_id, session_events in sessions.items():
            if len(session_events) < 2:
                continue
            
            start_time = min(e.timestamp for e in session_events)
            end_time = max(e.timestamp for e in session_events)
            duration = (end_time - start_time).total_seconds() / 60  # 分钟
            
            session_durations.append(duration)
            
            # 统计命令数
            cmd_count = sum(1 for e in session_events if e.event_type == 'command')
            commands_per_session.append(cmd_count)
        
        if session_durations:
            profile.avg_session_duration = statistics.mean(session_durations)
        
        if commands_per_session:
            profile.avg_commands_per_session = statistics.mean(commands_per_session)
        
        # 计算平均响应时间
        response_times = [e.duration_ms for e in events if e.duration_ms > 0]
        if response_times:
            profile.avg_response_time = statistics.mean(response_times)


class AnomalyDetector:
    """异常检测器"""
    
    def __init__(self, baseline: BehaviorProfile):
        self.baseline = baseline
        self.thresholds = {
            'temporal_zscore': 2.0,  # 时间异常Z分数阈值
            'frequency_ratio': 3.0,   # 频率异常比例阈值
            'session_duration_ratio': 2.0,  # 会话时长异常比例
        }
    
    def detect(self, event: BehaviorEvent) -> Dict[str, Any]:
        """
        检测单个事件是否异常
        
        Returns:
            {
                'is_anomaly': bool,
                'anomaly_types': List[str],
                'risk_score': float,
                'details': Dict
            }
        """
        anomalies = []
        details = {}
        total_score = 0.0
        
        # 1. 时间异常检测
        temporal_anomaly = self._check_temporal_anomaly(event)
        if temporal_anomaly['is_anomaly']:
            anomalies.append('temporal')
            total_score += temporal_anomaly['score']
            details['temporal'] = temporal_anomaly
        
        # 2. 操作异常检测
        operation_anomaly = self._check_operation_anomaly(event)
        if operation_anomaly['is_anomaly']:
            anomalies.append('operation')
            total_score += operation_anomaly['score']
            details['operation'] = operation_anomaly
        
        # 3. 频率异常检测
        frequency_anomaly = self._check_frequency_anomaly(event)
        if frequency_anomaly['is_anomaly']:
            anomalies.append('frequency')
            total_score += frequency_anomaly['score']
            details['frequency'] = frequency_anomaly
        
        # 4. 目标异常检测
        target_anomaly = self._check_target_anomaly(event)
        if target_anomaly['is_anomaly']:
            anomalies.append('target')
            total_score += target_anomaly['score']
            details['target'] = target_anomaly
        
        risk_score = min(total_score, 1.0)
        
        return {
            'is_anomaly': len(anomalies) > 0,
            'anomaly_types': anomalies,
            'risk_score': risk_score,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
    
    def _check_temporal_anomaly(self, event: BehaviorEvent) -> Dict:
        """检查时间异常"""
        hour = event.timestamp.hour
        weekday = event.timestamp.weekday()
        
        # 检查是否在活跃时段
        hour_count = self.baseline.active_hours.get(hour, 0)
        weekday_count = self.baseline.active_days.get(weekday, 0)
        
        total_events = sum(self.baseline.active_hours.values())
        
        if total_events == 0:
            return {'is_anomaly': False, 'score': 0.0}
        
        # 计算Z分数
        hour_freq = hour_count / total_events if total_events > 0 else 0
        
        # 如果在非常用时段操作
        if hour_freq < 0.01:  # 少于1%的活动在该时段
            return {
                'is_anomaly': True,
                'score': 0.3,
                'reason': f'Unusual hour: {hour}:00',
                'baseline_freq': hour_freq
            }
        
        return {'is_anomaly': False, 'score': 0.0}
    
    def _check_operation_anomaly(self, event: BehaviorEvent) -> Dict:
        """检查操作异常"""
        if event.event_type == 'command':
            cmd_key = f"{event.action}:{event.target}"
            
            # 检查是否是首次使用的命令
            if cmd_key not in self.baseline.command_frequency:
                # 检查命令危险性
                dangerous_commands = ['rm', 'del', 'format', 'dd', 'mkfs', 'shutdown']
                if event.action in dangerous_commands:
                    return {
                        'is_anomaly': True,
                        'score': 0.5,
                        'reason': f'First use of dangerous command: {event.action}'
                    }
                else:
                    return {
                        'is_anomaly': True,
                        'score': 0.1,
                        'reason': f'First use of command: {cmd_key}'
                    }
        
        return {'is_anomaly': False, 'score': 0.0}
    
    def _check_frequency_anomaly(self, event: BehaviorEvent) -> Dict:
        """检查频率异常"""
        # 简化的频率检查
        # 实际实现中应该维护一个滑动窗口计数器
        return {'is_anomaly': False, 'score': 0.0}
    
    def _check_target_anomaly(self, event: BehaviorEvent) -> Dict:
        """检查目标异常"""
        if event.event_type == 'network':
            domain = event.target.split('/')[2] if '//' in event.target else event.target
            
            # 检查是否是首次访问的域名
            if domain not in self.baseline.network_target_pattern:
                # 检查可疑域名
                suspicious_keywords = ['malware', 'phishing', 'attacker', 'evil']
                if any(kw in domain.lower() for kw in suspicious_keywords):
                    return {
                        'is_anomaly': True,
                        'score': 0.4,
                        'reason': f'Access to suspicious domain: {domain}'
                    }
                else:
                    return {
                        'is_anomaly': True,
                        'score': 0.15,
                        'reason': f'First access to domain: {domain}'
                    }
        
        return {'is_anomaly': False, 'score': 0.0}
    
    def detect_session_anomaly(self, events: List[BehaviorEvent]) -> Dict[str, Any]:
        """检测整个会话的异常"""
        if not events:
            return {'is_anomaly': False, 'risk_score': 0.0}
        
        # 会话时长异常
        start_time = min(e.timestamp for e in events)
        end_time = max(e.timestamp for e in events)
        duration = (end_time - start_time).total_seconds() / 60
        
        duration_anomaly = False
        if self.baseline.avg_session_duration > 0:
            ratio = duration / self.baseline.avg_session_duration
            if ratio > self.thresholds['session_duration_ratio']:
                duration_anomaly = True
        
        # 命令数量异常
        cmd_count = sum(1 for e in events if e.event_type == 'command')
        cmd_anomaly = False
        if self.baseline.avg_commands_per_session > 0:
            ratio = cmd_count / self.baseline.avg_commands_per_session
            if ratio > self.thresholds['frequency_ratio']:
                cmd_anomaly = True
        
        risk_score = 0.0
        if duration_anomaly:
            risk_score += 0.3
        if cmd_anomaly:
            risk_score += 0.3
        
        return {
            'is_anomaly': duration_anomaly or cmd_anomaly,
            'risk_score': risk_score,
            'details': {
                'duration_anomaly': duration_anomaly,
                'command_count_anomaly': cmd_anomaly,
                'session_duration_min': duration,
                'command_count': cmd_count
            }
        }


class BehaviorMonitor:
    """行为监控器 - 主入口"""
    
    def __init__(self, storage_path: str = "/tmp/behavior_logs"):
        self.collector = BehaviorCollector(storage_path)
        self.baselines: Dict[str, BehaviorProfile] = {}
        self.detectors: Dict[str, AnomalyDetector] = {}
    
    def record(self, user_id: str, event_type: str, action: str, 
               target: str, **kwargs):
        """记录行为事件"""
        event = BehaviorEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            user_id=user_id,
            session_id=kwargs.get('session_id', 'default'),
            action=action,
            target=target,
            parameters=kwargs.get('parameters', {}),
            result=kwargs.get('result', ''),
            duration_ms=kwargs.get('duration_ms', 0)
        )
        
        self.collector.record_event(event)
        
        # 实时检测
        if user_id in self.detectors:
            result = self.detectors[user_id].detect(event)
            if result['is_anomaly']:
                self._handle_anomaly(user_id, event, result)
    
    def build_user_baseline(self, user_id: str, days: int = 14):
        """建立用户行为基线"""
        builder = BaselineBuilder(self.collector)
        baseline = builder.build_baseline(user_id, days)
        
        self.baselines[user_id] = baseline
        self.detectors[user_id] = AnomalyDetector(baseline)
        
        return baseline
    
    def _handle_anomaly(self, user_id: str, event: BehaviorEvent, 
                        detection_result: Dict):
        """处理检测到的异常"""
        print(f"\n⚠️  Anomaly detected for user {user_id}:")
        print(f"  Event: {event.event_type} - {event.action}")
        print(f"  Risk Score: {detection_result['risk_score']:.2%}")
        print(f"  Types: {', '.join(detection_result['anomaly_types'])}")
        
        # 记录异常历史
        if user_id in self.baselines:
            self.baselines[user_id].anomaly_history.append({
                'timestamp': datetime.now().isoformat(),
                'event': event,
                'detection': detection_result
            })
    
    def get_user_profile(self, user_id: str) -> Optional[BehaviorProfile]:
        """获取用户行为画像"""
        return self.baselines.get(user_id)
    
    def export_baseline(self, user_id: str) -> Dict:
        """导出用户基线数据"""
        baseline = self.baselines.get(user_id)
        if not baseline:
            return {}
        
        return {
            'user_id': baseline.user_id,
            'created_at': baseline.created_at.isoformat(),
            'updated_at': baseline.updated_at.isoformat(),
            'active_hours': baseline.active_hours,
            'active_days': baseline.active_days,
            'command_frequency': dict(sorted(
                baseline.command_frequency.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),  # Top 10
            'avg_session_duration': baseline.avg_session_duration,
            'avg_commands_per_session': baseline.avg_commands_per_session,
            'avg_response_time': baseline.avg_response_time,
            'anomaly_count': len(baseline.anomaly_history)
        }


# 使用示例
if __name__ == '__main__':
    # 初始化监控器
    monitor = BehaviorMonitor()
    
    # 模拟记录一些行为事件
    print("Recording behavior events...")
    
    # 用户1的正常行为
    for i in range(10):
        monitor.record(
            user_id='user1',
            event_type='command',
            action='ls',
            target='/home/user1',
            session_id='session_1',
            duration_ms=100
        )
    
    # 用户1访问文件
    monitor.record(
        user_id='user1',
        event_type='file_access',
        action='read',
        target='document.txt',
        session_id='session_1'
    )
    
    # 建立基线
    print("\nBuilding baseline for user1...")
    baseline = monitor.build_user_baseline('user1', days=1)
    
    print(f"Baseline created:")
    print(f"  Active hours: {baseline.active_hours}")
    print(f"  Avg session duration: {baseline.avg_session_duration:.1f} min")
    print(f"  Avg commands per session: {baseline.avg_commands_per_session:.1f}")
    
    # 测试异常检测
    print("\nTesting anomaly detection...")
    
    # 正常行为 - 应该不触发异常
    monitor.record(
        user_id='user1',
        event_type='command',
        action='ls',
        target='/home/user1',
        session_id='session_2',
        duration_ms=100
    )
    
    # 异常行为 - 危险命令
    monitor.record(
        user_id='user1',
        event_type='command',
        action='rm',
        target='/ -rf',
        session_id='session_2',
        duration_ms=50
    )
    
    # 导出基线
    print("\nExporting baseline...")
    export = monitor.export_baseline('user1')
    print(json.dumps(export, indent=2, ensure_ascii=False))
