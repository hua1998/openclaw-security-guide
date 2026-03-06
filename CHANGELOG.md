# Changelog

所有项目的显著变更都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并且本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- 多平台适配器系统 (Dify, AutoGPT, FastGPT)
- 高级研究工具套件
  - 提示词注入检测器 (三层检测架构)
  - 行为基线建模系统
  - Skills 签名验证工具
  - MCP 安全测试框架
- 完整的 CI/CD 流水线 (GitHub Actions)
- 单元测试套件 (pytest)
- Python 包配置 (setup.py, pyproject.toml)

### Changed
- 重构核心机制：从 "复制提示词给 AI" 改为 "命令行工具使用"
- 统一工具路径到 `tools/` 目录
- 更新 README.md 为工具导向的使用说明
- 更新所有相关文档保持一致性

### Removed
- 删除所有作者个人信息
- 删除重复的工具目录

## [0.6.3] - 2026-03-06

### Added
- 完整的合规映射文档 (OWASP LLM Top 10, NIST AI RMF, 等保2.0)
- 深度提示词注入防御文档 (含 10 个真实攻击案例)
- 多平台配置适配器
- 研究级安全工具套件

### Changed
- 全面优化项目结构
- 完善测试体系
- 更新 CI 流水线配置

### Fixed
- 修复文档中的路径引用
- 统一工具调用方式

## [0.6.0] - 2026-02-28

### Added
- 基础安全工具集
  - security_detector.py - 安全检测器
  - security_hardening.py - 安全加固脚本
  - config_baseline.py - 配置基线检查
  - config_watcher.py - 配置变更监控
  - token_generator.py - Token 生成器
- 10 大安全模块文档
- 实战演练案例
- 红蓝对抗指南

## [0.4.0] - 2026-02-20

### Added
- 项目初始版本
- 基础治理框架文档
- 安全配置模板
- 检测清单

---

## 版本说明

- **MAJOR**: 不兼容的 API 变更
- **MINOR**: 向下兼容的功能添加
- **PATCH**: 向下兼容的问题修复

## 标签说明

- `Added` - 新功能
- `Changed` - 现有功能的变更
- `Deprecated` - 已弃用的功能
- `Removed` - 已删除的功能
- `Fixed` - 问题修复
- `Security` - 安全相关的修复
