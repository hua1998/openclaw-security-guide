# 贡献指南

感谢您对 OpenClaw 项目的关注！我们欢迎各种形式的贡献。

## 如何贡献

### 报告问题

如果您发现了 bug 或有功能建议：

1. 先搜索现有 issues，避免重复
2. 创建新 issue 时，请提供：
   - 问题描述
   - 复现步骤
   - 期望行为
   - 实际行为
   - 环境信息（操作系统、Python 版本等）

### 提交代码

#### 开发环境设置

```bash
# 1. Fork 并克隆项目
git clone https://github.com/YOUR_USERNAME/agent-security-guide.git
cd agent-security-guide

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 3. 安装开发依赖
pip install -r requirements.txt
pip install pytest flake8 pylint black

# 4. 运行测试确保环境正常
pytest tests/ -v
```

#### 代码规范

- **Python 版本**: 3.8+
- **代码风格**: PEP 8
- **行长度**: 最大 100 字符
- **文档字符串**: 所有函数必须有 docstring

```bash
# 代码格式化
black tools/ --line-length=100

# 代码检查
flake8 tools/ --max-line-length=100
pylint tools/*.py --disable=R,C
```

#### 提交规范

- 使用清晰的提交信息
- 一个提交只做一件事
- 提交信息格式：`<类型>: <描述>`

类型包括：
- `feat`: 新功能
- `fix`: 修复
- `docs`: 文档
- `test`: 测试
- `refactor`: 重构
- `style`: 代码格式
- `chore`: 其他

示例：
```
feat: 添加 MCP 安全测试框架
fix: 修复 token 生成器的密钥长度问题
docs: 更新快速开始指南
```

#### Pull Request 流程

1. **创建分支**
   ```bash
   git checkout -b feature/your-feature-name
   # 或
   git checkout -b fix/issue-description
   ```

2. **开发和测试**
   ```bash
   # 编写代码
   # 添加测试
   # 确保所有测试通过
   pytest tests/ -v
   ```

3. **提交更改**
   ```bash
   git add .
   git commit -m "feat: 添加新功能描述"
   git push origin feature/your-feature-name
   ```

4. **创建 PR**
   - 描述清楚做了什么改动
   - 关联相关的 issue
   - 确保 CI 通过

### 文档贡献

- 文档使用 Markdown 格式
- 保持中英文标点一致
- 代码块标注语言类型
- 及时更新目录和链接

### 测试贡献

```bash
# 运行测试
pytest tests/ -v

# 运行带覆盖率
pytest tests/ --cov=tools --cov-report=html

# 运行特定测试
pytest tests/test_security_detector.py::TestAuthConfig -v
```

## 项目结构

```
agent-security-guide/
├── tools/              # 核心工具
│   ├── adapters/       # 平台适配器
│   └── research/       # 研究工具
├── tests/              # 测试
├── scripts/            # 辅助脚本
├── config/             # 配置模板
├── docs/               # 详细文档
└── examples/           # 示例
```

## 开发路线图

查看 [待办研究项目.md](待办研究项目.md) 了解当前开发重点。

## 行为准则

- 尊重所有参与者
- 接受建设性批评
- 关注什么是最好的社区和项目
- 互相尊重，求同存异

## 获取帮助

- 📖 阅读 [README.md](README.md)
- 🚀 查看 [快速使用指南](快速使用指南.md)
- 💬 参与 GitHub Discussions

## 许可证

通过贡献代码，您同意您的贡献将在 [LICENSE](LICENSE) 下发布。

---

再次感谢您的贡献！
