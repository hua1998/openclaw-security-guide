#!/usr/bin/env python3
"""
OpenClaw 安全治理工具包
AI Agent 安全评估与治理工具
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="openclaw-security",
    version="0.7.0",
    author="OpenClaw Security Team",
    description="AI Agent Security Assessment and Governance Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/openclaw-security/agent-security-guide",
    packages=find_packages(where="tools"),
    package_dir={"": "tools"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "openclaw-scan=security_detector:main",
            "openclaw-harden=security_hardening:main",
            "openclaw-multi-scan=multi_platform_scanner:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
