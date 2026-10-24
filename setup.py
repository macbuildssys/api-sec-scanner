from pathlib import Path

from setuptools import find_packages, setup

long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="api-sec-scanner",
    version="0.0.1",
    author="macbuildssys",
    description="Evidence based API security scanner: CVSS 4.0, OWASP API Top 10 2023, CWE and MITRE ATT&CK mapping",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/macbuildssys/api-sec-scanner",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={"api_scanner.data": ["attack_subset.json"]},
    include_package_data=True,
    install_requires=[
        "aiohttp>=3.9",
        "click>=8.1",
        "cvss>=3.4",
        "pyyaml>=6.0",
        "rich>=13.0",
    ],
    extras_require={"dev": ["pytest>=8", "pytest-asyncio>=0.23", "PyJWT>=2.8"]},
    entry_points={"console_scripts": ["api-sec-scanner=api_scanner.cli:main", "scan=api_scanner.cli:main"]},
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
