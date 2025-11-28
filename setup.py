from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="api-sec-scanner",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced API Security Scanner - Professional vulnerability detection tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/api-sec-scanner",
    packages=find_packages(),
    install_requires=[
        "click",
        "aiohttp",
        "rich",
        "pydantic",
        "PyJWT",
        "pyyaml",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "api-sec-scanner=cli.main:main",
        ],
    },
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
