from setuptools import setup, find_packages

setup(
    name="agentguard",
    version="0.1.0",
    description="Python SDK for AgentGuard — the firewall for AI agents",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="AgentGuard Contributors",
    url="https://github.com/yourname/agentguard",
    packages=find_packages(),
    python_requires=">=3.8",
    extras_require={
        "langchain": ["langchain>=0.1.0"],
        "crewai": ["crewai>=0.1.0"],
        "browser-use": ["browser-use>=0.1.0"],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
)
