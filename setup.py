"""Setup script for AI Bug Detection & Highlighting System."""

from setuptools import setup, find_packages

setup(
    name="ai-bug-detection-engine",
    version="1.0.0",
    description="Dual-Phase AI Bug Detection & Highlighting System for Software Code and Hardware Circuits",
    author="Google Antigravity Advanced Agentic Coding",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
        "jinja2>=3.1.0",
        "markupsafe>=2.1.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Debuggers",
    ],
)

