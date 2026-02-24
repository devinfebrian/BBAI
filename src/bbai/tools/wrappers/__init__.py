"""Tool wrappers for BBAI.

Provides unified interface for:
- Python-native tools (no external dependencies)
- Binary wrappers (auto-downloaded on first use)
"""

from bbai.tools.wrappers.base import BinaryToolWrapper, PythonToolWrapper, ToolResult, ToolWrapper
from bbai.tools.wrappers.httpx import HttpxWrapper
from bbai.tools.wrappers.katana import KatanaWrapper
from bbai.tools.wrappers.nuclei import NucleiWrapper
from bbai.tools.wrappers.python_portscan import PythonPortScanner
from bbai.tools.wrappers.python_subdomain import PythonSubdomainEnum
from bbai.tools.wrappers.python_webcrawl import PythonWebCrawler
from bbai.tools.wrappers.registry import ToolRegistry, get_tool_registry
from bbai.tools.wrappers.subfinder import SubfinderWrapper

__all__ = [
    # Base classes
    "ToolWrapper",
    "BinaryToolWrapper",
    "PythonToolWrapper",
    "ToolResult",
    # Python-native tools
    "PythonSubdomainEnum",
    "PythonPortScanner",
    "PythonWebCrawler",
    # Binary wrappers
    "NucleiWrapper",
    "SubfinderWrapper",
    "HttpxWrapper",
    "KatanaWrapper",
    # Registry
    "ToolRegistry",
    "get_tool_registry",
]
