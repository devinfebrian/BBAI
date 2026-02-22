"""Tool abstraction and Docker integration.

This package provides Docker-based tool execution and output parsing
for security scanning tools.
"""

from bbai.tools.docker_client import (
    ContainerConfig,
    DockerImageManager,
    DockerToolRunner,
    ToolResult,
)
from bbai.tools.interfaces import (
    BaseTool,
    ReconTool,
    SecretScannerTool,
    ToolCategory,
    ToolMetadata,
    ToolPriority,
    VulnScannerTool,
)
from bbai.tools.parsers import (
    AmassParser,
    BaseParser,
    NucleiParser,
    ParsedEndpoint,
    ParsedFinding,
    ParsedSecret,
    ParsedSubdomain,
    SubfinderParser,
    TruffleHogParser,
    get_parser,
)
from bbai.tools.registry import (
    ToolRegistry,
    get_registry,
    get_tool,
    register_tool,
)

__all__ = [
    # Docker client
    "ContainerConfig",
    "DockerToolRunner",
    "DockerImageManager",
    "ToolResult",
    # Interfaces
    "BaseTool",
    "ReconTool",
    "VulnScannerTool",
    "SecretScannerTool",
    "ToolCategory",
    "ToolMetadata",
    "ToolPriority",
    # Registry
    "ToolRegistry",
    "get_registry",
    "get_tool",
    "register_tool",
    # Parsers
    "BaseParser",
    "ParsedFinding",
    "ParsedSubdomain",
    "ParsedEndpoint",
    "ParsedSecret",
    "NucleiParser",
    "SubfinderParser",
    "AmassParser",
    "TruffleHogParser",
    "get_parser",
]
