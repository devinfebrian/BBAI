"""Abstract interfaces for security tools.

Defines the contract that all security tools must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator

from bbai.core.config_models import ToolConfig
from bbai.tools.docker_client import ContainerConfig, ToolResult


class ToolCategory(str, Enum):
    """Categories of security tools."""

    RECON_PASSIVE = "recon_passive"
    RECON_ACTIVE = "recon_active"
    CONTENT_DISCOVERY = "content_discovery"
    VULNERABILITY = "vulnerability"
    SECRETS = "secrets"
    JS_ANALYSIS = "js_analysis"
    CLOUD = "cloud"
    VISUAL = "visual"


class ToolPriority(int, Enum):
    """Execution priority for tools."""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class ToolMetadata:
    """Metadata for a security tool."""

    name: str
    category: ToolCategory
    description: str
    version: str
    author: str
    website: str
    license: str
    
    # Execution properties
    priority: ToolPriority = ToolPriority.MEDIUM
    supports_streaming: bool = False
    supports_batch: bool = False
    
    # Input/output
    input_types: list[str] | None = None
    output_types: list[str] | None = None
    
    # Requirements
    requires_internet: bool = True
    requires_auth: bool = False


class BaseTool(ABC):
    """Abstract base class for all security tools.
    
    All tools must implement this interface to be registered
    and used by the orchestration system.
    
    Example:
        class NucleiTool(BaseTool):
            @property
            def metadata(self) -> ToolMetadata:
                return ToolMetadata(
                    name="nuclei",
                    category=ToolCategory.VULNERABILITY,
                    description="Fast vulnerability scanner",
                    version="3.0.0",
                    ...
                )
            
            async def execute(self, target: str, config: ToolConfig) -> ToolResult:
                # Implementation
                pass
    """

    def __init__(self, tool_config: ToolConfig | None = None):
        self.tool_config = tool_config

    @property
    @abstractmethod
    def metadata(self) -> ToolMetadata:
        """Return tool metadata."""
        raise NotImplementedError

    @abstractmethod
    async def execute(
        self,
        target: str,
        config: ToolConfig | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute the tool against a target.
        
        Args:
            target: Target URL/domain to scan
            config: Tool-specific configuration
            **kwargs: Additional execution parameters
            
        Returns:
            Tool execution result
        """
        raise NotImplementedError

    async def execute_streaming(
        self,
        target: str,
        config: ToolConfig | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Execute tool with streaming output.
        
        Args:
            target: Target URL/domain to scan
            config: Tool-specific configuration
            **kwargs: Additional execution parameters
            
        Yields:
            Output lines from the tool
        """
        raise NotImplementedError(f"Streaming not supported by {self.metadata.name}")

    def build_command(
        self,
        target: str,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        """Build command arguments for the tool.
        
        Args:
            target: Target to scan
            extra_args: Additional arguments
            
        Returns:
            Command as list of strings
        """
        cmd = [self.metadata.name, "-target", target]
        if extra_args:
            cmd.extend(extra_args)
        if self.tool_config and self.tool_config.extra_args:
            cmd.extend(self.tool_config.extra_args)
        return cmd

    def get_container_config(
        self,
        target: str,
        extra_args: list[str] | None = None,
    ) -> ContainerConfig:
        """Get Docker container configuration for this tool.
        
        Args:
            target: Target to scan
            extra_args: Additional arguments
            
        Returns:
            Container configuration
        """
        image = self.tool_config.image if self.tool_config else f"bbai-{self.metadata.category.value}:latest"
        
        return ContainerConfig(
            image=image,
            command=self.build_command(target, extra_args),
            timeout=self.tool_config.custom_timeout if self.tool_config else 300,
        )

    def validate_target(self, target: str) -> tuple[bool, str]:
        """Validate that target is appropriate for this tool.
        
        Args:
            target: Target to validate
            
        Returns:
            Tuple of (valid, error_message)
        """
        return True, ""


class ReconTool(BaseTool):
    """Base class for reconnaissance tools."""

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="base_recon",
            category=ToolCategory.RECON_PASSIVE,
            description="Base reconnaissance tool",
            version="1.0.0",
            author="BBAI",
            website="",
            license="MIT",
            priority=ToolPriority.HIGH,
            input_types=["domain"],
            output_types=["subdomains", "endpoints"],
        )


class VulnScannerTool(BaseTool):
    """Base class for vulnerability scanners."""

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="base_vuln_scanner",
            category=ToolCategory.VULNERABILITY,
            description="Base vulnerability scanner",
            version="1.0.0",
            author="BBAI",
            website="",
            license="MIT",
            priority=ToolPriority.CRITICAL,
            input_types=["url", "endpoint"],
            output_types=["vulnerabilities"],
        )


class SecretScannerTool(BaseTool):
    """Base class for secret scanners."""

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="base_secret_scanner",
            category=ToolCategory.SECRETS,
            description="Base secret scanner",
            version="1.0.0",
            author="BBAI",
            website="",
            license="MIT",
            priority=ToolPriority.HIGH,
            input_types=["url", "repository"],
            output_types=["secrets", "credentials"],
        )
