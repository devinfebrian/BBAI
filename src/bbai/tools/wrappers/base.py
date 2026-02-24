"""Base class for tool wrappers."""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import stat
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx


@dataclass
class ToolResult:
    """Result from a tool execution."""

    success: bool
    tool_name: str
    target: str
    findings: list[dict] = field(default_factory=list)
    raw_output: str = ""
    error_message: str = ""
    execution_time: float = 0.0


class ToolWrapper(ABC):
    """Abstract base class for security tool wrappers."""

    def __init__(self):
        """Initialize wrapper."""
        self.tools_dir = Path.home() / ".bbai" / "tools"
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self._check_task: asyncio.Task | None = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Tool category (e.g., 'subdomain_enum', 'vuln_scan')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if tool is ready to use."""
        pass

    @abstractmethod
    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Execute the tool against a target."""
        pass

    def _get_platform(self) -> str:
        """Get normalized platform name."""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == "darwin":
            return "macos"
        elif system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        return system

    def _get_arch(self) -> str:
        """Get normalized architecture."""
        machine = platform.machine().lower()
        
        if machine in ("amd64", "x86_64"):
            return "amd64"
        elif machine in ("arm64", "aarch64"):
            return "arm64"
        elif machine in ("i386", "i686"):
            return "386"
        return machine


class BinaryToolWrapper(ToolWrapper, ABC):
    """Base class for binary-based tools (auto-downloaded)."""

    @property
    @abstractmethod
    def binary_name(self) -> str:
        """Name of the binary file."""
        pass

    @property
    @abstractmethod
    def download_urls(self) -> dict[str, str]:
        """Map of platform_arch to download URL."""
        pass

    @property
    def binary_path(self) -> Path:
        """Full path to the binary."""
        name = self.binary_name
        if platform.system().lower() == "windows" and not name.endswith(".exe"):
            name += ".exe"
        return self.tools_dir / name

    def _find_system_binary(self) -> Path | None:
        """Find binary in system PATH.
        
        Returns:
            Path to system binary or None if not found
        """
        import shutil
        name = self.binary_name
        if platform.system().lower() == "windows" and not name.endswith(".exe"):
            name += ".exe"
        
        system_path = shutil.which(name)
        if system_path:
            return Path(system_path)
        return None

    @property
    def effective_binary_path(self) -> Path:
        """Get the effective binary path (local or system).
        
        Returns:
            Path to use for execution
        """
        # Prefer local binary
        if self.binary_path.exists():
            return self.binary_path
        
        # Fall back to system binary
        system_binary = self._find_system_binary()
        if system_binary:
            return system_binary
        
        # Return local path as default (will fail gracefully if not installed)
        return self.binary_path

    async def is_available(self) -> bool:
        """Check if binary exists (local or system)."""
        if self.binary_path.exists():
            return True
        return self._find_system_binary() is not None

    async def ensure_installed(self) -> bool:
        """Download and install binary if not present.
        
        First checks for system-installed binary, then tries to download.
        """
        # Check if already available (local or system)
        if await self.is_available():
            return True

        # Try to download
        key = f"{self._get_platform()}_{self._get_arch()}"
        
        # Fallback to amd64 if arm64 not available
        if key not in self.download_urls:
            key = f"{self._get_platform()}_amd64"
        
        if key not in self.download_urls:
            raise RuntimeError(f"No download available for {key}")

        url = self.download_urls[key]
        try:
            await self._download_binary(url)
            return True
        except Exception as e:
            # If download fails, suggest system installation
            raise RuntimeError(
                f"Failed to download {self.binary_name}. "
                f"Please install it manually:\n"
                f"  Windows: winget install ProjectDiscovery.{self.binary_name.title()}\n"
                f"  macOS: brew install {self.binary_name}\n"
                f"  Linux: apt install {self.binary_name}"
            ) from e

    async def _download_binary(self, url: str) -> None:
        """Download and extract binary."""
        import tempfile

        temp_dir = Path(tempfile.mkdtemp())
        archive_path = temp_dir / "download.zip"

        # Download with progress
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            archive_path.write_bytes(response.content)

        # Extract
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(temp_dir)

        # Find binary (might be nested)
        binary_found = False
        for extracted in temp_dir.rglob(self.binary_name + "*"):
            if extracted.is_file():
                shutil.move(str(extracted), str(self.binary_path))
                binary_found = True
                break

        if not binary_found:
            raise RuntimeError(f"Binary {self.binary_name} not found in archive")

        # Make executable on Unix
        if platform.system().lower() != "windows":
            self.binary_path.chmod(
                self.binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

        # Cleanup
        shutil.rmtree(temp_dir)


class PythonToolWrapper(ToolWrapper, ABC):
    """Base class for pure Python tools."""

    async def is_available(self) -> bool:
        """Python tools are always available if dependencies are installed."""
        return True
