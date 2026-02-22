"""Docker client wrapper for containerized security tools.

Provides async interface to Docker SDK with:
- Resource constraints (memory, CPU)
- Security hardening (read-only, no-privileges, non-root)
- Log streaming for real-time output
- Timeout handling
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, AsyncIterator

import docker
from docker.errors import ContainerError, ImageNotFound, NotFound
from docker.models.containers import Container

from bbai.core.config_models import ToolOutput

logger = logging.getLogger(__name__)


@dataclass
class ContainerConfig:
    """Configuration for container execution.
    
    Follows security best practices:
    - Non-root execution
    - Read-only filesystem
    - No new privileges
    - Resource limits
    """

    image: str
    command: list[str] | str
    
    # Resource limits
    mem_limit: str = "512m"
    cpu_quota: int = 50000  # 50% of CPU
    
    # Security options
    read_only: bool = True
    security_opt: list[str] | None = None
    cap_drop: list[str] | None = None
    cap_add: list[str] | None = None
    user: str = "1000:1000"  # Non-root UID:GID
    
    # Environment and volumes
    environment: dict[str, str] | None = None
    volumes: dict[str, dict[str, str]] | None = None
    working_dir: str = "/workspace"
    
    # Networking
    network_mode: str = "bridge"
    dns: list[str] | None = None
    
    # Timeouts
    timeout: int = 300
    
    def __post_init__(self):
        if self.security_opt is None:
            self.security_opt = ["no-new-privileges:true"]
        if self.cap_drop is None:
            self.cap_drop = ["ALL"]
        if self.cap_add is None:
            self.cap_add = ["NET_RAW"]  # For DNS operations


@dataclass
class ToolResult:
    """Result of a tool execution."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    container_id: str | None = None
    error_message: str | None = None

    def to_tool_output(self, tool_name: str) -> ToolOutput:
        """Convert to ToolOutput model."""
        return ToolOutput(
            tool_name=tool_name,
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            execution_time=self.execution_time,
        )


class DockerToolRunner:
    """Async Docker client for running security tools.
    
    Usage:
        runner = DockerToolRunner()
        
        # Simple execution
        result = await runner.run_tool(
            ContainerConfig(
                image="bbai-recon-passive:latest",
                command=["subfinder", "-d", "example.com"],
            )
        )
        
        # With log streaming
        async for log in runner.run_tool_streaming(config):
            print(log)
    
    Security features:
    - Non-root user execution
    - Read-only root filesystem
    - No new privileges
    - Resource limits (memory, CPU)
    - Dropped capabilities
    """

    def __init__(self, docker_host: str | None = None):
        """Initialize Docker client.
        
        Args:
            docker_host: Docker daemon URL (None for default)
        """
        self.docker_host = docker_host
        self._client: docker.DockerClient | None = None
        self._async_lock = asyncio.Lock()

    def _get_client(self) -> docker.DockerClient:
        """Get or create Docker client."""
        if self._client is None:
            kwargs = {}
            if self.docker_host:
                kwargs["base_url"] = self.docker_host
            self._client = docker.from_env(**kwargs)
        return self._client

    async def run_tool(
        self,
        config: ContainerConfig,
        stream_output: bool = False,
    ) -> ToolResult | AsyncIterator[str]:
        """Execute a tool in a Docker container.
        
        Args:
            config: Container configuration
            stream_output: If True, yields log lines instead of returning result
            
        Returns:
            ToolResult or AsyncIterator of log lines
        """
        if stream_output:
            return self.run_tool_streaming(config)
        return await self._run_tool_sync(config)

    async def _run_tool_sync(self, config: ContainerConfig) -> ToolResult:
        """Synchronous tool execution."""
        import time
        
        start_time = time.time()
        client = self._get_client()
        container: Container | None = None
        
        try:
            # Ensure image exists
            try:
                client.images.get(config.image)
            except ImageNotFound:
                logger.info(f"Pulling image: {config.image}")
                await asyncio.to_thread(client.images.pull, config.image)
            
            # Create and start container
            run_kwargs = self._build_run_kwargs(config)
            
            container = await asyncio.to_thread(
                client.containers.run,
                config.image,
                config.command,
                **run_kwargs,
            )
            
            # Wait for completion with timeout
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(container.wait),
                    timeout=config.timeout,
                )
                exit_code = result.get("StatusCode", -1)
            except asyncio.TimeoutError:
                logger.warning(f"Container timeout after {config.timeout}s")
                await asyncio.to_thread(container.kill)
                exit_code = -1
            
            # Get logs
            stdout = await asyncio.to_thread(
                lambda: container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            )
            stderr = await asyncio.to_thread(
                lambda: container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            )
            
            execution_time = time.time() - start_time
            
            return ToolResult(
                success=exit_code == 0,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                container_id=container.id,
            )
            
        except ContainerError as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                exit_code=e.exit_status,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                error_message=str(e),
            )
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Docker execution error: {e}")
            return ToolResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                error_message=str(e),
            )
        finally:
            # Cleanup
            if container:
                try:
                    await asyncio.to_thread(container.remove, force=True)
                except Exception as e:
                    logger.warning(f"Failed to remove container: {e}")

    async def run_tool_streaming(
        self,
        config: ContainerConfig,
    ) -> AsyncIterator[str]:
        """Stream tool output in real-time.
        
        Args:
            config: Container configuration
            
        Yields:
            Log lines from the container
        """
        client = self._get_client()
        container: Container | None = None
        
        try:
            # Ensure image exists
            try:
                client.images.get(config.image)
            except ImageNotFound:
                logger.info(f"Pulling image: {config.image}")
                await asyncio.to_thread(client.images.pull, config.image)
            
            # Create and start container
            run_kwargs = self._build_run_kwargs(config)
            run_kwargs["detach"] = True
            
            container = await asyncio.to_thread(
                client.containers.run,
                config.image,
                config.command,
                **run_kwargs,
            )
            
            # Stream logs
            logs = await asyncio.to_thread(
                container.logs,
                stdout=True,
                stderr=True,
                stream=True,
                follow=True,
            )
            
            for line in logs:
                yield line.decode("utf-8", errors="replace").rstrip()
            
            # Wait for completion
            await asyncio.wait_for(
                asyncio.to_thread(container.wait),
                timeout=config.timeout,
            )
            
        except asyncio.TimeoutError:
            logger.warning(f"Container timeout after {config.timeout}s")
            if container:
                await asyncio.to_thread(container.kill)
        finally:
            if container:
                try:
                    await asyncio.to_thread(container.remove, force=True)
                except Exception as e:
                    logger.warning(f"Failed to remove container: {e}")

    def _build_run_kwargs(self, config: ContainerConfig) -> dict[str, Any]:
        """Build kwargs for docker containers.run()."""
        kwargs: dict[str, Any] = {
            "detach": False,
            "mem_limit": config.mem_limit,
            "cpu_quota": config.cpu_quota,
            "read_only": config.read_only,
            "security_opt": config.security_opt,
            "cap_drop": config.cap_drop,
            "cap_add": config.cap_add,
            "user": config.user,
            "working_dir": config.working_dir,
            "network_mode": config.network_mode,
            "remove": False,  # We handle removal manually
        }
        
        if config.environment:
            kwargs["environment"] = config.environment
        
        if config.volumes:
            kwargs["volumes"] = config.volumes
        
        if config.dns:
            kwargs["dns"] = config.dns
        
        return kwargs

    async def build_image(
        self,
        path: str,
        tag: str,
        buildargs: dict[str, str] | None = None,
    ) -> tuple[bool, str]:
        """Build a Docker image.
        
        Args:
            path: Path to Dockerfile directory
            tag: Image tag
            buildargs: Build arguments
            
        Returns:
            Tuple of (success, message)
        """
        client = self._get_client()
        
        try:
            image, logs = await asyncio.to_thread(
                client.images.build,
                path=path,
                tag=tag,
                buildargs=buildargs,
                rm=True,
            )
            
            # Collect build logs
            log_lines = []
            for chunk in logs:
                if "stream" in chunk:
                    log_lines.append(chunk["stream"].strip())
                if "error" in chunk:
                    return False, chunk["error"]
            
            return True, f"Built image: {tag}"
        except Exception as e:
            return False, str(e)

    async def image_exists(self, image: str) -> bool:
        """Check if an image exists locally."""
        client = self._get_client()
        try:
            await asyncio.to_thread(client.images.get, image)
            return True
        except ImageNotFound:
            return False

    async def pull_image(self, image: str) -> bool:
        """Pull an image from registry."""
        client = self._get_client()
        try:
            await asyncio.to_thread(client.images.pull, image)
            return True
        except Exception as e:
            logger.error(f"Failed to pull image {image}: {e}")
            return False

    def close(self) -> None:
        """Close Docker client connection."""
        if self._client:
            self._client.close()
            self._client = None

    async def __aenter__(self) -> DockerToolRunner:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        self.close()


class DockerImageManager:
    """Manager for BBAI Docker images.
    
    Handles building and managing the 8 security tool images.
    """

    # Image definitions
    IMAGES = {
        "bbai-recon-passive": {
            "tools": ["amass", "subfinder", "assetfinder", "gau", "waybackurls"],
            "size": "150MB",
        },
        "bbai-recon-active": {
            "tools": ["katana", "naabu", "dnsx", "rustscan", "ffuf"],
            "size": "200MB",
        },
        "bbai-content-discovery": {
            "tools": ["feroxbuster", "gospider", "hakrawler", "httpx"],
            "size": "180MB",
        },
        "bbai-vulnerability-core": {
            "tools": ["nuclei"],
            "size": "800MB",
        },
        "bbai-secrets": {
            "tools": ["trufflehog", "gitleaks", "jsubfinder"],
            "size": "250MB",
        },
        "bbai-js-analysis": {
            "tools": ["linkfinder", "semgrep", "js-beautify"],
            "size": "300MB",
        },
        "bbai-cloud": {
            "tools": ["cloudenum", "s3scanner", "scouturl"],
            "size": "200MB",
        },
        "bbai-visual": {
            "tools": ["gowitness", "chromium"],
            "size": "500MB",
        },
    }

    def __init__(self, docker_host: str | None = None):
        self.runner = DockerToolRunner(docker_host)

    async def check_all_images(self) -> dict[str, bool]:
        """Check which images are available locally."""
        results = {}
        for image in self.IMAGES:
            exists = await self.runner.image_exists(f"{image}:latest")
            results[image] = exists
        return results

    async def pull_all_images(self) -> dict[str, bool]:
        """Pull all BBAI images from registry."""
        results = {}
        for image in self.IMAGES:
            success = await self.runner.pull_image(f"{image}:latest")
            results[image] = success
        return results

    def get_missing_images(self, status: dict[str, bool]) -> list[str]:
        """Get list of missing images."""
        return [img for img, exists in status.items() if not exists]
