"""httpx HTTP probing and analysis wrapper."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from bbai.tools.wrappers.base import BinaryToolWrapper, ToolResult


class HttpxWrapper(BinaryToolWrapper):
    """httpx - Fast and multi-purpose HTTP toolkit.
    
    Features:
    - Probe for live web servers
    - Technology fingerprinting (Wappalyzer)
    - Title extraction
    - Screenshot capabilities
    - Response analysis
    """

    @property
    def name(self) -> str:
        return "httpx"

    @property
    def category(self) -> str:
        return "tech_detect"

    @property
    def description(self) -> str:
        return "Fast HTTP prober with technology fingerprinting"

    @property
    def binary_name(self) -> str:
        return "httpx"

    @property
    def download_urls(self) -> dict[str, str]:
        """Download URLs for each platform."""
        version = "1.6.10"
        base = f"https://github.com/projectdiscovery/httpx/releases/download/v{version}"
        return {
            "linux_amd64": f"{base}/httpx_{version}_linux_amd64.zip",
            "linux_arm64": f"{base}/httpx_{version}_linux_arm64.zip",
            "macos_amd64": f"{base}/httpx_{version}_macOS_amd64.zip",
            "macos_arm64": f"{base}/httpx_{version}_macOS_arm64.zip",
            "windows_amd64": f"{base}/httpx_{version}_windows_amd64.zip",
        }

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Run httpx probe.
        
        Args:
            target: URL or domain to probe
            options: {
                "follow_redirects": bool,
                "title": bool,          # Extract page titles
                "tech_detect": bool,    # Detect technologies (Wappalyzer)
                "status_code": bool,    # Show status codes
                "content_length": bool, # Show content length
                "web_server": bool,     # Show web server
                "method": str,          # HTTP method (GET, POST, etc.)
                "threads": int,         # Number of threads
                "rate_limit": int,      # Requests per second
                "timeout": int,         # Timeout in seconds
                "retries": int,         # Number of retries
            }
        """
        import time
        
        start_time = time.time()
        options = options or {}
        
        # Ensure installed
        await self.ensure_installed()
        
        # Build command
        cmd = [
            str(self.effective_binary_path),
            "-u", target,
            "-json",
            "-silent",
            "-nc",  # No color
        ]
        
        # Output options
        if options.get("title", True):
            cmd.append("-title")
        
        if options.get("tech_detect", True):
            cmd.append("-tech-detect")
        
        if options.get("status_code", True):
            cmd.append("-status-code")
        
        if options.get("content_length", True):
            cmd.append("-content-length")
        
        if options.get("web_server", True):
            cmd.append("-web-server")
        
        if options.get("follow_redirects", True):
            cmd.append("-follow-redirects")
        
        # HTTP method
        method = options.get("method", "GET")
        if method != "GET":
            cmd.extend(["-x", method])
        
        # Performance options
        if "threads" in options:
            cmd.extend(["-threads", str(options["threads"])])
        
        if "rate_limit" in options:
            cmd.extend(["-rate-limit", str(options["rate_limit"])])
        
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])
        
        if "retries" in options:
            cmd.extend(["-retries", str(options["retries"])])
        
        # Run probe
        findings = []
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout_chunks = []
            stderr_chunks = []
            
            async def read_stdout():
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode().strip()
                    if line_str:
                        stdout_chunks.append(line_str)
                        try:
                            result = json.loads(line_str)
                            finding = {
                                "type": "http_probe",
                                "url": result.get("url", ""),
                                "host": result.get("host", ""),
                                "port": result.get("port", 0),
                                "status_code": result.get("status_code", 0),
                                "title": result.get("title", ""),
                                "webserver": result.get("webserver", ""),
                                "content_length": result.get("content_length", 0),
                                "content_type": result.get("content_type", ""),
                                "method": result.get("method", "GET"),
                                "response_time": result.get("time", ""),
                                "technologies": result.get("tech", []),
                                "chain": result.get("chain", []),
                                "failed": result.get("failed", False),
                            }
                            
                            # Only add if not failed
                            if not finding["failed"]:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            pass
            
            async def read_stderr():
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    stderr_chunks.append(line.decode())
            
            await asyncio.gather(
                read_stdout(),
                read_stderr(),
                proc.wait()
            )
            
            execution_time = time.time() - start_time
            
            return ToolResult(
                success=len(findings) > 0,
                tool_name=self.name,
                target=target,
                findings=findings,
                raw_output="\n".join(stdout_chunks),
                error_message="".join(stderr_chunks) if stderr_chunks else "",
                execution_time=execution_time
            )
            
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                target=target,
                error_message=str(e),
                execution_time=time.time() - start_time
            )

    async def probe_multiple(self, targets: list[str], options: dict | None = None) -> ToolResult:
        """Probe multiple targets from stdin.
        
        Args:
            targets: List of URLs/domains to probe
            options: Same as run()
        """
        import time
        
        start_time = time.time()
        options = options or {}
        
        await self.ensure_installed()
        
        # Build command (no -u flag, will use stdin)
        cmd = [
            str(self.effective_binary_path),
            "-json",
            "-silent",
            "-nc",
        ]
        
        # Same options as run()
        if options.get("title", True):
            cmd.append("-title")
        if options.get("tech_detect", True):
            cmd.append("-tech-detect")
        if options.get("status_code", True):
            cmd.append("-status-code")
        if options.get("follow_redirects", True):
            cmd.append("-follow-redirects")
        if "threads" in options:
            cmd.extend(["-threads", str(options["threads"])])
        
        findings = []
        
        try:
            # Start process
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Send targets to stdin
            stdin_data = "\n".join(targets).encode()
            
            # Read output
            stdout_chunks = []
            stderr_chunks = []
            
            async def read_stdout():
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode().strip()
                    if line_str:
                        stdout_chunks.append(line_str)
                        try:
                            result = json.loads(line_str)
                            if not result.get("failed", False):
                                findings.append({
                                    "type": "http_probe",
                                    "url": result.get("url", ""),
                                    "host": result.get("host", ""),
                                    "status_code": result.get("status_code", 0),
                                    "title": result.get("title", ""),
                                    "webserver": result.get("webserver", ""),
                                    "technologies": result.get("tech", []),
                                    "content_length": result.get("content_length", 0),
                                })
                        except json.JSONDecodeError:
                            pass
            
            async def read_stderr():
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    stderr_chunks.append(line.decode())
            
            # Run and send input
            stdout_task = asyncio.create_task(read_stdout())
            stderr_task = asyncio.create_task(read_stderr())
            
            proc.stdin.write(stdin_data)
            await proc.stdin.drain()
            proc.stdin.close()
            
            await proc.wait()
            await stdout_task
            await stderr_task
            
            execution_time = time.time() - start_time
            
            return ToolResult(
                success=len(findings) > 0,
                tool_name=self.name,
                target=f"{len(targets)} hosts",
                findings=findings,
                raw_output="\n".join(stdout_chunks),
                execution_time=execution_time
            )
            
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                target=f"{len(targets)} hosts",
                error_message=str(e),
                execution_time=time.time() - start_time
            )
