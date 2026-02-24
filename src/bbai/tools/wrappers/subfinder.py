"""Subfinder subdomain enumeration wrapper."""

from __future__ import annotations

import asyncio
import json
import platform
from pathlib import Path

from bbai.tools.wrappers.base import BinaryToolWrapper, ToolResult


class SubfinderWrapper(BinaryToolWrapper):
    """Subfinder - Passive subdomain discovery tool.
    
    Discovers subdomains using 50+ passive sources including:
    - crt.sh, VirusTotal, Shodan, Censys, Archive.org
    - DNSdumpster, ThreatCrowd, SecurityTrails, etc.
    """

    @property
    def name(self) -> str:
        return "subfinder"

    @property
    def category(self) -> str:
        return "subdomain_enum"

    @property
    def description(self) -> str:
        return "Fast passive subdomain discovery using 50+ sources"

    @property
    def binary_name(self) -> str:
        return "subfinder"

    @property
    def download_urls(self) -> dict[str, str]:
        """Download URLs for each platform."""
        version = "2.12.0"
        base = f"https://github.com/projectdiscovery/subfinder/releases/download/v{version}"
        return {
            "linux_amd64": f"{base}/subfinder_{version}_linux_amd64.zip",
            "linux_arm64": f"{base}/subfinder_{version}_linux_arm64.zip",
            "macos_amd64": f"{base}/subfinder_{version}_macOS_amd64.zip",
            "macos_arm64": f"{base}/subfinder_{version}_macOS_arm64.zip",
            "windows_amd64": f"{base}/subfinder_{version}_windows_amd64.zip",
            "windows_386": f"{base}/subfinder_{version}_windows_386.zip",
        }

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Run Subfinder scan.
        
        Args:
            target: Domain to enumerate (e.g., "example.com")
            options: {
                "all_sources": bool,  # Use all sources (slower but more results)
                "recursive": bool,    # Recursive enumeration
                "timeout": int,       # Timeout in seconds
            }
        """
        import time
        
        start_time = time.time()
        options = options or {}
        
        # Ensure installed
        await self.ensure_installed()
        
        # Normalize target
        target = target.replace("https://", "").replace("http://", "").strip("/")
        
        # Build command
        cmd = [
            str(self.effective_binary_path),
            "-d", target,
            "-json",
            "-silent",
            "-nc",  # No color
        ]
        
        # Use all sources (slower but more comprehensive)
        if options.get("all_sources", True):
            cmd.append("-all")
        
        # Recursive enumeration
        if options.get("recursive", False):
            cmd.append("-recursive")
        
        # Timeout
        timeout = options.get("timeout", 60)
        cmd.extend(["-timeout", str(timeout)])
        
        # Maximum time to run
        if "max_time" in options:
            cmd.extend(["-max-time", str(options["max_time"])])
        
        # Run scan
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
                            host = result.get("host", "")
                            sources = result.get("source", [])
                            if host:
                                findings.append({
                                    "type": "subdomain",
                                    "host": host,
                                    "sources": sources if isinstance(sources, list) else [sources],
                                    "method": "passive_enum",
                                    "tool": "subfinder"
                                })
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
                success=len(findings) > 0 or proc.returncode == 0,
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
