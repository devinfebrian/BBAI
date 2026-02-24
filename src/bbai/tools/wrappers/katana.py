"""Katana web crawler wrapper - Headless browser for JS rendering."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from bbai.tools.wrappers.base import BinaryToolWrapper, ToolResult


class KatanaWrapper(BinaryToolWrapper):
    """Katana - A next-generation crawling and spidering framework.
    
    Features:
    - Headless browser for JavaScript rendering
    - Smart filtering (deduplication, scope control)
    - Customizable crawl depth
    - Form and JavaScript event discovery
    - Output in multiple formats
    """

    @property
    def name(self) -> str:
        return "katana"

    @property
    def category(self) -> str:
        return "web_crawl"

    @property
    def description(self) -> str:
        return "Headless web crawler with JavaScript rendering"

    @property
    def binary_name(self) -> str:
        return "katana"

    @property
    def download_urls(self) -> dict[str, str]:
        """Download URLs for each platform."""
        version = "1.1.2"
        base = f"https://github.com/projectdiscovery/katana/releases/download/v{version}"
        return {
            "linux_amd64": f"{base}/katana_{version}_linux_amd64.zip",
            "linux_arm64": f"{base}/katana_{version}_linux_arm64.zip",
            "macos_amd64": f"{base}/katana_{version}_macOS_amd64.zip",
            "macos_arm64": f"{base}/katana_{version}_macOS_arm64.zip",
            "windows_amd64": f"{base}/katana_{version}_windows_amd64.zip",
        }

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Run Katana crawl.
        
        Args:
            target: URL to crawl (e.g., "https://example.com")
            options: {
                "depth": int,          # Maximum crawl depth (default: 3)
                "headless": bool,      # Use headless browser (default: True)
                "js_crawl": bool,      # Crawl JavaScript endpoints (default: True)
                "forms": bool,         # Crawl forms (default: True)
                "scope": str,          # Crawl scope: "domain", "directory", "custom"
                "concurrency": int,    # Number of concurrent workers
                "rate_limit": int,     # Requests per second
                "timeout": int,        # Timeout in seconds
                "output_fields": list, # Fields to output: ["url", "status", "title", ...]
                "exclude": list,       # URL patterns to exclude
            }
        """
        import time
        
        start_time = time.time()
        options = options or {}
        
        # Ensure installed
        await self.ensure_installed()
        
        # Normalize URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        # Build command
        cmd = [
            str(self.effective_binary_path),
            "-u", target,
            "-jsonl",
            "-silent",
            "-nc",
        ]
        
        # Crawl depth
        depth = options.get("depth", 3)
        cmd.extend(["-d", str(depth)])
        
        # Headless mode (JavaScript rendering)
        if options.get("headless", True):
            cmd.append("-headless")
        
        # JavaScript crawl
        if options.get("js_crawl", True):
            cmd.append("-jc")  # JavaScript crawl mode
        
        # Form crawling
        if options.get("forms", True):
            cmd.append("-kf")  # Crawl known forms
        
        # Scope
        scope = options.get("scope", "domain")
        if scope == "directory":
            cmd.append("-fs")  # Directory scope
        elif scope == "fqdn":
            cmd.append("-fqdn")  # Fully qualified domain name scope
        
        # Concurrency
        if "concurrency" in options:
            cmd.extend(["-c", str(options["concurrency"])])
        
        # Rate limit
        if "rate_limit" in options:
            cmd.extend(["-rate-limit", str(options["rate_limit"])])
        
        # Timeout
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])
        
        # Exclude patterns
        exclude = options.get("exclude", [])
        if exclude:
            for pattern in exclude:
                cmd.extend(["-e", pattern])
        
        # Run crawl
        findings = []
        endpoints = set()  # For deduplication
        
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
                            url = result.get("request", {}).get("endpoint", "")
                            
                            # Deduplicate
                            if url and url not in endpoints:
                                endpoints.add(url)
                                
                                finding = {
                                    "type": "endpoint",
                                    "url": url,
                                    "method": result.get("request", {}).get("method", "GET"),
                                    "status_code": result.get("response", {}).get("status_code", 0),
                                    "title": result.get("response", {}).get("title", ""),
                                    "content_type": result.get("response", {}).get("content_type", ""),
                                    "content_length": result.get("response", {}).get("content_length", 0),
                                    "headers": result.get("response", {}).get("headers", {}),
                                    "body_preview": result.get("response", {}).get("body", "")[:500],
                                    "depth": result.get("depth", 0),
                                    "source": result.get("source", ""),
                                    "tag": result.get("tag", ""),
                                    "attribute": result.get("attribute", ""),
                                }
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

    async def crawl_multiple(self, targets: list[str], options: dict | None = None) -> ToolResult:
        """Crawl multiple targets.
        
        Args:
            targets: List of URLs to crawl
            options: Same as run()
        """
        import time
        
        start_time = time.time()
        options = options or {}
        
        await self.ensure_installed()
        
        # Write targets to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                f.write(f"{target}\n")
            target_file = f.name
        
        try:
            # Build command with file input
            cmd = [
                str(self.effective_binary_path),
                "-list", target_file,
                "-jsonl",
                "-silent",
                "-nc",
            ]
            
            # Add options
            depth = options.get("depth", 2)  # Lower depth for multiple targets
            cmd.extend(["-d", str(depth)])
            
            if options.get("headless", True):
                cmd.append("-headless")
            if options.get("js_crawl", False):  # Disabled by default for speed
                cmd.append("-jc")
            if "concurrency" in options:
                cmd.extend(["-c", str(options["concurrency"])])
            
            findings = []
            endpoints = set()
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout_chunks = []
            
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
                            url = result.get("request", {}).get("endpoint", "")
                            if url and url not in endpoints:
                                endpoints.add(url)
                                findings.append({
                                    "type": "endpoint",
                                    "url": url,
                                    "method": result.get("request", {}).get("method", "GET"),
                                    "status_code": result.get("response", {}).get("status_code", 0),
                                    "title": result.get("response", {}).get("title", ""),
                                    "content_type": result.get("response", {}).get("content_type", ""),
                                    "depth": result.get("depth", 0),
                                })
                        except json.JSONDecodeError:
                            pass
            
            await asyncio.gather(
                read_stdout(),
                proc.wait()
            )
            
            execution_time = time.time() - start_time
            
            return ToolResult(
                success=len(findings) > 0,
                tool_name=self.name,
                target=f"{len(targets)} URLs",
                findings=findings,
                raw_output="\n".join(stdout_chunks),
                execution_time=execution_time
            )
            
        finally:
            # Cleanup temp file
            import os
            try:
                os.unlink(target_file)
            except:
                pass
