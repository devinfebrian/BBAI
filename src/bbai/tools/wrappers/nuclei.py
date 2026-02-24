"""Nuclei vulnerability scanner wrapper."""

from __future__ import annotations

import asyncio
import json
import platform
from pathlib import Path

from bbai.tools.wrappers.base import BinaryToolWrapper, ToolResult


class NucleiWrapper(BinaryToolWrapper):
    """Nuclei vulnerability scanner with auto-download."""

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def category(self) -> str:
        return "vuln_scan"

    @property
    def description(self) -> str:
        return "Fast vulnerability scanner with 4000+ templates"

    @property
    def binary_name(self) -> str:
        return "nuclei"

    @property
    def download_urls(self) -> dict[str, str]:
        """Download URLs for each platform."""
        version = "3.3.9"
        base = f"https://github.com/projectdiscovery/nuclei/releases/download/v{version}"
        return {
            "linux_amd64": f"{base}/nuclei_{version}_linux_amd64.zip",
            "linux_arm64": f"{base}/nuclei_{version}_linux_arm64.zip",
            "macos_amd64": f"{base}/nuclei_{version}_macOS_amd64.zip",
            "macos_arm64": f"{base}/nuclei_{version}_macOS_arm64.zip",
            "windows_amd64": f"{base}/nuclei_{version}_windows_amd64.zip",
        }

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Run Nuclei scan."""
        import time
        
        start_time = time.time()
        options = options or {}
        
        # Ensure installed
        await self.ensure_installed()
        
        # Build command using effective binary path (local or system)
        cmd = [
            str(self.effective_binary_path),
            "-u", target,
            "-jsonl",
            "-silent",
            "-nc",  # No color
        ]
        
        # Add severity filter if specified
        severity = options.get("severity", "critical,high,medium")
        if severity:
            cmd.extend(["-s", severity])
        
        # Add rate limiting
        rate_limit = options.get("rate_limit", 150)
        cmd.extend(["-rl", str(rate_limit)])
        
        # Add timeout
        timeout = options.get("timeout", 30)
        cmd.extend(["-timeout", str(timeout)])
        
        # Template filters
        templates = options.get("templates")
        if templates:
            cmd.extend(["-t", templates])
        
        # Exclude templates
        exclude = options.get("exclude")
        if exclude:
            cmd.extend(["-exclude-templates", exclude])
        
        # Run scan
        findings = []
        raw_output = ""
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024*1024,  # 1MB buffer
            )
            
            # Stream output
            stdout_chunks = []
            stderr_chunks = []
            
            async def read_stdout():
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    line_str = line.decode().strip()
                    stdout_chunks.append(line_str)
                    
                    # Parse JSON findings
                    if line_str:
                        try:
                            finding = json.loads(line_str)
                            findings.append({
                                "type": "vulnerability",
                                "template": finding.get("template-id"),
                                "name": finding.get("info", {}).get("name"),
                                "severity": finding.get("info", {}).get("severity"),
                                "host": finding.get("host"),
                                "matched_at": finding.get("matched-at"),
                                "extracted_results": finding.get("extracted-results", []),
                                "description": finding.get("info", {}).get("description"),
                                "reference": finding.get("info", {}).get("reference", []),
                                "curl_command": finding.get("curl-command"),
                            })
                        except json.JSONDecodeError:
                            pass
            
            async def read_stderr():
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    stderr_chunks.append(line.decode())
            
            # Run both readers concurrently
            await asyncio.gather(
                read_stdout(),
                read_stderr(),
                proc.wait()
            )
            
            raw_output = "\n".join(stdout_chunks)
            error_output = "".join(stderr_chunks)
            
            execution_time = time.time() - start_time
            
            return ToolResult(
                success=proc.returncode == 0 or len(findings) > 0,
                tool_name=self.name,
                target=target,
                findings=findings,
                raw_output=raw_output,
                error_message=error_output if error_output else "",
                execution_time=execution_time
            )
            
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                target=target,
                findings=findings,
                error_message=str(e),
                execution_time=time.time() - start_time
            )

    async def update_templates(self) -> bool:
        """Update Nuclei templates to latest."""
        if not await self.is_available():
            return False
        
        try:
            proc = await asyncio.create_subprocess_exec(
                str(self.effective_binary_path),
                "-ut",  # Update templates
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False
