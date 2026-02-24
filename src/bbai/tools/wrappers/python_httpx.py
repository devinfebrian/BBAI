"""Pure Python HTTP prober - lightweight alternative to httpx."""

from __future__ import annotations

import asyncio
import ssl
import time
from urllib.parse import urlparse

import httpx

from bbai.tools.wrappers.base import PythonToolWrapper, ToolResult


class PythonHttpx(PythonToolWrapper):
    """Pure Python HTTP prober using httpx library.
    
    Lightweight alternative to ProjectDiscovery's httpx.
    Good enough for most reconnaissance tasks.
    """

    @property
    def name(self) -> str:
        return "python_httpx"

    @property
    def category(self) -> str:
        return "http_probe"

    @property
    def description(self) -> str:
        return "Pure Python HTTP prober using httpx library"

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Probe a single URL.
        
        Args:
            target: URL to probe (e.g., https://example.com)
            options: {
                "follow_redirects": bool,
                "timeout": int,
                "tech_detect": bool,
            }
        """
        options = options or {}
        timeout = options.get("timeout", 10)
        follow_redirects = options.get("follow_redirects", True)
        tech_detect = options.get("tech_detect", True)
        
        start_time = time.time()
        findings = []
        
        try:
            async with httpx.AsyncClient(
                follow_redirects=follow_redirects,
                timeout=timeout,
                verify=False,  # Allow self-signed certs for recon
            ) as client:
                response = await client.get(target)
                
                # Extract info
                result = {
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "title": self._extract_title(response.text),
                    "content_length": len(response.content),
                    "response_time": round(time.time() - start_time, 3),
                }
                
                # Technology detection from headers
                if tech_detect:
                    result["technologies"] = self._detect_tech(response)
                
                # Server header
                server = response.headers.get("server", "")
                if server:
                    result["server"] = server
                
                findings.append(result)
                
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.name,
                target=target,
                findings=[],
                raw_output=str(e),
                error_message=str(e),
                execution_time=time.time() - start_time,
            )
        
        return ToolResult(
            success=True,
            tool_name=self.name,
            target=target,
            findings=findings,
            execution_time=time.time() - start_time,
        )

    async def probe_multiple(
        self,
        targets: list[str],
        options: dict | None = None,
    ) -> ToolResult:
        """Probe multiple URLs concurrently."""
        options = options or {}
        concurrency = options.get("concurrency", 10)
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def probe_one(target: str) -> dict | None:
            async with semaphore:
                result = await self.run(target, options)
                return result.findings[0] if result.findings else None
        
        start_time = time.time()
        tasks = [probe_one(t) for t in targets]
        results = await asyncio.gather(*tasks)
        
        findings = [r for r in results if r]
        
        return ToolResult(
            success=True,
            tool_name=self.name,
            target=f"{len(targets)} URLs",
            findings=findings,
            execution_time=time.time() - start_time,
        )

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML."""
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            # Clean up whitespace
            title = " ".join(title.split())
            return title[:100]  # Limit length
        return ""

    def _detect_tech(self, response: httpx.Response) -> list[str]:
        """Detect technologies from headers and content."""
        techs = []
        headers = response.headers
        
        # Server header
        server = headers.get("server", "").lower()
        if "nginx" in server:
            techs.append("nginx")
        elif "apache" in server:
            techs.append("Apache")
        elif "cloudflare" in server:
            techs.append("Cloudflare")
        elif "microsoft-iis" in server:
            techs.append("IIS")
        
        # X-Powered-By
        powered = headers.get("x-powered-by", "").lower()
        if "php" in powered:
            techs.append("PHP")
        elif "asp.net" in powered:
            techs.append("ASP.NET")
        
        # X-Generator (CMS)
        generator = headers.get("x-generator", "").lower()
        if "wordpress" in generator:
            techs.append("WordPress")
        elif "drupal" in generator:
            techs.append("Drupal")
        elif "joomla" in generator:
            techs.append("Joomla")
        
        # Content-Type
        content_type = headers.get("content-type", "").lower()
        if "application/json" in content_type:
            techs.append("JSON API")
        
        # Set-Cookie analysis
        cookies = headers.get("set-cookie", "").lower()
        if "wordpress" in cookies or "wp-" in cookies:
            techs.append("WordPress")
        if "session" in cookies:
            techs.append("Session-based")
        
        # WAF detection
        if "cf-ray" in headers:
            techs.append("Cloudflare WAF")
        if "akamai" in headers.get("x-cache", "").lower():
            techs.append("Akamai")
        if "fastly" in str(headers).lower():
            techs.append("Fastly")
        
        return list(set(techs))  # Deduplicate
