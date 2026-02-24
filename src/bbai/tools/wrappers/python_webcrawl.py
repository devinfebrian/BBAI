"""Python-native web crawler and content discovery."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from bbai.tools.wrappers.base import PythonToolWrapper, ToolResult


class PythonWebCrawler(PythonToolWrapper):
    """Pure Python web crawler for endpoint discovery."""

    # Common paths to check
    COMMON_PATHS = [
        "admin", "administrator", "adminpanel", "controlpanel", "cpanel",
        "login", "signin", "logout", "register", "signup", "auth",
        "api", "api/v1", "api/v2", "graphql", "graph", "swagger", "docs",
        "dashboard", "panel", "manage", "management", "backend",
        "test", "testing", "dev", "development", "staging", "stage",
        "debug", "phpinfo", "info", "server-status", "status",
        "config", "configuration", "settings", "env", "environment",
        "robots.txt", "sitemap.xml", ".well-known/security.txt",
        ".git", ".git/config", ".svn", ".hg", ".env", ".htaccess",
        "backup", "backups", "dump", "dumps", "archive", "archives",
        "old", "backup.zip", "backup.sql", "dump.sql", "database.sql",
        "wp-admin", "wp-login", "wp-content", "wp-includes",
        "phpmyadmin", "pma", "myadmin", "mysql", "dbadmin",
        "server", "phpinfo.php", "info.php", "test.php",
        "js", "javascript", "scripts", "css", "styles", "assets",
        "images", "img", "uploads", "files", "media", "static",
        "v1", "v2", "v3", "version", "versions", "release", "releases",
        "internal", "intranet", "private", "restricted", "secure",
        "webhook", "webhooks", "callback", "callbacks", "hook",
        "api/docs", "api/swagger", "api/openapi", "swagger-ui",
        "actuator", "health", "metrics", "prometheus", "metrics/prometheus",
    ]

    def __init__(self):
        """Initialize crawler."""
        super().__init__()
        self.visited_urls = set()
        self.found_endpoints = []

    @property
    def name(self) -> str:
        return "python_web_crawler"

    @property
    def category(self) -> str:
        return "content_discovery"

    @property
    def description(self) -> str:
        return "Pure Python web crawler and content discovery"

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Crawl target for endpoints."""
        import time
        
        start_time = time.time()
        options = options or {}
        
        # Normalize URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        base_url = target.rstrip("/")
        parsed = urlparse(base_url)
        base_domain = parsed.netloc
        
        findings = []
        
        # Method 1: Check common paths
        await self._check_common_paths(base_url, findings, options)
        
        # Method 2: Crawl homepage for links
        await self._crawl_page(base_url, findings, options, base_domain)
        
        execution_time = time.time() - start_time
        
        return ToolResult(
            success=True,
            tool_name=self.name,
            target=target,
            findings=findings,
            execution_time=execution_time
        )

    async def _check_common_paths(
        self,
        base_url: str,
        findings: list,
        options: dict
    ) -> None:
        """Check common paths for existence."""
        paths = options.get("paths", self.COMMON_PATHS)
        concurrency = options.get("concurrency", 20)
        timeout = options.get("timeout", 10)
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def check_path(path: str) -> dict | None:
            async with semaphore:
                url = f"{base_url}/{path}"
                try:
                    async with httpx.AsyncClient(
                        follow_redirects=True,
                        timeout=timeout,
                        verify=False
                    ) as client:
                        response = await client.get(url)
                        
                        # Check if path exists (not 404)
                        if response.status_code != 404:
                            return {
                                "type": "endpoint",
                                "url": url,
                                "status_code": response.status_code,
                                "content_length": len(response.content),
                                "content_type": response.headers.get("content-type", ""),
                                "method": "path_discovery"
                            }
                except Exception:
                    pass
                return None
        
        tasks = [check_path(path) for path in paths]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                findings.append(result)

    async def _crawl_page(
        self,
        url: str,
        findings: list,
        options: dict,
        base_domain: str,
        depth: int = 0
    ) -> None:
        """Crawl a single page for links."""
        max_depth = options.get("max_depth", 2)
        
        if depth > max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10,
                verify=False
            ) as client:
                response = await client.get(url)
                
                if response.status_code != 200:
                    return
                
                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type:
                    return
                
                content = response.text
                
                # Extract links
                links = self._extract_links(content, url, base_domain)
                
                # Add to findings
                for link in links:
                    findings.append({
                        "type": "endpoint",
                        "url": link,
                        "source_page": url,
                        "method": "web_crawl"
                    })
                
                # Recursively crawl (limited)
                if depth < max_depth:
                    tasks = [
                        self._crawl_page(link, findings, options, base_domain, depth + 1)
                        for link in links[:10]  # Limit branching
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    
        except Exception:
            pass

    def _extract_links(self, content: str, base_url: str, base_domain: str) -> list[str]:
        """Extract links from HTML content."""
        links = []
        
        # Find href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(href_pattern, content, re.IGNORECASE)
        
        for match in matches:
            # Skip empty, javascript, mailto, tel
            if not match or match.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            
            # Convert to absolute URL
            absolute_url = urljoin(base_url, match)
            parsed = urlparse(absolute_url)
            
            # Only keep same-domain URLs
            if parsed.netloc == base_domain:
                # Normalize
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean_url not in self.visited_urls:
                    links.append(clean_url)
        
        return list(set(links))
