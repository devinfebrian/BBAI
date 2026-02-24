"""Pure Python vulnerability scanner - lightweight alternative to Nuclei."""

from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urljoin, urlparse

import httpx

from bbai.tools.wrappers.base import PythonToolWrapper, ToolResult


class PythonVulnScanner(PythonToolWrapper):
    """Pure Python vulnerability scanner.
    
    Basic checks for common vulnerabilities:
    - Missing security headers
    - Information disclosure
    - Default pages
    - Sensitive files
    - SSL/TLS issues
    """

    @property
    def name(self) -> str:
        return "python_vulnscan"

    @property
    def category(self) -> str:
        return "vuln_scan"

    @property
    def description(self) -> str:
        return "Pure Python vulnerability scanner for basic checks"

    # Common sensitive files/paths
    SENSITIVE_PATHS = [
        "/.env",
        "/.git/config",
        "/config.php",
        "/wp-config.php",
        "/phpinfo.php",
        "/.htaccess",
        "/robots.txt",
        "/sitemap.xml",
        "/admin",
        "/administrator",
        "/login",
        "/api",
        "/swagger.json",
        "/openapi.json",
        "/.well-known/security.txt",
    ]

    # Security headers to check
    SECURITY_HEADERS = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "Clickjacking Protection",
        "x-content-type-options": "MIME Sniffing Protection",
        "referrer-policy": "Referrer Policy",
        "permissions-policy": "Permissions Policy",
    }

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Run vulnerability scan.
        
        Args:
            target: URL to scan
            options: {
                "severity": "critical,high,medium,low",
                "checks": ["headers", "sensitive", "info", "ssl"],
            }
        """
        options = options or {}
        severity_filter = options.get("severity", "critical,high,medium,low")
        checks = options.get("checks", ["headers", "sensitive", "info"])
        
        start_time = time.time()
        findings = []
        
        # Parse severity levels
        severity_levels = [s.strip().lower() for s in severity_filter.split(",")]
        
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10,
            verify=False,
        ) as client:
            
            # 1. Basic connectivity and header checks
            if "headers" in checks or "info" in checks:
                try:
                    response = await client.get(target)
                    
                    # Check security headers
                    header_findings = self._check_security_headers(
                        target, response.headers, severity_levels
                    )
                    findings.extend(header_findings)
                    
                    # Check for information disclosure
                    info_findings = self._check_info_disclosure(
                        target, response, severity_levels
                    )
                    findings.extend(info_findings)
                    
                except Exception as e:
                    findings.append({
                        "template": "connection-error",
                        "name": "Connection Error",
                        "severity": "info",
                        "host": target,
                        "matched_at": target,
                        "description": f"Could not connect: {e}",
                    })
            
            # 2. Check sensitive paths
            if "sensitive" in checks:
                sensitive_findings = await self._check_sensitive_paths(
                    client, target, severity_levels
                )
                findings.extend(sensitive_findings)
        
        return ToolResult(
            success=True,
            tool_name=self.name,
            target=target,
            findings=findings,
            execution_time=time.time() - start_time,
        )

    def _check_security_headers(
        self,
        target: str,
        headers: httpx.Headers,
        severity_levels: list[str],
    ) -> list[dict]:
        """Check for missing security headers."""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, description in self.SECURITY_HEADERS.items():
            if header not in headers_lower:
                # Missing security header
                severity = "low"
                if header in ["strict-transport-security", "content-security-policy"]:
                    severity = "medium"
                
                if severity in severity_levels:
                    findings.append({
                        "template": f"missing-{header.replace('_', '-')}",
                        "name": f"Missing {description}",
                        "severity": severity,
                        "host": urlparse(target).netloc,
                        "matched_at": target,
                        "description": f"The {header} header is missing.",
                    })
        
        return findings

    def _check_info_disclosure(
        self,
        target: str,
        response: httpx.Response,
        severity_levels: list[str],
    ) -> list[dict]:
        """Check for information disclosure."""
        findings = []
        host = urlparse(target).netloc
        
        # Server version disclosure
        server = response.headers.get("server", "")
        if server and any(char.isdigit() for char in server):
            # Server header contains version
            if "low" in severity_levels:
                findings.append({
                    "template": "server-version",
                    "name": "Server Version Disclosure",
                    "severity": "low",
                    "host": host,
                    "matched_at": target,
                    "description": f"Server header discloses version: {server}",
                })
        
        # X-Powered-By
        powered = response.headers.get("x-powered-by", "")
        if powered:
            if "low" in severity_levels:
                findings.append({
                    "template": "x-powered-by",
                    "name": "Technology Disclosure",
                    "severity": "low",
                    "host": host,
                    "matched_at": target,
                    "description": f"X-Powered-By header reveals: {powered}",
                })
        
        # Debug/error information in body
        body_lower = response.text.lower()
        debug_patterns = [
            ("stack trace", "Stack Trace Disclosure"),
            ("exception in", "Exception Disclosure"),
            ("sql syntax", "SQL Error Disclosure"),
            ("mysql error", "MySQL Error Disclosure"),
            ("database error", "Database Error Disclosure"),
            ("php warning", "PHP Warning Disclosure"),
            ("php error", "PHP Error Disclosure"),
            ("traceback", "Python Traceback Disclosure"),
        ]
        
        for pattern, name in debug_patterns:
            if pattern in body_lower and len(response.text) < 10000:
                if "medium" in severity_levels:
                    findings.append({
                        "template": f"debug-info-{pattern.replace(' ', '-')}",
                        "name": name,
                        "severity": "medium",
                        "host": host,
                        "matched_at": target,
                        "description": f"Debug information contains '{pattern}'",
                    })
                    break  # Only report one debug disclosure
        
        return findings

    async def _check_sensitive_paths(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        severity_levels: list[str],
    ) -> list[dict]:
        """Check for exposed sensitive files."""
        findings = []
        host = urlparse(base_url).netloc
        
        # Rate limiting for path checks
        semaphore = asyncio.Semaphore(5)
        
        async def check_path(path: str) -> dict | None:
            async with semaphore:
                try:
                    url = urljoin(base_url, path)
                    response = await client.get(url, timeout=5)
                    
                    # If we get 200 OK, it might be exposed
                    if response.status_code == 200:
                        content_length = len(response.content)
                        
                        # Skip if it's just a redirect to login or similar
                        if content_length < 100:
                            return None
                        
                        severity = "medium"
                        if path in ["/.env", "/config.php", "/wp-config.php"]:
                            severity = "high"
                        
                        if severity in severity_levels:
                            return {
                                "template": f"exposed-{path.strip('/').replace('/', '-')}",
                                "name": f"Exposed {path}",
                                "severity": severity,
                                "host": host,
                                "matched_at": url,
                                "description": f"Sensitive path {path} is accessible ({content_length} bytes)",
                            }
                    
                    elif response.status_code == 403:
                        # Forbidden but exists - might be worth noting for some paths
                        if path in ["/.git/config", "/.env"]:
                            if "low" in severity_levels:
                                return {
                                    "template": f"protected-{path.strip('/').replace('/', '-')}",
                                    "name": f"Protected {path} (exists)",
                                    "severity": "low",
                                    "host": host,
                                    "matched_at": url,
                                    "description": f"Path {path} exists but is forbidden (403)",
                                }
                
                except Exception:
                    pass
                
                return None
        
        # Check paths concurrently
        tasks = [check_path(path) for path in self.SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)
        
        findings = [r for r in results if r]
        
        return findings
