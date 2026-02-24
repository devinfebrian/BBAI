"""Python-native async port scanner."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

from bbai.tools.wrappers.base import PythonToolWrapper, ToolResult


class PythonPortScanner(PythonToolWrapper):
    """Pure Python async port scanner."""

    # Common web service ports
    WEB_PORTS = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 8001, 8081, 8888, 9000]
    
    # Common service ports
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        110,   # POP3
        143,   # IMAP
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        9200,  # Elasticsearch
        27017, # MongoDB
    ]

    TOP_100_PORTS = [
        80, 443, 8080, 8443, 21, 22, 23, 25, 53, 110, 143, 445, 3306, 3389,
        5900, 5432, 6379, 9200, 27017, 11211, 27018, 27019, 28017, 22, 2222,
        3000, 4000, 5000, 7000, 8000, 8008, 8081, 8888, 9000, 9090, 10000,
        32768, 49152, 49153, 49154, 1025, 1026, 1027, 1028, 1029, 1030,
        135, 139, 445, 515, 631, 587, 993, 995, 1433, 1521, 2049, 2401,
        4045, 5190, 5666, 6000, 6001, 6010, 6011, 6012, 6013, 6014, 6015,
        6016, 6017, 6018, 6019, 6020, 7001, 7002, 7003, 7004, 7005, 7006,
        7007, 7008, 7009, 7010, 7100, 7510, 8082, 8083, 8084, 8085, 8086,
        8087, 8088, 8089, 8090, 8880, 40000, 50000, 55000, 56000, 57000
    ]

    def __init__(self):
        """Initialize scanner."""
        super().__init__()

    @property
    def name(self) -> str:
        return "python_port_scanner"

    @property
    def category(self) -> str:
        return "port_scan"

    @property
    def description(self) -> str:
        return "Pure Python async TCP port scanner"

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Scan ports on target."""
        import time
        
        start_time = time.time()
        options = options or {}
        
        # Resolve hostname if needed
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return ToolResult(
                success=False,
                tool_name=self.name,
                target=target,
                error_message=f"Could not resolve {target}"
            )
        
        # Get port list
        scan_type = options.get("scan_type", "web")
        if scan_type == "web":
            ports = self.WEB_PORTS
        elif scan_type == "common":
            ports = self.COMMON_PORTS
        elif scan_type == "top100":
            ports = self.TOP_100_PORTS
        elif scan_type == "full":
            ports = list(range(1, 65536))
        else:
            ports = options.get("ports", self.WEB_PORTS)
        
        concurrency = options.get("concurrency", 100)
        timeout = options.get("timeout", 3)
        
        semaphore = asyncio.Semaphore(concurrency)
        open_ports = []
        
        async def scan_port(port: int) -> dict | None:
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    # Try to get banner
                    service = self._guess_service(port)
                    
                    return {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "protocol": "tcp"
                    }
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None
        
        # Run scans
        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        findings = [r for r in results if r is not None]
        
        execution_time = time.time() - start_time
        
        return ToolResult(
            success=True,
            tool_name=self.name,
            target=target,
            findings=findings,
            execution_time=execution_time
        )

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https",
            445: "microsoft-ds", 587: "smtp", 631: "ipp",
            8080: "http-proxy", 8443: "https-alt",
            3000: "http", 4000: "http", 5000: "http", 8000: "http",
            3306: "mysql", 5432: "postgresql", 6379: "redis",
            9200: "elasticsearch", 27017: "mongodb",
            3389: "ms-wbt-server", 5900: "vnc",
        }
        return services.get(port, "unknown")
