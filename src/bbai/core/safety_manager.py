"""Safety Manager - Centralized safety controls for scanning.

Integrates scope validation, rate limiting, and safety guards
into the scanning workflow.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from bbai.core.config_models import BBAIConfig, ProgramConfig
from bbai.core.rate_limiter import MultiRateLimiter
from bbai.core.scope_engine import ScopeValidator, ValidationResult

console = Console()


class SafetyManager:
    """Manages all safety aspects during scanning.
    
    Combines:
    - Scope validation (in-scope/out-of-scope)
    - Private IP blocking
    - Rate limiting
    - Program configuration enforcement
    """

    # Private IP ranges that should never be scanned
    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),  # Link-local
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT
    ]

    def __init__(self, config: BBAIConfig | ProgramConfig | None = None):
        """Initialize safety manager.
        
        Args:
            config: Program configuration with scope rules
        """
        self.config = config
        self.scope_validator = None
        self.rate_limiter = None
        
        if isinstance(config, ProgramConfig):
            self.scope_validator = ScopeValidator(config)
            self.rate_limiter = MultiRateLimiter(config.rate_limit)

    def validate_target(self, target: str) -> ValidationResult:
        """Validate a target URL/domain before scanning.
        
        Checks:
        1. Private IP blocking
        2. Scope validation (if program config provided)
        3. Basic format validation
        
        Args:
            target: URL or domain to validate
            
        Returns:
            ValidationResult with allowed status and reason
        """
        # Parse the target
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # 1. Check for private IPs
        ip_check = self._check_private_ip(hostname)
        if not ip_check.allowed:
            return ip_check
        
        # 2. Check scope if configured
        if self.scope_validator:
            return self.scope_validator.validate_url(target)
        
        # 3. No scope configured - allow but warn
        return ValidationResult(
            allowed=True,
            decision="allowed",
            reason="No scope validation configured - proceeding with caution"
        )

    def _check_private_ip(self, hostname: str) -> ValidationResult:
        """Check if hostname is a private IP address.
        
        Args:
            hostname: Hostname or IP to check
            
        Returns:
            ValidationResult
        """
        try:
            # Try to parse as IP
            ip = ipaddress.ip_address(hostname)
            
            # Check against private networks
            for network in self.PRIVATE_NETWORKS:
                if ip in network:
                    return ValidationResult(
                        allowed=False,
                        decision="private_ip_blocked",
                        reason=f"Private IP address blocked: {hostname}",
                        details={"ip": str(ip), "network": str(network)}
                    )
            
            # Public IP - allowed
            return ValidationResult(
                allowed=True,
                decision="allowed",
                reason="Public IP address"
            )
            
        except ValueError:
            # Not an IP address (it's a hostname) - allowed
            return ValidationResult(
                allowed=True,
                decision="allowed",
                reason="Hostname (not IP)"
            )

    async def check_rate_limit(self, tool_name: str = "default") -> bool:
        """Check if we can proceed based on rate limiting.
        
        Args:
            tool_name: Name of the tool being rate limited
            
        Returns:
            True if allowed to proceed
        """
        if not self.rate_limiter:
            return True
        
        return await self.rate_limiter.acquire(tool_name)

    def validate_scope_file(self, scope_file: Path) -> tuple[bool, str]:
        """Validate a scope configuration file.
        
        Args:
            scope_file: Path to YAML scope file
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import yaml
        
        try:
            with open(scope_file) as f:
                data = yaml.safe_load(f)
            
            # Try to create ProgramConfig
            config = ProgramConfig(**data)
            
            # Validate scope rules
            if not config.scope_in and not config.is_fully_open_scope:
                return False, "No in-scope rules defined"
            
            return True, "Valid"
            
        except Exception as e:
            return False, str(e)

    def print_safety_banner(self) -> None:
        """Print safety information before scanning."""
        text = Text()
        text.append("Safety Controls Active\n\n", style="bold red")
        
        text.append("OK Private IP blocking enabled\n", style="green")
        
        if self.scope_validator:
            text.append("OK Scope validation enabled\n", style="green")
            text.append(f"  In-scope rules: {len(self.config.scope_in)}\n", style="dim")
            text.append(f"  Out-of-scope rules: {len(self.config.scope_out)}\n", style="dim")
        else:
            text.append("WARNING: No scope validation configured\n", style="yellow")
            text.append("  Use --scope-file to define scope\n", style="dim")
        
        if self.rate_limiter:
            text.append("OK Rate limiting enabled\n", style="green")
        
        console.print(Panel(text, border_style="red", title="[bold]Safety[/]"))

    def format_scope_report(self, target: str, result: ValidationResult) -> str:
        """Format a scope validation result for display.
        
        Args:
            target: Target that was checked
            result: Validation result
            
        Returns:
            Formatted string
        """
        if result.allowed:
            return f"[green]OK[/] {target} - {result.reason}"
        else:
            return f"[red]BLOCKED[/] {target} - {result.reason}"


def load_program_config(path: Path) -> ProgramConfig:
    """Load program configuration from YAML file.
    
    Args:
        path: Path to YAML config file
        
    Returns:
        ProgramConfig instance
        
    Raises:
        ValueError: If file is invalid
    """
    import yaml
    
    with open(path) as f:
        data = yaml.safe_load(f)
    
    return ProgramConfig(**data)


def create_safety_manager(
    scope_file: Path | None = None,
    config: BBAIConfig | None = None
) -> SafetyManager:
    """Create a safety manager with optional scope file.
    
    Args:
        scope_file: Optional path to scope YAML file
        config: Optional BBAI config
        
    Returns:
        Configured SafetyManager
    """
    if scope_file and scope_file.exists():
        program_config = load_program_config(scope_file)
        return SafetyManager(program_config)
    
    return SafetyManager(config)


# Global safety manager instance
_safety_manager: SafetyManager | None = None


def get_safety_manager() -> SafetyManager:
    """Get the global safety manager instance."""
    global _safety_manager
    if _safety_manager is None:
        _safety_manager = SafetyManager()
    return _safety_manager
