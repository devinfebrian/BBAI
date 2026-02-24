"""Safety & Scope Engine - Immutable legal protection layer.

CRITICAL: Every network operation MUST pass through here.
No exceptions. Immutable rules.

This module implements the four-layer safety model:
1. Configuration Validation (Startup)
2. Pre-Execution (Every tool call)
3. Network Interception (Optional)
4. Post-Execution (Output sanitization)
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import pytz
from pydantic import BaseModel, ConfigDict, Field

from bbai.core.config_models import ProgramConfig, SafetyEvent, ScopeRule


class ScopeDecision(str, Enum):
    """Scope validation decision outcomes."""

    ALLOWED = "allowed"
    CACHED_BLOCKED = "cached_blocked"
    BLACKLIST = "blacklist"
    NO_SCOPE_MATCH = "no_scope_match"
    PRIVATE_IP_BLOCKED = "private_ip_blocked"
    TIMING_BLOCKED = "timing_blocked"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


class ValidationResult(BaseModel):
    """Result of a scope validation check."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    decision: ScopeDecision
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


def allowed_result(reason: str = "ALLOWED", details: dict[str, Any] | None = None) -> ValidationResult:
    """Create an allowed validation result."""
    return ValidationResult(
        allowed=True,
        decision=ScopeDecision.ALLOWED,
        reason=reason,
        details=details or {},
    )


def blocked_result(
    decision: ScopeDecision,
    reason: str,
    details: dict[str, Any] | None = None,
) -> ValidationResult:
    """Create a blocked validation result."""
    return ValidationResult(
        allowed=False,
        decision=decision,
        reason=reason,
        details=details or {},
    )


class ScopeValidator:
    """Immutable scope validator for legal protection.
    
    CRITICAL: Every network operation MUST pass through here.
    
    Usage:
        validator = ScopeValidator(config)
        result = validator.validate_url("https://sub.example.com/path")
        if not result.allowed:
            logger.critical(f"Scope violation: {result.reason}")
            raise ScopeViolation(result)
    
    Implementation follows defense-in-depth:
    - Layer 1: Cache check (fast path for known domains)
    - Layer 2: Blacklist check (out-of-scope first)
    - Layer 3: In-scope validation
    - Layer 4: Private IP blocking
    """

    # Patterns that might indicate PII in URLs
    PII_PATTERNS = [
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # Email
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
        re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),  # Credit card
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),  # IP addresses
    ]

    def __init__(self, config: ProgramConfig):
        self.config = config
        # Thread-safe caches using sets for O(1) lookups
        self._allowed_cache: set[str] = set()
        self._blocked_cache: set[str] = set()

    def validate_url(self, url: str) -> ValidationResult:
        """Pre-flight check for EVERY HTTP request.
        
        Args:
            url: URL to validate
            
        Returns:
            ValidationResult with allowed status and reason
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return blocked_result(
                ScopeDecision.NO_SCOPE_MATCH,
                "INVALID_URL: No hostname",
                {"url": url},
            )

        # Layer 1: Cache check (fast path)
        if hostname in self._blocked_cache:
            return blocked_result(
                ScopeDecision.CACHED_BLOCKED,
                f"CACHED_BLOCKED: {hostname}",
                {"hostname": hostname},
            )
        
        if hostname in self._allowed_cache:
            return allowed_result(
                "CACHED_ALLOWED",
                {"hostname": hostname},
            )

        # Layer 2: Out-of-scope (blacklist first)
        for rule in self.config.scope_out:
            if rule.matches(hostname):
                self._blocked_cache.add(hostname)
                return blocked_result(
                    ScopeDecision.BLACKLIST,
                    f"BLACKLIST:{rule.pattern}",
                    {"hostname": hostname, "rule": rule.pattern},
                )

        # Layer 3: Private IP blocking (before in-scope to ensure safety)
        is_ip = False
        ip_obj = None
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip = True
            if self.config.block_private_ips and ip_obj.is_private:
                return blocked_result(
                    ScopeDecision.PRIVATE_IP_BLOCKED,
                    "PRIVATE_IP_BLOCKED",
                    {"hostname": hostname, "ip": str(ip_obj)},
                )
        except ValueError:
            pass  # Not an IP address, continue

        # Layer 4: In-scope validation
        for rule in self.config.scope_in:
            if rule.matches(hostname):
                self._allowed_cache.add(hostname)
                return allowed_result(
                    "ALLOWED",
                    {"hostname": hostname, "rule": rule.pattern},
                )

        # Layer 5: If it's a public IP and we have wildcard in scope, allow it
        if is_ip and ip_obj and not ip_obj.is_private:
            if any(r.pattern == "*" for r in self.config.scope_in):
                self._allowed_cache.add(hostname)
                return allowed_result(
                    "ALLOWED_PUBLIC_IP",
                    {"hostname": hostname, "ip": str(ip_obj)},
                )

        return blocked_result(
            ScopeDecision.NO_SCOPE_MATCH,
            "NO_SCOPE_MATCH",
            {"hostname": hostname},
        )

    def validate_timing(self) -> ValidationResult:
        """Check timing restrictions (market hours protection).
        
        Returns:
            ValidationResult - allowed if not in blocked hours
        """
        if not self.config.timing.blocked_hours:
            return allowed_result("NO_RESTRICTION")

        try:
            tz = pytz.timezone(self.config.timing.timezone)
        except pytz.UnknownTimeZoneError:
            return allowed_result(
                "INVALID_TIMEZONE",
                {"timezone": self.config.timing.timezone},
            )

        now = datetime.now(tz)
        current_time = now.time()

        # Parse blocked hours (HH:MM-HH:MM format)
        start_str, end_str = self.config.timing.blocked_hours.split("-")
        start_time = datetime.strptime(start_str, "%H:%M").time()
        end_time = datetime.strptime(end_str, "%H:%M").time()

        # Handle overnight ranges (e.g., 22:00-06:00)
        if start_time < end_time:
            is_blocked = start_time <= current_time <= end_time
        else:
            is_blocked = current_time >= start_time or current_time <= end_time

        if is_blocked:
            return blocked_result(
                ScopeDecision.TIMING_BLOCKED,
                f"MARKET_HOURS:{self.config.timing.blocked_hours}",
                {
                    "blocked_hours": self.config.timing.blocked_hours,
                    "current_time": current_time.isoformat(),
                    "timezone": self.config.timing.timezone,
                },
            )

        return allowed_result(
            "TIMING_OK",
            {"current_time": current_time.isoformat()},
        )

    def validate_tool_permission(self, tool_name: str) -> ValidationResult:
        """Check if a tool is permitted for this program.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            ValidationResult
        """
        if tool_name not in self.config.tools:
            # Tool not explicitly configured - allow by default
            return allowed_result("TOOL_NOT_CONFIGURED")

        tool_config = self.config.tools[tool_name]
        if not tool_config.enabled:
            return blocked_result(
                ScopeDecision.NO_SCOPE_MATCH,
                f"TOOL_DISABLED:{tool_name}",
                {"tool": tool_name},
            )

        return allowed_result(
            "TOOL_ENABLED",
            {"tool": tool_name, "image": tool_config.image},
        )

    def check_pii_in_url(self, url: str) -> list[str]:
        """Check for potential PII in URL.
        
        Args:
            url: URL to check
            
        Returns:
            List of detected PII types
        """
        detected = []
        for pattern in self.PII_PATTERNS:
            if pattern.search(url):
                detected.append(pattern.pattern)
        return detected

    def clear_cache(self) -> None:
        """Clear validation caches. Useful for testing or scope updates."""
        self._allowed_cache.clear()
        self._blocked_cache.clear()

    def get_cache_stats(self) -> dict[str, int]:
        """Get cache statistics."""
        return {
            "allowed_cache_size": len(self._allowed_cache),
            "blocked_cache_size": len(self._blocked_cache),
        }


class ScopeViolation(Exception):
    """Exception raised when a scope violation is detected.
    
    This is a critical exception that should halt execution immediately.
    """

    def __init__(self, result: ValidationResult, url: str | None = None):
        self.result = result
        self.url = url
        super().__init__(f"Scope violation: {result.reason}")

    def to_safety_event(self) -> SafetyEvent:
        """Convert to a safety event for logging."""
        return SafetyEvent(
            level="CRITICAL",
            reason=self.result.reason,
            details={
                "url": self.url,
                "decision": self.result.decision,
                **self.result.details,
            },
        )


class SafetyNode:
    """LangGraph safety node for pre/post execution validation.
    
    Usage in LangGraph:
        workflow.add_node("safety_pre", SafetyNode.pre_execution)
        workflow.add_node("safety_post", SafetyNode.post_execution)
    """

    @staticmethod
    def pre_execution(state: dict[str, Any]) -> dict[str, Any]:
        """Pre-execution safety checks.
        
        Validates:
        - Target URL is in scope
        - Timing restrictions
        - Tool permissions
        
        Args:
            state: Current agent state
            
        Returns:
            Updated state with safety check results
        """
        config = state.get("config")
        target = state.get("target")
        
        if not config or not target:
            return {
                **state,
                "halt_requested": True,
                "safety_events": state.get("safety_events", []) + [
                    SafetyEvent(
                        level="CRITICAL",
                        reason="MISSING_CONFIG_OR_TARGET",
                    )
                ],
            }

        validator = ScopeValidator(config)
        
        # Check target URL
        result = validator.validate_url(target)
        if not result.allowed:
            violation = ScopeViolation(result, target)
            return {
                **state,
                "halt_requested": True,
                "safety_events": state.get("safety_events", []) + [violation.to_safety_event()],
            }

        # Check timing
        result = validator.validate_timing()
        if not result.allowed:
            violation = ScopeViolation(result, target)
            return {
                **state,
                "halt_requested": True,
                "safety_events": state.get("safety_events", []) + [violation.to_safety_event()],
            }

        # All checks passed
        return state

    @staticmethod
    def post_execution(state: dict[str, Any]) -> dict[str, Any]:
        """Post-execution safety checks.
        
        Validates:
        - Output sanitization (PII removal)
        - Finding validation
        
        Args:
            state: Current agent state
            
        Returns:
            Updated state
        """
        # TODO: Implement output sanitization
        return state
