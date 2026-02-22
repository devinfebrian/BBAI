"""Pydantic v2 configuration models for BBAI.

This module defines all configuration schemas using Pydantic v2 best practices:
- Using model_config = ConfigDict() instead of class Config
- Using computed_fields for derived properties
- Proper type annotations with Optional and Annotated
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThoughtType(str, Enum):
    """Types of AI thoughts for visualization."""

    ANALYZING = "analyzing"
    DECIDING = "deciding"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"
    INFO = "info"


class ScopeRule(BaseModel):
    """A single scope rule (in-scope or out-of-scope)."""

    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    pattern: str = Field(..., description="Wildcard pattern for matching domains/URLs")
    description: str | None = Field(default=None, description="Human-readable description")
    is_regex: bool = Field(default=False, description="Whether pattern is a regex")

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        """Validate pattern is not empty."""
        if not v or not v.strip():
            raise ValueError("Pattern cannot be empty")
        return v.strip()

    def matches(self, hostname: str) -> bool:
        """Check if hostname matches this rule."""
        if self.is_regex:
            try:
                return bool(re.search(self.pattern, hostname, re.IGNORECASE))
            except re.error:
                return False
        
        # Wildcard matching: *.example.com matches sub.example.com
        pattern = self.pattern.lower()
        hostname = hostname.lower()
        
        # Full wildcard matches everything
        if pattern == "*":
            return True
        
        if pattern.startswith("*."):
            # *.example.com matches example.com and sub.example.com
            domain = pattern[2:]
            return hostname == domain or hostname.endswith("." + domain)
        
        return hostname == pattern


class TimingConfig(BaseModel):
    """Timing restrictions for scanning."""

    model_config = ConfigDict(frozen=True)

    timezone: str = Field(default="UTC", description="Timezone for blocked hours")
    blocked_hours: str | None = Field(
        default=None,
        description="Blocked time range in HH:MM-HH:MM format (e.g., 09:00-17:00)",
    )
    max_requests_per_second: float = Field(
        default=5.0,
        ge=0.1,
        le=100.0,
        description="Maximum requests per second",
    )

    @field_validator("blocked_hours")
    @classmethod
    def validate_blocked_hours(cls, v: str | None) -> str | None:
        """Validate blocked hours format."""
        if v is None:
            return v
        
        pattern = r"^([0-1]?[0-9]|2[0-3]):([0-5][0-9])-([0-1]?[0-9]|2[0-3]):([0-5][0-9])$"
        if not re.match(pattern, v):
            raise ValueError(
                "Blocked hours must be in HH:MM-HH:MM format (e.g., 09:00-17:00)"
            )
        return v


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""

    model_config = ConfigDict(frozen=True)

    requests_per_second: float = Field(default=5.0, ge=0.1, le=100.0)
    burst_size: int = Field(default=10, ge=1, le=100)
    concurrent_tools: int = Field(default=3, ge=1, le=10)
    tool_timeout: int = Field(default=300, ge=30, le=3600, description="Timeout in seconds")


class ToolConfig(BaseModel):
    """Configuration for a specific security tool."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(..., min_length=1)
    enabled: bool = Field(default=True)
    image: str = Field(..., description="Docker image name")
    extra_args: list[str] = Field(default_factory=list)
    custom_timeout: int | None = Field(default=None, ge=30, le=3600)


class ProgramConfig(BaseModel):
    """Bug bounty program configuration.
    
    This is the main configuration model that defines the scope and rules
    for a bug bounty program. It uses frozen=True to ensure immutability
    for safety-critical scope rules.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Metadata
    name: str = Field(..., min_length=1, description="Program name")
    description: str | None = Field(default=None)
    platform: Literal["hackerone", "bugcrowd", "intigriti", "custom"] = Field(
        default="custom"
    )
    program_url: str | None = Field(default=None)

    # Scope - CRITICAL: These are immutable for legal protection
    scope_in: list[ScopeRule] = Field(
        default_factory=list,
        description="In-scope targets (allowed for testing)",
    )
    scope_out: list[ScopeRule] = Field(
        default_factory=list,
        description="Out-of-scope targets (explicitly forbidden)",
    )

    # Timing and rate limits
    timing: TimingConfig = Field(default_factory=TimingConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)

    # Tool configurations
    tools: dict[str, ToolConfig] = Field(default_factory=dict)

    # Safety settings
    auto_halt_on_critical: bool = Field(
        default=True,
        description="Auto-pause on CVSS 9.0+ findings",
    )
    block_private_ips: bool = Field(default=True)
    require_human_confirmation: list[Severity] = Field(
        default_factory=lambda: [Severity.CRITICAL, Severity.HIGH],
        description="Severity levels requiring human confirmation",
    )

    @model_validator(mode="after")
    def validate_scope_conflicts(self) -> ProgramConfig:
        """Ensure no conflicting scope rules."""
        # Check for identical patterns in both in and out scope
        in_patterns = {r.pattern for r in self.scope_in}
        out_patterns = {r.pattern for r in self.scope_out}
        conflicts = in_patterns & out_patterns
        if conflicts:
            raise ValueError(f"Scope conflict: patterns in both in and out scope: {conflicts}")
        return self

    @computed_field
    @property
    def has_restricted_timing(self) -> bool:
        """Check if program has timing restrictions."""
        return self.timing.blocked_hours is not None

    @computed_field
    @property
    def is_fully_open_scope(self) -> bool:
        """Check if program has wildcard in-scope."""
        return any(r.pattern == "*" for r in self.scope_in)


class SafetyEvent(BaseModel):
    """A safety event during scanning."""

    model_config = ConfigDict(frozen=True)

    level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(...)
    reason: str = Field(...)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    """A discovered vulnerability."""

    model_config = ConfigDict(frozen=True)

    # Identification
    id: str = Field(..., description="Unique vulnerability ID")
    type: str = Field(..., description="Vulnerability type (e.g., SQL Injection)")
    cwe_id: str | None = Field(default=None, description="CWE identifier")
    
    # Location
    target: str = Field(..., description="Affected target/URL")
    endpoint: str | None = Field(default=None)
    parameter: str | None = Field(default=None)

    # Severity
    severity: Severity = Field(default=Severity.MEDIUM)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)

    # Evidence
    description: str = Field(...)
    reproduction_steps: str = Field(...)
    evidence: str = Field(...)
    
    # AI Analysis
    ai_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    ai_reasoning: str | None = Field(default=None)
    is_false_positive: bool = Field(default=False)

    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    tool_source: str = Field(..., description="Tool that discovered this")


class ToolOutput(BaseModel):
    """Output from a tool execution."""

    model_config = ConfigDict(frozen=True)

    tool_name: str = Field(...)
    exit_code: int = Field(...)
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    execution_time: float = Field(..., description="Execution time in seconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Thought(BaseModel):
    """A single AI thought for visualization."""

    model_config = ConfigDict(frozen=True)

    type: ThoughtType = Field(...)
    message: str = Field(...)
    details: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    timestamp: float = Field(...)


class AgentState(BaseModel):
    """LangGraph agent state.
    
    This is NOT frozen as it represents mutable state during execution.
    """

    model_config = ConfigDict(extra="allow")

    # Config
    target: str = Field(...)
    config: ProgramConfig = Field(...)
    thread_id: str = Field(...)

    # Progress
    current_phase: str = Field(default="initialized")
    discovered_endpoints: list[str] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)

    # AI Reasoning
    thoughts: list[Thought] = Field(default_factory=list)
    next_recommended_action: str | None = Field(default=None)

    # Safety
    halt_requested: bool = Field(default=False)
    safety_events: list[SafetyEvent] = Field(default_factory=list)

    # Metadata
    start_time: datetime = Field(default_factory=datetime.utcnow)
    tool_outputs: list[ToolOutput] = Field(default_factory=list)

    def add_thought(
        self,
        thought_type: ThoughtType,
        message: str,
        details: list[str] | None = None,
        confidence: float | None = None,
    ) -> None:
        """Add a thought to the state."""
        import time
        
        self.thoughts.append(
            Thought(
                type=thought_type,
                message=message,
                details=details or [],
                confidence=confidence,
                timestamp=time.time(),
            )
        )

    def add_safety_event(
        self,
        level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Add a safety event and optionally halt."""
        self.safety_events.append(
            SafetyEvent(
                level=level,
                reason=reason,
                details=details or {},
            )
        )
        if level == "CRITICAL":
            self.halt_requested = True


class BBAIConfig(BaseModel):
    """Global BBAI application configuration.
    
    Loaded from environment variables and config files.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # LLM Settings
    moonshot_api_key: str | None = Field(default=None)
    moonshot_model: str = Field(default="kimi-k2-5")
    moonshot_base_url: str | None = Field(default=None)

    # Paths
    data_dir: Path = Field(default=Path.home() / ".bbai")
    projects_dir: Path = Field(default=Path.home() / ".bbai" / "projects")
    logs_dir: Path = Field(default=Path.home() / ".bbai" / "logs")

    # UI Settings
    theme: Literal["dark", "light", "system"] = Field(default="dark")
    show_thought_stream: bool = Field(default=True)
    thought_stream_refresh_rate: int = Field(default=10, ge=1, le=60)

    # Docker Settings
    docker_host: str | None = Field(default=None)
    docker_timeout: int = Field(default=300, ge=10, le=600)

    @field_validator("data_dir", "projects_dir", "logs_dir", mode="before")
    @classmethod
    def ensure_path(cls, v: Any) -> Path:
        """Ensure value is a Path."""
        if isinstance(v, str):
            return Path(v)
        return v

    @model_validator(mode="after")
    def ensure_directories(self) -> BBAIConfig:
        """Ensure data directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        return self
