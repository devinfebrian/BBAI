"""Core modules for BBAI.

This package contains the core safety, configuration, and state management
modules for BBAI.
"""

from bbai.core.config_models import (
    AgentState,
    BBAIConfig,
    LLMProvider,
    LLMProviderConfig,
    ProgramConfig,
    RateLimitConfig,
    SafetyEvent,
    ScopeRule,
    Severity,
    Thought,
    ThoughtType,
    TimingConfig,
    ToolConfig,
    ToolOutput,
    Vulnerability,
)
from bbai.core.rate_limiter import MultiRateLimiter, RateLimiter
from bbai.core.safety_guards import PIIDetector, SafetyCheckResult, SafetyGuard
from bbai.core.scope_engine import (
    SafetyNode,
    ScopeDecision,
    ScopeValidator,
    ScopeViolation,
    ValidationResult,
    allowed_result,
    blocked_result,
)
from bbai.core.state_manager import StateManager

__all__ = [
    # Config models
    "AgentState",
    "BBAIConfig",
    "LLMProvider",
    "LLMProviderConfig",
    "ProgramConfig",
    "RateLimitConfig",
    "SafetyEvent",
    "ScopeRule",
    "Severity",
    "Thought",
    "ThoughtType",
    "TimingConfig",
    "ToolConfig",
    "ToolOutput",
    "Vulnerability",
    # Scope engine
    "SafetyNode",
    "ScopeDecision",
    "ScopeValidator",
    "ScopeViolation",
    "ValidationResult",
    "allowed_result",
    "blocked_result",
    # Rate limiting
    "MultiRateLimiter",
    "RateLimiter",
    # Safety guards
    "PIIDetector",
    "SafetyCheckResult",
    "SafetyGuard",
    # State management
    "StateManager",
]
