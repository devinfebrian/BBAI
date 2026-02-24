"""Kimi K2.5 LLM client for BBAI (Legacy compatibility).

This module is kept for backward compatibility.
New code should use the multi-provider clients from bbai.llm.providers or
bbai.llm.factory for automatic provider selection.
"""

from __future__ import annotations

# Re-export from providers for backward compatibility
from bbai.llm.providers import (
    AnalysisResult,
    LLMResponse,
    MoonshotClient as KimiClient,
    MockLLMClient as MockKimiClient,
)

__all__ = [
    "AnalysisResult",
    "KimiClient",
    "LLMResponse",
    "MockKimiClient",
]
