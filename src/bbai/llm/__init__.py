"""LLM integration and AI reasoning modules for BBAI.

Provides Kimi K2.5 integration for vulnerability analysis,
strategy selection, and report generation.
"""

from bbai.llm.client import (
    AnalysisResult,
    KimiClient,
    LLMResponse,
    MockKimiClient,
)
from bbai.llm.prompts import (
    ENDPOINT_ANALYSIS_PROMPT,
    PII_DETECTION_PROMPT,
    REPORT_GENERATION_PROMPT,
    SCOPE_VALIDATION_PROMPT,
    STRATEGY_SELECTION_PROMPT,
    SUBDOMAIN_CLASSIFICATION_PROMPT,
    VULNERABILITY_ANALYSIS_PROMPT,
    format_endpoint_list,
    format_strategy_input,
    format_vulnerability_finding,
)
from bbai.llm.schemas import (
    EndpointAnalysis,
    PIIDetection,
    ScopeValidation,
    StrategyDecision,
    SubdomainClassification,
    VulnerabilityAnalysis,
)
from bbai.llm.thought_stream import (
    AIThoughtStreamer,
    ThoughtBranch,
    ThoughtLogger,
    ThoughtTheme,
    think,
)

__all__ = [
    # Client
    "KimiClient",
    "MockKimiClient",
    "LLMResponse",
    "AnalysisResult",
    # Thought streaming
    "AIThoughtStreamer",
    "ThoughtLogger",
    "ThoughtTheme",
    "ThoughtBranch",
    "think",
    # Prompts
    "VULNERABILITY_ANALYSIS_PROMPT",
    "ENDPOINT_ANALYSIS_PROMPT",
    "REPORT_GENERATION_PROMPT",
    "STRATEGY_SELECTION_PROMPT",
    "SCOPE_VALIDATION_PROMPT",
    "PII_DETECTION_PROMPT",
    "SUBDOMAIN_CLASSIFICATION_PROMPT",
    "format_vulnerability_finding",
    "format_endpoint_list",
    "format_strategy_input",
    # Schemas
    "VulnerabilityAnalysis",
    "EndpointAnalysis",
    "StrategyDecision",
    "ScopeValidation",
    "PIIDetection",
    "SubdomainClassification",
]
