"""LLM integration and AI reasoning modules for BBAI.

Provides multi-provider LLM integration for vulnerability analysis,
strategy selection, and report generation.

Supported providers:
- Moonshot AI (Kimi K2.5)
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Ollama (local models)
- OpenAI-compatible APIs
"""

# New multi-provider imports
from bbai.llm.factory import (
    LLMProvider,
    create_llm_client,
    fetch_models,
    fetch_models_sync,
    get_available_providers,
)
from bbai.llm.providers import (
    AnalysisResult,
    BaseLLMClient,
    LLMResponse,
    MockLLMClient,
)

# Keep backward compatibility with old imports
from bbai.llm.client import (
    AnalysisResult as LegacyAnalysisResult,
    KimiClient,
    LLMResponse as LegacyLLMResponse,
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
    # Factory (new multi-provider)
    "LLMProvider",
    "create_llm_client",
    "fetch_models",
    "fetch_models_sync",
    "get_available_providers",
    # Providers
    "BaseLLMClient",
    "MockLLMClient",
    "LLMResponse",
    "AnalysisResult",
    # Legacy clients (backward compatibility)
    "KimiClient",
    "MockKimiClient",
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
