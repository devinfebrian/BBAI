"""LLM Client Factory - creates the appropriate client based on configuration."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from bbai.llm.providers import (
    AnthropicClient,
    BaseLLMClient,
    MockLLMClient,
    MoonshotClient,
    OllamaClient,
    OpenAIClient,
    OpenAICompatibleClient,
)

if TYPE_CHECKING:
    from bbai.core.config_models import LLMProviderConfig


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    MOONSHOT = "moonshot"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai_compatible"
    MOCK = "mock"

    @classmethod
    def get_display_name(cls, provider: str) -> str:
        """Get human-readable display name for provider."""
        names = {
            cls.MOONSHOT: "Moonshot AI (Kimi K)",
            cls.OPENAI: "OpenAI (GPT)",
            cls.ANTHROPIC: "Anthropic (Claude)",
            cls.OLLAMA: "Ollama (Local Models)",
            cls.OPENAI_COMPATIBLE: "OpenAI-Compatible API",
            cls.MOCK: "Mock (for testing)",
        }
        return names.get(provider, provider)

    @classmethod
    def get_default_models(cls, provider: str) -> list[str]:
        """Get default models for a provider."""
        # Updated: 2025-02 with latest model versions
        models = {
            cls.MOONSHOT: ["kimi-k2.5", "kimi-k2-thinking", "kimi-k2-turbo-preview"],
            cls.OPENAI: ["gpt-4o", "o3-mini", "gpt-4o-mini"],
            cls.ANTHROPIC: ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
            cls.OLLAMA: ["llama3.3", "qwen2.5", "llama3.2", "deepseek-r1", "codellama"],
            cls.OPENAI_COMPATIBLE: ["custom-model"],
            cls.MOCK: ["mock-model"],
        }
        return models.get(provider, [])

    @classmethod
    def get_api_key_env(cls, provider: str) -> str:
        """Get environment variable name for API key."""
        env_vars = {
            cls.MOONSHOT: "MOONSHOT_API_KEY",
            cls.OPENAI: "OPENAI_API_KEY",
            cls.ANTHROPIC: "ANTHROPIC_API_KEY",
            cls.OLLAMA: "",
            cls.OPENAI_COMPATIBLE: "OPENAI_API_KEY",
            cls.MOCK: "",
        }
        return env_vars.get(provider, "")

    @classmethod
    def requires_api_key(cls, provider: str) -> bool:
        """Check if provider requires an API key."""
        return cls.get_api_key_env(provider) != ""

    @classmethod
    def get_description(cls, provider: str) -> str:
        """Get description for provider."""
        descriptions = {
            cls.MOONSHOT: "Kimi K2.5 - SOTA model with 256K context, supports thinking mode",
            cls.OPENAI: "GPT-4o and o3-mini - Industry standard models for analysis",
            cls.ANTHROPIC: "Claude 3.5 Sonnet - Strong reasoning and code analysis",
            cls.OLLAMA: "Run models locally - Free, private, no API keys needed",
            cls.OPENAI_COMPATIBLE: "Custom OpenAI-compatible endpoint (LocalAI, vLLM, etc.)",
            cls.MOCK: "Mock responses for testing without API costs or network",
        }
        return descriptions.get(provider, "")


# Mapping of provider enum to client class
PROVIDER_CLIENT_MAP: dict[LLMProvider, type[BaseLLMClient]] = {
    LLMProvider.MOONSHOT: MoonshotClient,
    LLMProvider.OPENAI: OpenAIClient,
    LLMProvider.ANTHROPIC: AnthropicClient,
    LLMProvider.OLLAMA: OllamaClient,
    LLMProvider.OPENAI_COMPATIBLE: OpenAICompatibleClient,
    LLMProvider.MOCK: MockLLMClient,
}


def create_llm_client(config: LLMProviderConfig | None = None, **kwargs) -> BaseLLMClient:
    """Create an LLM client from configuration.
    
    Args:
        config: LLM provider configuration
        **kwargs: Additional arguments to pass to client constructor
        
    Returns:
        Configured LLM client instance
        
    Raises:
        ValueError: If provider is not supported or config is invalid
        
    Examples:
        # From config
        client = create_llm_client(config)
        
        # Direct creation
        client = create_llm_client(
            provider="openai",
            api_key="sk-...",
            model="gpt-4"
        )
    """
    if config is not None:
        provider = LLMProvider(config.provider)
        client_class = PROVIDER_CLIENT_MAP.get(provider)
        
        if not client_class:
            raise ValueError(f"Unsupported provider: {config.provider}")
        
        return client_class(
            api_key=config.api_key,
            base_url=config.base_url,
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            timeout=config.timeout,
            **kwargs,
        )
    else:
        # Create from kwargs
        provider_str = kwargs.pop("provider", "mock")
        provider = LLMProvider(provider_str)
        client_class = PROVIDER_CLIENT_MAP.get(provider)
        
        if not client_class:
            raise ValueError(f"Unsupported provider: {provider_str}")
        
        return client_class(**kwargs)


def get_available_providers() -> list[dict[str, str]]:
    """Get list of available providers with metadata.
    
    Returns:
        List of provider metadata dictionaries
    """
    providers = []
    for provider in LLMProvider:
        providers.append({
            "id": provider.value,
            "name": LLMProvider.get_display_name(provider.value),
            "description": LLMProvider.get_description(provider.value),
            "requires_api_key": LLMProvider.requires_api_key(provider.value),
            "api_key_env": LLMProvider.get_api_key_env(provider.value),
        })
    return providers


async def fetch_models(
    provider: str,
    api_key: str | None = None,
    base_url: str | None = None,
    use_cache: bool = True,
) -> list[dict[str, Any]]:
    """Fetch available models from a provider API.
    
    Fetches models dynamically from the provider's API. Falls back to
    default hardcoded models if the API call fails.
    
    Args:
        provider: Provider identifier (e.g., "openai", "moonshot")
        api_key: API key for authentication (optional for some providers)
        base_url: Custom base URL (optional)
        use_cache: Whether to use cached results (not implemented yet)
        
    Returns:
        List of model info dictionaries with keys:
        - id: Model identifier string
        - name: Human-readable name
        - description: Model description
        - context_length: Context window size
        
    Examples:
        # Fetch OpenAI models
        models = await fetch_models("openai", api_key="sk-...")
        
        # Fetch Ollama models (no API key needed)
        models = await fetch_models("ollama")
        
        # Fetch with fallback on error
        try:
            models = await fetch_models("openai", api_key=key)
        except Exception:
            models = LLMProvider.get_default_models("openai")
    """
    import os
    
    provider_enum = LLMProvider(provider)
    client_class = PROVIDER_CLIENT_MAP.get(provider_enum)
    
    if not client_class:
        raise ValueError(f"Unsupported provider: {provider}")
    
    # Get API key from environment if not provided
    if api_key is None and LLMProvider.requires_api_key(provider):
        env_var = LLMProvider.get_api_key_env(provider)
        api_key = os.environ.get(env_var)
    
    # Create temporary client
    client = client_class(
        api_key=api_key,
        base_url=base_url,
        model="",  # Not needed for listing
    )
    
    try:
        models = await client.list_models()
        return models
    except Exception:
        # Fallback to default models
        default_models = LLMProvider.get_default_models(provider)
        return [
            {
                "id": m,
                "name": m,
                "description": f"Default {provider} model",
                "context_length": None,
            }
            for m in default_models
        ]
    finally:
        await client.close()


def fetch_models_sync(
    provider: str,
    api_key: str | None = None,
    base_url: str | None = None,
) -> list[dict[str, Any]]:
    """Synchronous version of fetch_models.
    
    Convenience wrapper for non-async contexts.
    """
    import asyncio
    return asyncio.run(fetch_models(provider, api_key, base_url))
