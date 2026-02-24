"""Multi-provider LLM client implementations.

Supports:
- Moonshot AI (Kimi K2.5)
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Ollama (local models)
- OpenAI-compatible APIs (custom endpoints)
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class LLMResponse:
    """Structured LLM response."""

    content: str
    reasoning: str | None = None
    confidence: float = 0.0
    model: str = ""
    usage: dict[str, int] | None = None


@dataclass
class AnalysisResult:
    """Vulnerability analysis result."""

    is_true_positive: bool
    vulnerability_type: str
    cvss_score: float | None
    confidence: float
    reasoning: str
    recommendations: list[str] | None = None


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "",
        temperature: float = 0.1,
        max_tokens: int = 4000,
        timeout: float = 60.0,
    ):
        """Initialize base LLM client.
        
        Args:
            api_key: API key for the provider
            base_url: Custom base URL for the API
            model: Model name to use
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @abstractmethod
    def _get_api_key_env(self) -> str:
        """Get environment variable name for API key."""
        pass

    @abstractmethod
    def _get_default_base_url(self) -> str:
        """Get default base URL for the API."""
        pass

    @abstractmethod
    def _get_default_model(self) -> str:
        """Get default model name."""
        pass

    @abstractmethod
    def _build_request_payload(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
    ) -> dict[str, Any]:
        """Build the request payload for the API."""
        pass

    @abstractmethod
    def _extract_response_content(self, data: dict[str, Any]) -> tuple[str, str]:
        """Extract content and model from response data.
        
        Returns:
            Tuple of (content, model_name)
        """
        pass

    async def list_models(self) -> list[dict[str, Any]]:
        """List available models from the provider.
        
        Returns:
            List of model info dictionaries with keys:
            - id: Model identifier
            - name: Human-readable name (optional)
            - description: Model description (optional)
            - context_length: Context window size (optional)
        
        Raises:
            NotImplementedError: If provider doesn't support model listing
            httpx.HTTPError: If API request fails
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support listing models")

    def _get_api_key(self) -> str | None:
        """Get API key from parameter or environment."""
        if self.api_key:
            return self.api_key
        return os.environ.get(self._get_api_key_env())

    def _get_base_url(self) -> str:
        """Get base URL."""
        return self.base_url or self._get_default_base_url()

    def _get_model(self) -> str:
        """Get model name."""
        return self.model or self._get_default_model()

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            headers = {
                "Content-Type": "application/json",
            }
            if self._get_api_key():
                headers["Authorization"] = f"Bearer {self._get_api_key()}"
            
            self._client = httpx.AsyncClient(
                base_url=self._get_base_url(),
                headers=headers,
                timeout=self.timeout,
            )
        return self._client

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def complete(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Send completion request.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            json_mode: Request JSON formatted response
            
        Returns:
            LLM response
        """
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        request_data = self._build_request_payload(messages, json_mode)
        
        client = self._get_client()
        
        response = await client.post(
            "/chat/completions",
            json=request_data,
        )
        response.raise_for_status()
        
        data = response.json()
        
        content, model_used = self._extract_response_content(data)
        
        # Extract reasoning if available
        reasoning = None
        if "REASONING:" in content:
            parts = content.split("VERDICT:", 1)
            if len(parts) == 2:
                reasoning = parts[0].replace("REASONING:", "").strip()
        
        return LLMResponse(
            content=content,
            reasoning=reasoning,
            model=model_used,
            usage=data.get("usage"),
        )

    async def analyze_finding(self, finding: dict[str, Any]) -> AnalysisResult:
        """Analyze a security finding with chain-of-thought reasoning.
        
        Args:
            finding: Finding data dictionary
            
        Returns:
            Structured analysis result
        """
        system_prompt = """You are an expert security analyst. Analyze the vulnerability finding and provide structured output.

Think step by step:
1. TECHNICAL VALIDITY: Is the vulnerability technically real and exploitable?
2. SCOPE COMPLIANCE: Is this finding within the defined scope?
3. BUSINESS IMPACT: What's the actual severity for this target type?
4. CONFIDENCE: Rate your certainty (0.0-1.0)

Respond in JSON format:
{
    "reasoning": "detailed step-by-step analysis",
    "is_true_positive": true/false,
    "vulnerability_type": "CWE-ID or category name",
    "cvss_score": 0.0-10.0 or null,
    "confidence": 0.0-1.0,
    "recommendations": ["list", "of", "remediation", "steps"]
}"""

        prompt = f"Analyze this vulnerability finding:\n\n```json\n{json.dumps(finding, indent=2)}\n```"
        
        try:
            response = await self.complete(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True,
            )
            
            # Parse JSON response
            result_data = json.loads(response.content)
            
            return AnalysisResult(
                is_true_positive=result_data.get("is_true_positive", True),
                vulnerability_type=result_data.get("vulnerability_type", "unknown"),
                cvss_score=result_data.get("cvss_score"),
                confidence=result_data.get("confidence", 0.5),
                reasoning=result_data.get("reasoning", "No reasoning provided"),
                recommendations=result_data.get("recommendations", []),
            )
            
        except (json.JSONDecodeError, KeyError) as e:
            # Fallback if JSON parsing fails
            return AnalysisResult(
                is_true_positive=True,
                vulnerability_type=finding.get("type", "unknown"),
                cvss_score=None,
                confidence=0.5,
                reasoning=f"Analysis parsing failed: {e}. Treating as true positive.",
                recommendations=["Manual review recommended"],
            )

    async def analyze_batch(
        self,
        findings: list[dict[str, Any]],
    ) -> list[AnalysisResult]:
        """Analyze multiple findings in batch.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            List of analysis results
        """
        results = []
        for finding in findings:
            result = await self.analyze_finding(finding)
            results.append(result)
        return results

    async def generate_summary(
        self,
        target: str,
        findings: list[dict[str, Any]],
    ) -> str:
        """Generate executive summary of findings.
        
        Args:
            target: Target that was scanned
            findings: List of findings
            
        Returns:
            Summary text
        """
        system_prompt = """You are a security report writer. Create a concise executive summary.

Guidelines:
- Be objective and factual
- Highlight critical findings first
- Include risk assessment
- Suggest next steps"""

        prompt = f"""Generate an executive summary for security scan of {target}.

Findings: {len(findings)}

Finding details:
```json
{json.dumps(findings[:10], indent=2)}
```

Provide a 2-3 paragraph executive summary suitable for stakeholders."""

        response = await self.complete(
            prompt=prompt,
            system_prompt=system_prompt,
        )
        
        return response.content

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> BaseLLMClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()


class MoonshotClient(BaseLLMClient):
    """Moonshot AI (Kimi K2.5) client."""

    def _get_api_key_env(self) -> str:
        return "MOONSHOT_API_KEY"

    def _get_default_base_url(self) -> str:
        return "https://api.moonshot.cn/v1"

    def _get_default_model(self) -> str:
        return "kimi-k2-5"

    def _build_request_payload(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
    ) -> dict[str, Any]:
        """Build Moonshot API request payload."""
        request_data: dict[str, Any] = {
            "model": self._get_model(),
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        if json_mode:
            request_data["response_format"] = {"type": "json_object"}
        
        return request_data

    def _extract_response_content(self, data: dict[str, Any]) -> tuple[str, str]:
        """Extract content from Moonshot response."""
        choice = data["choices"][0]
        message = choice["message"]
        content = message.get("content", "")
        model = data.get("model", self._get_model())
        return content, model

    async def list_models(self) -> list[dict[str, Any]]:
        """List available models from Moonshot API.
        
        https://platform.moonshot.cn/docs/api/models#list-models
        """
        client = self._get_client()
        response = await client.get("/models")
        response.raise_for_status()
        data = response.json()
        
        models = []
        for model in data.get("data", []):
            model_id = model.get("id", "")
            models.append({
                "id": model_id,
                "name": model.get("display_name") or model_id,
                "description": self._get_moonshot_model_description(model_id),
                "context_length": model.get("context_length") or 256000,
            })
        
        # Sort by preference
        models.sort(key=lambda m: self._moonshot_model_priority(m["id"]), reverse=True)
        return models
    
    def _get_moonshot_model_description(self, model_id: str) -> str:
        """Get description for Moonshot model using pattern matching.
        
        Handles known models and provides generic descriptions for new variants.
        """
        model_id_lower = model_id.lower()
        
        # Pattern-based matching for flexibility with new model variants
        if "k2.5" in model_id_lower or "k2-5" in model_id_lower:
            if "thinking" in model_id_lower:
                return "Kimi K2.5 Thinking - Extended reasoning mode"
            return "Kimi K2.5 - State-of-the-art with 256K context"
        elif "k2-turbo" in model_id_lower or "k2-turbo" in model_id_lower:
            return "Kimi K2 Turbo - Fast and efficient"
        elif "k1.5" in model_id_lower or "k1-5" in model_id_lower:
            return "Kimi K1.5 - Long context specialist"
        elif "k1" in model_id_lower:
            return "Kimi K1 - Long context model"
        
        return "Moonshot AI model"
    
    def _moonshot_model_priority(self, model_id: str) -> int:
        """Get priority for sorting (higher = first).
        
        Uses pattern matching to handle new model variants.
        """
        model_id_lower = model_id.lower()
        
        # Pattern-based priority (newer/better models = higher priority)
        if "k2.5" in model_id_lower or "k2-5" in model_id_lower:
            return 100 if "thinking" not in model_id_lower else 95
        elif "k2-turbo" in model_id_lower:
            return 90
        elif "k1.5" in model_id_lower or "k1-5" in model_id_lower:
            return 80
        elif "k1" in model_id_lower:
            return 70
        
        return 0  # Unknown models at the end


class OpenAIClient(BaseLLMClient):
    """OpenAI API client (GPT-4, GPT-3.5)."""

    def _get_api_key_env(self) -> str:
        return "OPENAI_API_KEY"

    def _get_default_base_url(self) -> str:
        return "https://api.openai.com/v1"

    def _get_default_model(self) -> str:
        return "gpt-4"

    def _build_request_payload(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
    ) -> dict[str, Any]:
        """Build OpenAI API request payload."""
        request_data: dict[str, Any] = {
            "model": self._get_model(),
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        if json_mode:
            request_data["response_format"] = {"type": "json_object"}
        
        return request_data

    def _extract_response_content(self, data: dict[str, Any]) -> tuple[str, str]:
        """Extract content from OpenAI response."""
        choice = data["choices"][0]
        message = choice["message"]
        content = message.get("content", "")
        model = data.get("model", self._get_model())
        return content, model

    async def list_models(self) -> list[dict[str, Any]]:
        """List available models from OpenAI API.
        
        https://platform.openai.com/docs/api-reference/models/list
        """
        client = self._get_client()
        response = await client.get("/models")
        response.raise_for_status()
        data = response.json()
        
        models = []
        for model in data.get("data", []):
            model_id = model.get("id", "")
            # Filter for chat completion models (exclude embeddings, audio, etc.)
            if any(x in model_id for x in ["gpt-", "o1", "o3", "chatgpt"]):
                models.append({
                    "id": model_id,
                    "name": model.get("display_name") or model_id,
                    "description": self._get_openai_model_description(model_id),
                    "context_length": self._get_openai_context_length(model_id),
                    "created": model.get("created"),
                })
        
        # Sort by preference (newer/better models first)
        models.sort(key=lambda m: self._openai_model_priority(m["id"]), reverse=True)
        return models
    
    def _get_openai_model_description(self, model_id: str) -> str:
        """Get description for OpenAI model using pattern matching.
        
        Handles known models and provides generic descriptions for new variants.
        """
        model_id_lower = model_id.lower()
        
        # Pattern-based matching for flexibility with new model variants
        if "gpt-4o" in model_id_lower:
            if "mini" in model_id_lower:
                return "GPT-4o Mini - Fast, cost-effective multimodal model"
            return "GPT-4o - Most capable multimodal model"
        elif "o3" in model_id_lower:
            if "mini" in model_id_lower:
                return "o3-mini - Reasoning model for coding and STEM"
            return "o3 - Advanced reasoning model"
        elif "o1" in model_id_lower:
            if "mini" in model_id_lower:
                return "o1-mini - Faster reasoning model"
            return "o1 - Advanced reasoning model"
        elif "gpt-4-turbo" in model_id_lower:
            return "GPT-4 Turbo - Previous generation GPT-4"
        elif "gpt-4" in model_id_lower:
            return "GPT-4 - Original GPT-4 model"
        elif "gpt-3.5" in model_id_lower:
            return "GPT-3.5 Turbo - Fast, cost-effective for simple tasks"
        
        return "OpenAI model"
    
    def _get_openai_context_length(self, model_id: str) -> int:
        """Get context length for OpenAI model using pattern matching."""
        model_id_lower = model_id.lower()
        
        # Pattern-based context lengths
        if any(x in model_id_lower for x in ["gpt-4o", "o1-mini"]):
            return 128000
        elif any(x in model_id_lower for x in ["o3", "o1-"]):
            return 200000  # o3 and o1 (non-mini)
        elif "gpt-4-turbo" in model_id_lower:
            return 128000
        elif "gpt-4" in model_id_lower:
            return 8192
        elif "gpt-3.5" in model_id_lower:
            return 16385
        
        return 128000  # Default for new models (most modern models support 128K)
    
    def _openai_model_priority(self, model_id: str) -> int:
        """Get priority for sorting (higher = first).
        
        Uses pattern matching to handle new model variants.
        """
        model_id_lower = model_id.lower()
        
        # Pattern-based priority (better models = higher priority)
        if "gpt-4o" in model_id_lower:
            return 85 if "mini" in model_id_lower else 100
        elif "o3" in model_id_lower:
            return 90 if "mini" not in model_id_lower else 88
        elif "o1" in model_id_lower:
            return 85 if "mini" not in model_id_lower else 80
        elif "gpt-4-turbo" in model_id_lower:
            return 70
        elif "gpt-4" in model_id_lower:
            return 60
        elif "gpt-3.5" in model_id_lower:
            return 50
        
        return 0  # Unknown models at the end


class AnthropicClient(BaseLLMClient):
    """Anthropic API client (Claude)."""

    def _get_api_key_env(self) -> str:
        return "ANTHROPIC_API_KEY"

    def _get_default_base_url(self) -> str:
        return "https://api.anthropic.com/v1"

    def _get_default_model(self) -> str:
        return "claude-3-5-sonnet-20241022"

    def _build_request_payload(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
    ) -> dict[str, Any]:
        """Build Anthropic API request payload."""
        # Separate system message from other messages
        system_message = None
        user_messages = []
        
        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
            else:
                user_messages.append(msg)
        
        request_data: dict[str, Any] = {
            "model": self._get_model(),
            "messages": user_messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        
        if system_message:
            request_data["system"] = system_message
        
        return request_data

    def _extract_response_content(self, data: dict[str, Any]) -> tuple[str, str]:
        """Extract content from Anthropic response."""
        content_blocks = data.get("content", [])
        content = ""
        for block in content_blocks:
            if block.get("type") == "text":
                content += block.get("text", "")
        
        model = data.get("model", self._get_model())
        return content, model

    async def list_models(self) -> list[dict[str, Any]]:
        """List available models from Anthropic API.
        
        Note: Anthropic doesn't have a public /models endpoint yet.
        Returns hardcoded list of current models with metadata.
        
        https://docs.anthropic.com/en/docs/about-claude/models
        """
        # Anthropic doesn't expose a models endpoint, so we return known models
        # This list should be updated periodically
        models = [
            {
                "id": "claude-3-5-sonnet-20241022",
                "name": "Claude 3.5 Sonnet (New)",
                "description": "Most intelligent model - best for complex tasks",
                "context_length": 200000,
                "created": 1729728000,
            },
            {
                "id": "claude-3-5-sonnet-20240620",
                "name": "Claude 3.5 Sonnet (Old)",
                "description": "Previous version of Claude 3.5 Sonnet",
                "context_length": 200000,
                "created": 1718841600,
            },
            {
                "id": "claude-3-opus-20240229",
                "name": "Claude 3 Opus",
                "description": "Powerful model for highly complex tasks",
                "context_length": 200000,
                "created": 1709164800,
            },
            {
                "id": "claude-3-sonnet-20240229",
                "name": "Claude 3 Sonnet",
                "description": "Balance of intelligence and speed",
                "context_length": 200000,
                "created": 1709164800,
            },
            {
                "id": "claude-3-haiku-20240307",
                "name": "Claude 3 Haiku",
                "description": "Fastest model for lightweight actions",
                "context_length": 200000,
                "created": 1709769600,
            },
        ]
        return models


class OllamaClient(BaseLLMClient):
    """Ollama local API client."""

    def _get_api_key_env(self) -> str:
        """Ollama doesn't require an API key for local use."""
        return ""

    def _get_default_base_url(self) -> str:
        return "http://localhost:11434/v1"

    def _get_default_model(self) -> str:
        return "llama3.1"

    def _build_request_payload(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
    ) -> dict[str, Any]:
        """Build Ollama-compatible request payload."""
        request_data: dict[str, Any] = {
            "model": self._get_model(),
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        
        return request_data

    def _extract_response_content(self, data: dict[str, Any]) -> tuple[str, str]:
        """Extract content from Ollama/OpenAI-compatible response."""
        choice = data["choices"][0]
        message = choice["message"]
        content = message.get("content", "")
        model = data.get("model", self._get_model())
        return content, model

    async def list_models(self) -> list[dict[str, Any]]:
        """List available models from Ollama API.
        
        https://ollama.com/docs/api#list-local-models
        """
        # Ollama uses a different endpoint structure
        base_url = self._get_base_url().replace("/v1", "")  # Remove /v1 suffix
        
        async with httpx.AsyncClient(base_url=base_url, timeout=self.timeout) as client:
            response = await client.get("/api/tags")
            response.raise_for_status()
            data = response.json()
        
        models = []
        for model in data.get("models", []):
            model_name = model.get("name", "")
            models.append({
                "id": model_name,
                "name": model_name,
                "description": self._get_ollama_model_description(model_name),
                "context_length": self._get_ollama_context_length(model_name),
                "size": model.get("size"),
                "modified_at": model.get("modified_at"),
            })
        
        # Sort alphabetically
        models.sort(key=lambda m: m["id"])
        return models
    
    def _get_ollama_model_description(self, model_id: str) -> str:
        """Get description for Ollama model using pattern matching.
        
        Handles known models and provides generic descriptions for new variants.
        """
        model_id_lower = model_id.lower()
        
        # Pattern-based matching for flexibility with new model variants
        if "llama3.3" in model_id_lower:
            return "Meta's Llama 3.3 70B - State-of-the-art open model"
        elif "llama3.2" in model_id_lower:
            return "Meta's Llama 3.2 (1B-3B) - Lightweight, efficient"
        elif "llama3.1" in model_id_lower:
            return "Meta's Llama 3.1 (8B-405B) - Strong general performance"
        elif "llama3" in model_id_lower:
            return "Meta's Llama 3 - Modern open model"
        elif "llama2" in model_id_lower:
            return "Meta's Llama 2 - Previous generation open model"
        elif "qwen2.5" in model_id_lower or "qwen2-5" in model_id_lower:
            return "Alibaba's Qwen 2.5 - Excellent multilingual model"
        elif "qwen2" in model_id_lower:
            return "Alibaba's Qwen 2 - Strong multilingual model"
        elif "deepseek-r1" in model_id_lower:
            return "DeepSeek-R1 - Reasoning-focused model"
        elif "deepseek" in model_id_lower:
            return "DeepSeek - Open reasoning model"
        elif "codellama" in model_id_lower:
            return "Meta's CodeLlama - Code-specialized model"
        elif "mixtral" in model_id_lower:
            return "Mistral's Mixtral MoE - Powerful but large"
        elif "mistral" in model_id_lower:
            return "Mistral AI's model - Strong performance"
        elif "phi4" in model_id_lower:
            return "Microsoft's Phi-4 - Small but capable"
        elif "phi3" in model_id_lower:
            return "Microsoft's Phi-3 - Efficient small model"
        elif "gemma2" in model_id_lower or "gemma-2" in model_id_lower:
            return "Google's Gemma 2 - Open models by Google"
        elif "gemma" in model_id_lower:
            return "Google's Gemma - Open models by Google"
        elif "command" in model_id_lower:
            return "Cohere's Command model - Enterprise-focused"
        elif "dolphin" in model_id_lower:
            return "Dolphin - Uncensored conversational model"
        
        return "Local Ollama model"
    
    def _get_ollama_context_length(self, model_id: str) -> int:
        """Get context length for Ollama model."""
        # Most modern models support at least 8K, many support 128K
        if any(x in model_id.lower() for x in ["llama3", "qwen2.5", "mistral", "mixtral"]):
            return 128000
        elif "deepseek" in model_id.lower():
            return 64000
        return 8192  # Default


class OpenAICompatibleClient(OpenAIClient):
    """Generic OpenAI-compatible API client for custom endpoints.
    
    Examples:
        - LocalAI
        - text-generation-webui
        - vLLM
        - Any OpenAI-compatible proxy
    """

    def _get_api_key_env(self) -> str:
        """Allow custom env var or default to OPENAI_API_KEY."""
        return "OPENAI_API_KEY"


class MockLLMClient(BaseLLMClient):
    """Mock client for testing without API calls."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize without requiring API key."""
        self.api_key = "mock"
        self.base_url = "mock"
        self.model = kwargs.get("model", "mock-model")
        self.temperature = 0.1
        self.max_tokens = 4000
        self.timeout = 60.0
        self._client = None

    def _get_api_key_env(self) -> str:
        return ""

    def _get_default_base_url(self) -> str:
        return ""

    def _get_default_model(self) -> str:
        return "mock-model"

    def _build_request_payload(
        self,
        messages: list[dict[str, str]],
        json_mode: bool = False,
    ) -> dict[str, Any]:
        return {}

    def _extract_response_content(self, data: dict[str, Any]) -> tuple[str, str]:
        return "", ""

    async def list_models(self) -> list[dict[str, Any]]:
        """Return mock models."""
        return [
            {
                "id": "mock-model",
                "name": "Mock Model",
                "description": "Mock model for testing",
                "context_length": 4096,
            }
        ]

    async def complete(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Return mock response."""
        if json_mode:
            content = json.dumps({
                "reasoning": "Mock analysis: This appears to be a valid finding.",
                "is_true_positive": True,
                "vulnerability_type": "Mock Type",
                "cvss_score": 5.0,
                "confidence": 0.85,
                "recommendations": ["Fix the issue", "Verify the fix"],
            })
        else:
            content = f"Mock response from {self.model}"
        
        return LLMResponse(
            content=content,
            reasoning="Mock reasoning",
            confidence=0.85,
            model=self.model,
            usage={"prompt_tokens": 100, "completion_tokens": 50},
        )

    async def close(self) -> None:
        """No-op for mock."""
        pass
