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
