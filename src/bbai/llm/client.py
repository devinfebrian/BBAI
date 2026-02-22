"""Kimi K2.5 LLM client for BBAI.

Provides async interface to Moonshot AI API with:
- Chain-of-thought prompting
- Structured output (JSON mode)
- Confidence scoring
- Error handling and retries
"""

from __future__ import annotations

import json
import os
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


class KimiClient:
    """Kimi K2.5 API client.
    
    Usage:
        client = KimiClient(api_key="your-key")
        
        # Simple completion
        response = await client.complete("Analyze this vulnerability...")
        
        # Structured analysis
        result = await client.analyze_finding(finding_data)
        
        # With system prompt
        response = await client.complete(
            prompt,
            system_prompt="You are a security analyst..."
        )
    """

    DEFAULT_BASE_URL = "https://api.moonshot.cn/v1"
    DEFAULT_MODEL = "kimi-k2-5"
    
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = DEFAULT_MODEL,
        temperature: float = 0.1,
        max_tokens: int = 4000,
        timeout: float = 60.0,
    ):
        """Initialize Kimi client.
        
        Args:
            api_key: Moonshot API key (or MOONSHOT_API_KEY env var)
            base_url: API base URL
            model: Model name
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
        """
        self.api_key = api_key or os.environ.get("MOONSHOT_API_KEY")
        if not self.api_key:
            raise ValueError(
                "API key required. Set MOONSHOT_API_KEY env var or pass api_key."
            )
        
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
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
        
        request_data: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        if json_mode:
            request_data["response_format"] = {"type": "json_object"}
        
        client = self._get_client()
        
        response = await client.post(
            "/chat/completions",
            json=request_data,
        )
        response.raise_for_status()
        
        data = response.json()
        
        choice = data["choices"][0]
        message = choice["message"]
        
        # Extract reasoning if available
        reasoning = None
        if choice.get("finish_reason") == "stop":
            # Check for reasoning in content
            content = message.get("content", "")
            if "REASONING:" in content:
                parts = content.split("VERDICT:", 1)
                if len(parts) == 2:
                    reasoning = parts[0].replace("REASONING:", "").strip()
        
        return LLMResponse(
            content=message.get("content", ""),
            reasoning=reasoning,
            model=data.get("model", self.model),
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
{json.dumps(findings[:10], indent=2)}  # Limit to first 10
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

    async def __aenter__(self) -> KimiClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()


class MockKimiClient(KimiClient):
    """Mock client for testing without API calls."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize without requiring API key."""
        self.api_key = "mock"
        self.base_url = "mock"
        self.model = "mock-kimi"
        self.temperature = 0.1
        self.max_tokens = 4000
        self.timeout = 60.0
        self._client = None

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
            content = "Mock response from Kimi K2.5"
        
        return LLMResponse(
            content=content,
            reasoning="Mock reasoning",
            confidence=0.85,
            model="mock-kimi",
            usage={"prompt_tokens": 100, "completion_tokens": 50},
        )

    async def close(self) -> None:
        """No-op for mock."""
        pass
