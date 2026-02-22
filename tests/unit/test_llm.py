"""Unit tests for LLM client and integration."""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from bbai.llm.client import (
    AnalysisResult,
    KimiClient,
    LLMResponse,
    MockKimiClient,
)
from bbai.llm.schemas import VulnerabilityAnalysis


class TestKimiClient:
    """Test KimiClient functionality."""

    def test_init_with_api_key(self):
        """Test initialization with explicit API key."""
        client = KimiClient(api_key="test-key")
        assert client.api_key == "test-key"
        assert client.model == "kimi-k2-5"

    def test_init_with_env_var(self, monkeypatch):
        """Test initialization with environment variable."""
        monkeypatch.setenv("MOONSHOT_API_KEY", "env-key")
        client = KimiClient()
        assert client.api_key == "env-key"

    def test_init_without_api_key_raises(self, monkeypatch):
        """Test that initialization fails without API key."""
        monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
        with pytest.raises(ValueError, match="API key required"):
            KimiClient()

    @pytest.mark.asyncio
    async def test_complete_success(self):
        """Test successful completion."""
        client = KimiClient(api_key="test-key")
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Test response"},
                "finish_reason": "stop",
            }],
            "model": "kimi-k2-5",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._client = mock_client
        
        response = await client.complete("Test prompt")
        
        assert response.content == "Test response"
        assert response.model == "kimi-k2-5"
        assert response.usage == {"prompt_tokens": 10, "completion_tokens": 5}

    @pytest.mark.asyncio
    async def test_complete_with_system_prompt(self):
        """Test completion with system prompt."""
        client = KimiClient(api_key="test-key")
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Response"},
                "finish_reason": "stop",
            }],
            "model": "kimi-k2-5",
            "usage": {},
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._client = mock_client
        
        response = await client.complete(
            "Test prompt",
            system_prompt="You are a helpful assistant.",
        )
        
        # Verify the request was made with system message
        call_args = mock_client.post.call_args
        request_data = call_args[1]["json"]
        assert len(request_data["messages"]) == 2
        assert request_data["messages"][0]["role"] == "system"

    @pytest.mark.asyncio
    async def test_analyze_finding(self):
        """Test vulnerability analysis."""
        client = KimiClient(api_key="test-key")
        
        analysis_result = {
            "reasoning": "This is clearly an XSS vulnerability.",
            "is_true_positive": True,
            "vulnerability_type": "CWE-79: XSS",
            "cvss_score": 6.1,
            "confidence": 0.95,
            "recommendations": ["Sanitize user input", "Use CSP"],
        }
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": json.dumps(analysis_result)},
                "finish_reason": "stop",
            }],
            "model": "kimi-k2-5",
            "usage": {},
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._client = mock_client
        
        finding = {
            "type": "XSS",
            "target": "https://example.com/search",
            "evidence": "<script>alert(1)</script>",
        }
        
        result = await client.analyze_finding(finding)
        
        assert isinstance(result, AnalysisResult)
        assert result.is_true_positive is True
        assert result.vulnerability_type == "CWE-79: XSS"
        assert result.cvss_score == 6.1
        assert result.confidence == 0.95
        assert len(result.recommendations) == 2

    @pytest.mark.asyncio
    async def test_analyze_finding_fallback(self):
        """Test analysis with invalid JSON response."""
        client = KimiClient(api_key="test-key")
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "not valid json"},
                "finish_reason": "stop",
            }],
            "model": "kimi-k2-5",
            "usage": {},
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._client = mock_client
        
        finding = {"type": "XSS"}
        
        result = await client.analyze_finding(finding)
        
        # Should fallback to treating as true positive
        assert result.is_true_positive is True
        assert result.confidence == 0.5

    @pytest.mark.asyncio
    async def test_analyze_batch(self):
        """Test batch analysis."""
        client = KimiClient(api_key="test-key")
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "is_true_positive": True,
                        "vulnerability_type": "XSS",
                        "confidence": 0.9,
                        "reasoning": "Test",
                    })
                },
                "finish_reason": "stop",
            }],
            "model": "kimi-k2-5",
            "usage": {},
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._client = mock_client
        
        findings = [
            {"type": "XSS"},
            {"type": "SQLi"},
        ]
        
        results = await client.analyze_batch(findings)
        
        assert len(results) == 2
        assert all(isinstance(r, AnalysisResult) for r in results)

    @pytest.mark.asyncio
    async def test_generate_summary(self):
        """Test summary generation."""
        client = KimiClient(api_key="test-key")
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{
                "message": {"content": "Executive summary here."},
                "finish_reason": "stop",
            }],
            "model": "kimi-k2-5",
            "usage": {},
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post = AsyncMock(return_value=mock_response)
        client._client = mock_client
        
        findings = [{"type": "XSS"}, {"type": "SQLi"}]
        
        summary = await client.generate_summary("https://example.com", findings)
        
        assert summary == "Executive summary here."


class TestMockKimiClient:
    """Test MockKimiClient for testing."""

    @pytest.mark.asyncio
    async def test_mock_complete(self):
        """Test mock completion."""
        client = MockKimiClient()
        
        response = await client.complete("Test prompt")
        
        assert isinstance(response, LLMResponse)
        assert response.content == "Mock response from Kimi K2.5"
        assert response.confidence == 0.85

    @pytest.mark.asyncio
    async def test_mock_json_mode(self):
        """Test mock JSON response."""
        client = MockKimiClient()
        
        response = await client.complete("Test", json_mode=True)
        
        data = json.loads(response.content)
        assert "is_true_positive" in data
        assert "confidence" in data

    @pytest.mark.asyncio
    async def test_mock_analyze_finding(self):
        """Test mock analysis."""
        client = MockKimiClient()
        
        result = await client.analyze_finding({"type": "XSS"})
        
        assert isinstance(result, AnalysisResult)
        assert result.is_true_positive is True
        assert result.confidence == 0.85


class TestLLMSchemas:
    """Test LLM schema validation."""

    def test_vulnerability_analysis_valid(self):
        """Test valid vulnerability analysis."""
        analysis = VulnerabilityAnalysis(
            reasoning="Test reasoning",
            is_true_positive=True,
            vulnerability_type="CWE-79: XSS",
            cvss_score=6.1,
            confidence=0.95,
            recommendations=["Fix 1", "Fix 2"],
        )
        
        assert analysis.is_true_positive is True
        assert analysis.confidence == 0.95
        assert analysis.cvss_score == 6.1

    def test_vulnerability_analysis_invalid_confidence(self):
        """Test invalid confidence value."""
        with pytest.raises(ValueError):
            VulnerabilityAnalysis(
                reasoning="Test",
                is_true_positive=True,
                vulnerability_type="XSS",
                confidence=1.5,  # Invalid: > 1.0
            )

    def test_vulnerability_analysis_invalid_cvss(self):
        """Test invalid CVSS score."""
        with pytest.raises(ValueError):
            VulnerabilityAnalysis(
                reasoning="Test",
                is_true_positive=True,
                vulnerability_type="XSS",
                cvss_score=15.0,  # Invalid: > 10.0
                confidence=0.5,
            )
