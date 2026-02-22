"""Unit tests for safety guards and PII detection."""

import pytest

from bbai.core.config_models import Severity, Vulnerability
from bbai.core.safety_guards import (
    PIIDetector,
    SafetyCheckResult,
    SafetyGuard,
    create_safety_event,
)


class TestPIIDetector:
    """Test PII detection patterns."""

    @pytest.fixture
    def detector(self):
        return PIIDetector()

    def test_email_detection(self, detector):
        text = "Contact us at admin@example.com or support@company.org"
        findings = detector.detect(text)
        
        email_findings = [f for f in findings if f["type"] == "email"]
        assert len(email_findings) == 2

    def test_ssn_detection(self, detector):
        text = "SSN: 123-45-6789"
        findings = detector.detect(text)
        
        ssn_findings = [f for f in findings if f["type"] == "ssn"]
        assert len(ssn_findings) == 1

    def test_credit_card_detection(self, detector):
        text = "Card: 4111 1111 1111 1111"
        findings = detector.detect(text)
        
        cc_findings = [f for f in findings if f["type"] == "credit_card"]
        assert len(cc_findings) == 1

    def test_phone_detection(self, detector):
        text = "Call (555) 123-4567"
        findings = detector.detect(text)
        
        phone_findings = [f for f in findings if f["type"] == "phone"]
        assert len(phone_findings) == 1

    def test_api_key_detection(self, detector):
        text = "api_key: abcdefghijklmnop1234"
        findings = detector.detect(text)
        
        api_findings = [f for f in findings if f["type"] == "api_key"]
        assert len(api_findings) == 1

    def test_jwt_detection(self, detector):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0.NTQ"
        findings = detector.detect(text)
        
        jwt_findings = [f for f in findings if f["type"] == "jwt"]
        assert len(jwt_findings) == 1

    def test_no_pii(self, detector):
        text = "This is a normal text without any PII"
        assert not detector.has_pii(text)

    def test_has_pii(self, detector):
        text = "Contact admin@example.com"
        assert detector.has_pii(text)

    def test_sanitize_with_hash(self, detector):
        text = "Email: admin@example.com"
        sanitized = detector.sanitize(text, keep_hash=True)
        
        assert "[REDACTED]" in sanitized
        assert "admin@example.com" not in sanitized
        assert ":email:" in sanitized

    def test_sanitize_without_hash(self, detector):
        text = "Email: admin@example.com"
        sanitized = detector.sanitize(text, keep_hash=False)
        
        assert "[REDACTED]:email" in sanitized
        assert "admin@example.com" not in sanitized

    def test_multiple_pii_types(self, detector):
        text = "Email: user@example.com, SSN: 123-45-6789"
        findings = detector.detect(text)
        
        types = set(f["type"] for f in findings)
        assert "email" in types
        assert "ssn" in types

    def test_get_pattern_names(self, detector):
        names = detector.get_pattern_names()
        assert "email" in names
        assert "ssn" in names
        assert "credit_card" in names


class TestSafetyGuard:
    """Test SafetyGuard functionality."""

    @pytest.fixture
    def guard(self):
        return SafetyGuard(auto_sanitize=True)

    @pytest.mark.asyncio
    async def test_check_tool_output_with_pii(self, guard):
        output = "Found user email: admin@example.com"
        result = guard.check_tool_output(output, "nuclei", "example.com")
        
        assert result.has_pii is True
        assert len(result.pii_findings) > 0
        assert "[REDACTED]" in result.sanitized_output

    @pytest.mark.asyncio
    async def test_check_tool_output_without_pii(self, guard):
        output = "Server: nginx/1.18.0"
        result = guard.check_tool_output(output, "nuclei", "example.com")
        
        assert result.has_pii is False
        assert result.original_output == result.sanitized_output

    @pytest.mark.asyncio
    async def test_safety_events_generated(self, guard):
        output = "Email: a@b.com, c@d.com, e@f.com"  # Multiple PII
        result = guard.check_tool_output(output, "nuclei", "example.com")
        
        assert len(result.safety_events) > 0
        # HIGH level for many PII instances
        assert result.safety_events[0].level in ("HIGH", "MEDIUM")

    def test_safety_check_result_properties(self):
        event = create_safety_event("CRITICAL", "TEST", key="value")
        result = SafetyCheckResult(
            has_pii=True,
            pii_findings=[],
            original_output="test",
            sanitized_output="sanitized",
            safety_events=[event],
        )
        
        assert result.should_halt is True
        assert result.requires_review is True

    def test_safety_check_result_no_halt(self):
        event = create_safety_event("LOW", "TEST")
        result = SafetyCheckResult(
            has_pii=False,
            pii_findings=[],
            original_output="test",
            sanitized_output="test",
            safety_events=[event],
        )
        
        assert result.should_halt is False
        assert result.requires_review is False

    def test_validate_finding_with_pii(self, guard):
        finding = Vulnerability(
            id="VULN-001",
            type="XSS",
            target="https://example.com",
            description="XSS vulnerability",
            reproduction_steps="Inject <script>",
            evidence="Email leaked: user@example.com",
            severity=Severity.MEDIUM,
            tool_source="nuclei",
        )
        
        event = guard.validate_finding(finding)
        assert event is not None
        assert event.level == "HIGH"
        assert "PII_IN_FINDING_EVIDENCE" in event.reason

    def test_validate_finding_critical_severity(self, guard):
        finding = Vulnerability(
            id="VULN-001",
            type="RCE",
            target="https://example.com",
            description="RCE vulnerability",
            reproduction_steps="Send payload",
            evidence="Command output",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            tool_source="nuclei",
        )
        
        event = guard.validate_finding(finding)
        assert event is not None
        assert event.level == "CRITICAL"
        assert "CRITICAL_FINDING_REQUIRES_REVIEW" in event.reason

    def test_validate_finding_financial_endpoint(self, guard):
        finding = Vulnerability(
            id="VULN-001",
            type="SQLi",
            target="https://example.com/api/v1/payment/process",
            description="SQL injection",
            reproduction_steps="Inject SQL",
            evidence="Error message",
            severity=Severity.HIGH,
            tool_source="nuclei",
        )
        
        event = guard.validate_finding(finding)
        assert event is not None
        assert "FINANCIAL_ENDPOINT_DETECTED" in event.reason

    def test_validate_finding_valid(self, guard):
        finding = Vulnerability(
            id="VULN-001",
            type="Info Disclosure",
            target="https://example.com/about",
            description="Server version disclosed",
            reproduction_steps="Visit page",
            evidence="Server: nginx",
            severity=Severity.LOW,
            tool_source="nuclei",
        )
        
        event = guard.validate_finding(finding)
        assert event is None

    def test_is_financial_endpoint(self, guard):
        assert guard._is_financial_endpoint("https://example.com/payment")
        assert guard._is_financial_endpoint("https://example.com/checkout")
        assert guard._is_financial_endpoint("https://example.com/api/v1/transaction")
        assert not guard._is_financial_endpoint("https://example.com/about")


class TestCreateSafetyEvent:
    """Test safety event factory."""

    def test_create_event(self):
        event = create_safety_event("HIGH", "TEST_REASON", extra="detail")
        
        assert event.level == "HIGH"
        assert event.reason == "TEST_REASON"
        assert event.details["extra"] == "detail"

    def test_create_critical_event(self):
        event = create_safety_event("CRITICAL", "SCOPE_VIOLATION")
        
        assert event.level == "CRITICAL"
        assert event.reason == "SCOPE_VIOLATION"
