"""Safety Guards - PII detection and data sanitization.

Implements Layer 4 of the safety model: Post-execution safety checks.
- PII regex detection
- Output sanitization
- Finding validation
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Pattern

from pydantic import BaseModel, ConfigDict, Field

from bbai.core.config_models import SafetyEvent, Severity, Vulnerability


class PIIDetector:
    """PII (Personally Identifiable Information) detector.
    
    Uses regex patterns to detect common PII in text outputs.
    Can be used to:
    - Sanitize tool outputs before storage
    - Trigger alerts when PII is detected
    - Validate findings don't contain PII
    
    Usage:
        detector = PIIDetector()
        findings = detector.detect(text)
        if findings:
            sanitized = detector.sanitize(text)
    """

    # Regex patterns for PII detection
    PATTERNS: dict[str, Pattern[str]] = {
        # Email addresses
        "email": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            re.IGNORECASE,
        ),
        # US Social Security Numbers
        "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        # Credit card numbers (major vendors)
        "credit_card": re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b(?:\d{4}[-\s]?){4}\b"
        ),
        # Phone numbers (US format)
        "phone": re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
        ),
        # API keys (common patterns)
        "api_key": re.compile(
            r"\b(?:api[_-]?key|apikey|key)[\s]*[:=][\s]*['\"]?[a-zA-Z0-9]{16,}['\"]?",
            re.IGNORECASE,
        ),
        # Private keys
        "private_key": re.compile(
            r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        # AWS Access Key ID
        "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        # AWS Secret Key (in context)
        "aws_secret_key": re.compile(
            r"\b[A-Za-z0-9/+=]{40}\b",
        ),
        # Generic secrets in URLs
        "url_secret": re.compile(
            r"[?&](?:api[_-]?key|token|secret|password|passwd|pwd)=[^&\s]+",
            re.IGNORECASE,
        ),
        # JWT tokens
        "jwt": re.compile(r"\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b"),
        # IPv4 addresses (might be internal)
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        # Session IDs / Cookies
        "session_id": re.compile(
            r"\b(?:session|sess|sid|cookie)[_\-]?id['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{8,}",
            re.IGNORECASE,
        ),
    }

    def __init__(self, patterns: dict[str, Pattern[str]] | None = None):
        """Initialize detector with optional custom patterns."""
        self.patterns = patterns or self.PATTERNS.copy()

    def detect(self, text: str) -> list[dict[str, Any]]:
        """Detect PII in text.
        
        Args:
            text: Text to scan
            
        Returns:
            List of detections with type, match, and position
        """
        findings = []
        for pii_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                findings.append({
                    "type": pii_type,
                    "match": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                    "hash": self._hash_match(match.group()),
                })
        return findings

    def has_pii(self, text: str) -> bool:
        """Quick check if text contains any PII.
        
        Args:
            text: Text to check
            
        Returns:
            True if PII detected
        """
        for pattern in self.patterns.values():
            if pattern.search(text):
                return True
        return False

    def sanitize(
        self,
        text: str,
        replacement: str = "[REDACTED]",
        keep_hash: bool = True,
    ) -> str:
        """Sanitize PII from text.
        
        Args:
            text: Text to sanitize
            replacement: String to replace PII with
            keep_hash: If True, append hash of original value
            
        Returns:
            Sanitized text
        """
        result = text
        for pii_type, pattern in self.patterns.items():
            def replacer(match: re.Match[str]) -> str:
                if keep_hash:
                    hash_val = self._hash_match(match.group())[:8]
                    return f"{replacement}:{pii_type}:{hash_val}"
                return f"{replacement}:{pii_type}"
            
            result = pattern.sub(replacer, result)
        return result

    def _hash_match(self, match: str) -> str:
        """Create hash of matched PII for reference without storing actual value."""
        return hashlib.sha256(match.encode()).hexdigest()

    def get_pattern_names(self) -> list[str]:
        """Get list of available pattern names."""
        return list(self.patterns.keys())


class SafetyGuard:
    """Main safety guard coordinator.
    
    Coordinates PII detection, output sanitization, and safety event generation.
    
    Usage:
        guard = SafetyGuard()
        
        # Check tool output
        result = guard.check_tool_output(output)
        if result.has_pii:
            sanitized = result.sanitized_output
            
        # Check finding
        event = guard.validate_finding(finding)
        if event:
            # Handle safety event
    """

    def __init__(self, auto_sanitize: bool = True):
        self.pii_detector = PIIDetector()
        self.auto_sanitize = auto_sanitize

    def check_tool_output(
        self,
        output: str,
        tool_name: str,
        target: str,
    ) -> SafetyCheckResult:
        """Check tool output for safety issues.
        
        Args:
            output: Tool output text
            tool_name: Name of the tool
            target: Target being scanned
            
        Returns:
            SafetyCheckResult with findings and sanitized output
        """
        pii_findings = self.pii_detector.detect(output)
        
        sanitized = output
        if pii_findings and self.auto_sanitize:
            sanitized = self.pii_detector.sanitize(output)

        events: list[SafetyEvent] = []
        if pii_findings:
            events.append(
                SafetyEvent(
                    level="HIGH" if len(pii_findings) > 3 else "MEDIUM",
                    reason="PII_DETECTED_IN_OUTPUT",
                    details={
                        "tool": tool_name,
                        "target": target,
                        "pii_types": list(set(f["type"] for f in pii_findings)),
                        "count": len(pii_findings),
                    },
                )
            )

        return SafetyCheckResult(
            has_pii=bool(pii_findings),
            pii_findings=pii_findings,
            original_output=output,
            sanitized_output=sanitized,
            safety_events=events,
        )

    def validate_finding(self, finding: Vulnerability) -> SafetyEvent | None:
        """Validate a finding for safety issues.
        
        Checks:
        - PII in evidence
        - Critical severity without human review
        - Financial transaction endpoints
        
        Args:
            finding: Vulnerability finding to validate
            
        Returns:
            SafetyEvent if issue found, None otherwise
        """
        # Check PII in evidence
        evidence_text = finding.evidence + " " + finding.description
        if self.pii_detector.has_pii(evidence_text):
            return SafetyEvent(
                level="HIGH",
                reason="PII_IN_FINDING_EVIDENCE",
                details={
                    "finding_id": finding.id,
                    "target": finding.target,
                    "type": finding.type,
                },
            )

        # Check critical severity
        if finding.severity == Severity.CRITICAL:
            return SafetyEvent(
                level="CRITICAL",
                reason="CRITICAL_FINDING_REQUIRES_REVIEW",
                details={
                    "finding_id": finding.id,
                    "cvss_score": finding.cvss_score,
                    "target": finding.target,
                },
            )

        # Check for financial transaction patterns
        if self._is_financial_endpoint(finding.target):
            return SafetyEvent(
                level="HIGH",
                reason="FINANCIAL_ENDPOINT_DETECTED",
                details={
                    "finding_id": finding.id,
                    "target": finding.target,
                },
            )

        return None

    def _is_financial_endpoint(self, url: str) -> bool:
        """Check if URL appears to be a financial transaction endpoint."""
        financial_patterns = [
            r"/payment",
            r"/checkout",
            r"/transaction",
            r"/transfer",
            r"/withdraw",
            r"/deposit",
            r"/billing",
            r"/invoice/pay",
            r"/api/v\d+/payment",
            r"/v\d+/transaction",
        ]
        url_lower = url.lower()
        for pattern in financial_patterns:
            if re.search(pattern, url_lower):
                return True
        return False


class SafetyCheckResult(BaseModel):
    """Result of a safety check."""

    model_config = ConfigDict(frozen=True)

    has_pii: bool
    pii_findings: list[dict[str, Any]]
    original_output: str
    sanitized_output: str
    safety_events: list[SafetyEvent]

    @property
    def should_halt(self) -> bool:
        """Check if execution should halt based on safety events."""
        return any(
            event.level == "CRITICAL" for event in self.safety_events
        )

    @property
    def requires_review(self) -> bool:
        """Check if human review is required."""
        return any(
            event.level in ("CRITICAL", "HIGH") for event in self.safety_events
        )


def create_safety_event(
    level: str,
    reason: str,
    **details: Any,
) -> SafetyEvent:
    """Factory function to create safety events."""
    return SafetyEvent(
        level=level,  # type: ignore
        reason=reason,
        details=details,
    )
