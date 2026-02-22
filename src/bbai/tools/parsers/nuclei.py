"""Parser for Nuclei vulnerability scanner output.

Nuclei outputs JSON with the following structure:
{
    "template-id": "CVE-2021-44228",
    "template-path": "cves/2021/CVE-2021-44228.yaml",
    "info": {
        "name": "Log4j RCE Detection",
        "severity": "critical",
        "tags": ["cve", "log4j", "rce"],
        "description": "...",
        "reference": ["https://..."]
    },
    "type": "http",
    "host": "https://example.com",
    "matched-at": "https://example.com/path",
    "extracted-results": ["..."],
    "ip": "1.2.3.4",
    "timestamp": "2024-01-01T00:00:00Z"
}
"""

from typing import Any

from bbai.core.config_models import Severity
from bbai.tools.parsers.base import JSONParser, ParsedFinding


class NucleiParser(JSONParser):
    """Parser for Nuclei JSON output."""

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "unknown": Severity.INFO,
    }

    @property
    def tool_name(self) -> str:
        return "nuclei"

    def _parse_item(self, item: dict[str, Any]) -> ParsedFinding:
        """Parse a single Nuclei finding."""
        info = item.get("info", {})
        
        # Map severity
        raw_severity = info.get("severity", "info").lower()
        severity = self.SEVERITY_MAP.get(raw_severity, Severity.INFO)
        
        # Get references
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        
        return ParsedFinding(
            tool="nuclei",
            finding_type=item.get("template-id", "unknown"),
            severity=severity.value,
            target=item.get("host", ""),
            title=info.get("name", "Unknown"),
            description=info.get("description", ""),
            evidence=item.get("matched-at", ""),
            remediation=None,
            cwe_id=self._extract_cwe(info.get("classification", {})),
            cvss_score=self._extract_cvss(info.get("classification", {})),
            references=references,
            metadata={
                "template_path": item.get("template-path"),
                "type": item.get("type"),
                "ip": item.get("ip"),
                "timestamp": item.get("timestamp"),
                "curl_command": item.get("curl-command"),
            },
        )

    def _extract_cwe(self, classification: dict[str, Any]) -> str | None:
        """Extract CWE ID from classification."""
        cwe = classification.get("cwe-id", [])
        if cwe:
            if isinstance(cwe, list):
                return cwe[0]
            return str(cwe)
        return None

    def _extract_cvss(self, classification: dict[str, Any]) -> float | None:
        """Extract CVSS score from classification."""
        score = classification.get("cvss-score")
        if score is not None:
            try:
                return float(score)
            except (ValueError, TypeError):
                pass
        return None
