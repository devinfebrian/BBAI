"""Parser for TruffleHog secret scanner output.

TruffleHog outputs JSON with detected secrets.
"""

import json
from typing import Any

from bbai.core.config_models import Severity
from bbai.tools.parsers.base import ParsedSecret


class TruffleHogParser:
    """Parser for TruffleHog JSON output."""

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "unknown": Severity.INFO,
    }

    def parse(self, output: str) -> list[ParsedSecret]:
        """Parse TruffleHog JSON output."""
        if not output or not output.strip():
            return []
        
        results = []
        
        # TruffleHog outputs one JSON object per line
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                source_metadata = data.get("SourceMetadata", {}).get("Data", {})
                
                # Determine file path
                file_path = ""
                if "Filesystem" in source_metadata:
                    file_path = source_metadata["Filesystem"].get("file", "")
                elif "Git" in source_metadata:
                    file_path = source_metadata["Git"].get("file", "")
                
                # Get detector name
                detector = data.get("DetectorName", "unknown")
                
                # Get raw result
                raw = data.get("Raw", "")
                
                results.append(
                    ParsedSecret(
                        secret_type=detector,
                        file=file_path,
                        line=data.get("SourceMetadata", {})
                        .get("Data", {})
                        .get("Filesystem", {})
                        .get("line", 0),
                        match=raw[:100] if raw else "",  # Truncate for safety
                        severity="high",  # Secrets are always high severity
                    )
                )
            except (json.JSONDecodeError, KeyError):
                continue
        
        return results
