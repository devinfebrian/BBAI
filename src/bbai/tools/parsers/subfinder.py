"""Parser for Subfinder output.

Subfinder outputs one subdomain per line by default.
Can also output JSON with -json flag.
"""

import json
from typing import Any

from bbai.tools.parsers.base import LineParser, ParsedSubdomain


class SubfinderParser(LineParser):
    """Parser for Subfinder output."""

    @property
    def tool_name(self) -> str:
        return "subfinder"

    def parse_line(self, line: str) -> ParsedSubdomain | None:
        """Parse a single line of Subfinder output."""
        line = line.strip()
        
        # Skip empty lines and headers
        if not line or line.startswith("["):
            return None
        
        # Try JSON format first
        try:
            data = json.loads(line)
            return self._parse_json_item(data)
        except json.JSONDecodeError:
            # Plain text format - just a subdomain per line
            if "." in line and " " not in line:
                return ParsedSubdomain(
                    subdomain=line,
                    source="subfinder",
                )
        
        return None

    def _parse_json_item(self, item: dict[str, Any]) -> ParsedSubdomain:
        """Parse JSON format output."""
        return ParsedSubdomain(
            subdomain=item.get("host", ""),
            source=item.get("source", "subfinder"),
            ip=item.get("ip"),
        )


class SubfinderJSONParser(LineParser):
    """Parser for Subfinder JSON output (full JSON mode)."""

    @property
    def tool_name(self) -> str:
        return "subfinder-json"

    def parse(self, output: str) -> list[ParsedSubdomain]:
        """Parse JSON array output."""
        if not self.is_valid_output(output):
            return []
        
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return [
                    ParsedSubdomain(
                        subdomain=item.get("host", ""),
                        source=item.get("source", "subfinder"),
                        ip=item.get("ip"),
                    )
                    for item in data
                    if item.get("host")
                ]
        except json.JSONDecodeError:
            pass
        
        return []
