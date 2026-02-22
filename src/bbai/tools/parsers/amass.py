"""Parser for Amass output.

Amass outputs JSON with domain enumeration results.
"""

import json
from typing import Any

from bbai.tools.parsers.base import ParsedSubdomain


class AmassParser:
    """Parser for Amass JSON output."""

    def parse(self, output: str) -> list[ParsedSubdomain]:
        """Parse Amass JSON output."""
        if not output or not output.strip():
            return []
        
        results = []
        
        # Amass outputs one JSON object per line
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                name = data.get("name", "")
                if name:
                    results.append(
                        ParsedSubdomain(
                            subdomain=name,
                            source="amass",
                            ip=data.get("addresses", [{}])[0].get("ip"),
                        )
                    )
            except json.JSONDecodeError:
                continue
        
        return results
