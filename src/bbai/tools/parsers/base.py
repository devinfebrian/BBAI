"""Base classes for tool output parsers.

Output parsers convert raw tool output into structured data.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ParsedFinding:
    """A parsed security finding."""

    tool: str
    finding_type: str
    severity: str
    target: str
    title: str
    description: str
    evidence: str
    remediation: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    references: list[str] | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class ParsedSubdomain:
    """A parsed subdomain."""

    subdomain: str
    source: str
    ip: str | None = None
    tools: list[str] | None = None


@dataclass
class ParsedEndpoint:
    """A parsed endpoint/URL."""

    url: str
    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    technology: list[str] | None = None


@dataclass
class ParsedSecret:
    """A parsed secret/credential finding."""

    secret_type: str
    file: str
    line: int
    match: str
    severity: str


class BaseParser(ABC):
    """Abstract base class for output parsers."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the tool name this parser handles."""
        raise NotImplementedError

    @abstractmethod
    def parse(self, output: str) -> list[Any]:
        """Parse tool output.
        
        Args:
            output: Raw tool output
            
        Returns:
            List of parsed items
        """
        raise NotImplementedError

    def parse_line(self, line: str) -> Any | None:
        """Parse a single line of output.
        
        Args:
            line: Single line of output
            
        Returns:
            Parsed item or None if line should be skipped
        """
        return None

    def is_valid_output(self, output: str) -> bool:
        """Check if output is valid for this parser.
        
        Args:
            output: Raw output
            
        Returns:
            True if valid
        """
        return bool(output and output.strip())


class JSONParser(BaseParser):
    """Parser for JSON output."""

    def parse(self, output: str) -> list[Any]:
        """Parse JSON output."""
        if not self.is_valid_output(output):
            return []
        
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return [self._parse_item(item) for item in data]
            elif isinstance(data, dict):
                return [self._parse_item(data)]
            return []
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

    @abstractmethod
    def _parse_item(self, item: dict[str, Any]) -> Any:
        """Parse a single JSON item."""
        raise NotImplementedError


class LineParser(BaseParser):
    """Parser for line-based output."""

    def parse(self, output: str) -> list[Any]:
        """Parse line-based output."""
        if not self.is_valid_output(output):
            return []
        
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            parsed = self.parse_line(line)
            if parsed:
                results.append(parsed)
        
        return results
