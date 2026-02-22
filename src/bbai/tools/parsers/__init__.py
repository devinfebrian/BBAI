"""Tool output parsers.

Converts raw tool output into structured data.
"""

from bbai.tools.parsers.amass import AmassParser
from bbai.tools.parsers.base import (
    BaseParser,
    JSONParser,
    LineParser,
    ParsedEndpoint,
    ParsedFinding,
    ParsedSecret,
    ParsedSubdomain,
)
from bbai.tools.parsers.nuclei import NucleiParser
from bbai.tools.parsers.subfinder import SubfinderJSONParser, SubfinderParser
from bbai.tools.parsers.trufflehog import TruffleHogParser

__all__ = [
    # Base classes
    "BaseParser",
    "JSONParser",
    "LineParser",
    # Data classes
    "ParsedFinding",
    "ParsedSubdomain",
    "ParsedEndpoint",
    "ParsedSecret",
    # Parsers
    "NucleiParser",
    "SubfinderParser",
    "SubfinderJSONParser",
    "AmassParser",
    "TruffleHogParser",
]

# Registry of parsers by tool name
PARSERS = {
    "nuclei": NucleiParser,
    "subfinder": SubfinderParser,
    "subfinder-json": SubfinderJSONParser,
    "amass": AmassParser,
    "trufflehog": TruffleHogParser,
}


def get_parser(tool_name: str) -> BaseParser | None:
    """Get parser for a tool.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Parser instance or None
    """
    parser_class = PARSERS.get(tool_name.lower())
    if parser_class:
        return parser_class()
    return None
