"""Unit tests for tool output parsers."""

import json

import pytest

from bbai.core.config_models import Severity
from bbai.tools.parsers import (
    AmassParser,
    NucleiParser,
    ParsedFinding,
    ParsedSecret,
    ParsedSubdomain,
    SubfinderParser,
    TruffleHogParser,
    get_parser,
)


class TestNucleiParser:
    """Test Nuclei output parser."""

    @pytest.fixture
    def parser(self):
        return NucleiParser()

    def test_parse_single_finding(self, parser):
        """Test parsing a single Nuclei finding."""
        data = {
            "template-id": "CVE-2021-44228",
            "host": "https://example.com",
            "matched-at": "https://example.com/api",
            "info": {
                "name": "Log4j RCE Detection",
                "severity": "critical",
                "description": "Apache Log4j2",
                "reference": ["https://nvd.nist.gov/"],
            },
        }
        
        output = json.dumps(data)
        results = parser.parse(output)
        
        assert len(results) == 1
        assert results[0].tool == "nuclei"
        assert results[0].finding_type == "CVE-2021-44228"
        assert results[0].severity == "critical"
        assert results[0].target == "https://example.com"

    def test_parse_multiple_findings(self, parser):
        """Test parsing multiple findings."""
        data = [
            {
                "template-id": "test-1",
                "host": "https://example.com",
                "info": {"name": "Test 1", "severity": "high"},
            },
            {
                "template-id": "test-2",
                "host": "https://test.com",
                "info": {"name": "Test 2", "severity": "medium"},
            },
        ]
        
        output = json.dumps(data)
        results = parser.parse(output)
        
        assert len(results) == 2

    def test_parse_with_cvss(self, parser):
        """Test parsing with CVSS score."""
        data = {
            "template-id": "CVE-2021-44228",
            "host": "https://example.com",
            "info": {
                "name": "Log4j RCE",
                "severity": "critical",
                "classification": {
                    "cvss-score": 10.0,
                    "cwe-id": ["CWE-78"],
                },
            },
        }
        
        output = json.dumps(data)
        results = parser.parse(output)
        
        assert results[0].cvss_score == 10.0
        assert results[0].cwe_id == "CWE-78"

    def test_invalid_json(self, parser):
        """Test handling invalid JSON."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            parser.parse("not valid json")

    def test_empty_output(self, parser):
        """Test parsing empty output."""
        results = parser.parse("")
        assert len(results) == 0


class TestSubfinderParser:
    """Test Subfinder output parser."""

    @pytest.fixture
    def parser(self):
        return SubfinderParser()

    def test_parse_plain_text(self, parser):
        """Test parsing plain text output."""
        output = """
        sub1.example.com
        sub2.example.com
        """
        
        results = parser.parse(output)
        
        assert len(results) == 2
        assert results[0].subdomain == "sub1.example.com"
        assert results[1].subdomain == "sub2.example.com"

    def test_parse_json_line(self, parser):
        """Test parsing JSON line output."""
        output = json.dumps({"host": "sub.example.com", "ip": "1.2.3.4", "source": "dnsdumpster"})
        
        results = parser.parse(output)
        
        assert len(results) == 1
        assert results[0].subdomain == "sub.example.com"
        assert results[0].ip == "1.2.3.4"

    def test_skip_empty_lines(self, parser):
        """Test that empty lines are skipped."""
        output = """
        
        sub.example.com
        
        """
        
        results = parser.parse(output)
        
        assert len(results) == 1


class TestAmassParser:
    """Test Amass output parser."""

    @pytest.fixture
    def parser(self):
        return AmassParser()

    def test_parse_json_lines(self, parser):
        """Test parsing JSON lines output."""
        lines = [
            json.dumps({"name": "sub1.example.com", "addresses": [{"ip": "1.2.3.4"}]}),
            json.dumps({"name": "sub2.example.com", "addresses": [{"ip": "5.6.7.8"}]}),
        ]
        output = "\n".join(lines)
        
        results = parser.parse(output)
        
        assert len(results) == 2
        assert results[0].subdomain == "sub1.example.com"
        assert results[0].ip == "1.2.3.4"

    def test_skip_invalid_lines(self, parser):
        """Test that invalid lines are skipped."""
        output = """
        not valid json
        {"name": "sub.example.com"}
        """
        
        results = parser.parse(output)
        
        assert len(results) == 1


class TestTruffleHogParser:
    """Test TruffleHog output parser."""

    @pytest.fixture
    def parser(self):
        return TruffleHogParser()

    def test_parse_secret(self, parser):
        """Test parsing a secret finding."""
        data = {
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "/app/config.py",
                        "line": 42,
                    }
                }
            },
        }
        
        output = json.dumps(data)
        results = parser.parse(output)
        
        assert len(results) == 1
        assert results[0].secret_type == "AWS"
        assert results[0].file == "/app/config.py"
        assert results[0].severity == "high"

    def test_parse_git_source(self, parser):
        """Test parsing with git source."""
        data = {
            "DetectorName": "Slack",
            "Raw": "xoxb-secret-token",
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "file": ".env",
                    }
                }
            },
        }
        
        output = json.dumps(data)
        results = parser.parse(output)
        
        assert len(results) == 1
        assert results[0].secret_type == "Slack"


class TestParserRegistry:
    """Test parser registry."""

    def test_get_existing_parser(self):
        """Test getting existing parser."""
        parser = get_parser("nuclei")
        assert parser is not None
        assert isinstance(parser, NucleiParser)

    def test_get_nonexistent_parser(self):
        """Test getting nonexistent parser."""
        parser = get_parser("nonexistent")
        assert parser is None

    def test_get_parser_case_insensitive(self):
        """Test that parser lookup is case insensitive."""
        parser = get_parser("NUCLEI")
        assert parser is not None
