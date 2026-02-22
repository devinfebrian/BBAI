"""Unit tests for reporting modules."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from bbai.core.config_models import Severity, Vulnerability
from bbai.reporting.hackerone import HackerOneReporter
from bbai.reporting.json_export import JSONExporter
from bbai.reporting.manager import ReportManager


class TestHackerOneReporter:
    """Test HackerOne reporter."""

    @pytest.fixture
    def reporter(self):
        return HackerOneReporter()

    @pytest.fixture
    def sample_finding(self):
        return Vulnerability(
            id="VULN-001",
            type="XSS",
            target="https://example.com",
            description="Cross-site scripting vulnerability",
            reproduction_steps="1. Input script\n2. Submit",
            evidence="<script>alert(1)</script>",
            severity=Severity.HIGH,
            cvss_score=7.5,
            cwe_id="CWE-79",
            ai_confidence=0.95,
            ai_reasoning="Clear evidence of XSS",
            tool_source="nuclei",
        )

    def test_generate_empty_findings(self, reporter):
        """Test report with no findings."""
        report = reporter.generate([], target="example.com")
        
        assert "# Vulnerability Report: example.com" in report
        assert "No vulnerabilities were identified" in report

    def test_generate_with_findings(self, reporter, sample_finding):
        """Test report with findings."""
        report = reporter.generate(
            [sample_finding],
            target="example.com",
            program_name="Test Program",
        )
        
        assert "Test Program" in report
        assert "XSS" in report
        assert "HIGH" in report
        assert "7.5" in report
        assert "CWE-79" in report
        assert "<script>alert(1)</script>" in report

    def test_generate_summary_counts(self, reporter):
        """Test severity counting in summary."""
        findings = [
            Vulnerability(
                id=f"V{i}",
                type="XSS",
                target="https://example.com",
                description="XSS",
                reproduction_steps="1. Test",
                evidence="script",
                severity=Severity.HIGH,
                tool_source="nuclei",
            )
            for i in range(3)
        ]
        findings.append(
            Vulnerability(
                id="V4",
                type="Info",
                target="https://example.com",
                description="Info",
                reproduction_steps="1. Test",
                evidence="header",
                severity=Severity.LOW,
                tool_source="nuclei",
            )
        )
        
        report = reporter.generate(findings, target="example.com")
        
        assert "3" in report  # Count of high findings
        assert "1" in report  # Count of low findings

    def test_get_severity_icon(self, reporter):
        """Test severity icon mapping."""
        assert reporter._get_severity_icon("critical") == "🔴"
        assert reporter._get_severity_icon("high") == "🟠"
        assert reporter._get_severity_icon("medium") == "🟡"
        assert reporter._get_severity_icon("low") == "🟢"
        assert reporter._get_severity_icon("info") == "🔵"
        assert reporter._get_severity_icon("unknown") == "⚪"

    def test_generate_impact(self, reporter):
        """Test impact generation for different severities."""
        finding = Vulnerability(
            id="V1",
            type="RCE",
            target="https://example.com",
            description="RCE",
            reproduction_steps="1. Exploit",
            evidence="shell",
            severity=Severity.CRITICAL,
            tool_source="nuclei",
        )
        
        impact = reporter._generate_impact(finding)
        
        assert "complete system compromise" in impact

    def test_save_report(self, reporter, tmp_path):
        """Test saving report to file."""
        report = reporter.generate([], target="example.com")
        filename = tmp_path / "report.md"
        
        reporter.save_report(report, str(filename))
        
        assert filename.exists()
        content = filename.read_text()
        assert "Vulnerability Report" in content

    def test_generate_json(self, reporter, sample_finding):
        """Test JSON report generation."""
        data = reporter.generate_json([sample_finding], target="example.com")
        
        assert data["target"] == "example.com"
        assert "generator" in data  # Check for generator field
        assert len(data["findings"]) == 1
        assert data["summary"]["total_findings"] == 1


class TestJSONExporter:
    """Test JSON exporter."""

    @pytest.fixture
    def exporter(self):
        return JSONExporter()

    @pytest.fixture
    def sample_findings(self):
        return [
            Vulnerability(
                id="V1",
                type="XSS",
                target="https://example.com",
                description="XSS vuln",
                reproduction_steps="1. Test",
                evidence="script",
                severity=Severity.HIGH,
                cvss_score=7.5,
                tool_source="nuclei",
            ),
            Vulnerability(
                id="V2",
                type="Info Disclosure",
                target="https://example.com",
                description="Info",
                reproduction_steps="1. Check",
                evidence="header",
                severity=Severity.LOW,
                tool_source="nuclei",
            ),
        ]

    def test_export_standard(self, exporter, sample_findings):
        """Test standard JSON export."""
        data = exporter.export_standard(sample_findings, "example.com")
        
        assert data["format"] == "bbai-standard"
        assert data["target"] == "example.com"
        assert len(data["findings"]) == 2
        assert "exported_at" in data

    def test_export_standard_with_metadata(self, exporter, sample_findings):
        """Test export with metadata."""
        metadata = {"scanner": "BBAI", "version": "1.0"}
        data = exporter.export_standard(
            sample_findings, "example.com", metadata
        )
        
        assert data["metadata"]["scanner"] == "BBAI"

    def test_export_sarif(self, exporter, sample_findings):
        """Test SARIF export."""
        data = exporter.export_sarif(sample_findings, "example.com")
        
        assert data["$schema"].endswith("sarif-schema-2.1.0.json")
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 2

    def test_export_sarif_severity_mapping(self, exporter):
        """Test SARIF severity level mapping."""
        assert exporter._severity_to_sarif_level("critical") == "error"
        assert exporter._severity_to_sarif_level("high") == "error"
        assert exporter._severity_to_sarif_level("medium") == "warning"
        assert exporter._severity_to_sarif_level("low") == "note"
        assert exporter._severity_to_sarif_level("info") == "none"

    def test_export_github_advisory(self, exporter, sample_findings):
        """Test GitHub Advisory export."""
        advisories = exporter.export_github_advisory(
            sample_findings, "example.com"
        )
        
        assert len(advisories) == 2
        assert advisories[0]["id"] == "V1"
        assert "affected" in advisories[0]

    def test_export_csv_rows(self, exporter, sample_findings):
        """Test CSV export."""
        rows = exporter.export_csv_rows(sample_findings)
        
        assert len(rows) == 2
        assert rows[0]["ID"] == "V1"
        assert rows[0]["Severity"] == "high"
        assert "AI Confidence" in rows[0]

    def test_save_json(self, exporter, tmp_path):
        """Test saving JSON to file."""
        data = {"test": "data"}
        filename = tmp_path / "test.json"
        
        exporter.save_json(data, str(filename))
        
        assert filename.exists()
        loaded = json.loads(filename.read_text())
        assert loaded["test"] == "data"

    def test_save_csv(self, exporter, tmp_path):
        """Test saving CSV to file."""
        rows = [{"col1": "a", "col2": "b"}, {"col1": "c", "col2": "d"}]
        filename = tmp_path / "test.csv"
        
        exporter.save_csv(rows, str(filename))
        
        assert filename.exists()
        content = filename.read_text()
        assert "col1,col2" in content
        assert "a,b" in content


class TestReportManager:
    """Test report manager."""

    @pytest.fixture
    def manager(self, tmp_path):
        return ReportManager(output_dir=tmp_path)

    @pytest.fixture
    def sample_findings(self):
        return [
            Vulnerability(
                id="V1",
                type="XSS",
                target="https://example.com",
                description="XSS",
                reproduction_steps="1. Test",
                evidence="script",
                severity=Severity.HIGH,
                tool_source="nuclei",
            ),
        ]

    def test_generate_base_name(self, manager):
        """Test base name generation."""
        name = manager._generate_base_name("https://example.com", None)
        assert name == "example_com"
        
        name = manager._generate_base_name("https://example.com", "session12345678")
        assert name == "example_com_session1"  # First 8 chars of session_id

    def test_generate_all(self, manager, sample_findings):
        """Test generating all report formats."""
        outputs = manager.generate_all(
            sample_findings,
            target="https://example.com",
            program_name="Test",
            session_id="abc123",
        )
        
        assert "hackerone" in outputs
        assert "json" in outputs
        assert "sarif" in outputs
        assert "csv" in outputs
        
        # Verify files exist
        for path in outputs.values():
            assert path.exists()

    def test_generate_hackerone(self, manager, sample_findings):
        """Test generating HackerOne report."""
        path = manager.generate_hackerone(
            sample_findings,
            target="https://example.com",
        )
        
        assert path.exists()
        assert path.suffix == ".md"
        assert "hackerone" in path.name

    def test_generate_json(self, manager, sample_findings):
        """Test generating JSON report."""
        path = manager.generate_json(
            sample_findings,
            target="https://example.com",
        )
        
        assert path.exists()
        assert path.suffix == ".json"

    def test_generate_sarif(self, manager, sample_findings):
        """Test generating SARIF report."""
        path = manager.generate_sarif(
            sample_findings,
            target="https://example.com",
        )
        
        assert path.exists()
        assert path.suffix == ".sarif"

    def test_generate_csv(self, manager, sample_findings):
        """Test generating CSV report."""
        path = manager.generate_csv(
            sample_findings,
            target="https://example.com",
        )
        
        assert path.exists()
        assert path.suffix == ".csv"

    def test_get_report_summary(self, manager, sample_findings):
        """Test report summary generation."""
        summary = manager.get_report_summary(
            sample_findings,
            target="example.com",
        )
        
        assert summary["target"] == "example.com"
        assert summary["total_findings"] == 1
        assert summary["severity_counts"]["high"] == 1
        assert "generated_at" in summary

    def test_get_report_summary_empty(self, manager):
        """Test summary with no findings."""
        summary = manager.get_report_summary([], target="example.com")
        
        assert summary["total_findings"] == 0
        assert summary["avg_ai_confidence"] == 0

    def test_output_dir_created(self, tmp_path):
        """Test that output directory is created."""
        new_dir = tmp_path / "new_reports"
        manager = ReportManager(output_dir=new_dir)
        
        assert new_dir.exists()
