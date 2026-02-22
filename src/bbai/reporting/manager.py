"""Report manager for unified report generation and export.

Coordinates multiple reporters and exporters.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bbai.core.config_models import Vulnerability
from bbai.reporting.hackerone import HackerOneReporter
from bbai.reporting.json_export import JSONExporter


class ReportManager:
    """Unified report manager.
    
    Coordinates multiple report formats and handles output.
    
    Usage:
        manager = ReportManager(output_dir="./reports")
        
        # Generate all formats
        manager.generate_all(
            findings=vulnerabilities,
            target="example.com",
            program_name="My Program",
        )
        
        # Generate specific format
        manager.generate_hackerone(
            findings=vulnerabilities,
            target="example.com",
        )
    """

    def __init__(self, output_dir: str | Path = "./reports"):
        """Initialize report manager.
        
        Args:
            output_dir: Directory for output files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.hackerone = HackerOneReporter()
        self.json_exporter = JSONExporter()

    def generate_all(
        self,
        findings: list[Vulnerability],
        target: str,
        program_name: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Path]:
        """Generate all report formats.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            program_name: Optional program name
            session_id: Optional session ID for filenames
            
        Returns:
            Dictionary mapping format to file path
        """
        base_name = self._generate_base_name(target, session_id)
        outputs = {}
        
        # HackerOne markdown
        hackerone_path = self.output_dir / f"{base_name}_hackerone.md"
        report = self.hackerone.generate(findings, target, program_name)
        self.hackerone.save_report(report, str(hackerone_path))
        outputs["hackerone"] = hackerone_path
        
        # Standard JSON
        json_path = self.output_dir / f"{base_name}.json"
        data = self.json_exporter.export_standard(
            findings, target, {"program": program_name}
        )
        self.json_exporter.save_json(data, str(json_path))
        outputs["json"] = json_path
        
        # SARIF
        sarif_path = self.output_dir / f"{base_name}.sarif"
        data = self.json_exporter.export_sarif(findings, target)
        self.json_exporter.save_json(data, str(sarif_path))
        outputs["sarif"] = sarif_path
        
        # CSV
        csv_path = self.output_dir / f"{base_name}.csv"
        rows = self.json_exporter.export_csv_rows(findings)
        self.json_exporter.save_csv(rows, str(csv_path))
        outputs["csv"] = csv_path
        
        return outputs

    def generate_hackerone(
        self,
        findings: list[Vulnerability],
        target: str,
        program_name: str | None = None,
        session_id: str | None = None,
    ) -> Path:
        """Generate HackerOne report.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            program_name: Optional program name
            session_id: Optional session ID
            
        Returns:
            Path to generated file
        """
        base_name = self._generate_base_name(target, session_id)
        path = self.output_dir / f"{base_name}_hackerone.md"
        
        report = self.hackerone.generate(findings, target, program_name)
        self.hackerone.save_report(report, str(path))
        
        return path

    def generate_json(
        self,
        findings: list[Vulnerability],
        target: str,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """Generate JSON report.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            session_id: Optional session ID
            metadata: Optional metadata
            
        Returns:
            Path to generated file
        """
        base_name = self._generate_base_name(target, session_id)
        path = self.output_dir / f"{base_name}.json"
        
        data = self.json_exporter.export_standard(findings, target, metadata)
        self.json_exporter.save_json(data, str(path))
        
        return path

    def generate_sarif(
        self,
        findings: list[Vulnerability],
        target: str,
        session_id: str | None = None,
    ) -> Path:
        """Generate SARIF report.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            session_id: Optional session ID
            
        Returns:
            Path to generated file
        """
        base_name = self._generate_base_name(target, session_id)
        path = self.output_dir / f"{base_name}.sarif"
        
        data = self.json_exporter.export_sarif(findings, target)
        self.json_exporter.save_json(data, str(path))
        
        return path

    def generate_csv(
        self,
        findings: list[Vulnerability],
        target: str,
        session_id: str | None = None,
    ) -> Path:
        """Generate CSV report.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            session_id: Optional session ID
            
        Returns:
            Path to generated file
        """
        base_name = self._generate_base_name(target, session_id)
        path = self.output_dir / f"{base_name}.csv"
        
        rows = self.json_exporter.export_csv_rows(findings)
        self.json_exporter.save_csv(rows, str(path))
        
        return path

    def _generate_base_name(
        self,
        target: str,
        session_id: str | None = None,
    ) -> str:
        """Generate base filename.
        
        Args:
            target: Target URL
            session_id: Optional session ID
            
        Returns:
            Base filename string
        """
        # Clean target for filename
        clean_target = target.replace("https://", "").replace("http://", "")
        clean_target = "".join(c if c.isalnum() else "_" for c in clean_target)
        
        if session_id:
            return f"{clean_target}_{session_id[:8]}"
        
        return clean_target

    def get_report_summary(
        self,
        findings: list[Vulnerability],
        target: str,
    ) -> dict[str, Any]:
        """Get summary of findings for display.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            
        Returns:
            Summary dictionary
        """
        from datetime import datetime
        
        from bbai.core.config_models import Severity
        
        return {
            "target": target,
            "generated_at": datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "severity_counts": {
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == Severity.LOW),
                "info": sum(1 for f in findings if f.severity == Severity.INFO),
            },
            "false_positives": sum(1 for f in findings if f.is_false_positive),
            "ai_analyzed": sum(1 for f in findings if f.ai_confidence > 0),
            "avg_ai_confidence": (
                sum(f.ai_confidence for f in findings) / len(findings)
                if findings else 0
            ),
        }

    def print_summary(
        self,
        findings: list[Vulnerability],
        target: str,
        console=None,
    ) -> None:
        """Print summary to console.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            console: Optional Rich console
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            
            if console is None:
                console = Console()
            
            summary = self.get_report_summary(findings, target)
            
            # Title panel
            console.print(Panel(
                f"[bold]Scan Complete:[/] {target}",
                border_style="green",
            ))
            
            # Severity table
            table = Table(title="Findings by Severity")
            table.add_column("Severity", style="cyan")
            table.add_column("Count", justify="right", style="magenta")
            
            for sev, count in summary["severity_counts"].items():
                if count > 0:
                    emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🟢",
                        "info": "🔵",
                    }.get(sev, "⚪")
                    table.add_row(f"{emoji} {sev.upper()}", str(count))
            
            console.print(table)
            
            # Stats
            console.print(f"\n[dim]Total Findings:[/] {summary['total_findings']}")
            console.print(f"[dim]AI Analyzed:[/] {summary['ai_analyzed']}")
            console.print(f"[dim]Avg AI Confidence:[/] {summary['avg_ai_confidence']:.0%}")
            
        except ImportError:
            # Fallback to plain text
            print(f"\nScan Complete: {target}")
            print(f"Total Findings: {len(findings)}")
