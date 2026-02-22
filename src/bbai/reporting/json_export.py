"""JSON export for vulnerability data.

Supports multiple JSON formats for integration with other tools.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from bbai.core.config_models import Vulnerability


class JSONExporter:
    """Export findings to various JSON formats."""

    def export_standard(
        self,
        findings: list[Vulnerability],
        target: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Export to standard BBAI JSON format.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            metadata: Optional metadata
            
        Returns:
            Export data as dictionary
        """
        return {
            "format": "bbai-standard",
            "version": "1.0.0",
            "target": target,
            "exported_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
            "findings": [self._vulnerability_to_dict(f) for f in findings],
        }

    def export_sarif(
        self,
        findings: list[Vulnerability],
        target: str,
    ) -> dict[str, Any]:
        """Export to SARIF (Static Analysis Results Interchange Format).
        
        SARIF is an OASIS standard for static analysis tools.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            
        Returns:
            SARIF data as dictionary
        """
        results = []
        for finding in findings:
            result = {
                "ruleId": finding.type,
                "level": self._severity_to_sarif_level(finding.severity.value),
                "message": {
                    "text": finding.description,
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.target,
                        },
                    },
                }],
                "properties": {
                    "cvssScore": finding.cvss_score,
                    "cweId": finding.cwe_id,
                    "confidence": finding.ai_confidence,
                },
            }
            results.append(result)
        
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "BBAI",
                        "version": "0.1.0",
                    },
                },
                "results": results,
            }],
        }

    def export_github_advisory(
        self,
        findings: list[Vulnerability],
        target: str,
    ) -> list[dict[str, Any]]:
        """Export to GitHub Advisory format.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            
        Returns:
            List of advisory dictionaries
        """
        advisories = []
        
        for finding in findings:
            advisory = {
                "id": finding.id,
                "title": f"{finding.type} in {target}",
                "severity": finding.severity.value,
                "description": finding.description,
                "affected": [{
                    "package": {
                        "ecosystem": "web",
                        "name": target,
                    },
                    "ranges": [{
                        "type": "semver",
                        "events": [{"introduced": "0"}],
                    }],
                }],
                "references": [{
                    "type": "WEB",
                    "url": finding.target,
                }],
            }
            
            if finding.cwe_id:
                advisory["cwe_ids"] = [finding.cwe_id]
            
            advisories.append(advisory)
        
        return advisories

    def export_csv_rows(
        self,
        findings: list[Vulnerability],
    ) -> list[dict[str, str]]:
        """Export to CSV-compatible format.
        
        Args:
            findings: List of vulnerabilities
            
        Returns:
            List of row dictionaries
        """
        rows = []
        for finding in findings:
            row = {
                "ID": finding.id,
                "Type": finding.type,
                "Severity": finding.severity.value,
                "CVSS": str(finding.cvss_score) if finding.cvss_score else "",
                "Target": finding.target,
                "Endpoint": finding.endpoint or "",
                "Description": finding.description,
                "Evidence": finding.evidence,
                "AI Confidence": f"{finding.ai_confidence:.0%}",
                "False Positive": str(finding.is_false_positive),
                "Tool Source": finding.tool_source,
                "Discovered At": finding.discovered_at.isoformat(),
            }
            rows.append(row)
        
        return rows

    def _vulnerability_to_dict(self, vuln: Vulnerability) -> dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            "id": vuln.id,
            "type": vuln.type,
            "cwe_id": vuln.cwe_id,
            "target": vuln.target,
            "endpoint": vuln.endpoint,
            "parameter": vuln.parameter,
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_score,
            "description": vuln.description,
            "reproduction_steps": vuln.reproduction_steps,
            "evidence": vuln.evidence,
            "ai_confidence": vuln.ai_confidence,
            "ai_reasoning": vuln.ai_reasoning,
            "is_false_positive": vuln.is_false_positive,
            "tool_source": vuln.tool_source,
            "discovered_at": vuln.discovered_at.isoformat(),
        }

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        return mapping.get(severity.lower(), "warning")

    def save_json(
        self,
        data: dict[str, Any],
        filename: str,
        indent: int = 2,
    ) -> None:
        """Save JSON data to file.
        
        Args:
            data: Data to save
            filename: Output filename
            indent: JSON indentation
        """
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, default=str)

    def save_csv(
        self,
        rows: list[dict[str, str]],
        filename: str,
    ) -> None:
        """Save CSV data to file.
        
        Args:
            rows: List of row dictionaries
            filename: Output filename
        """
        import csv
        
        if not rows:
            return
        
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
