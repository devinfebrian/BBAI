"""HackerOne report generator.

Generates HackerOne-compatible markdown reports.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from bbai.core.config_models import Severity, Vulnerability


class HackerOneReporter:
    """Generate HackerOne-compatible vulnerability reports.
    
    Usage:
        reporter = HackerOneReporter()
        report = reporter.generate(findings, target="example.com")
        
        # Save to file
        reporter.save_report(report, "hackerone_report.md")
    """

    def generate(
        self,
        findings: list[Vulnerability],
        target: str,
        program_name: str | None = None,
    ) -> str:
        """Generate HackerOne markdown report.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            program_name: Optional program name
            
        Returns:
            Markdown report string
        """
        lines = [
            f"# Vulnerability Report: {target}",
            "",
            f"**Program:** {program_name or 'Not specified'}",
            f"**Report Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Reporter:** BBAI Automated Scanner",
            "",
            "## Summary",
            "",
            self._generate_summary(findings),
            "",
            "---",
            "",
        ]
        
        # Generate detailed findings
        for i, vuln in enumerate(findings, 1):
            lines.extend(self._generate_vulnerability_section(i, vuln))
        
        # Add methodology
        lines.extend(self._generate_methodology())
        
        return "\n".join(lines)

    def _generate_summary(self, findings: list[Vulnerability]) -> str:
        """Generate executive summary."""
        if not findings:
            return "No vulnerabilities were identified during this scan."
        
        # Count by severity
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity.value] += 1
        
        lines = [
            f"This report contains **{len(findings)}** vulnerability findings:",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts[sev] > 0:
                icon = self._get_severity_icon(sev)
                lines.append(f"| {icon} {sev.upper()} | {counts[sev]} |")
        
        lines.extend([
            "",
            "### Risk Assessment",
            "",
        ])
        
        if counts["critical"] > 0:
            lines.append(
                "**CRITICAL:** Immediate action required. Critical vulnerabilities "
                "present an immediate risk to the security of the application."
            )
        elif counts["high"] > 0:
            lines.append(
                "**HIGH:** High priority vulnerabilities should be addressed as soon "
                "as possible to prevent potential security incidents."
            )
        elif counts["medium"] > 0:
            lines.append(
                "**MEDIUM:** Medium severity issues should be addressed in the next "
                "development cycle."
            )
        else:
            lines.append(
                "**LOW:** Low severity findings are informational and should be "
                "considered for defense in depth."
            )
        
        return "\n".join(lines)

    def _generate_vulnerability_section(
        self,
        index: int,
        vuln: Vulnerability,
    ) -> list[str]:
        """Generate section for a single vulnerability."""
        icon = self._get_severity_icon(vuln.severity.value)
        
        lines = [
            f"## {index}. {icon} {vuln.type}",
            "",
            f"**Severity:** {vuln.severity.value.upper()}",
        ]
        
        if vuln.cvss_score:
            lines.append(f"**CVSS Score:** {vuln.cvss_score}")
        
        if vuln.cwe_id:
            lines.append(f"**CWE:** {vuln.cwe_id}")
        
        lines.extend([
            f"**Affected URL:** {vuln.target}",
            "",
            "### Description",
            "",
            vuln.description,
            "",
            "### Proof of Concept",
            "",
            "```",
            vuln.evidence,
            "```",
            "",
            "### Steps to Reproduce",
            "",
        ])
        
        # Format reproduction steps
        for step in vuln.reproduction_steps.split("\n"):
            if step.strip():
                lines.append(f"1. {step.strip()}")
        
        lines.extend([
            "",
            "### Impact",
            "",
            self._generate_impact(vuln),
            "",
            "### Remediation",
            "",
            self._generate_remediation(vuln),
            "",
        ])
        
        if vuln.ai_reasoning:
            lines.extend([
                "### AI Analysis",
                "",
                f"**Confidence:** {vuln.ai_confidence:.0%}",
                "",
                vuln.ai_reasoning,
                "",
            ])
        
        lines.extend([
            "---",
            "",
        ])
        
        return lines

    def _generate_impact(self, vuln: Vulnerability) -> str:
        """Generate impact statement."""
        impact_map = {
            Severity.CRITICAL: (
                "This vulnerability could lead to complete system compromise, "
                "unauthorized data access, or remote code execution."
            ),
            Severity.HIGH: (
                "This vulnerability could lead to significant data exposure "
                "or authentication bypass."
            ),
            Severity.MEDIUM: (
                "This vulnerability could be exploited to gain unauthorized "
                "access or disclose sensitive information under specific conditions."
            ),
            Severity.LOW: (
                "This issue presents a minor security concern and could aid "
                "attackers in reconnaissance."
            ),
            Severity.INFO: (
                "This is an informational finding that may help improve "
                "security posture."
            ),
        }
        
        return impact_map.get(vuln.severity, "Impact unknown.")

    def _generate_remediation(self, vuln: Vulnerability) -> str:
        """Generate remediation guidance."""
        if vuln.type == "Information Disclosure":
            return (
                "Remove or restrict access to sensitive information in HTTP headers. "
                "Configure web server to not expose version information."
            )
        elif vuln.type == "Missing Security Headers":
            return (
                "Implement recommended security headers including Content-Security-Policy, "
                "X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security."
            )
        elif "XSS" in vuln.type:
            return (
                "Implement proper input validation and output encoding. "
                "Use Content-Security-Policy to mitigate XSS attacks. "
                "Consider using auto-escaping template engines."
            )
        elif "SQL" in vuln.type:
            return (
                "Use parameterized queries or prepared statements. "
                "Implement proper input validation. "
                "Apply the principle of least privilege to database accounts."
            )
        else:
            return (
                "Review the vulnerability and implement appropriate security controls. "
                "Consider defense in depth strategies."
            )

    def _generate_methodology(self) -> list[str]:
        """Generate methodology section."""
        return [
            "## Methodology",
            "",
            "This assessment was conducted using BBAI (Bug Bounty AI Agent), "
            "an automated security scanning framework.",
            "",
            "### Tools Used",
            "",
            "- **Passive Reconnaissance:** Amass, Subfinder, Assetfinder",
            "- **Active Reconnaissance:** Katana, Naabu, DNSx",
            "- **Content Discovery:** Feroxbuster, GoSpider, Hakrawler",
            "- **Vulnerability Scanning:** Nuclei",
            "- **Secret Detection:** TruffleHog, Gitleaks",
            "- **Analysis:** Kimi K2.5 AI",
            "",
            "### Scope",
            "",
            "Testing was performed within the defined scope. All testing was "
            "conducted in accordance with responsible disclosure practices.",
            "",
            "### Timeline",
            "",
            f"- **Scan Start:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "## Disclaimer",
            "",
            "This report contains the results of automated security testing. "
            "While every effort is made to ensure accuracy, manual verification "
            "of findings is recommended before taking action. False positives "
            "may be present.",
            "",
        ]

    def _get_severity_icon(self, severity: str) -> str:
        """Get emoji icon for severity."""
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        return icons.get(severity.lower(), "⚪")

    def save_report(self, report: str, filename: str) -> None:
        """Save report to file.
        
        Args:
            report: Report content
            filename: Output filename
        """
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report)

    def generate_json(
        self,
        findings: list[Vulnerability],
        target: str,
    ) -> dict[str, Any]:
        """Generate JSON format report.
        
        Args:
            findings: List of vulnerabilities
            target: Target that was scanned
            
        Returns:
            Report as dictionary
        """
        return {
            "target": target,
            "generated_at": datetime.utcnow().isoformat(),
            "generator": "BBAI v0.1.0",
            "summary": {
                "total_findings": len(findings),
                "severity_breakdown": {
                    "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                    "high": sum(1 for f in findings if f.severity == Severity.HIGH),
                    "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                    "low": sum(1 for f in findings if f.severity == Severity.LOW),
                    "info": sum(1 for f in findings if f.severity == Severity.INFO),
                },
            },
            "findings": [f.model_dump() for f in findings],
        }
