"""Reporting node for LangGraph workflow.

Generates reports in various formats.
"""

from __future__ import annotations

from datetime import datetime

from bbai.core.config_models import Severity, ThoughtType
from bbai.orchestration.state import AgentState


class ReportingNode:
    """Report generation node."""

    @staticmethod
    def generate_report(state: AgentState) -> AgentState:
        """Generate vulnerability report.
        
        Args:
            state: Current agent state
            
        Returns:
            Updated state with report data
        """
        import time
        
        target = state["target"]
        vulnerabilities = [
            v for v in state.get("vulnerabilities", [])
            if not v.is_false_positive
        ]
        thoughts = state.get("thoughts", [])
        
        thoughts.append({
            "type": ThoughtType.ANALYZING,
            "message": "Generating vulnerability report",
            "details": [
                f"Target: {target}",
                f"Total findings: {len(vulnerabilities)}",
                "Format: HackerOne markdown",
            ],
            "confidence": 0.95,
            "timestamp": time.time(),
        })
        
        # Generate report
        report = ReportingNode._generate_markdown_report(target, vulnerabilities)
        
        thoughts.append({
            "type": ThoughtType.SUCCESS,
            "message": "Report generated successfully",
            "details": [
                f"Report size: {len(report)} characters",
                f"Vulnerabilities included: {len(vulnerabilities)}",
            ],
            "confidence": 0.95,
            "timestamp": time.time(),
        })
        
        return {
            **state,
            "tool_results": {
                **state.get("tool_results", {}),
                "report": report,
                "report_generated_at": datetime.utcnow().isoformat(),
            },
            "current_phase": "report_generated",
            "end_time": datetime.utcnow(),
        }

    @staticmethod
    def _generate_markdown_report(target: str, vulnerabilities: list) -> str:
        """Generate HackerOne-style markdown report.
        
        Args:
            target: Target URL
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Markdown report string
        """
        lines = [
            f"# Bug Bounty Report: {target}",
            "",
            f"**Report Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Target:** {target}",
            f"**Total Findings:** {len(vulnerabilities)}",
            "",
            "## Executive Summary",
            "",
        ]
        
        # Summary table
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            severity_counts[v.severity.value] += 1
        
        lines.extend([
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {severity_counts['critical']} |",
            f"| High | {severity_counts['high']} |",
            f"| Medium | {severity_counts['medium']} |",
            f"| Low | {severity_counts['low']} |",
            f"| Info | {severity_counts['info']} |",
            "",
        ])
        
        # Detailed findings
        lines.append("## Detailed Findings")
        lines.append("")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            lines.extend([
                f"### {i}. {vuln.type}",
                "",
                f"**Severity:** {vuln.severity.value.upper()}",
            ])
            
            if vuln.cvss_score:
                lines.append(f"**CVSS Score:** {vuln.cvss_score}")
            
            lines.extend([
                f"**Target:** {vuln.target}",
                "",
                "#### Description",
                "",
                vuln.description,
                "",
                "#### Evidence",
                "",
                "```",
                vuln.evidence,
                "```",
                "",
                "#### Reproduction Steps",
                "",
                vuln.reproduction_steps,
                "",
            ])
            
            if vuln.ai_reasoning:
                lines.extend([
                    "#### AI Analysis",
                    "",
                    f"**Confidence:** {vuln.ai_confidence:.0%}",
                    "",
                    vuln.ai_reasoning,
                    "",
                ])
            
            lines.append("---")
            lines.append("")
        
        return "\n".join(lines)

    @staticmethod
    def generate_json_report(state: AgentState) -> dict:
        """Generate JSON format report.
        
        Args:
            state: Current agent state
            
        Returns:
            Report as dictionary
        """
        vulnerabilities = [
            v.model_dump() for v in state.get("vulnerabilities", [])
            if not v.is_false_positive
        ]
        
        return {
            "target": state["target"],
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_findings": len(vulnerabilities),
                "severity_breakdown": {
                    "critical": sum(1 for v in vulnerabilities if v["severity"] == "critical"),
                    "high": sum(1 for v in vulnerabilities if v["severity"] == "high"),
                    "medium": sum(1 for v in vulnerabilities if v["severity"] == "medium"),
                    "low": sum(1 for v in vulnerabilities if v["severity"] == "low"),
                    "info": sum(1 for v in vulnerabilities if v["severity"] == "info"),
                },
            },
            "findings": vulnerabilities,
            "metadata": {
                "start_time": state.get("start_time"),
                "end_time": datetime.utcnow().isoformat(),
                "tool_count": len(state.get("tool_outputs", [])),
            },
        }


class FinalizeNode:
    """Workflow finalization node."""

    @staticmethod
    def finalize(state: AgentState) -> AgentState:
        """Finalize workflow and cleanup.
        
        Args:
            state: Current agent state
            
        Returns:
            Final state
        """
        import time
        
        thoughts = state.get("thoughts", [])
        
        end_time = datetime.utcnow()
        start_time = state.get("start_time")
        
        # Calculate duration
        duration = None
        if start_time:
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            duration = (end_time - start_time).total_seconds()
        
        thoughts.append({
            "type": ThoughtType.SUCCESS,
            "message": "Workflow complete",
            "details": [
                f"Total endpoints discovered: {len(state.get('discovered_endpoints', []))}",
                f"Total vulnerabilities found: {len(state.get('vulnerabilities', []))}",
                f"Duration: {duration:.1f}s" if duration else "",
            ],
            "confidence": 1.0,
            "timestamp": time.time(),
        })
        
        return {
            **state,
            "current_phase": "completed",
            "end_time": end_time,
            "halt_requested": False,  # Ensure clean completion
        }

    @staticmethod
    def handle_error(state: AgentState, error: Exception) -> AgentState:
        """Handle workflow errors.
        
        Args:
            state: Current state
            error: Exception that occurred
            
        Returns:
            Updated state with error info
        """
        import time
        
        thoughts = state.get("thoughts", [])
        
        thoughts.append({
            "type": ThoughtType.ERROR,
            "message": f"Workflow error: {str(error)}",
            "details": [],
            "confidence": 1.0,
            "timestamp": time.time(),
        })
        
        return {
            **state,
            "current_phase": "error",
            "end_time": datetime.utcnow(),
            "halt_requested": True,
        }
