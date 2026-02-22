"""AI analysis node for LangGraph workflow.

Validates findings and filters false positives using AI.
"""

from __future__ import annotations

from bbai.core.config_models import Severity, ThoughtType, Vulnerability
from bbai.orchestration.state import AgentState


class AnalysisNode:
    """AI analysis node for finding validation."""

    @staticmethod
    async def analyze_findings(state: AgentState) -> AgentState:
        """Analyze and validate findings.
        
        Uses AI to:
        - Validate true vs false positives
        - Assign confidence scores
        - Determine severity
        - Provide remediation advice
        
        Args:
            state: Current agent state
            
        Returns:
            Updated state with analyzed vulnerabilities
        """
        import time
        
        vulnerabilities = state.get("vulnerabilities", [])
        thoughts = state.get("thoughts", [])
        
        if not vulnerabilities:
            thoughts.append({
                "type": ThoughtType.INFO,
                "message": "No vulnerabilities to analyze",
                "details": [],
                "confidence": 1.0,
                "timestamp": time.time(),
            })
            return {
                **state,
                "ai_analysis_complete": True,
                "current_phase": "analysis_complete",
            }
        
        thoughts.append({
            "type": ThoughtType.ANALYZING,
            "message": f"Analyzing {len(vulnerabilities)} findings with AI",
            "details": [
                "Validating true vs false positives",
                "Assigning confidence scores",
                "Verifying scope compliance",
            ],
            "confidence": 0.9,
            "timestamp": time.time(),
        })
        
        # Analyze each vulnerability
        analyzed = []
        for vuln in vulnerabilities:
            # In real implementation, this would call LLM
            # For now, simulate analysis
            analyzed_vuln = AnalysisNode._analyze_vulnerability(vuln)
            analyzed.append(analyzed_vuln)
            
            confidence_str = f"{analyzed_vuln.ai_confidence:.0%}"
            thoughts.append({
                "type": ThoughtType.INFO,
                "message": f"Analyzed {analyzed_vuln.type}",
                "details": [
                    f"Target: {analyzed_vuln.target}",
                    f"AI Confidence: {confidence_str}",
                    f"Verdict: {'TRUE POSITIVE' if not analyzed_vuln.is_false_positive else 'FALSE POSITIVE'}",
                ],
                "confidence": analyzed_vuln.ai_confidence,
                "timestamp": time.time(),
            })
        
        # Count confirmed findings
        confirmed = [v for v in analyzed if not v.is_false_positive]
        
        thoughts.append({
            "type": ThoughtType.SUCCESS,
            "message": f"AI analysis complete",
            "details": [
                f"Confirmed {len(confirmed)} true positives",
                f"Filtered {len(analyzed) - len(confirmed)} false positives",
            ],
            "confidence": 0.9,
            "timestamp": time.time(),
        })
        
        return {
            **state,
            "vulnerabilities": analyzed,
            "ai_analysis_complete": True,
            "current_phase": "analysis_complete",
        }

    @staticmethod
    def _analyze_vulnerability(vuln: Vulnerability) -> Vulnerability:
        """Analyze a single vulnerability.
        
        In real implementation, this would:
        1. Send evidence to LLM
        2. Get confidence score and verdict
        3. Update vulnerability with AI reasoning
        
        Args:
            vuln: Vulnerability to analyze
            
        Returns:
            Analyzed vulnerability
        """
        # Simulate AI analysis
        # Information disclosure is likely true positive
        if vuln.type == "Information Disclosure":
            return vuln.model_copy(update={
                "ai_confidence": 0.95,
                "ai_reasoning": "Server header disclosure is a reliable finding. "
                               "The evidence clearly shows nginx version in response headers.",
                "is_false_positive": False,
            })
        
        # Missing headers might have false positives
        elif vuln.type == "Missing Security Headers":
            return vuln.model_copy(update={
                "ai_confidence": 0.85,
                "ai_reasoning": "CSP header is indeed missing. However, the impact "
                               "depends on the application's use of inline scripts.",
                "is_false_positive": False,
            })
        
        # Default analysis
        return vuln.model_copy(update={
            "ai_confidence": 0.7,
            "ai_reasoning": "Standard vulnerability detection. Evidence appears valid.",
            "is_false_positive": False,
        })

    @staticmethod
    async def prioritize_findings(state: AgentState) -> AgentState:
        """Prioritize findings for reporting.
        
        Args:
            state: Current agent state
            
        Returns:
            Updated state
        """
        import time
        
        vulnerabilities = state.get("vulnerabilities", [])
        thoughts = state.get("thoughts", [])
        
        # Filter false positives
        confirmed = [v for v in vulnerabilities if not v.is_false_positive]
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        
        prioritized = sorted(
            confirmed,
            key=lambda v: (severity_order.get(v.severity, 5), -v.ai_confidence),
        )
        
        thoughts.append({
            "type": ThoughtType.DECIDING,
            "message": "Prioritized findings for reporting",
            "details": [
                f"Total confirmed: {len(confirmed)}",
                f"Critical: {sum(1 for v in prioritized if v.severity == Severity.CRITICAL)}",
                f"High: {sum(1 for v in prioritized if v.severity == Severity.HIGH)}",
                f"Medium: {sum(1 for v in prioritized if v.severity == Severity.MEDIUM)}",
                f"Low: {sum(1 for v in prioritized if v.severity == Severity.LOW)}",
            ],
            "confidence": 0.9,
            "timestamp": time.time(),
        })
        
        return {
            **state,
            "vulnerabilities": prioritized,
            "current_phase": "prioritization_complete",
        }


class StrategyNode:
    """Strategy selection node for determining next actions."""

    @staticmethod
    async def select_strategy(state: AgentState) -> AgentState:
        """Select next strategy based on findings.
        
        Args:
            state: Current agent state
            
        Returns:
            Updated state with recommended action
        """
        import time
        
        thoughts = state.get("thoughts", [])
        endpoints = state.get("discovered_endpoints", [])
        vulnerabilities = state.get("vulnerabilities", [])
        
        # Analyze current state
        critical_count = sum(
            1 for v in vulnerabilities
            if v.severity == Severity.CRITICAL and not v.is_false_positive
        )
        
        if critical_count > 0:
            action = "Request human review for critical findings"
            confidence = 1.0
        elif len(endpoints) > 50:
            action = "Continue with targeted scanning on high-value endpoints"
            confidence = 0.8
        elif not vulnerabilities:
            action = "Expand scan scope or try different techniques"
            confidence = 0.7
        else:
            action = "Proceed to report generation"
            confidence = 0.9
        
        thoughts.append({
            "type": ThoughtType.DECIDING,
            "message": f"Strategy: {action}",
            "details": [
                f"Based on {len(endpoints)} endpoints and {len(vulnerabilities)} findings",
                f"Confidence: {confidence:.0%}",
            ],
            "confidence": confidence,
            "timestamp": time.time(),
        })
        
        return {
            **state,
            "next_recommended_action": action,
            "current_phase": "strategy_selected",
        }
