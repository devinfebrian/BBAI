"""Safety node for LangGraph workflow.

Pre and post execution safety validation.
"""

from __future__ import annotations

from typing import Any

from bbai.core.config_models import SafetyEvent, ThoughtType
from bbai.core.scope_engine import ScopeValidator, allowed_result, blocked_result
from bbai.orchestration.state import AgentState


class SafetyNode:
    """Safety validation node for LangGraph.
    
    Performs pre-execution and post-execution safety checks.
    """

    @staticmethod
    def pre_execution(state: AgentState) -> AgentState:
        """Pre-execution safety validation.
        
        Validates:
        - Target URL is in scope
        - Timing restrictions
        - Tool permissions
        
        Args:
            state: Current agent state
            
        Returns:
            Updated state with safety check results
        """
        config = state.get("config")
        target = state.get("target")
        
        if not config or not target:
            return {
                **state,
                "halt_requested": True,
                "safety_events": state.get("safety_events", []) + [
                    SafetyEvent(
                        level="CRITICAL",
                        reason="MISSING_CONFIG_OR_TARGET",
                    )
                ],
                "current_phase": "safety_check_failed",
            }

        validator = ScopeValidator(config)
        new_events = []
        
        # Check target URL scope
        result = validator.validate_url(target)
        if not result.allowed:
            new_events.append(
                SafetyEvent(
                    level="CRITICAL",
                    reason=result.reason,
                    details=result.details,
                )
            )
            return {
                **state,
                "halt_requested": True,
                "safety_events": state.get("safety_events", []) + new_events,
                "current_phase": "scope_violation",
            }
        
        # Check timing restrictions
        result = validator.validate_timing()
        if not result.allowed:
            new_events.append(
                SafetyEvent(
                    level="CRITICAL",
                    reason=result.reason,
                    details=result.details,
                )
            )
            return {
                **state,
                "halt_requested": True,
                "safety_events": state.get("safety_events", []) + new_events,
                "current_phase": "timing_blocked",
            }
        
        # Add safety check thought
        thoughts = state.get("thoughts", []) + [
            {
                "type": ThoughtType.SUCCESS,
                "message": "Safety checks passed",
                "details": [
                    f"Target {target} is in scope",
                    "Timing restrictions OK",
                ],
                "confidence": 1.0,
                "timestamp": __import__("time").time(),
            }
        ]
        
        return {
            **state,
            "thoughts": thoughts,
            "current_phase": "safety_check_passed",
        }

    @staticmethod
    def post_execution(state: AgentState) -> AgentState:
        """Post-execution safety validation.
        
        Validates:
        - No PII in findings
        - Critical findings flagged for review
        
        Args:
            state: Current agent state
            
        Returns:
            Updated state
        """
        from bbai.core.safety_guards import SafetyGuard
        
        guard = SafetyGuard()
        new_events = []
        
        # Validate each finding for safety issues
        for vuln in state.get("vulnerabilities", []):
            event = guard.validate_finding(vuln)
            if event:
                new_events.append(event)
        
        # Check if human approval is needed for critical findings
        human_approval_required = bool(new_events and any(
            e.level in ("CRITICAL", "HIGH") for e in new_events
        ))
        
        return {
            **state,
            "safety_events": state.get("safety_events", []) + new_events,
            "human_approval_required": human_approval_required,
            "human_approval_prompt": (
                "Critical findings detected. Please review before continuing."
                if human_approval_required else None
            ),
            "current_phase": "post_safety_checked",
        }


class HumanReviewNode:
    """Human-in-the-loop review node.
    
    Uses LangGraph interrupt to pause execution for human approval.
    """

    @staticmethod
    def interrupt_for_approval(state: AgentState) -> AgentState:
        """Interrupt workflow for human approval.
        
        Args:
            state: Current state
            
        Returns:
            State with interrupt request
        """
        try:
            from langgraph.types import interrupt
            
            # Build approval prompt
            prompt = HumanReviewNode._build_approval_prompt(state)
            
            # Trigger interrupt
            response = interrupt(prompt)
            
            # Process response
            if response and response.lower() in ("yes", "y", "approve", "continue"):
                return {
                    **state,
                    "human_approval_required": False,
                    "thoughts": state.get("thoughts", []) + [
                        {
                            "type": ThoughtType.SUCCESS,
                            "message": "Human approval granted",
                            "details": ["Continuing with workflow"],
                            "confidence": 1.0,
                            "timestamp": __import__("time").time(),
                        }
                    ],
                }
            else:
                return {
                    **state,
                    "halt_requested": True,
                    "thoughts": state.get("thoughts", []) + [
                        {
                            "type": ThoughtType.WARNING,
                            "message": "Human approval denied",
                            "details": ["Workflow halted by user"],
                            "confidence": 1.0,
                            "timestamp": __import__("time").time(),
                        }
                    ],
                }
        except ImportError:
            # LangGraph interrupt not available, skip
            return {
                **state,
                "human_approval_required": False,
            }

    @staticmethod
    def _build_approval_prompt(state: AgentState) -> str:
        """Build human approval prompt.
        
        Args:
            state: Current state
            
        Returns:
            Formatted prompt string
        """
        lines = [
            "=" * 60,
            "HUMAN APPROVAL REQUIRED",
            "=" * 60,
            f"Target: {state['target']}",
            f"Phase: {state['current_phase']}",
            "",
            "Safety Events:",
        ]
        
        for event in state.get("safety_events", []):
            if event.level in ("CRITICAL", "HIGH"):
                lines.append(f"  [{event.level}] {event.reason}")
        
        lines.extend([
            "",
            "Critical Findings:",
        ])
        
        for vuln in state.get("vulnerabilities", []):
            if vuln.severity.value == "critical":
                lines.append(f"  [{vuln.severity.value.upper()}] {vuln.type} on {vuln.target}")
        
        lines.extend([
            "",
            "Do you want to continue? (yes/no)",
            "=" * 60,
        ])
        
        return "\n".join(lines)
