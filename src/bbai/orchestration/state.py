"""LangGraph state definitions for BBAI.

Defines the state schema and state management for the agent workflow.
"""

from __future__ import annotations

import operator
from datetime import datetime
from typing import Annotated, Any

from typing_extensions import TypedDict

from bbai.core.config_models import ProgramConfig, SafetyEvent, Thought, ToolOutput, Vulnerability


class AgentState(TypedDict):
    """LangGraph agent state schema.
    
    This TypedDict defines the structure of the state that flows
    through the LangGraph workflow. Fields with Annotated[..., operator.add]
    use the add operator to accumulate values across nodes.
    """

    # Core configuration
    target: str
    config: ProgramConfig
    thread_id: str
    session_id: str

    # Execution progress
    current_phase: str
    discovered_endpoints: Annotated[list[str], operator.add]
    discovered_subdomains: Annotated[list[str], operator.add]
    vulnerabilities: Annotated[list[Vulnerability], operator.add]

    # AI Reasoning
    thoughts: Annotated[list[Thought], operator.add]
    next_recommended_action: str | None
    ai_analysis_complete: bool

    # Safety
    halt_requested: bool
    safety_events: Annotated[list[SafetyEvent], operator.add]
    human_approval_required: bool
    human_approval_prompt: str | None

    # Tool execution
    tool_outputs: Annotated[list[ToolOutput], operator.add]
    current_tool: str | None
    tool_results: dict[str, Any]

    # Metadata
    start_time: datetime
    end_time: datetime | None
    execution_count: int

    # Checkpoint data for resumption
    workflow_checkpoint_id: str | None


def create_initial_state(
    target: str,
    config: ProgramConfig,
    thread_id: str,
    session_id: str,
) -> AgentState:
    """Create initial state for a new workflow.
    
    Args:
        target: Target URL/domain
        config: Program configuration
        thread_id: Thread identifier for persistence
        session_id: Session identifier for audit logging
        
    Returns:
        Initial agent state
    """
    return {
        "target": target,
        "config": config,
        "thread_id": thread_id,
        "session_id": session_id,
        "current_phase": "initialized",
        "discovered_endpoints": [],
        "discovered_subdomains": [],
        "vulnerabilities": [],
        "thoughts": [],
        "next_recommended_action": None,
        "ai_analysis_complete": False,
        "halt_requested": False,
        "safety_events": [],
        "human_approval_required": False,
        "human_approval_prompt": None,
        "tool_outputs": [],
        "current_tool": None,
        "tool_results": {},
        "start_time": datetime.utcnow(),
        "end_time": None,
        "execution_count": 0,
        "workflow_checkpoint_id": None,
    }


def should_halt(state: AgentState) -> bool:
    """Check if workflow should halt.
    
    Args:
        state: Current state
        
    Returns:
        True if workflow should halt
    """
    if state.get("halt_requested", False):
        return True
    
    # Check for critical safety events
    for event in state.get("safety_events", []):
        if event.level == "CRITICAL":
            return True
    
    return False


def has_critical_findings(state: AgentState) -> bool:
    """Check if state has critical vulnerability findings.
    
    Args:
        state: Current state
        
    Returns:
        True if critical findings exist
    """
    from bbai.core.config_models import Severity
    
    for vuln in state.get("vulnerabilities", []):
        if vuln.severity == Severity.CRITICAL:
            return True
    
    return False


def requires_human_approval(state: AgentState) -> bool:
    """Check if human approval is required.
    
    Args:
        state: Current state
        
    Returns:
        True if approval required
    """
    return state.get("human_approval_required", False)


def get_state_summary(state: AgentState) -> dict[str, Any]:
    """Get a summary of the current state.
    
    Args:
        state: Current state
        
    Returns:
        State summary dictionary
    """
    return {
        "target": state["target"],
        "phase": state["current_phase"],
        "endpoints_found": len(state.get("discovered_endpoints", [])),
        "subdomains_found": len(state.get("discovered_subdomains", [])),
        "vulnerabilities_found": len(state.get("vulnerabilities", [])),
        "safety_events": len(state.get("safety_events", [])),
        "halt_requested": state.get("halt_requested", False),
        "human_approval_required": state.get("human_approval_required", False),
    }
