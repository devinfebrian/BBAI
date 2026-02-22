"""LangGraph workflow builder for BBAI.

Builds and compiles the state graph for security scanning workflow.
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, START, StateGraph
from langgraph.checkpoint.memory import InMemorySaver

from bbai.orchestration.nodes.analysis import AnalysisNode, StrategyNode
from bbai.orchestration.nodes.recon import DiscoveryNode, ReconNode
from bbai.orchestration.nodes.reporting import FinalizeNode, ReportingNode
from bbai.orchestration.nodes.safety import HumanReviewNode, SafetyNode
from bbai.orchestration.nodes.scanning import CloudScanNode, SecretScanNode, VulnScanNode
from bbai.orchestration.state import (
    AgentState,
    create_initial_state,
    has_critical_findings,
    requires_human_approval,
    should_halt,
)


def create_workflow(checkpointer=None) -> StateGraph:
    """Create the BBAI LangGraph workflow.
    
    Workflow:
    1. Safety check (pre-execution)
    2. Passive reconnaissance
    3. Active reconnaissance
    4. Content discovery
    5. Service discovery
    6. Secret scanning
    7. Vulnerability scanning
    8. JS analysis
    9. Cloud scanning
    10. AI analysis
    11. Strategy selection
    12. Human review (if critical findings)
    13. Report generation
    14. Safety check (post-execution)
    15. Finalize
    
    Args:
        checkpointer: Optional checkpointer for persistence
        
    Returns:
        Compiled StateGraph
    """
    # Create workflow
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("safety_pre", SafetyNode.pre_execution)
    workflow.add_node("recon_passive", ReconNode.passive_recon)
    workflow.add_node("recon_active", ReconNode.active_recon)
    workflow.add_node("content_discovery", ReconNode.content_discovery)
    workflow.add_node("service_discovery", DiscoveryNode.service_discovery)
    workflow.add_node("secret_scan", SecretScanNode.scan_secrets)
    workflow.add_node("vuln_scan", VulnScanNode.run_vuln_scan)
    workflow.add_node("js_analysis", VulnScanNode.run_js_analysis)
    workflow.add_node("cloud_scan", CloudScanNode.scan_cloud_resources)
    workflow.add_node("ai_analysis", AnalysisNode.analyze_findings)
    workflow.add_node("prioritize", AnalysisNode.prioritize_findings)
    workflow.add_node("strategy", StrategyNode.select_strategy)
    workflow.add_node("human_review", HumanReviewNode.interrupt_for_approval)
    workflow.add_node("report", ReportingNode.generate_report)
    workflow.add_node("safety_post", SafetyNode.post_execution)
    workflow.add_node("finalize", FinalizeNode.finalize)
    
    # Define edges
    workflow.set_entry_point("safety_pre")
    
    # Safety check -> halt or continue
    workflow.add_conditional_edges(
        "safety_pre",
        lambda s: "halt" if should_halt(s) else "continue",
        {
            "halt": "finalize",
            "continue": "recon_passive",
        },
    )
    
    # Reconnaissance flow
    workflow.add_edge("recon_passive", "recon_active")
    workflow.add_edge("recon_active", "content_discovery")
    workflow.add_edge("content_discovery", "service_discovery")
    
    # Scanning flow
    workflow.add_edge("service_discovery", "secret_scan")
    workflow.add_edge("secret_scan", "vuln_scan")
    workflow.add_edge("vuln_scan", "js_analysis")
    workflow.add_edge("js_analysis", "cloud_scan")
    
    # Analysis flow
    workflow.add_edge("cloud_scan", "ai_analysis")
    workflow.add_edge("ai_analysis", "prioritize")
    workflow.add_edge("prioritize", "strategy")
    
    # Strategy -> human review or report
    workflow.add_conditional_edges(
        "strategy",
        lambda s: "review" if has_critical_findings(s) else "report",
        {
            "review": "human_review",
            "report": "report",
        },
    )
    
    # Human review -> report
    workflow.add_edge("human_review", "report")
    
    # Report -> safety post -> finalize
    workflow.add_edge("report", "safety_post")
    workflow.add_edge("safety_post", "finalize")
    
    # Finalize -> END
    workflow.add_edge("finalize", END)
    
    # Compile with checkpointer
    if checkpointer is None:
        checkpointer = InMemorySaver()
    
    return workflow.compile(checkpointer=checkpointer)


def create_condensed_workflow(checkpointer=None) -> StateGraph:
    """Create a condensed workflow for quick scans.
    
    Skips some steps for faster execution:
    - No JS analysis
    - No cloud scanning
    - No human review
    
    Args:
        checkpointer: Optional checkpointer for persistence
        
    Returns:
        Compiled StateGraph
    """
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("safety_pre", SafetyNode.pre_execution)
    workflow.add_node("recon", ReconNode.passive_recon)
    workflow.add_node("vuln_scan", VulnScanNode.run_vuln_scan)
    workflow.add_node("ai_analysis", AnalysisNode.analyze_findings)
    workflow.add_node("report", ReportingNode.generate_report)
    workflow.add_node("finalize", FinalizeNode.finalize)
    
    # Define edges
    workflow.set_entry_point("safety_pre")
    
    workflow.add_conditional_edges(
        "safety_pre",
        lambda s: "halt" if should_halt(s) else "continue",
        {
            "halt": "finalize",
            "continue": "recon",
        },
    )
    
    workflow.add_edge("recon", "vuln_scan")
    workflow.add_edge("vuln_scan", "ai_analysis")
    workflow.add_edge("ai_analysis", "report")
    workflow.add_edge("report", "finalize")
    workflow.add_edge("finalize", END)
    
    if checkpointer is None:
        checkpointer = InMemorySaver()
    
    return workflow.compile(checkpointer=checkpointer)


class WorkflowRunner:
    """High-level workflow runner.
    
    Usage:
        runner = WorkflowRunner()
        result = await runner.run(target="example.com", config=program_config)
    """

    def __init__(self, checkpointer=None, condensed: bool = False):
        """Initialize workflow runner.
        
        Args:
            checkpointer: Optional checkpointer for persistence
            condensed: Use condensed workflow for quick scans
        """
        if condensed:
            self.workflow = create_condensed_workflow(checkpointer)
        else:
            self.workflow = create_workflow(checkpointer)

    async def run(
        self,
        target: str,
        config,
        thread_id: str | None = None,
        session_id: str | None = None,
    ) -> AgentState:
        """Run the workflow.
        
        Args:
            target: Target URL/domain
            config: Program configuration
            thread_id: Optional thread ID for persistence
            session_id: Optional session ID for audit logging
            
        Returns:
            Final state
        """
        import uuid
        from datetime import datetime
        
        thread_id = thread_id or str(uuid.uuid4())
        session_id = session_id or str(uuid.uuid4())
        
        # Create initial state
        initial_state = create_initial_state(
            target=target,
            config=config,
            thread_id=thread_id,
            session_id=session_id,
        )
        
        # Run workflow
        result = await self.workflow.ainvoke(
            initial_state,
            config={"configurable": {"thread_id": thread_id}},
        )
        
        return result

    async def resume(
        self,
        thread_id: str,
        user_input: str,
    ) -> AgentState:
        """Resume workflow after human review.
        
        Args:
            thread_id: Thread ID to resume
            user_input: User response
            
        Returns:
            Updated state
        """
        from langgraph.types import Command
        
        result = await self.workflow.ainvoke(
            Command(resume=user_input),
            config={"configurable": {"thread_id": thread_id}},
        )
        
        return result
