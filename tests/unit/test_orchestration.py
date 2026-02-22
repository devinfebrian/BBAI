"""Unit tests for LangGraph orchestration."""

import pytest

from bbai.core.config_models import ProgramConfig, SafetyEvent, Severity, Vulnerability
from bbai.orchestration.graph import create_condensed_workflow, create_workflow
from bbai.orchestration.state import (
    AgentState,
    create_initial_state,
    get_state_summary,
    has_critical_findings,
    requires_human_approval,
    should_halt,
)


class TestStateCreation:
    """Test state creation functions."""

    def test_create_initial_state(self):
        config = ProgramConfig(name="test")
        state = create_initial_state(
            target="https://example.com",
            config=config,
            thread_id="thread-123",
            session_id="session-456",
        )
        
        assert state["target"] == "https://example.com"
        assert state["config"] == config
        assert state["thread_id"] == "thread-123"
        assert state["session_id"] == "session-456"
        assert state["current_phase"] == "initialized"
        assert state["halt_requested"] is False


class TestStateChecks:
    """Test state check functions."""

    def test_should_halt_with_flag(self):
        state: AgentState = {
            "target": "",
            "config": ProgramConfig(name="test"),
            "thread_id": "",
            "session_id": "",
            "halt_requested": True,
        }
        assert should_halt(state) is True

    def test_should_halt_with_critical_safety_event(self):
        state: AgentState = {
            "target": "",
            "config": ProgramConfig(name="test"),
            "thread_id": "",
            "session_id": "",
            "halt_requested": False,
            "safety_events": [
                SafetyEvent(level="CRITICAL", reason="SCOPE_VIOLATION"),
            ],
        }
        assert should_halt(state) is True

    def test_should_not_halt(self):
        state: AgentState = {
            "target": "",
            "config": ProgramConfig(name="test"),
            "thread_id": "",
            "session_id": "",
            "halt_requested": False,
            "safety_events": [],
        }
        assert should_halt(state) is False

    def test_has_critical_findings_true(self):
        state: AgentState = {
            "target": "",
            "config": ProgramConfig(name="test"),
            "thread_id": "",
            "session_id": "",
            "vulnerabilities": [
                Vulnerability(
                    id="V1",
                    type="RCE",
                    target="https://example.com",
                    description="RCE",
                    reproduction_steps="1. Exploit",
                    evidence="shell",
                    severity=Severity.CRITICAL,
                    tool_source="nuclei",
                ),
            ],
        }
        assert has_critical_findings(state) is True

    def test_has_critical_findings_false(self):
        state: AgentState = {
            "target": "",
            "config": ProgramConfig(name="test"),
            "thread_id": "",
            "session_id": "",
            "vulnerabilities": [
                Vulnerability(
                    id="V1",
                    type="Info",
                    target="https://example.com",
                    description="Info",
                    reproduction_steps="1. Look",
                    evidence="header",
                    severity=Severity.LOW,
                    tool_source="nuclei",
                ),
            ],
        }
        assert has_critical_findings(state) is False

    def test_requires_human_approval_true(self):
        state: AgentState = {
            "target": "",
            "config": ProgramConfig(name="test"),
            "thread_id": "",
            "session_id": "",
            "human_approval_required": True,
        }
        assert requires_human_approval(state) is True

    def test_requires_human_approval_false(self):
        state: AgentState = {
            "target": "",
            "config": ProgramConfig(name="test"),
            "thread_id": "",
            "session_id": "",
            "human_approval_required": False,
        }
        assert requires_human_approval(state) is False

    def test_get_state_summary(self):
        state: AgentState = {
            "target": "https://example.com",
            "config": ProgramConfig(name="test"),
            "thread_id": "t1",
            "session_id": "s1",
            "current_phase": "scanning",
            "discovered_endpoints": ["/api", "/admin"],
            "discovered_subdomains": ["www.example.com"],
            "vulnerabilities": [],
            "safety_events": [],
            "halt_requested": False,
            "human_approval_required": False,
        }
        
        summary = get_state_summary(state)
        
        assert summary["target"] == "https://example.com"
        assert summary["phase"] == "scanning"
        assert summary["endpoints_found"] == 2
        assert summary["subdomains_found"] == 1


class TestWorkflowCreation:
    """Test workflow graph creation."""

    def test_create_workflow(self):
        """Test that workflow can be created."""
        workflow = create_workflow()
        assert workflow is not None

    def test_create_condensed_workflow(self):
        """Test that condensed workflow can be created."""
        workflow = create_condensed_workflow()
        assert workflow is not None


class TestSafetyNode:
    """Test safety validation nodes."""

    def test_pre_execution_scope_violation(self):
        from bbai.orchestration.nodes.safety import SafetyNode
        
        # Create config with no scope
        config = ProgramConfig(
            name="test",
            scope_in=[],
            scope_out=[],
        )
        
        state: AgentState = {
            "target": "https://example.com",
            "config": config,
            "thread_id": "t1",
            "session_id": "s1",
            "safety_events": [],
        }
        
        result = SafetyNode.pre_execution(state)
        
        assert result["halt_requested"] is True
        assert any("NO_SCOPE_MATCH" in e.reason for e in result["safety_events"])

    def test_pre_execution_allowed(self):
        from bbai.orchestration.nodes.safety import SafetyNode
        
        config = ProgramConfig(
            name="test",
            scope_in=[{"pattern": "*.example.com", "is_regex": False}],
        )
        
        state: AgentState = {
            "target": "https://www.example.com",
            "config": config,
            "thread_id": "t1",
            "session_id": "s1",
            "safety_events": [],
            "thoughts": [],
            "halt_requested": False,
            "current_phase": "initialized",
        }
        
        result = SafetyNode.pre_execution(state)
        
        assert result.get("halt_requested") is False
        assert result["current_phase"] == "safety_check_passed"


class TestAnalysisNode:
    """Test analysis nodes."""

    @pytest.mark.asyncio
    async def test_analyze_findings_empty(self):
        from bbai.orchestration.nodes.analysis import AnalysisNode
        
        state: AgentState = {
            "target": "https://example.com",
            "config": ProgramConfig(name="test"),
            "thread_id": "t1",
            "session_id": "s1",
            "vulnerabilities": [],
            "thoughts": [],
        }
        
        result = await AnalysisNode.analyze_findings(state)
        
        assert result["ai_analysis_complete"] is True
        assert len(result["vulnerabilities"]) == 0

    @pytest.mark.asyncio
    async def test_analyze_findings_with_vulns(self):
        from bbai.orchestration.nodes.analysis import AnalysisNode
        
        vuln = Vulnerability(
            id="V1",
            type="XSS",
            target="https://example.com",
            description="XSS",
            reproduction_steps="1. Inject",
            evidence="<script>",
            severity=Severity.HIGH,
            tool_source="nuclei",
        )
        
        state: AgentState = {
            "target": "https://example.com",
            "config": ProgramConfig(name="test"),
            "thread_id": "t1",
            "session_id": "s1",
            "vulnerabilities": [vuln],
            "thoughts": [],
        }
        
        result = await AnalysisNode.analyze_findings(state)
        
        assert result["ai_analysis_complete"] is True
        assert len(result["vulnerabilities"]) == 1
        # AI should have assigned confidence
        assert result["vulnerabilities"][0].ai_confidence > 0


class TestReportingNode:
    """Test reporting nodes."""

    def test_generate_report_empty(self):
        from bbai.orchestration.nodes.reporting import ReportingNode
        
        state: AgentState = {
            "target": "https://example.com",
            "config": ProgramConfig(name="test"),
            "thread_id": "t1",
            "session_id": "s1",
            "vulnerabilities": [],
            "thoughts": [],
        }
        
        result = ReportingNode.generate_report(state)
        
        assert result["current_phase"] == "report_generated"
        assert "report" in result.get("tool_results", {})

    def test_generate_report_with_findings(self):
        from bbai.orchestration.nodes.reporting import ReportingNode
        
        vuln = Vulnerability(
            id="V1",
            type="XSS",
            target="https://example.com",
            description="Cross-site scripting vulnerability",
            reproduction_steps="1. Inject payload",
            evidence="<script>alert(1)</script>",
            severity=Severity.HIGH,
            cvss_score=8.5,
            tool_source="nuclei",
        )
        
        state: AgentState = {
            "target": "https://example.com",
            "config": ProgramConfig(name="test"),
            "thread_id": "t1",
            "session_id": "s1",
            "vulnerabilities": [vuln],
            "thoughts": [],
        }
        
        result = ReportingNode.generate_report(state)
        
        assert result["current_phase"] == "report_generated"
        report = result.get("tool_results", {}).get("report", "")
        assert "XSS" in report
        assert "8.5" in report

    def test_generate_json_report(self):
        from bbai.orchestration.nodes.reporting import ReportingNode
        
        vuln = Vulnerability(
            id="V1",
            type="XSS",
            target="https://example.com",
            description="XSS",
            reproduction_steps="Inject",
            evidence="script",
            severity=Severity.HIGH,
            tool_source="nuclei",
        )
        
        state: AgentState = {
            "target": "https://example.com",
            "config": ProgramConfig(name="test"),
            "thread_id": "t1",
            "session_id": "s1",
            "vulnerabilities": [vuln],
        }
        
        report = ReportingNode.generate_json_report(state)
        
        assert report["target"] == "https://example.com"
        assert report["summary"]["total_findings"] == 1
        assert report["summary"]["severity_breakdown"]["high"] == 1
