"""Unit tests for state manager and SQLite persistence."""

import json
from datetime import datetime
from pathlib import Path

import pytest
import pytest_asyncio

from bbai.core.config_models import SafetyEvent, Severity, ToolOutput, Vulnerability
from bbai.core.state_manager import StateManager


class TestStateManager:
    """Test StateManager functionality."""

    @pytest_asyncio.fixture
    async def manager(self, tmp_path):
        db_path = tmp_path / "test.db"
        mgr = StateManager(db_path)
        await mgr.initialize()
        return mgr

    @pytest.mark.asyncio
    async def test_initialization(self, tmp_path):
        db_path = tmp_path / "test.db"
        manager = StateManager(db_path)
        await manager.initialize()
        
        assert db_path.exists()

    @pytest.mark.asyncio
    async def test_create_session(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={"name": "test"},
        )
        
        # Verify by getting audit trail
        trail = await manager.get_audit_trail("test-001")
        assert trail["session"]["id"] == "test-001"
        assert trail["session"]["target"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_end_session(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        await manager.end_session("test-001", status="completed")
        
        trail = await manager.get_audit_trail("test-001")
        assert trail["session"]["status"] == "completed"
        assert trail["session"]["end_time"] is not None

    @pytest.mark.asyncio
    async def test_log_safety_event(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        event = SafetyEvent(
            level="CRITICAL",
            reason="SCOPE_VIOLATION",
            details={"url": "https://evil.com"},
        )
        
        event_id = await manager.log_safety_event("test-001", event)
        assert event_id > 0
        
        events = await manager.get_safety_events("test-001")
        assert len(events) == 1
        assert events[0].level == "CRITICAL"

    @pytest.mark.asyncio
    async def test_log_multiple_safety_events(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        for i in range(3):
            event = SafetyEvent(
                level="HIGH",
                reason=f"EVENT_{i}",
            )
            await manager.log_safety_event("test-001", event)
        
        events = await manager.get_safety_events("test-001")
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_get_safety_events_min_level(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        # Create events of different levels
        for level in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            event = SafetyEvent(
                level=level,  # type: ignore
                reason=f"TEST_{level}",
            )
            await manager.log_safety_event("test-001", event)
        
        # Get only HIGH and above
        events = await manager.get_safety_events("test-001", min_level="HIGH")
        assert len(events) == 2  # HIGH and CRITICAL

    @pytest.mark.asyncio
    async def test_save_vulnerability(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        vuln = Vulnerability(
            id="VULN-001",
            type="XSS",
            target="https://example.com",
            description="Cross-site scripting",
            reproduction_steps="Inject script",
            evidence="<script>alert(1)</script>",
            severity=Severity.HIGH,
            cvss_score=8.5,
            tool_source="nuclei",
        )
        
        await manager.save_vulnerability("test-001", vuln)
        
        vulns = await manager.get_vulnerabilities("test-001")
        assert len(vulns) == 1
        assert vulns[0].id == "VULN-001"
        assert vulns[0].type == "XSS"

    @pytest.mark.asyncio
    async def test_get_vulnerabilities_min_severity(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        # Create vulnerabilities of different severities
        for sev in [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]:
            vuln = Vulnerability(
                id=f"VULN-{sev.value}",
                type="Test",
                target="https://example.com",
                description="Test",
                reproduction_steps="Test",
                evidence="Test",
                severity=sev,
                tool_source="nuclei",
            )
            await manager.save_vulnerability("test-001", vuln)
        
        # Get only HIGH and above
        vulns = await manager.get_vulnerabilities("test-001", min_severity="high")
        assert len(vulns) == 2  # HIGH and CRITICAL

    @pytest.mark.asyncio
    async def test_log_tool_output(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        output = ToolOutput(
            tool_name="nuclei",
            exit_code=0,
            stdout="Found 3 vulnerabilities",
            stderr="",
            execution_time=5.5,
        )
        
        log_id = await manager.log_tool_output("test-001", output)
        assert log_id > 0

    @pytest.mark.asyncio
    async def test_save_checkpoint(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        state = {"phase": "recon", "endpoints": ["/api", "/admin"]}
        checkpoint_id = await manager.save_checkpoint("test-001", "thread-1", state)
        
        assert checkpoint_id > 0

    @pytest.mark.asyncio
    async def test_get_session_stats(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={},
        )
        
        # Add safety events
        for level in ["HIGH", "HIGH", "MEDIUM"]:
            event = SafetyEvent(level=level, reason="TEST")  # type: ignore
            await manager.log_safety_event("test-001", event)
        
        # Add vulnerabilities
        for sev in [Severity.HIGH, Severity.MEDIUM]:
            vuln = Vulnerability(
                id=f"VULN-{sev.value}",
                type="Test",
                target="https://example.com",
                description="Test",
                reproduction_steps="Test",
                evidence="Test",
                severity=sev,
                tool_source="nuclei",
            )
            await manager.save_vulnerability("test-001", vuln)
        
        stats = await manager.get_session_stats("test-001")
        
        assert stats["safety_events"]["HIGH"] == 2
        assert stats["safety_events"]["MEDIUM"] == 1
        assert stats["vulnerabilities"]["high"] == 1
        assert stats["vulnerabilities"]["medium"] == 1

    @pytest.mark.asyncio
    async def test_get_audit_trail(self, manager):
        await manager.create_session(
            session_id="test-001",
            target="https://example.com",
            program_name="test-program",
            config={"test": "config"},
        )
        
        trail = await manager.get_audit_trail("test-001")
        
        assert "session" in trail
        assert "safety_events" in trail
        assert "vulnerabilities" in trail
        assert "stats" in trail
        assert trail["session"]["id"] == "test-001"

    @pytest.mark.asyncio
    async def test_get_audit_trail_not_found(self, manager):
        with pytest.raises(ValueError, match="Session not found"):
            await manager.get_audit_trail("nonexistent")

    @pytest.mark.asyncio
    async def test_initialize_idempotent(self, manager):
        # Calling initialize again should not fail
        await manager.initialize()
        await manager.initialize()
