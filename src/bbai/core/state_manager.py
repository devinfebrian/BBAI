"""State Manager - SQLite persistence for audit logs and state.

Uses aiosqlite for async SQLite operations.
Implements immutable audit logging for compliance.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

from bbai.core.config_models import AgentState, SafetyEvent, ToolOutput, Vulnerability


class StateManager:
    """Manages persistent state and audit logging in SQLite.
    
    All operations are async and use aiosqlite.
    Tables:
    - sessions: Scan session metadata
    - safety_events: Immutable audit log of safety events
    - tool_outputs: Tool execution logs
    - vulnerabilities: Discovered vulnerabilities
    - state_checkpoints: LangGraph state checkpoints
    
    Usage:
        manager = StateManager(db_path)
        await manager.initialize()
        
        # Log safety event (immutable)
        await manager.log_safety_event(session_id, event)
        
        # Save vulnerability
        await manager.save_vulnerability(session_id, vuln)
        
        # Get audit trail
        events = await manager.get_safety_events(session_id)
    """

    SCHEMA = """
    -- Sessions table
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        program_name TEXT NOT NULL,
        config TEXT NOT NULL,  -- JSON serialized
        start_time TEXT NOT NULL,
        end_time TEXT,
        status TEXT DEFAULT 'running',
        halt_reason TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Safety events (immutable audit log)
    CREATE TABLE IF NOT EXISTS safety_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        level TEXT NOT NULL,
        reason TEXT NOT NULL,
        details TEXT,  -- JSON serialized
        timestamp TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
    );

    -- Tool execution logs
    CREATE TABLE IF NOT EXISTS tool_outputs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        exit_code INTEGER NOT NULL,
        stdout TEXT,
        stderr TEXT,
        execution_time REAL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
    );

    -- Vulnerabilities
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        vuln_type TEXT NOT NULL,
        cwe_id TEXT,
        target TEXT NOT NULL,
        endpoint TEXT,
        parameter TEXT,
        severity TEXT NOT NULL,
        cvss_score REAL,
        description TEXT NOT NULL,
        reproduction_steps TEXT NOT NULL,
        evidence TEXT NOT NULL,
        ai_confidence REAL,
        ai_reasoning TEXT,
        is_false_positive BOOLEAN DEFAULT FALSE,
        tool_source TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
    );

    -- State checkpoints for LangGraph
    CREATE TABLE IF NOT EXISTS state_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        checkpoint TEXT NOT NULL,  -- JSON serialized state
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
    );

    -- Indexes for performance
    CREATE INDEX IF NOT EXISTS idx_safety_events_session ON safety_events(session_id);
    CREATE INDEX IF NOT EXISTS idx_tool_outputs_session ON tool_outputs(session_id);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_session ON vulnerabilities(session_id);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_checkpoints_thread ON state_checkpoints(thread_id);
    """

    def __init__(self, db_path: Path | str = "~/.bbai/bbai.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize database with schema."""
        if self._initialized:
            return

        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(self.SCHEMA)
            await db.commit()

        self._initialized = True

    async def create_session(
        self,
        session_id: str,
        target: str,
        program_name: str,
        config: dict[str, Any],
    ) -> None:
        """Create a new scan session.
        
        Args:
            session_id: Unique session identifier
            target: Target being scanned
            program_name: Bug bounty program name
            config: Serialized program configuration
        """
        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO sessions (id, target, program_name, config, start_time)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    target,
                    program_name,
                    json.dumps(config),
                    datetime.utcnow().isoformat(),
                ),
            )
            await db.commit()

    async def end_session(
        self,
        session_id: str,
        status: str = "completed",
        halt_reason: str | None = None,
    ) -> None:
        """Mark session as ended.
        
        Args:
            session_id: Session identifier
            status: Final status (completed, halted, error)
            halt_reason: Reason for halting (if applicable)
        """
        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE sessions
                SET end_time = ?, status = ?, halt_reason = ?
                WHERE id = ?
                """,
                (datetime.utcnow().isoformat(), status, halt_reason, session_id),
            )
            await db.commit()

    async def log_safety_event(
        self,
        session_id: str,
        event: SafetyEvent,
    ) -> int:
        """Log a safety event (immutable audit log).
        
        Args:
            session_id: Session identifier
            event: Safety event to log
            
        Returns:
            Row ID of inserted event
        """
        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO safety_events (session_id, level, reason, details, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    event.level,
                    event.reason,
                    json.dumps(event.details) if event.details else None,
                    event.timestamp.isoformat(),
                ),
            )
            await db.commit()
            return cursor.lastrowid  # type: ignore

    async def log_tool_output(
        self,
        session_id: str,
        output: ToolOutput,
    ) -> int:
        """Log a tool execution.
        
        Args:
            session_id: Session identifier
            output: Tool output to log
            
        Returns:
            Row ID of inserted log
        """
        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO tool_outputs
                (session_id, tool_name, exit_code, stdout, stderr, execution_time, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    output.tool_name,
                    output.exit_code,
                    output.stdout,
                    output.stderr,
                    output.execution_time,
                    output.timestamp.isoformat(),
                ),
            )
            await db.commit()
            return cursor.lastrowid  # type: ignore

    async def save_vulnerability(
        self,
        session_id: str,
        vuln: Vulnerability,
    ) -> None:
        """Save a vulnerability finding.
        
        Args:
            session_id: Session identifier
            vuln: Vulnerability to save
        """
        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities
                (id, session_id, vuln_type, cwe_id, target, endpoint, parameter,
                 severity, cvss_score, description, reproduction_steps, evidence,
                 ai_confidence, ai_reasoning, is_false_positive, tool_source, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln.id,
                    session_id,
                    vuln.type,
                    vuln.cwe_id,
                    vuln.target,
                    vuln.endpoint,
                    vuln.parameter,
                    vuln.severity.value,
                    vuln.cvss_score,
                    vuln.description,
                    vuln.reproduction_steps,
                    vuln.evidence,
                    vuln.ai_confidence,
                    vuln.ai_reasoning,
                    vuln.is_false_positive,
                    vuln.tool_source,
                    vuln.discovered_at.isoformat(),
                ),
            )
            await db.commit()

    async def save_checkpoint(
        self,
        session_id: str,
        thread_id: str,
        state: dict[str, Any],
    ) -> int:
        """Save a state checkpoint for LangGraph.
        
        Args:
            session_id: Session identifier
            thread_id: Thread identifier
            state: Serialized state
            
        Returns:
            Row ID of inserted checkpoint
        """
        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO state_checkpoints (session_id, thread_id, checkpoint)
                VALUES (?, ?, ?)
                """,
                (session_id, thread_id, json.dumps(state)),
            )
            await db.commit()
            return cursor.lastrowid  # type: ignore

    async def get_safety_events(
        self,
        session_id: str,
        min_level: str | None = None,
    ) -> list[SafetyEvent]:
        """Get safety events for a session.
        
        Args:
            session_id: Session identifier
            min_level: Minimum severity level to include
            
        Returns:
            List of safety events
        """
        await self.initialize()

        level_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_level_value = level_order.get(min_level, 0) if min_level else 0

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            async with db.execute(
                "SELECT * FROM safety_events WHERE session_id = ? ORDER BY timestamp DESC",
                (session_id,),
            ) as cursor:
                rows = await cursor.fetchall()

        events = []
        for row in rows:
            if level_order.get(row["level"], 0) >= min_level_value:
                events.append(
                    SafetyEvent(
                        level=row["level"],
                        reason=row["reason"],
                        details=json.loads(row["details"]) if row["details"] else {},
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                    )
                )

        return events

    async def get_vulnerabilities(
        self,
        session_id: str,
        min_severity: str | None = None,
    ) -> list[Vulnerability]:
        """Get vulnerabilities for a session.
        
        Args:
            session_id: Session identifier
            min_severity: Minimum severity to include
            
        Returns:
            List of vulnerabilities
        """
        await self.initialize()

        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_severity_value = severity_order.get(min_severity, 0) if min_severity else 0

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            async with db.execute(
                "SELECT * FROM vulnerabilities WHERE session_id = ?",
                (session_id,),
            ) as cursor:
                rows = await cursor.fetchall()

        vulns = []
        for row in rows:
            if severity_order.get(row["severity"], 0) >= min_severity_value:
                vulns.append(
                    Vulnerability(
                        id=row["id"],
                        type=row["vuln_type"],
                        cwe_id=row["cwe_id"],
                        target=row["target"],
                        endpoint=row["endpoint"],
                        parameter=row["parameter"],
                        severity=row["severity"],
                        cvss_score=row["cvss_score"],
                        description=row["description"],
                        reproduction_steps=row["reproduction_steps"],
                        evidence=row["evidence"],
                        ai_confidence=row["ai_confidence"] or 0.0,
                        ai_reasoning=row["ai_reasoning"],
                        is_false_positive=bool(row["is_false_positive"]),
                        tool_source=row["tool_source"],
                        discovered_at=datetime.fromisoformat(row["discovered_at"]),
                    )
                )

        return vulns

    async def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """Get statistics for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Dictionary with statistics
        """
        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            # Count safety events by level
            async with db.execute(
                "SELECT level, COUNT(*) FROM safety_events WHERE session_id = ? GROUP BY level",
                (session_id,),
            ) as cursor:
                safety_counts = {row[0]: row[1] async for row in cursor}

            # Count vulnerabilities by severity
            async with db.execute(
                "SELECT severity, COUNT(*) FROM vulnerabilities WHERE session_id = ? GROUP BY severity",
                (session_id,),
            ) as cursor:
                vuln_counts = {row[0]: row[1] async for row in cursor}

            # Count tool executions
            async with db.execute(
                "SELECT COUNT(*) FROM tool_outputs WHERE session_id = ?",
                (session_id,),
            ) as cursor:
                tool_count = (await cursor.fetchone())[0]

        return {
            "safety_events": safety_counts,
            "vulnerabilities": vuln_counts,
            "tool_executions": tool_count,
        }

    async def get_audit_trail(self, session_id: str) -> dict[str, Any]:
        """Get complete audit trail for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Complete audit trail
        """
        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            # Get session info
            async with db.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (session_id,),
            ) as cursor:
                session_row = await cursor.fetchone()

        if not session_row:
            raise ValueError(f"Session not found: {session_id}")

        return {
            "session": {
                "id": session_row["id"],
                "target": session_row["target"],
                "program_name": session_row["program_name"],
                "start_time": session_row["start_time"],
                "end_time": session_row["end_time"],
                "status": session_row["status"],
                "halt_reason": session_row["halt_reason"],
            },
            "safety_events": await self.get_safety_events(session_id),
            "vulnerabilities": await self.get_vulnerabilities(session_id),
            "stats": await self.get_session_stats(session_id),
        }
