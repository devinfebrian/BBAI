"""AI Thought Streamer - Real-time AI reasoning visualization.

This module implements the real-time visualization of AI thinking process,
showing confidence levels, decision branches, and safety validations as they happen.

Best practices from Rich documentation:
- Use Live() context manager for auto-refreshing displays
- Use Tree() for hierarchical data visualization
- Use Panel() with border_style for visual distinction
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Callable

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.style import Style
from rich.tree import Tree

from bbai.core.config_models import Thought, ThoughtType


class ThoughtTheme:
    """Color theme for different thought types."""

    ANALYZING = Style(color="cyan", bold=True)
    DECIDING = Style(color="blue", bold=True)
    WARNING = Style(color="yellow", bold=True)
    ERROR = Style(color="red", bold=True)
    SUCCESS = Style(color="green", bold=True)
    INFO = Style(color="white")

    ICONS = {
        ThoughtType.ANALYZING: "🤔",
        ThoughtType.DECIDING: "🎯",
        ThoughtType.WARNING: "⚠️",
        ThoughtType.ERROR: "❌",
        ThoughtType.SUCCESS: "✅",
        ThoughtType.INFO: "ℹ️",
    }

    @classmethod
    def get_style(cls, thought_type: ThoughtType) -> Style:
        """Get the style for a thought type."""
        return getattr(cls, thought_type.value.upper(), cls.INFO)

    @classmethod
    def get_icon(cls, thought_type: ThoughtType) -> str:
        """Get the icon for a thought type."""
        return cls.ICONS.get(thought_type, "ℹ️")


@dataclass
class ConfidenceBar:
    """Visual confidence indicator."""

    value: float  # 0.0 to 1.0
    width: int = 20

    def __rich__(self) -> str:
        """Render confidence bar."""
        filled = int(self.value * self.width)
        empty = self.width - filled
        
        # Color based on confidence level
        if self.value >= 0.8:
            color = "green"
        elif self.value >= 0.5:
            color = "yellow"
        else:
            color = "red"
        
        bar = f"[bold {color}]{'█' * filled}[/][dim]{'░' * empty}[/]"
        return f"{bar} [bold]{self.value:.0%}[/]"


@dataclass
class ThoughtBranch:
    """A branch in the thought tree (decision alternative)."""

    name: str
    status: str  # "pending", "active", "selected", "rejected"
    reason: str | None = None


class AIThoughtStreamer:
    """Real-time AI reasoning visualization.
    
    Usage:
        async with AIThoughtStreamer(console) as streamer:
            streamer.think("Analyzing target scope...", ThoughtType.ANALYZING)
            streamer.detail("Pattern match: *.example.com [ALLOWED]")
            streamer.detail("Confidence:", confidence=0.95)
    
    Best practices from Rich docs:
    - Use refresh_per_second=10 for smooth updates
    - Call update() explicitly when state changes
    - Use Live as async context manager
    """

    def __init__(
        self,
        console: Console | None = None,
        refresh_per_second: int = 10,
        show_confidence: bool = True,
    ):
        self.console = console or Console()
        self.refresh_per_second = refresh_per_second
        self.show_confidence = show_confidence
        
        self._thoughts: list[Thought] = []
        self._current_thought: Thought | None = None
        self._branches: list[ThoughtBranch] = []
        self._progress: Progress | None = None
        self._live: Live | None = None
        self._start_time: float = 0.0

    @asynccontextmanager
    async def stream(self) -> AsyncIterator[AIThoughtStreamer]:
        """Async context manager for streaming thoughts.
        
        Usage:
            async with streamer.stream():
                streamer.think("Processing...")
        """
        self._start_time = time.time()
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console,
            transient=True,
        )
        
        self._live = Live(
            self._render(),
            refresh_per_second=self.refresh_per_second,
            console=self.console,
        )
        
        with self._live:
            yield self

    def think(
        self,
        message: str,
        thought_type: ThoughtType = ThoughtType.INFO,
        confidence: float | None = None,
    ) -> None:
        """Start a new thought.
        
        Args:
            message: Main thought message
            thought_type: Type of thought for styling
            confidence: Optional confidence level (0.0-1.0)
        """
        # Save previous thought if exists
        if self._current_thought:
            self._thoughts.append(self._current_thought)
        
        self._current_thought = Thought(
            type=thought_type,
            message=message,
            details=[],
            confidence=confidence,
            timestamp=time.time(),
        )
        self._branches = []  # Reset branches for new thought
        self._refresh()

    def detail(self, message: str, confidence: float | None = None) -> None:
        """Add a detail to the current thought.
        
        Args:
            message: Detail message
            confidence: Optional confidence for this detail
        """
        if self._current_thought:
            self._current_thought.details.append(message)
            if confidence is not None:
                self._current_thought.confidence = confidence
            self._refresh()

    def add_branch(self, name: str, status: str = "pending", reason: str | None = None) -> None:
        """Add a decision branch.
        
        Args:
            name: Branch name/label
            status: Branch status (pending, active, selected, rejected)
            reason: Optional reason for status
        """
        self._branches.append(ThoughtBranch(name, status, reason))
        self._refresh()

    def update_branch(self, name: str, status: str, reason: str | None = None) -> None:
        """Update a branch status."""
        for branch in self._branches:
            if branch.name == name:
                branch.status = status
                if reason:
                    branch.reason = reason
                break
        self._refresh()

    def complete_thought(self, message: str | None = None) -> None:
        """Complete the current thought with optional summary."""
        if self._current_thought and message:
            self._current_thought.details.append(f"[bold green]✓ {message}[/]")
            self._refresh()

    def _refresh(self) -> None:
        """Refresh the live display."""
        if self._live:
            self._live.update(self._render())

    def _render(self) -> Panel:
        """Render the thought stream as a Rich Panel."""
        elements: list = []
        
        # Render previous thoughts (collapsed)
        if self._thoughts:
            for thought in self._thoughts[-3:]:  # Show last 3 thoughts
                elements.append(self._render_thought(thought, collapsed=True))
        
        # Render current thought (expanded)
        if self._current_thought:
            elements.append(self._render_thought(self._current_thought, collapsed=False))
        
        # Render branches if any
        if self._branches:
            elements.append(self._render_branches())
        
        # Render elapsed time
        elapsed = time.time() - self._start_time
        footer = f"[dim]Elapsed: {elapsed:.1f}s[/]"
        
        content = Group(*elements) if elements else footer
        
        return Panel(
            content,
            title="[bold blue]🧠 AI Reasoning Stream[/]",
            border_style="blue",
            subtitle=footer,
        )

    def _render_thought(self, thought: Thought, collapsed: bool = False) -> str | Tree:
        """Render a single thought."""
        icon = ThoughtTheme.get_icon(thought.type)
        style = ThoughtTheme.get_style(thought.type)
        
        if collapsed:
            # Simple one-line representation
            conf_str = ""
            if thought.confidence is not None:
                conf_str = f" ([dim]{thought.confidence:.0%}[/])"
            return f"[dim]{icon} {thought.message}{conf_str}[/]"
        
        # Full tree representation
        tree = Tree(f"[{style}]{icon} AI > {thought.message}[/]")
        
        # Add details as branches
        for detail in thought.details:
            tree.add(f"[dim]└─[/] {detail}")
        
        # Add confidence bar
        if self.show_confidence and thought.confidence is not None:
            bar = ConfidenceBar(thought.confidence)
            tree.add(f"[dim]└─[/] Confidence: {bar}")
        
        return tree

    def _render_branches(self) -> Panel:
        """Render decision branches."""
        tree = Tree("[bold]Decision Options[/]")
        
        for branch in self._branches:
            status_icon = {
                "pending": "⏳",
                "active": "▶️",
                "selected": "✅",
                "rejected": "❌",
            }.get(branch.status, "⏳")
            
            status_style = {
                "pending": "dim",
                "active": "yellow",
                "selected": "green",
                "rejected": "red",
            }.get(branch.status, "dim")
            
            label = f"[{status_style}]{status_icon} {branch.name}[/]"
            if branch.reason:
                label += f" [dim]({branch.reason})[/]"
            
            tree.add(label)
        
        return Panel(tree, border_style="dim", padding=(0, 1))

    def get_thoughts(self) -> list[Thought]:
        """Get all thoughts including current."""
        thoughts = list(self._thoughts)
        if self._current_thought:
            thoughts.append(self._current_thought)
        return thoughts


class ThoughtLogger:
    """Non-visual thought logger for headless/CI environments."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._thoughts: list[Thought] = []

    def think(
        self,
        message: str,
        thought_type: ThoughtType = ThoughtType.INFO,
        confidence: float | None = None,
    ) -> None:
        """Log a thought."""
        import time
        
        thought = Thought(
            type=thought_type,
            message=message,
            details=[],
            confidence=confidence,
            timestamp=time.time(),
        )
        self._thoughts.append(thought)
        
        icon = ThoughtTheme.get_icon(thought_type)
        self.console.print(f"{icon} AI > {message}")

    def detail(self, message: str, confidence: float | None = None) -> None:
        """Log a detail."""
        if self._thoughts:
            self._thoughts[-1].details.append(message)
            if confidence is not None:
                self._thoughts[-1].confidence = confidence
        
        conf_str = f" ({confidence:.0%})" if confidence else ""
        self.console.print(f"   └─ {message}{conf_str}")

    def get_thoughts(self) -> list[Thought]:
        """Get all logged thoughts."""
        return list(self._thoughts)


# Convenience function for quick thought streaming
@asynccontextmanager
async def think(
    message: str,
    thought_type: ThoughtType = ThoughtType.ANALYZING,
    console: Console | None = None,
) -> AsyncIterator[AIThoughtStreamer]:
    """Quick context manager for single thought streaming.
    
    Usage:
        async with think("Analyzing...") as t:
            t.detail("Found 5 subdomains")
    """
    streamer = AIThoughtStreamer(console)
    async with streamer.stream():
        streamer.think(message, thought_type)
        yield streamer
