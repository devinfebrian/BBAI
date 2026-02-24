"""
AI Agent for security testing.

The agent follows a ReAct pattern (Reasoning + Acting):
1. THINK: Analyze current state and decide next action
2. ACT: Execute a tool
3. OBSERVE: Process results and update state
4. REPEAT until done
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field
from rich.console import Console

from bbai.agent.tools import (
    ToolRegistry,
    SubfinderOutput,
    HttpxOutput,
    KatanaOutput,
    NucleiOutput,
)
from bbai.llm.factory import create_llm_client
from bbai.core.config_models import BBAIConfig


# ============================================================================
# Decision Models
# ============================================================================

class ActionType(str, Enum):
    RUN_TOOL = "run_tool"
    REPORT_FINDINGS = "report_findings"
    HALT = "halt"


class Strategy(str, Enum):
    """High-level strategy the agent is following."""
    INITIAL_RECON = "initial_recon"      # Discover what exists
    DEEP_DIVE = "deep_dive"              # Investigate interesting findings
    CONFIRM_FINDING = "confirm_finding"  # Verify a potential vulnerability
    ATTACK_SURFACE_MAPPING = "attack_surface_mapping"
    REPORT = "report"                    # Done, generate final output


class ToolDecision(BaseModel):
    """AI's decision to run a tool."""
    tool_name: str = Field(description="Which tool to run")
    params: dict = Field(description="Tool parameters")


class AgentDecision(BaseModel):
    """AI's decision about what to do next."""
    reasoning: str = Field(description="Step-by-step reasoning for this decision")
    action: ActionType = Field(description="What action to take")
    tool_decision: ToolDecision | None = Field(
        default=None,
        description="Tool to run (if action=run_tool)"
    )
    new_strategy: Strategy | None = Field(
        default=None,
        description="Change strategy if needed"
    )
    halt_reason: str | None = Field(
        default=None,
        description="Why halting (if action=halt)"
    )


# ============================================================================
# State Models
# ============================================================================

@dataclass
class DiscoveredHost:
    """A host we've discovered."""
    hostname: str
    source: str  # How we found it
    status: str = "unknown"  # alive, dead, unknown
    tech: list[str] = field(default_factory=list)
    interesting: bool = False


@dataclass
class DiscoveredEndpoint:
    """An endpoint we've found."""
    url: str
    method: str = "GET"
    status_code: int = 0
    tech: list[str] = field(default_factory=list)
    is_api: bool = False
    parameters: list[str] = field(default_factory=list)


@dataclass 
class Finding:
    """A security finding."""
    name: str
    severity: str
    host: str
    description: str = ""
    confirmed: bool = False
    evidence: str = ""


@dataclass
class AgentState:
    """Current state of the security investigation."""
    # Target
    root_domain: str
    current_focus: str  # What we're looking at right now
    
    # Discoveries
    hosts: dict[str, DiscoveredHost] = field(default_factory=dict)
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    
    # Context
    observations: list[str] = field(default_factory=list)
    strategy: Strategy = Strategy.INITIAL_RECON
    
    # Execution tracking
    tool_calls: list[dict] = field(default_factory=list)
    max_tool_calls: int = 30
    
    # Safety
    halt_requested: bool = False
    halt_reason: str | None = None
    
    def add_observation(self, text: str) -> None:
        """Add an observation to the context."""
        self.observations.append(text)
        # Keep last 20 observations to avoid context overflow
        if len(self.observations) > 20:
            self.observations = self.observations[-20:]
    
    def to_context(self) -> str:
        """Format state as context for the LLM."""
        lines = [
            f"Target: {self.root_domain}",
            f"Current Focus: {self.current_focus}",
            f"Strategy: {self.strategy.value}",
            f"Hosts Discovered: {len(self.hosts)}",
            f"Endpoints Found: {len(self.endpoints)}",
            f"Security Findings: {len(self.findings)}",
            f"Tool Calls Made: {len(self.tool_calls)} / {self.max_tool_calls}",
            "",
            "Recent Observations:",
        ]
        for obs in self.observations[-10:]:
            lines.append(f"  - {obs[:200]}..." if len(obs) > 200 else f"  - {obs}")
        
        # Highlight interesting hosts
        interesting = [h for h in self.hosts.values() if h.interesting]
        if interesting:
            lines.extend(["", "Interesting Hosts:"])
            for h in interesting[:5]:
                tech = f" [{', '.join(h.tech[:3])}]" if h.tech else ""
                lines.append(f"  - {h.hostname}{tech}")
        
        # Highlight findings
        if self.findings:
            lines.extend(["", "Key Findings:"])
            for f in self.findings[:5]:
                lines.append(f"  - [{f.severity}] {f.name} on {f.host}")
        
        return "\n".join(lines)


# ============================================================================
# The Agent
# ============================================================================

class SecurityAgent:
    """
    AI-driven security testing agent.
    
    The agent investigates a target by making intelligent decisions about:
    - Which tools to run
    - What parameters to use
    - When to dig deeper vs move on
    - When to stop
    """
    
    def __init__(
        self,
        tool_registry: ToolRegistry | None = None,
        console: Console | None = None,
        max_iterations: int = 30,
        llm_client = None,
    ):
        self.tools = tool_registry or ToolRegistry()
        self.console = console or Console()
        self.max_iterations = max_iterations
        
        # Initialize LLM client
        if llm_client:
            self.llm = llm_client
        else:
            config = BBAIConfig.load_with_env()
            self.llm = create_llm_client(config.llm)
    
    async def investigate(self, target: str) -> AgentState:
        """
        Run a full security investigation.
        
        This is the main entry point. The agent will:
        1. Start with initial reconnaissance
        2. Adapt strategy based on findings
        3. Continue until done or max iterations
        4. Return final state with all findings
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn
        from rich.live import Live
        from rich.panel import Panel
        from rich.table import Table
        
        state = AgentState(
            root_domain=target,
            current_focus=target
        )
        
        self.console.print(f"\n[bold cyan]>> Starting investigation of {target}[/]")
        self.console.print(f"[dim]Press Ctrl+C to stop gracefully\n")
        
        # Create progress display
        def make_progress_table() -> Table:
            table = Table(show_header=False, box=None)
            table.add_column("Metric", style="cyan")
            table.add_column("Value")
            
            # Progress bar
            progress_pct = min(100, int(len(state.tool_calls) / self.max_iterations * 100))
            bar = "#" * (progress_pct // 5) + "-" * (20 - progress_pct // 5)
            table.add_row("Progress", f"{bar} {progress_pct}%")
            table.add_row("Strategy", f"[yellow]{state.strategy.value}[/]")
            table.add_row("Hosts", str(len(state.hosts)))
            table.add_row("Endpoints", str(len(state.endpoints)))
            
            # Findings by severity
            if state.findings:
                critical = len([f for f in state.findings if f.severity == "critical"])
                high = len([f for f in state.findings if f.severity == "high"])
                medium = len([f for f in state.findings if f.severity == "medium"])
                findings_str = f"[red]{critical} critical[/], [orange3]{high} high[/], [yellow]{medium} medium[/]"
            else:
                findings_str = "0"
            table.add_row("Findings", findings_str)
            
            return table
        
        iteration = 0
        with Live(make_progress_table(), refresh_per_second=2, console=self.console) as live:
            while iteration < self.max_iterations and not state.halt_requested:
                iteration += 1
                
                # 1. THINK: What should we do next?
                try:
                    decision = await self._think(state)
                except Exception as e:
                    self.console.print(f"\n[yellow]! AI decision failed: {e}[/]")
                    self.console.print("[dim]Retrying with simplified prompt...[/]")
                    continue
                
                # 2. ACT: Execute the decision
                if decision.action == ActionType.HALT:
                    state.halt_requested = True
                    state.halt_reason = decision.halt_reason
                    break
                
                elif decision.action == ActionType.REPORT_FINDINGS:
                    break
                
                elif decision.action == ActionType.RUN_TOOL and decision.tool_decision:
                    # Show what we're doing
                    tool_name = decision.tool_decision.tool_name
                    live.stop()
                    self.console.print(f"[dim]->[/] [blue]{tool_name}[/] - {decision.reasoning[:60]}...")
                    live.start()
                    
                    await self._execute_tool(state, decision.tool_decision)
                
                # Update strategy if changed
                if decision.new_strategy and decision.new_strategy != state.strategy:
                    state.strategy = decision.new_strategy
                
                # Update display
                live.update(make_progress_table())
        
        # Final summary
        self.console.print()
        if state.halt_requested:
            self.console.print(f"[yellow]STOP Investigation halted:[/] {state.halt_reason}")
        elif iteration >= self.max_iterations:
            self.console.print(f"[yellow]! Reached max iterations ({self.max_iterations})[/]")
        else:
            self.console.print("[green]OK Investigation complete[/]")
        
        return state
    
    async def _think(self, state: AgentState) -> AgentDecision:
        """
        Ask the AI what to do next.
        
        This is the core decision-making. We give the AI:
        - Current context (what we know)
        - Available tools
        - Current strategy
        
        And it decides the next action.
        """
        # Build the prompt
        tools_description = self._format_tools()
        
        prompt = f"""You are an expert security researcher conducting a bug bounty investigation.

## Current Investigation State
{state.to_context()}

## Available Tools
{tools_description}

## Your Task
Based on the current state, decide what to do next.

Think step by step:
1. What do we know so far? What's most interesting?
2. What information are we missing?
3. Which tool would give us the most value right now?
4. Should we change our strategy?

## Strategy Guidelines
- **initial_recon**: Broad discovery - find subdomains, check what's alive
- **deep_dive**: Focus on interesting targets - crawl, look for specific vulns
- **confirm_finding**: Verify a potential vulnerability with targeted scans
- **attack_surface_mapping**: Systematically map all entry points
- **report**: Done investigating, ready to generate final report

## Decision Rules
- Switch to **deep_dive** when you find interesting tech (GraphQL, admin panels, APIs)
- Use **confirm_finding** when nuclei finds something you want to verify
- Choose **report** when you have good findings or exhausted interesting paths
- Choose **halt** only for scope violations or safety issues

## Response Format
Respond with a JSON object:
```json
{{
  "reasoning": "Your step-by-step thought process",
  "action": "run_tool" | "report_findings" | "halt",
  "tool_decision": {{
    "tool_name": "name of tool to run",
    "params": {{ /* tool-specific parameters */ }}
  }},
  "new_strategy": "initial_recon" | "deep_dive" | "confirm_finding" | "attack_surface_mapping" | "report" | null,
  "halt_reason": "reason if halting" | null
}}
```

Make your decision now:"""

        # Get structured decision from LLM
        try:
            response = await self.llm.complete(
                prompt=prompt,
                system_prompt="You are an expert security researcher. Respond with valid JSON only.",
                json_mode=True,
            )
            
            # Parse the JSON response
            data = json.loads(response.content)
            
            # Convert to AgentDecision
            tool_decision = None
            if data.get("tool_decision"):
                tool_decision = ToolDecision(**data["tool_decision"])
            
            return AgentDecision(
                reasoning=data.get("reasoning", ""),
                action=ActionType(data.get("action", "run_tool")),
                tool_decision=tool_decision,
                new_strategy=Strategy(data["new_strategy"]) if data.get("new_strategy") else None,
                halt_reason=data.get("halt_reason"),
            )
            
        except Exception as e:
            # Fallback: if LLM fails, try a simple recon
            self.console.print(f"[red]LLM error: {e}[/], falling back to safe default")
            return AgentDecision(
                reasoning="LLM error, using safe default",
                action=ActionType.RUN_TOOL,
                tool_decision=ToolDecision(
                    tool_name="subfinder",
                    params={"domain": state.root_domain}
                )
            )
    
    async def _execute_tool(self, state: AgentState, decision: ToolDecision) -> None:
        """Execute a tool and update state with results."""
        self.console.print(f"[blue]> Running {decision.tool_name}[/]")
        
        # Record the call
        state.tool_calls.append({
            "tool": decision.tool_name,
            "params": decision.params
        })
        
        try:
            # Execute the tool with timeout (5 minutes max per tool)
            result = await asyncio.wait_for(
                self.tools.execute(decision.tool_name, decision.params),
                timeout=300  # 5 minutes
            )
            
            # Process and update state
            await self._process_result(state, decision.tool_name, result)
            
        except asyncio.TimeoutError:
            error_msg = f"{decision.tool_name} timed out (5 min limit)"
            state.add_observation(error_msg)
            self.console.print(f"\n[yellow]⏱ {error_msg}[/]")
            self.console.print("[dim]   This usually means the target is very large or slow.[/]")
            self.console.print("[dim]   Try reducing scope or increasing the timeout.[/]")
            
        except Exception as e:
            error_str = str(e).lower()
            
            # Provide helpful error messages
            if "download" in error_str or "not found" in error_str:
                error_msg = f"{decision.tool_name} binary not available"
                help_text = f"Run: [cyan]bbai tools install {decision.tool_name}[/]"
            elif "connection" in error_str or "network" in error_str:
                error_msg = f"Network error running {decision.tool_name}"
                help_text = "Check your internet connection and try again."
            elif "permission" in error_str:
                error_msg = f"Permission denied running {decision.tool_name}"
                help_text = "Try running with appropriate permissions."
            else:
                error_msg = f"{decision.tool_name} failed: {str(e)[:50]}"
                help_text = "This might be temporary. The AI will try a different approach."
            
            state.add_observation(error_msg)
            self.console.print(f"\n[red]X {error_msg}[/]")
            self.console.print(f"[dim]   {help_text}[/]")
    
    async def _process_result(
        self, 
        state: AgentState, 
        tool_name: str, 
        result: Any
    ) -> None:
        """Process tool output and update agent state."""
        
        if tool_name == "subfinder" and isinstance(result, SubfinderOutput):
            # Add subdomains to hosts
            for sd in result.subdomains:
                if sd.subdomain not in state.hosts:
                    state.hosts[sd.subdomain] = DiscoveredHost(
                        hostname=sd.subdomain,
                        source="subfinder"
                    )
            
            observation = result.to_observation()
            state.add_observation(observation)
            self.console.print(f"[green]OK Found {result.total_found} subdomains[/]")
        
        elif tool_name == "httpx" and isinstance(result, HttpxOutput):
            # Update host status and tech
            for r in result.results:
                hostname = r.url.replace("https://", "").replace("http://", "").split("/")[0]
                
                if hostname in state.hosts:
                    state.hosts[hostname].status = "alive"
                    state.hosts[hostname].tech = r.tech
                    # Mark as interesting if has interesting tech
                    interesting_tech = ["graphql", "api", "wordpress", "admin", "jenkins"]
                    state.hosts[hostname].interesting = any(
                        t.lower() in [x.lower() for x in r.tech] or t.lower() in r.title.lower()
                        for t in interesting_tech
                    )
                else:
                    state.hosts[hostname] = DiscoveredHost(
                        hostname=hostname,
                        source="httpx",
                        status="alive",
                        tech=r.tech,
                        interesting=any(t.lower() in [x.lower() for x in r.tech] for t in ["graphql", "api"])
                    )
            
            observation = result.to_observation()
            state.add_observation(observation)
            self.console.print(f"[green]OK {result.alive_count} hosts alive[/]")
        
        elif tool_name == "katana" and isinstance(result, KatanaOutput):
            # Add endpoints
            for ep in result.endpoints:
                state.endpoints.append(DiscoveredEndpoint(
                    url=ep.url,
                    method=ep.method,
                    is_api=ep.is_api_endpoint,
                    parameters=ep.parameters
                ))
            
            observation = result.to_observation()
            state.add_observation(observation)
            self.console.print(f"[green]OK Crawled {result.total_discovered} endpoints[/]")
            
            # If we found API endpoints, update current focus
            if result.api_endpoints:
                state.current_focus = result.api_endpoints[0]
        
        elif tool_name == "nuclei" and isinstance(result, NucleiOutput):
            # Add findings
            for f in result.findings:
                state.findings.append(Finding(
                    name=f.name,
                    severity=f.severity,
                    host=f.host,
                    description=f.description,
                    confirmed=f.severity in ["critical", "high"]
                ))
            
            observation = result.to_observation()
            state.add_observation(observation)
            self.console.print(f"[green]OK Found {len(result.findings)} vulnerabilities[/]")
    
    def _format_tools(self) -> str:
        """Format tool schemas for the prompt."""
        schemas = self.tools.list_tools()
        lines = []
        for schema in schemas:
            lines.append(f"\n### {schema['name']}")
            lines.append(f"Description: {schema['description']}")
            lines.append(f"Parameters: {json.dumps(schema['parameters'], indent=2)}")
        return "\n".join(lines)


# ============================================================================
# Report Generation
# ============================================================================

def generate_report(state: AgentState) -> str:
    """Generate a markdown report from the final state."""
    lines = [
        f"# Security Assessment Report: {state.root_domain}",
        "",
        "## Summary",
        f"- **Hosts Discovered**: {len(state.hosts)}",
        f"- **Endpoints Mapped**: {len(state.endpoints)}",
        f"- **Security Findings**: {len(state.findings)}",
        f"- **Tool Executions**: {len(state.tool_calls)}",
        "",
        "## Findings",
    ]
    
    if not state.findings:
        lines.append("No security findings identified.")
    else:
        # Group by severity
        by_severity: dict[str, list[Finding]] = {}
        for f in state.findings:
            by_severity.setdefault(f.severity, []).append(f)
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                lines.append(f"\n### {sev.upper()} Severity")
                for f in by_severity[sev]:
                    lines.append(f"\n#### {f.name}")
                    lines.append(f"- **Host**: {f.host}")
                    lines.append(f"- **Description**: {f.description}")
                    if f.evidence:
                        lines.append(f"- **Evidence**: {f.evidence}")
    
    lines.extend([
        "",
        "## Attack Surface",
        "",
        "### Interesting Hosts",
    ])
    
    interesting = [h for h in state.hosts.values() if h.interesting]
    if interesting:
        for h in interesting:
            tech = f" ({', '.join(h.tech[:3])})" if h.tech else ""
            lines.append(f"- `{h.hostname}`{tech}")
    else:
        lines.append("No particularly interesting hosts identified.")
    
    lines.extend([
        "",
        "### API Endpoints",
    ])
    
    api_endpoints = [e for e in state.endpoints if e.is_api]
    if api_endpoints:
        for e in api_endpoints[:20]:
            lines.append(f"- {e.method} `{e.url}`")
    else:
        lines.append("No API endpoints discovered.")
    
    return "\n".join(lines)
