"""CLI commands for the AI-driven agent."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from bbai.agent import SecurityAgent, generate_report
from bbai.cli.setup_wizard import ensure_configured
from bbai.core.safety_manager import create_safety_manager

# Create Typer app for agent commands
app = typer.Typer(
    name="agent",
    help="AI-driven security testing agent",
)

console = Console()


@app.command()
def investigate(
    target: Annotated[
        str,
        typer.Argument(help="Target domain to investigate")
    ],
    max_iterations: Annotated[
        int,
        typer.Option(
            "--max-iterations",
            "-i",
            help="Maximum number of tool executions",
        )
    ] = 20,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file for report (markdown)",
        )
    ] = None,
    scope_file: Annotated[
        Path | None,
        typer.Option(
            "--scope-file",
            "-S",
            help="Path to scope configuration YAML",
        )
    ] = None,
):
    """
    Run AI-driven security investigation.
    
    The AI agent will:
    1. Analyze the target and decide what to investigate
    2. Run appropriate security tools based on findings
    3. Adapt strategy as it discovers more
    4. Generate a comprehensive report
    
    Examples:
        bbai agent investigate example.com
        bbai agent investigate api.example.com --max-iterations 30
        bbai agent investigate example.com -o report.md
    """
    # Ensure BBAI is configured
    config = ensure_configured()
    
    # Create safety manager
    safety_manager = create_safety_manager(scope_file, config)
    
    # Validate target scope
    console.print(Panel(
        f"[bold cyan]AI Security Investigation[/]\n\n"
        f"Target: {target}\n"
        f"Max Iterations: {max_iterations}\n"
        f"LLM: {config.llm.provider} ({config.llm.model})",
        border_style="blue"
    ))
    
    # Validate target is in scope
    is_valid, reason = safety_manager.validate_target(target)
    if not is_valid:
        console.print(f"[red]✗ Target validation failed: {reason}[/]")
        raise typer.Exit(1)
    
    console.print(f"[green]✓ Target validation passed[/]\n")
    
    # Run the agent
    async def run_investigation():
        agent = SecurityAgent(
            console=console,
            max_iterations=max_iterations
        )
        
        try:
            state = await agent.investigate(target)
            return state
        except Exception as e:
            console.print(f"[red]Investigation failed: {e}[/]")
            raise
    
    try:
        state = asyncio.run(run_investigation())
        
        # Generate report
        report = generate_report(state)
        
        # Display summary
        console.print("\n" + "=" * 60)
        console.print("[bold green]Investigation Complete[/]")
        console.print("=" * 60)
        console.print(f"\n[bold]Summary:[/]")
        console.print(f"  Hosts discovered: {len(state.hosts)}")
        console.print(f"  Endpoints mapped: {len(state.endpoints)}")
        console.print(f"  Security findings: {len(state.findings)}")
        console.print(f"  Tool executions: {len(state.tool_calls)}")
        
        if state.findings:
            console.print(f"\n[bold]Key Findings:[/]")
            for f in state.findings[:5]:
                sev_color = {
                    "critical": "red",
                    "high": "orange3",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "dim"
                }.get(f.severity, "white")
                console.print(f"  [{sev_color}]{f.severity.upper()}[/{sev_color}]: {f.name} on {f.host}")
        
        # Save or display report
        if output:
            output.write_text(report)
            console.print(f"\n[green]✓ Report saved to:[/] {output}")
        else:
            console.print("\n[bold]Report:[/]")
            console.print(report)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Investigation interrupted by user.[/]")
        raise typer.Exit(1)


@app.command()
def demo(
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show what the agent would do without running tools",
        )
    ] = False,
):
    """
    Demo the agent's decision-making process.
    
    Shows how the AI would think through an investigation
    without actually executing tools (unless --dry-run is False).
    """
    console.print(Panel(
        "[bold cyan]AI Agent Demo[/]\n\n"
        "This demonstrates how the AI makes decisions.",
        border_style="blue"
    ))
    
    console.print("""
The AI agent follows this loop:

1. [bold]THINK[/]: Analyze what we know, decide next action
   Example: "Found api.example.com with GraphQL. Should run nuclei 
   with graphql templates to check for introspection."

2. [bold]ACT[/]: Execute the chosen tool
   Example: Run nuclei(targets=["api.example.com"], templates=["graphql"])

3. [bold]OBSERVE[/]: Process results, update knowledge
   Example: "Found GraphQL introspection enabled. This is a HIGH severity 
   finding. Should continue investigating or report."

4. [bold]REPEAT[/]: Continue until findings are complete

Key advantages:
• Adapts strategy based on discoveries
• Chooses specific tool parameters for the target
• Can dig deep on interesting findings
• Knows when to stop
""")
    
    if not dry_run:
        console.print("\n[cyan]Run 'bbai agent investigate example.com' to see it in action.[/]")
