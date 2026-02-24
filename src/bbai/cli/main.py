"""Main CLI entry point using Typer."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from bbai.cli.setup_wizard import ensure_configured, run_setup_wizard
from bbai.cli.shell import start_shell
from bbai.cli.tools_commands import app as tools_app
from bbai.core.config_models import BBAIConfig
from bbai.core.safety_manager import create_safety_manager, SafetyManager, load_program_config

# Create Typer app
app = typer.Typer(
    name="bbai",
    help="Bug Bounty AI Agent - AI-driven security testing",
    no_args_is_help=False,
    add_completion=True,
    rich_markup_mode="rich",
    invoke_without_command=True,
)

# Shared console instance
console = Console()


def is_first_run() -> bool:
    """Check if this is the first time running BBAI."""
    config_file = Path.home() / ".bbai" / "config.json"
    return not config_file.exists()


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            help="Show version information",
            callback=lambda v: print("BBAI version 0.1.0") or exit(0) if v else None,
            is_eager=True,
        ),
    ] = False,
    skip_setup: Annotated[
        bool,
        typer.Option(
            "--skip-setup",
            help="Skip first-time setup check",
            is_eager=True,
        ),
    ] = False,
) -> None:
    """BBAI - Bug Bounty AI Agent.
    
    An AI-driven security testing framework that makes intelligent decisions
    about what to investigate and which tools to run.
    
    Run without arguments to start the shell (with first-time setup if needed).
    """
    # If a subcommand is being invoked, let it handle things
    if ctx.invoked_subcommand is not None:
        return
    
    # Check for first run
    if not skip_setup and is_first_run():
        from rich.panel import Panel
        console.print(Panel(
            "[bold cyan]Welcome to BBAI![/]\n\n"
            "It looks like this is your first time running BBAI.\n"
            "Let's get you set up with an AI provider.",
            border_style="blue",
            padding=(1, 2),
        ))
        console.print()
        
        # Run setup wizard
        run_setup_wizard()
        
        # After setup, ask if they want to start shell
        console.print()
        from rich.prompt import Confirm
        if Confirm.ask("Start BBAI shell now?", default=True):
            start_shell()
        return
    
    # Not first run - start shell directly
    start_shell()


@app.command()
def shell(
    project: Annotated[
        str | None,
        typer.Option(
            "--project",
            "-p",
            help="Project directory to work in",
        ),
    ] = None,
) -> None:
    """Start the interactive BBAI shell.
    
    [cyan]Examples:[/]
        bbai shell
        bbai shell --project mytarget
    """
    # Ensure configuration is set up
    config = ensure_configured()
    
    if project:
        config = config.model_copy(update={"projects_dir": Path(project)})
    
    start_shell(config=config, console=console)


@app.command()
def validate_scope(
    scope_file: Annotated[
        Path,
        typer.Argument(
            help="Path to scope YAML file to validate",
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ],
) -> None:
    """Validate a scope configuration file.
    
    Checks that the scope file is properly formatted and contains
    valid scope rules.
    
    [cyan]Examples:[/]
        bbai validate-scope ./myprogram.yaml
    """
    from rich.panel import Panel
    
    console.print(f"[bold]Validating scope file:[/] {scope_file}")
    
    safety = SafetyManager()
    is_valid, message = safety.validate_scope_file(scope_file)
    
    if is_valid:
        console.print(f"[green]OK[/] Scope file is valid")
        
        # Show scope summary
        try:
            config = load_program_config(scope_file)
            console.print(f"\n[bold]Program:[/] {config.name}")
            console.print(f"[bold]Platform:[/] {config.platform}")
            console.print(f"[bold]In-scope:[/] {len(config.scope_in)} rules")
            for rule in config.scope_in:
                console.print(f"  • {rule.pattern}")
            console.print(f"[bold]Out-of-scope:[/] {len(config.scope_out)} rules")
            for rule in config.scope_out:
                console.print(f"  • {rule.pattern}")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not display details: {e}[/]")
    else:
        console.print(f"[red]ERROR[/] Scope file is invalid")
        console.print(f"[red]Error: {message}[/]")
        raise typer.Exit(1)


@app.command()
def create_scope_template(
    output: Annotated[
        Path,
        typer.Argument(
            help="Output file path",
        ),
    ],
    name: Annotated[
        str,
        typer.Option(
            "--name",
            "-n",
            help="Program name",
        ),
    ] = "my-program",
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Target domain",
        ),
    ] = "example.com",
) -> None:
    """Create a sample scope configuration file.
    
    Generates a YAML template for scope configuration that can be
    used with the scan command.
    
    [cyan]Examples:[/]
        bbai create-scope-template ./hackerone.yaml --name "HackerOne" --target hackerone.com
    """
    import yaml
    
    template = {
        "name": name,
        "platform": "hackerone",
        "description": f"Bug bounty scope for {name}",
        "scope_in": [
            {"pattern": f"*.{target}", "description": "All subdomains"},
            {"pattern": target, "description": "Main domain"},
        ],
        "scope_out": [
            {"pattern": f"*.internal.{target}", "description": "Internal systems"},
            {"pattern": f"*.corp.{target}", "description": "Corporate network"},
        ],
        "timing": {
            "timezone": "UTC",
            "max_requests_per_second": 5.0,
        },
        "rate_limit": {
            "requests_per_second": 5.0,
            "burst_size": 10,
            "concurrent_tools": 3,
        },
        "auto_halt_on_critical": True,
        "block_private_ips": True,
    }
    
    with open(output, 'w') as f:
        yaml.dump(template, f, default_flow_style=False, sort_keys=False)
    
    console.print(f"[green]OK[/] Scope template created: {output}")
    console.print(f"\n[dim]Edit this file to customize your scope rules.[/]")
    console.print(f"[dim]Then run:[/] bbai scan --scope-file {output}")


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            help="Target domain to investigate (e.g., example.com)",
        ),
    ],
    iterations: Annotated[
        int,
        typer.Option(
            "--iterations",
            "-i",
            help="Maximum number of tool executions",
        ),
    ] = 20,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file for report",
        ),
    ] = None,
    scope_file: Annotated[
        Path | None,
        typer.Option(
            "--scope-file",
            "-S",
            help="Path to scope configuration YAML file",
        ),
    ] = None,
    preview: Annotated[
        bool,
        typer.Option(
            "--preview",
            help="Show investigation plan without running",
        ),
    ] = False,
) -> None:
    """Quick start - Run AI-driven security investigation.
    
    This is the simplest way to start investigating a target.
    The AI will automatically discover subdomains, check for live hosts,
    crawl websites, and scan for vulnerabilities.
    
    [bold]Examples:[/]
        bbai scan example.com                    # Basic scan
        bbai scan example.com -i 30              # Deeper investigation
        bbai scan example.com -o report.md       # Save report
        bbai scan example.com --preview          # Preview only
    """
    import asyncio
    from rich.panel import Panel
    
    # Ensure configured
    config = ensure_configured()
    
    # Validate target
    safety_manager = create_safety_manager(scope_file, config)
    is_valid, reason = safety_manager.validate_target(target)
    if not is_valid:
        console.print(f"[red]✗ Target validation failed:[/] {reason}")
        raise typer.Exit(1)
    
    # Show preview if requested
    if preview:
        console.print(Panel(
            f"[bold cyan]📋 Investigation Plan: {target}[/]\n\n"
            f"The AI will perform approximately [bold]{iterations}[/] tool executions:\n\n"
            f"[dim]Phase 1:[/] Reconnaissance\n"
            f"  • subfinder - Find subdomains\n"
            f"  • httpx - Check which hosts are alive\n\n"
            f"[dim]Phase 2:[/] Discovery\n"
            f"  • katana - Crawl discovered hosts\n"
            f"  • nuclei - Run vulnerability scans\n\n"
            f"[dim]Phase 3:[/] Analysis\n"
            f"  • AI analysis of findings\n"
            f"  • Report generation\n\n"
            f"Estimated time: [bold]10-20 minutes[/]\n"
            f"Estimated cost: [bold]~$0.05[/] (depends on LLM provider)",
            border_style="blue"
        ))
        return
    
    # Run investigation
    console.print(Panel(
        f"[bold cyan]🔍 Starting Investigation[/]\n\n"
        f"Target: [bold]{target}[/]\n"
        f"Max iterations: {iterations}\n"
        f"LLM: {config.llm.provider} ({config.llm.model})",
        border_style="blue"
    ))
    
    from bbai.agent import SecurityAgent, generate_report
    
    async def run():
        agent = SecurityAgent(
            console=console,
            max_iterations=iterations
        )
        return await agent.investigate(target)
    
    try:
        state = asyncio.run(run())
        
        # Generate and display report
        report = generate_report(state)
        
        # Save if requested
        if output:
            output.write_text(report)
            console.print(f"\n[green]✓ Report saved:[/] {output}")
        else:
            console.print("\n" + report)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Investigation interrupted[/]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[red]✗ Investigation failed:[/] {e}")
        raise typer.Exit(1)


@app.command()
def setup(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force reconfiguration even if already configured",
        ),
    ] = False,
) -> None:
    """Run the interactive setup wizard to configure BBAI.
    
    Guides you through selecting an LLM provider, model, and API key.
    Configuration is saved to ~/.bbai/config.json
    
    [cyan]Examples:[/]
        bbai setup           # First-time setup
        bbai setup --force   # Reconfigure existing setup
    """
    run_setup_wizard(force=force)


@app.command()
def config(
    list_all: Annotated[
        bool,
        typer.Option(
            "--list",
            "-l",
            help="List all configuration values",
        ),
    ] = False,
    get: Annotated[
        str | None,
        typer.Option(
            "--get",
            "-g",
            help="Get a specific configuration value",
        ),
    ] = None,
) -> None:
    """Manage BBAI configuration.
    
    [cyan]Examples:[/]
        bbai config --list
        bbai config --get llm.provider
    """
    bbai_config = BBAIConfig.load_with_env()
    
    if list_all:
        console.print("[bold cyan]BBAI Configuration[/]\n")
        
        # LLM Settings
        console.print("[bold green]LLM Settings:[/]")
        console.print(f"  Provider: [cyan]{bbai_config.llm.provider}[/]")
        console.print(f"  Model: [cyan]{bbai_config.llm.model}[/]")
        
        # Check API key status
        from bbai.llm.factory import get_available_providers
        providers = get_available_providers()
        provider_info = next(
            (p for p in providers if p['id'] == bbai_config.llm.provider),
            None
        )
        
        if provider_info and provider_info.get('requires_api_key'):
            env_var = provider_info.get('env_var', '')
            env_key = os.environ.get(env_var) if env_var else None
            config_key = bbai_config.llm.api_key
            
            if env_key:
                masked = env_key[:8] + "..." if len(env_key) > 10 else "***"
                console.print(f"  API Key: [green]OK[/] [dim]{masked}[/] [green](from {env_var})[/]")
            elif config_key:
                masked = config_key[:8] + "..." if len(config_key) > 10 else "***"
                console.print(f"  API Key: [green]OK[/] [dim]{masked}[/] [green](from config)[/]")
            else:
                console.print(f"  API Key: [yellow]! Not configured[/]")
                console.print(f"  [dim]Run 'bbai shell' then '/login' to configure[/]")
        else:
            console.print(f"  API Key: [dim]Not required[/]")
        
        if bbai_config.llm.base_url:
            console.print(f"  Base URL: [cyan]{bbai_config.llm.base_url}[/]")
        console.print(f"  Temperature: [cyan]{bbai_config.llm.temperature}[/]")
        console.print(f"  Max Tokens: [cyan]{bbai_config.llm.max_tokens}[/]")
        console.print()
        
        # Paths
        console.print("[bold green]Paths:[/]")
        console.print(f"  Data Dir: [cyan]{bbai_config.data_dir}[/]")
        console.print(f"  Projects Dir: [cyan]{bbai_config.projects_dir}[/]")
        console.print(f"  Logs Dir: [cyan]{bbai_config.logs_dir}[/]")
        console.print(f"  Config File: [cyan]{bbai_config.config_file}[/]")
        console.print()
        
        # UI Settings
        console.print("[bold green]UI Settings:[/]")
        console.print(f"  Theme: [cyan]{bbai_config.theme}[/]")
        console.print(f"  Thought Stream: [cyan]{bbai_config.show_thought_stream}[/]")
        return
    
    if get:
        # Handle nested keys like llm.provider
        if "." in get:
            parts = get.split(".")
            value = bbai_config
            for part in parts:
                if hasattr(value, part):
                    value = getattr(value, part)
                else:
                    console.print(f"[red]Unknown config key: {get}[/]")
                    return
            console.print(f"[bold]{get}:[/] {value}")
        elif hasattr(bbai_config, get):
            value = getattr(bbai_config, get)
            console.print(f"[bold]{get}:[/] {value}")
        else:
            console.print(f"[red]Unknown config key: {get}[/]")
        return
    
    # Default: show help
    console.print("[dim]Use --list to see all configuration values.[/]")
    console.print("[dim]Use [cyan]bbai setup[/] to reconfigure LLM settings.[/]")


@app.command()
def doctor(
    fix: Annotated[
        bool,
        typer.Option(
            "--fix",
            help="Attempt to fix issues automatically",
        ),
    ] = False,
) -> None:
    """Check BBAI installation and configuration.
    
    Diagnoses common issues and suggests fixes.
    
    [cyan]Examples:[/]
        bbai doctor              # Check status
        bbai doctor --fix        # Try to fix issues
    """
    from rich.table import Table
    import os
    
    console.print("[bold cyan]BBAI Health Check[/]\n")
    
    issues = []
    checks = []
    
    # Check 1: Configuration exists
    config_file = Path.home() / ".bbai" / "config.json"
    if config_file.exists():
        checks.append(("Configuration", "OK", "green"))
    else:
        checks.append(("Configuration", "Missing", "red"))
        issues.append("Run 'bbai setup' to configure")
    
    # Check 2: LLM API key
    config = BBAIConfig.load_with_env()
    api_key = config.llm.api_key or os.getenv("MOONSHOT_API_KEY") or os.getenv("OPENAI_API_KEY")
    if api_key:
        checks.append(("API Key", "Set", "green"))
    else:
        checks.append(("API Key", "Missing", "red"))
        issues.append("Set your LLM API key or run 'bbai setup'")
    
    # Check 3: Tools directory
    tools_dir = Path.home() / ".bbai" / "tools"
    if tools_dir.exists():
        checks.append(("Tools Directory", "OK", "green"))
    else:
        checks.append(("Tools Directory", "Not created", "yellow"))
        if fix:
            tools_dir.mkdir(parents=True, exist_ok=True)
            console.print("[green]  Created tools directory[/]")
    
    # Check 4: Binary tools
    binaries = ["subfinder.exe", "httpx.exe", "katana.exe", "nuclei.exe"]
    found = sum(1 for b in binaries if (tools_dir / b).exists())
    if found == len(binaries):
        checks.append(("Binary Tools", f"All {len(binaries)} present", "green"))
    else:
        checks.append(("Binary Tools", f"{found}/{len(binaries)} present", "yellow"))
        if fix:
            console.print("\n[yellow]Downloading missing tools...[/]")
            # Tools will auto-download on first use
    
    # Check 5: Internet connectivity
    import urllib.request
    try:
        urllib.request.urlopen("https://github.com", timeout=5)
        checks.append(("Internet", "Connected", "green"))
    except:
        checks.append(("Internet", "No connection", "red"))
        issues.append("Internet connection required for tool downloads")
    
    # Display results
    table = Table(show_header=False)
    table.add_column("Check")
    table.add_column("Status")
    
    for check, status, color in checks:
        table.add_row(check, f"[{color}]{status}[/{color}]")
    
    console.print(table)
    
    # Summary
    console.print()
    if not issues:
        console.print("[bold green]All checks passed! BBAI is ready to use.[/]")
        console.print("\n[dim]Try: bbai scan example.com[/]")
    else:
        console.print(f"[bold yellow]Found {len(issues)} issue(s):[/]")
        for issue in issues:
            console.print(f"  - {issue}")
        
        if not fix:
            console.print("\n[dim]Run 'bbai doctor --fix' to attempt automatic fixes[/]")


# Add tools subcommand
app.add_typer(tools_app, name="tools", help="Manage security tools")

# Add agent subcommand
from bbai.cli.agent_commands import app as agent_app
app.add_typer(agent_app, name="agent", help="AI-driven security testing")

if __name__ == "__main__":
    app()
