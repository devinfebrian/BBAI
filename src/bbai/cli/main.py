"""Main CLI entry point using Typer."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from bbai.cli.shell import start_shell
from bbai.core.config_models import BBAIConfig, ProgramConfig

# Create Typer app
app = typer.Typer(
    name="bbai",
    help="Bug Bounty AI Agent - Production-grade automation framework",
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode="rich",
)

# Shared console instance
console = Console()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print("[bold cyan]BBAI[/] version [green]0.1.0[/]")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            help="Show version information",
            callback=version_callback,
            is_eager=True,
        ),
    ] = False,
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to configuration file",
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
) -> None:
    """BBAI - Bug Bounty AI Agent.
    
    A production-grade, interactive bug bounty automation framework featuring
    a Kimi Code CLI-style interface with visible AI reasoning streams.
    """
    pass


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
    config = BBAIConfig()
    
    if project:
        config = config.model_copy(update={"projects_dir": Path(project)})
    
    start_shell(config=config, console=console)


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Target domain or URL to scan",
            prompt="Target domain/URL",
        ),
    ],
    program: Annotated[
        str,
        typer.Option(
            "--program",
            "-p",
            help="Bug bounty program name/config",
            prompt="Program name",
        ),
    ],
    passive_only: Annotated[
        bool,
        typer.Option(
            "--passive",
            help="Only use passive reconnaissance (no active scanning)",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output directory for results",
            file_okay=False,
            dir_okay=True,
        ),
    ] = None,
) -> None:
    """Run a security scan against a target.
    
    [cyan]Examples:[/]
        bbai scan --target example.com --program myprogram
        bbai scan -t example.com -p myprogram --passive
    """
    console.print(f"[bold]Target:[/] {target}")
    console.print(f"[bold]Program:[/] {program}")
    console.print(f"[bold]Passive only:[/] {passive_only}")
    
    if output:
        console.print(f"[bold]Output:[/] {output}")
    
    console.print("\n[yellow]Scan command not yet fully implemented.[/]")
    console.print("[dim]Use 'bbai shell' for interactive mode.[/]")


@app.command()
def init(
    name: Annotated[
        str,
        typer.Argument(help="Project name"),
    ],
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Initial target domain",
        ),
    ] = None,
    program_url: Annotated[
        str | None,
        typer.Option(
            "--program-url",
            "-u",
            help="Bug bounty program URL",
        ),
    ] = None,
) -> None:
    """Initialize a new bug bounty project.
    
    Creates a new project directory with default configuration.
    
    [cyan]Examples:[/]
        bbai init myproject
        bbai init myproject --target example.com --program-url https://hackerone.com/example
    """
    config = BBAIConfig()
    project_dir = config.projects_dir / name
    
    if project_dir.exists():
        console.print(f"[red]Error:[/] Project '{name}' already exists at {project_dir}")
        raise typer.Exit(1)
    
    # Create project directory
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create default config
    program_config = ProgramConfig(
        name=name,
        program_url=program_url,
        scope_in=[],
        scope_out=[],
    )
    
    # Write config file
    import yaml
    config_file = project_dir / "bbai.yaml"
    
    # Convert to dict for YAML serialization
    config_dict = program_config.model_dump(mode="json", exclude_none=True)
    
    with open(config_file, "w") as f:
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
    
    console.print(f"[green][OK][/] Created project: [bold]{name}[/]")
    console.print(f"  Location: {project_dir}")
    console.print(f"  Config: {config_file}")
    
    if target:
        console.print(f"\n[cyan]Next steps:[/]")
        console.print(f"  cd {project_dir}")
        console.print(f"  bbai shell")


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
    set_key: Annotated[
        str | None,
        typer.Option(
            "--set-key",
            "-k",
            help="Configuration key to set (use with --set-value)",
        ),
    ] = None,
    set_value: Annotated[
        str | None,
        typer.Option(
            "--set-value",
            "-v",
            help="Value to set (use with --set-key)",
        ),
    ] = None,
) -> None:
    """Manage BBAI configuration.
    
    [cyan]Examples:[/]
        bbai config --list
        bbai config --get theme
        bbai config --set-key theme --set-value light
    """
    bbai_config = BBAIConfig()
    
    if list_all:
        console.print("[bold cyan]BBAI Configuration[/]\n")
        config_dict = bbai_config.model_dump()
        for key, value in sorted(config_dict.items()):
            console.print(f"  [bold]{key}:[/] {value}")
        return
    
    if get:
        if hasattr(bbai_config, get):
            value = getattr(bbai_config, get)
            console.print(f"[bold]{get}:[/] {value}")
        else:
            console.print(f"[red]Unknown config key: {get}[/]")
        return
    
    if set_key and set_value:
        console.print(f"[yellow]Setting {set_key} = {set_value}[/]")
        console.print("[dim]Note: Persistent config storage not yet implemented.[/]")
        return
    
    if set_key or set_value:
        console.print("[red]Error: Both --set-key and --set-value are required together.[/]")
        raise typer.Exit(1)
    
    # Default: show help
    console.print("[dim]Use --list to see all configuration values.[/]")


if __name__ == "__main__":
    app()
