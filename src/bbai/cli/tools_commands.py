"""Tool management commands for BBAI.

Provides commands to install, update, and manage security tools.
"""

from __future__ import annotations

import asyncio
import platform
import subprocess
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bbai.tools.wrappers import get_tool_registry

console = Console()
app = typer.Typer(help="Manage security tools")


def get_package_manager() -> str | None:
    """Detect available package manager on Windows."""
    system = platform.system().lower()
    
    if system == "windows":
        # Check for winget (Windows 10/11)
        try:
            subprocess.run(["winget", "--version"], capture_output=True, check=True)
            return "winget"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        # Check for choco
        try:
            subprocess.run(["choco", "--version"], capture_output=True, check=True)
            return "choco"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        # Check for scoop
        try:
            subprocess.run(["scoop", "--version"], capture_output=True, check=True)
            return "scoop"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    elif system == "darwin":
        # macOS - check for brew
        try:
            subprocess.run(["brew", "--version"], capture_output=True, check=True)
            return "brew"
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    elif system == "linux":
        # Linux - check for common package managers
        for pm in ["apt", "apt-get", "yum", "dnf", "pacman", "zypper"]:
            try:
                subprocess.run([pm, "--version"], capture_output=True, check=True)
                return pm
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
    
    return None


def get_install_command(tool: str, pm: str) -> list[str] | None:
    """Get installation command for a tool via package manager.
    
    Args:
        tool: Tool name (nuclei, subfinder, httpx, katana)
        pm: Package manager name
        
    Returns:
        Command list or None if not available
    """
    commands = {
        "winget": {
            "nuclei": ["winget", "install", "ProjectDiscovery.Nuclei", "--silent"],
            "subfinder": ["winget", "install", "ProjectDiscovery.Subfinder", "--silent"],
            "httpx": ["winget", "install", "ProjectDiscovery.Httpx", "--silent"],
            "katana": ["winget", "install", "ProjectDiscovery.Katana", "--silent"],
        },
        "choco": {
            "nuclei": ["choco", "install", "nuclei", "-y"],
        },
        "brew": {
            "nuclei": ["brew", "install", "nuclei"],
            "subfinder": ["brew", "install", "subfinder"],
            "httpx": ["brew", "install", "httpx"],
            "katana": ["brew", "install", "katana"],
        },
    }
    
    if pm in commands and tool in commands[pm]:
        return commands[pm][tool]
    return None


@app.command()
def status():
    """Check status of all security tools."""
    console.print(Panel("[bold cyan]Security Tool Status[/]", border_style="blue"))
    
    registry = get_tool_registry()
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Tool")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Location")
    
    for category, tools in sorted(registry._tools.items()):
        for tool in tools:
            name = tool.name
            
            # Check if binary tool (has binary_path attribute)
            if hasattr(tool, 'binary_path'):
                # It's a BinaryToolWrapper
                try:
                    available = asyncio.run(tool.is_available())
                    if available:
                        status = "[green]Available[/]"
                        # Get effective path
                        path = str(tool.effective_binary_path)
                        # Truncate if too long
                        if len(path) > 40:
                            path = "..." + path[-37:]
                    else:
                        status = "[red]Not Installed[/]"
                        path = "-"
                except Exception as e:
                    status = f"[yellow]Error: {e}[/]"
                    path = "-"
            else:
                # It's a PythonToolWrapper
                status = "[green]Built-in[/]"
                path = "Python"
            
            table.add_row(name, category, status, path)
    
    console.print(table)
    
    # Show package manager
    pm = get_package_manager()
    if pm:
        console.print(f"\n[dim]Package manager detected: {pm}[/]")
        console.print("[dim]Run 'bbai tools install --all' to install missing tools[/]")
    else:
        console.print("\n[yellow]No package manager detected.[/]")
        console.print("[dim]Install tools manually or use Docker mode[/]")


@app.command()
def install(
    tool: Annotated[str, typer.Argument(help="Tool to install (or 'all')")] = "all",
    force: Annotated[bool, typer.Option("--force", help="Force reinstall")] = False,
):
    """Install security tools via package manager.
    
    Examples:
        bbai tools install nuclei
        bbai tools install --all
    """
    pm = get_package_manager()
    
    if not pm:
        console.print("[red]No supported package manager found.[/]")
        console.print("\nPlease install tools manually:")
        console.print("  Windows: winget install ProjectDiscovery.Nuclei")
        console.print("  macOS: brew install nuclei")
        console.print("  Linux: See https://docs.projectdiscovery.io/tools/nuclei/install")
        raise typer.Exit(1)
    
    console.print(Panel(
        f"[bold cyan]Installing Tools[/]\n"
        f"Package manager: [green]{pm}[/]",
        border_style="blue"
    ))
    
    tools_to_install = ["nuclei", "subfinder", "httpx", "katana"] if tool == "all" else [tool]
    
    installed = []
    failed = []
    skipped = []
    
    for t in tools_to_install:
        cmd = get_install_command(t, pm)
        
        if not cmd:
            console.print(f"[yellow]⚠ {t}: Not available via {pm}[/]")
            failed.append(t)
            continue
        
        # Check if already installed
        if not force:
            try:
                result = subprocess.run([t, "--version"], capture_output=True)
                if result.returncode == 0:
                    console.print(f"[green]✓ {t}: Already installed[/]")
                    skipped.append(t)
                    continue
            except FileNotFoundError:
                pass
        
        # Install
        console.print(f"[cyan]→ Installing {t}...[/]")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                console.print(f"[green]✓ {t}: Installed successfully[/]")
                installed.append(t)
            else:
                console.print(f"[red]✗ {t}: Installation failed[/]")
                if result.stderr:
                    console.print(f"[dim]{result.stderr[:200]}[/]")
                failed.append(t)
        except Exception as e:
            console.print(f"[red]✗ {t}: {e}[/]")
            failed.append(t)
    
    # Summary
    console.print("\n" + "=" * 50)
    console.print(f"[bold]Summary:[/]")
    console.print(f"  Installed: {len(installed)}")
    console.print(f"  Skipped: {len(skipped)}")
    console.print(f"  Failed: {len(failed)}")
    
    if failed:
        console.print("\n[yellow]Failed installations may require manual setup.[/]")
        console.print("Visit: https://docs.projectdiscovery.io/")


@app.command()
def update(
    tool: Annotated[str, typer.Argument(help="Tool to update (or 'all')")] = "all",
):
    """Update security tools to latest versions."""
    pm = get_package_manager()
    
    if not pm:
        console.print("[red]No supported package manager found.[/]")
        raise typer.Exit(1)
    
    tools_to_update = ["nuclei", "subfinder", "httpx", "katana"] if tool == "all" else [tool]
    
    console.print(Panel(
        f"[bold cyan]Updating Tools[/]\n"
        f"Package manager: [green]{pm}[/]",
        border_style="blue"
    ))
    
    for t in tools_to_update:
        console.print(f"[cyan]→ Updating {t}...[/]")
        
        if pm == "winget":
            cmd = ["winget", "upgrade", f"ProjectDiscovery.{t.title()}", "--silent"]
        elif pm == "brew":
            cmd = ["brew", "upgrade", t]
        elif pm in ["choco"]:
            cmd = [pm, "upgrade", t, "-y"]
        else:
            console.print(f"[yellow]⚠ {t}: Update not supported for {pm}[/]")
            continue
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                console.print(f"[green]✓ {t}: Updated[/]")
            elif "No applicable update found" in result.stdout or "already installed" in result.stdout.lower():
                console.print(f"[dim]{t}: Already up to date[/]")
            else:
                console.print(f"[yellow]⚠ {t}: Update result unclear[/]")
        except Exception as e:
            console.print(f"[red]✗ {t}: {e}[/]")


@app.command()
def uninstall(
    tool: Annotated[str, typer.Argument(help="Tool to uninstall")],
):
    """Uninstall a security tool."""
    pm = get_package_manager()
    
    if not pm:
        console.print("[red]No supported package manager found.[/]")
        raise typer.Exit(1)
    
    console.print(f"[yellow]Uninstalling {tool}...[/]")
    
    if pm == "winget":
        cmd = ["winget", "uninstall", f"ProjectDiscovery.{tool.title()}", "--silent"]
    elif pm == "brew":
        cmd = ["brew", "uninstall", tool]
    elif pm in ["choco"]:
        cmd = [pm, "uninstall", tool, "-y"]
    else:
        console.print(f"[red]Uninstall not supported for {pm}[/]")
        raise typer.Exit(1)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"[green]✓ {tool}: Uninstalled[/]")
        else:
            console.print(f"[red]✗ {tool}: Uninstall failed[/]")
    except Exception as e:
        console.print(f"[red]✗ {tool}: {e}[/]")
