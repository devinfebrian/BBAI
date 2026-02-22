"""Interactive BBAI Shell with Rich UI.

Implements a Kimi Code CLI-style interface with:
- Rich panels and styling
- Prompt toolkit for auto-completion
- Command history
- Session management
"""

from __future__ import annotations

import uuid
from typing import Callable

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style as PTStyle
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from bbai.core.config_models import BBAIConfig


class BBAIShell:
    """Interactive BBAI Shell.
    
    Design target: Kimi Code CLI aesthetic with REPL.
    
    Features:
    - Rich UI with panels and styled output
    - Auto-completion for commands
    - Command history persistence
    - Session management
    """

    # Shell commands
    COMMANDS = [
        "/help",
        "/exit",
        "/quit",
        "/status",
        "/web",
        "/clear",
        "/history",
        "scan",
        "recon",
        "analyze",
        "report",
        "config",
    ]

    # Prompt toolkit style
    PT_STYLE = PTStyle.from_dict({
        "prompt": "ansicyan bold",
        "prompt.path": "ansiyellow",
    })

    def __init__(
        self,
        config: BBAIConfig | None = None,
        console: Console | None = None,
    ):
        self.config = config or BBAIConfig()
        self.console = console or Console()
        
        # Session info
        self.session_id = str(uuid.uuid4())[:8]
        self.project_dir = self.config.projects_dir
        self.running = False
        
        # Command registry
        self._commands: dict[str, Callable] = {}
        self._register_default_commands()
        
        # Prompt toolkit setup
        history_file = self.config.data_dir / ".shell_history"
        self._completer = WordCompleter(self.COMMANDS, ignore_case=True)
        self._session = PromptSession(
            history=FileHistory(str(history_file)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=self._completer,
            style=self.PT_STYLE,
            key_bindings=self._create_key_bindings(),
        )

    def _register_default_commands(self) -> None:
        """Register default shell commands."""
        self._commands = {
            "/help": self.cmd_help,
            "/exit": self.cmd_exit,
            "/quit": self.cmd_exit,
            "/status": self.cmd_status,
            "/clear": self.cmd_clear,
            "/web": self.cmd_web,
            "/history": self.cmd_history,
        }

    def _create_key_bindings(self) -> KeyBindings:
        """Create custom key bindings."""
        bindings = KeyBindings()
        
        @bindings.add("c-c")
        def _(event):
            """Ctrl+C - Cancel current input."""
            event.app.current_buffer.reset()
        
        @bindings.add("c-d")
        def _(event):
            """Ctrl+D - Exit shell."""
            event.app.exit()
        
        return bindings

    def print_banner(self) -> None:
        """Print welcome banner."""
        banner_text = Text()
        banner_text.append("🎯 Welcome to BBAI Shell v0.1.0!\n", style="bold cyan")
        banner_text.append("Send /help for help information.\n", style="dim")
        banner_text.append(f"Directory: {self.project_dir}\n", style="dim")
        banner_text.append(f"Session: {self.session_id}\n", style="dim")
        banner_text.append("Model: kimi-k2-5 (connected)", style="dim")
        
        panel = Panel(
            banner_text,
            border_style="blue",
            padding=(1, 2),
        )
        self.console.print(panel)
        
        # Web UI hint
        self.console.print(
            f"[dim]Tip: BBAI Web UI available. Type[/] [yellow]/web[/yellow] [dim]to switch.[/]\n"
        )

    def get_prompt_text(self) -> list[tuple[str, str]]:
        """Get styled prompt text for prompt_toolkit."""
        return [
            ("class:prompt", "💀 "),
            ("class:prompt", "bbai "),
            ("class:prompt.path", "> "),
        ]

    def run(self) -> None:
        """Run the interactive shell."""
        self.running = True
        self.print_banner()
        
        while self.running:
            try:
                # Get user input
                user_input = self._session.prompt(self.get_prompt_text()).strip()
                
                if not user_input:
                    continue
                
                # Process command
                self._process_input(user_input)
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use /exit to quit.[/]")
            except EOFError:
                self.running = False
                self.console.print("\n[dim]Goodbye! 👋[/]")

    def _process_input(self, user_input: str) -> None:
        """Process user input."""
        parts = user_input.split()
        command = parts[0].lower()
        args = parts[1:]
        
        # Handle slash commands
        if command.startswith("/"):
            handler = self._commands.get(command)
            if handler:
                handler(args)
            else:
                self.console.print(f"[red]Unknown command: {command}[/]")
                self.console.print("[dim]Type /help for available commands.[/]")
            return
        
        # Handle action commands (scan, recon, etc.)
        if command in ("scan", "recon", "analyze", "report", "config"):
            self._handle_action(command, args)
            return
        
        # Unknown input
        self.console.print(f"[red]Unknown command: {command}[/]")
        self.console.print("[dim]Type /help for available commands.[/]")

    def _handle_action(self, action: str, args: list[str]) -> None:
        """Handle action commands."""
        self.console.print(f"[cyan]{action.capitalize()} command:[/] {' '.join(args)}")
        self.console.print("[dim]Not yet implemented. Coming in Phase 2+.[/]")

    # Command handlers
    def cmd_help(self, args: list[str]) -> None:
        """Show help information."""
        help_text = """
[bold cyan]BBAI Shell Commands[/]

[bold]Navigation:[/]
  /help       Show this help message
  /exit       Exit the shell
  /clear      Clear the screen
  /status     Show current session status
  /history    Show command history

[bold]Actions:[/]
  scan        Start a security scan
  recon       Perform reconnaissance
  analyze     Analyze findings with AI
  report      Generate reports
  config      Manage configuration

[bold]Examples:[/]
  bbai > scan --target example.com --program myprogram
  bbai > recon --target example.com --passive
  bbai > report --format hackerone
"""
        self.console.print(help_text)

    def cmd_exit(self, args: list[str]) -> None:
        """Exit the shell."""
        self.running = False
        self.console.print("[dim]Goodbye! 👋[/]")

    def cmd_status(self, args: list[str]) -> None:
        """Show session status."""
        status = f"""
[bold cyan]Session Status[/]

Session ID:     {self.session_id}
Project Dir:    {self.project_dir}
Data Dir:       {self.config.data_dir}
Theme:          {self.config.theme}
Thought Stream: {'Enabled' if self.config.show_thought_stream else 'Disabled'}
"""
        self.console.print(status)

    def cmd_clear(self, args: list[str]) -> None:
        """Clear the screen."""
        self.console.clear()

    def cmd_web(self, args: list[str]) -> None:
        """Switch to web UI."""
        self.console.print("[yellow]Web UI not yet implemented. Coming in Phase 6.[/]")

    def cmd_history(self, args: list[str]) -> None:
        """Show command history."""
        history_file = self.config.data_dir / ".shell_history"
        if history_file.exists():
            lines = history_file.read_text().strip().split("\n")
            # Filter out empty lines and meta lines
            commands = [line for line in lines if line and not line.startswith("#")]
            
            self.console.print("[bold cyan]Command History[/]\n")
            for i, cmd in enumerate(commands[-20:], 1):  # Show last 20
                self.console.print(f"  {i:2}. {cmd}")
        else:
            self.console.print("[dim]No command history yet.[/]")


def start_shell(
    config: BBAIConfig | None = None,
    console: Console | None = None,
) -> None:
    """Start the BBAI interactive shell.
    
    Args:
        config: Optional BBAI configuration
        console: Optional Rich console instance
    """
    shell = BBAIShell(config=config, console=console)
    shell.run()
