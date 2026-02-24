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
from bbai.llm.factory import LLMProvider


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
        "/login",
        "/logout",
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
            "/login": self.cmd_login,
            "/logout": self.cmd_logout,
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

    def _get_llm_status(self) -> tuple[str, str]:
        """Get LLM provider and model info.
        
        Returns:
            Tuple of (provider_display, status)
        """
        llm = self.config.llm
        
        # Map provider to display name
        provider_names = {
            "moonshot": "🌙 Moonshot",
            "openai": "🤖 OpenAI",
            "anthropic": "Anthropic",
            "ollama": "🏠 Ollama",
            "openai_compatible": "🔌 Custom API",
            "mock": "🧪 Mock",
        }
        provider_display = provider_names.get(llm.provider, llm.provider)
        
        # Check if API key is configured
        has_key = bool(llm.api_key)
        if not has_key:
            # Check environment
            env_vars = {
                "moonshot": "MOONSHOT_API_KEY",
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "openai_compatible": "OPENAI_API_KEY",
            }
            env_var = env_vars.get(llm.provider)
            if env_var:
                import os
                has_key = bool(os.environ.get(env_var))
        
        if llm.provider in ["ollama", "mock"]:
            status = "(ready)"
        elif has_key:
            status = "(connected)"
        else:
            status = "[yellow](no API key)[/]"
        
        return provider_display, status

    def print_banner(self) -> None:
        """Print welcome banner."""
        provider_display, status = self._get_llm_status()
        
        banner_text = Text()
        banner_text.append("Welcome to BBAI Shell v0.1.0!\n", style="bold cyan")
        banner_text.append("Send /help for help information.\n", style="dim")
        banner_text.append(f"Directory: {self.project_dir}\n", style="dim")
        banner_text.append(f"Session: {self.session_id}\n", style="dim")
        
        # Show LLM info
        self.console.print(banner_text, end="")
        self.console.print(f"LLM: {provider_display} - {self.config.llm.model} ", style="dim", end="")
        self.console.print(status)
        
        panel = Panel(
            "",  # Empty content since we printed above
            border_style="blue",
            padding=(1, 2),
        )
        # Re-print as panel
        banner_text.append(f"LLM: {provider_display} - {self.config.llm.model} {status}\n", style="dim")
        
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
        import asyncio
        
        if action == "scan":
            # Parse scan arguments
            target = None
            max_iterations = 20
            
            for i, arg in enumerate(args):
                if arg in ("-t", "--target") and i + 1 < len(args):
                    target = args[i + 1]
                elif arg in ("-i", "--iterations") and i + 1 < len(args):
                    max_iterations = int(args[i + 1])
            
            if not target:
                self.console.print("[red]Usage: scan --target example.com [--iterations 30][/]")
                return
            
            self.console.print(f"[bold cyan]Starting AI investigation of {target}...[/]")
            
            try:
                from bbai.agent import SecurityAgent, generate_report
                
                agent = SecurityAgent(
                    console=self.console,
                    max_iterations=max_iterations
                )
                
                state = asyncio.run(agent.investigate(target))
                
                # Display summary
                self.console.print("\n[bold green]Investigation Complete[/]")
                self.console.print(f"Hosts discovered: {len(state.hosts)}")
                self.console.print(f"Findings: {len(state.findings)}")
                
                if state.findings:
                    self.console.print("\n[bold]Key Findings:[/]")
                    for f in state.findings[:5]:
                        self.console.print(f"  [{f.severity}] {f.name} on {f.host}")
                
            except Exception as e:
                self.console.print(f"[red]Investigation failed: {e}[/]")
        
        elif action == "recon":
            self.console.print("[cyan]Recon command:[/] {' '.join(args)}")
            self.console.print("[dim]Use 'scan' instead for full reconnaissance.[/]")
        
        elif action == "analyze":
            self.console.print("[cyan]Analyze command:[/] {' '.join(args)}")
            self.console.print("[dim]Use 'scan --analyze' for AI analysis.[/]")
        
        else:
            self.console.print(f"[cyan]{action.capitalize()} command:[/] {' '.join(args)}")
            self.console.print("[dim]Not yet implemented.[/]")

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

[bold]Authentication:[/]
  /login      Configure or update API key
  /logout     Remove stored API key

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
        provider_display, llm_status = self._get_llm_status()
        
        status = f"""
[bold cyan]Session Status[/]

Session ID:     {self.session_id}
Project Dir:    {self.project_dir}
Data Dir:       {self.config.data_dir}
Theme:          {self.config.theme}
Thought Stream: {'Enabled' if self.config.show_thought_stream else 'Disabled'}

[bold cyan]LLM Configuration[/]
Provider:       {provider_display}
Model:          {self.config.llm.model}
Temperature:    {self.config.llm.temperature}
Max Tokens:     {self.config.llm.max_tokens}
Status:         {llm_status}
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

    def cmd_login(self, args: list[str]) -> None:
        """Configure or update API key."""
        import os
        import asyncio
        from prompt_toolkit import prompt as pt_prompt
        from bbai.llm.factory import create_llm_client, get_available_providers
        
        current_provider = self.config.llm.provider
        current_model = self.config.llm.model
        
        self.console.print("[bold cyan]API Key Configuration[/]\n")
        self.console.print(f"Current provider: [green]{current_provider}[/]")
        self.console.print(f"Current model: [green]{current_model}[/]")
        
        # Get provider info
        providers = get_available_providers()
        provider_info = next(
            (p for p in providers if p['id'] == current_provider),
            None
        )
        
        if not provider_info:
            self.console.print("[red]Unknown provider[/]")
            return
        
        if provider_info['id'] in ['ollama', 'mock']:
            self.console.print(f"[green]OK[/] {provider_info['name']} doesn't require an API key")
            return
        
        # Show current key status
        env_var = provider_info.get('env_var', '')
        existing_env = os.environ.get(env_var) if env_var else None
        existing_config = self.config.llm.api_key
        
        if existing_env:
            masked = existing_env[:8] + "..." if len(existing_env) > 10 else "***"
            self.console.print(f"\nCurrent key: [dim]{masked}[/] [green](from {env_var})[/]")
        elif existing_config:
            masked = existing_config[:8] + "..." if len(existing_config) > 10 else "***"
            self.console.print(f"\nCurrent key: [dim]{masked}[/] [green](from config)[/]")
        else:
            self.console.print("\n[yellow]WARNING: No API key configured[/]")
        
        # Show where to get key
        if provider_info.get('api_key_url'):
            self.console.print(f"Get your API key: [cyan]{provider_info['api_key_url']}[/]")
        
        # Prompt for new key
        self.console.print("\n[dim]Input is hidden. Press Tab to show/hide.[/]\n")
        
        try:
            new_key = pt_prompt(
                "Enter API key (leave empty to keep current): ",
                is_password=True,
            )
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cancelled[/]")
            return
        
        new_key = new_key.strip()
        
        if not new_key:
            self.console.print("[dim]No changes made.[/]")
            return
        
        # Test the key with a real API call
        self.console.print("\n[dim]Testing API key...[/]")
        
        try:
            client = create_llm_client(
                provider=current_provider,
                api_key=new_key,
                model=current_model,
            )
            
            async def test():
                try:
                    await client.complete(prompt="Hi", max_tokens=5)
                    return True, None
                except Exception as e:
                    error_msg = str(e).lower()
                    if "auth" in error_msg or "key" in error_msg or "unauthorized" in error_msg:
                        return False, "Invalid API key - authentication failed"
                    return False, str(e)
                finally:
                    await client.close()
            
            success, error = asyncio.run(test())
            
            if success:
                self.console.print("[green]OK[/] API key is valid!")
            else:
                self.console.print(f"[yellow]WARNING: {error}[/]")
                proceed = input("Save this key anyway? [y/N]: ").lower().strip() == 'y'
                if not proceed:
                    return
        except Exception as e:
            self.console.print(f"[yellow]WARNING: Could not test key: {e}[/]")
        
        # Ask storage method
        self.console.print("\n[bold]Where to store the API key?[/]")
        self.console.print("  1. 🔑 Environment Variable (recommended)")
        self.console.print(f"     Set {env_var} in your shell")
        self.console.print("  2. 💾 Config File")
        self.console.print("     Store in ~/.bbai/config.json")
        
        try:
            choice = input("\nSelect (1 or 2): ").strip()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cancelled[/]")
            return
        
        if choice == "1" or choice.lower() == "env":
            # Set for current session and show command
            os.environ[env_var] = new_key
            self.console.print(f"\n[green]OK[/] Set for current session")
            self.console.print(f"\n[yellow]To make permanent, run:[/]")
            self.console.print(f"   export {env_var}={new_key}")
            self.console.print(f"\n[dim]Or add to ~/.bashrc or ~/.zshrc[/]")
            
            # Update config to not store key
            updated = self.config.model_copy(update={
                'llm': self.config.llm.model_copy(update={'api_key': None})
            })
            self.config = updated
            updated.save()
            
        elif choice == "2" or choice.lower() == "config":
            # Save to config
            updated = self.config.model_copy(update={
                'llm': self.config.llm.model_copy(update={'api_key': new_key})
            })
            self.config = updated
            updated.save()
            self.console.print("\n[green]OK[/] API key saved to config file")
        else:
            self.console.print("[yellow]Invalid choice. Key will be used for this session only.[/]")
            os.environ[env_var] = new_key

    def cmd_logout(self, args: list[str]) -> None:
        """Remove stored API key."""
        import os
        from bbai.llm.factory import get_available_providers
        
        current_provider = self.config.llm.provider
        
        # Get provider info
        providers = get_available_providers()
        provider_info = next(
            (p for p in providers if p['id'] == current_provider),
            None
        )
        
        if not provider_info:
            self.console.print("[red]Unknown provider[/]")
            return
        
        env_var = provider_info.get('env_var', '')
        existing_env = os.environ.get(env_var) if env_var else None
        existing_config = self.config.llm.api_key
        
        if not existing_env and not existing_config:
            self.console.print("[yellow]WARNING: No API key is currently stored[/]")
            return
        
        self.console.print("[bold cyan]Remove API Key[/]\n")
        self.console.print(f"Provider: [green]{current_provider}[/]")
        
        if existing_config:
            self.console.print("Storage: [dim]Config file[/]")
        elif existing_env:
            self.console.print(f"Storage: [dim]Environment variable ({env_var})[/]")
        
        confirm = input("\nRemove this API key? [y/N]: ").lower().strip() == 'y'
        
        if confirm:
            # Remove from config
            if existing_config:
                updated = self.config.model_copy(update={
                    'llm': self.config.llm.model_copy(update={'api_key': None})
                })
                self.config = updated
                updated.save()
            
            # Note: Can't unset env var for current process
            self.console.print("\n[green]OK[/] API key removed from config")
            self.console.print("[dim]Note: If set as environment variable, restart your shell to clear.[/]")


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
