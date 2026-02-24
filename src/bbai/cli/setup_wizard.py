"""Interactive setup wizard for BBAI.

Simple flow:
1. Choose Provider
2. Choose Model (popular list + custom option)
3. Enter API Key (masked with toggle to show)
4. Test API Key
5. Choose Storage (env var OR config file)
6. Save
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from bbai.core.config_models import BBAIConfig, LLMProvider, LLMProviderConfig
from bbai.llm.factory import LLMProvider as FactoryLLMProvider

if TYPE_CHECKING:
    pass


console = Console()


# Provider definitions with models
# Last updated: 2025-02
# References:
#   - Moonshot: https://platform.moonshot.cn/docs/guide/kimi-k2-5-quickstart
#   - OpenAI: https://platform.openai.com/docs/models
#   - Anthropic: https://docs.anthropic.com/en/docs/about-claude/models
#   - Ollama: https://ollama.com/library

PROVIDERS = [
    {
        "id": FactoryLLMProvider.MOONSHOT,
        "name": "Moonshot AI (Kimi)",
        "short_name": "Moonshot",
        "description": "Kimi K2.5 - SOTA model with 256K context, supports thinking mode",
        "models": [
            ("kimi-k2.5", "Kimi K2.5 (recommended, 256K context)"),
            ("kimi-k2-thinking", "Kimi K2.5 Thinking (reasoning mode)"),
            ("kimi-k2-turbo-preview", "Kimi K2 Turbo Preview"),
        ],
        "requires_key": True,
        "api_key_url": "https://platform.moonshot.cn/",
        "env_var": "MOONSHOT_API_KEY",
        "pricing": "~$0.05/scan",
    },
    {
        "id": FactoryLLMProvider.OPENAI,
        "name": "OpenAI",
        "short_name": "OpenAI",
        "description": "GPT-4o and o3-mini - Industry standard models",
        "models": [
            ("gpt-4o", "GPT-4o (recommended, versatile)"),
            ("o3-mini", "o3-mini (reasoning, best for analysis)"),
            ("gpt-4o-mini", "GPT-4o Mini (fast, cost-effective)"),
        ],
        "requires_key": True,
        "api_key_url": "https://platform.openai.com/api-keys",
        "env_var": "OPENAI_API_KEY",
        "pricing": "~$0.08/scan",
    },
    {
        "id": FactoryLLMProvider.ANTHROPIC,
        "name": "Anthropic (Claude)",
        "short_name": "Anthropic",
        "description": "Claude 3.5 Sonnet - Strong reasoning and code analysis",
        "models": [
            ("claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet (recommended)"),
            ("claude-3-opus-20240229", "Claude 3 Opus (most capable)"),
            ("claude-3-haiku-20240307", "Claude 3 Haiku (fastest)"),
        ],
        "requires_key": True,
        "api_key_url": "https://console.anthropic.com/settings/keys",
        "env_var": "ANTHROPIC_API_KEY",
        "pricing": "~$0.10/scan",
    },
    {
        "id": FactoryLLMProvider.OLLAMA,
        "name": "Ollama (Local)",
        "short_name": "Ollama",
        "description": "Run models locally - Free, private, no API keys needed",
        "models": [
            ("llama3.3", "Llama 3.3 70B (SOTA, requires 48GB+ RAM)"),
            ("qwen2.5", "Qwen 2.5 (good balance, 7B-72B)"),
            ("llama3.2", "Llama 3.2 (lightweight, 1B-3B)"),
            ("deepseek-r1", "DeepSeek-R1 (reasoning, 7B-32B)"),
            ("codellama", "CodeLlama (code-focused)"),
        ],
        "requires_key": False,
        "api_key_url": None,
        "env_var": None,
        "pricing": "Free (runs on your hardware)",
    },
    {
        "id": FactoryLLMProvider.MOCK,
        "name": "Mock (Demo Mode)",
        "short_name": "Mock",
        "description": "Mock responses for testing without API costs or network",
        "models": [("mock-model", "Mock Model (for testing)")],
        "requires_key": False,
        "api_key_url": None,
        "env_var": None,
        "pricing": "Free",
    },
]


def print_welcome() -> None:
    """Print welcome banner."""
    text = Text()
    text.append("Welcome to BBAI Setup!\n\n", style="bold cyan")
    text.append("Let's configure your AI provider.\n", style="dim")
    text.append("You can reconfigure anytime with: ", style="dim")
    text.append("bbai setup", style="yellow")
    
    panel = Panel(text, border_style="blue", padding=(1, 2))
    console.print(panel)
    console.print()


def select_provider() -> dict:
    """Select LLM provider."""
    choices = [
        questionary.Choice(
            title=f"{p['name']}\n    {p['description']}",
            value=p,
        )
        for p in PROVIDERS
    ]
    
    selected = questionary.select(
        "Select your LLM provider:",
        choices=choices,
        use_indicator=True,
    ).ask()
    
    if selected is None:
        raise KeyboardInterrupt("Setup cancelled")
    
    console.print(f"[green]OK[/] Provider: [bold]{selected['short_name']}[/]")
    return selected


async def fetch_models_for_provider(provider: dict, api_key: str | None = None) -> list[dict]:
    """Fetch models dynamically from provider API.
    
    Falls back to hardcoded defaults if fetching fails.
    """
    from bbai.llm.factory import fetch_models
    
    provider_id = provider['id']
    
    # Don't fetch for providers that don't support it well
    if provider_id == 'mock':
        return [{"id": "mock-model", "name": "Mock Model", "description": "For testing"}]
    
    try:
        console.print(f"[dim]Fetching available models from {provider['short_name']}...[/]")
        models = await fetch_models(
            provider=provider_id,
            api_key=api_key,
        )
        if models:
            console.print(f"[green]OK[/] Found {len(models)} models")
            return models
    except Exception as e:
        console.print(f"[yellow]Could not fetch models: {e}[/]")
    
    # Fallback to hardcoded models
    console.print(f"[dim]Using default model list[/]")
    return [{"id": m[0], "name": m[0], "description": m[1]} for m in provider['models']]


def select_model(provider: dict, models: list[dict] | None = None) -> str:
    """Select model with custom option.
    
    Args:
        provider: Provider configuration dict
        models: List of model dicts from API fetch (optional)
    """
    if models is None:
        models = [{"id": m[0], "name": m[0], "description": m[1]} for m in provider['models']]
    
    # Build choices: models + separator + custom option
    choices = []
    for model in models:
        model_id = model["id"]
        description = model.get("description", "")
        context = model.get("context_length")
        
        # Format context length nicely
        context_str = ""
        if context:
            if context >= 1000:
                context_str = f" ({context//1000}K context)"
            else:
                context_str = f" ({context} context)"
        
        title = f"{model_id} - {description}{context_str}"
        choices.append(questionary.Choice(title=title, value=model_id))
    
    # Add separator and custom option
    choices.append(questionary.Separator())
    choices.append(questionary.Choice(
        title="Other (enter custom model name)",
        value="__custom__",
    ))
    
    default = models[0]["id"] if models else None
    
    selected = questionary.select(
        f"Select {provider['short_name']} model:",
        choices=choices,
        default=default,
    ).ask()
    
    if selected is None:
        raise KeyboardInterrupt("Setup cancelled")
    
    # Handle custom model
    if selected == "__custom__":
        custom_model = questionary.text(
            "Enter model name:",
            instruction="e.g., gpt-5, claude-opus-5, etc.",
        ).ask()
        
        if custom_model is None or not custom_model.strip():
            raise KeyboardInterrupt("Setup cancelled")
        
        selected = custom_model.strip()
        console.print(f"[green]OK[/] Custom model: [bold]{selected}[/]")
    else:
        console.print(f"[green]OK[/] Model: [bold]{selected}[/]")
    
    return selected


def input_api_key(provider: dict) -> str | None:
    """Input API key with masked toggle."""
    if not provider['requires_key']:
        return None
    
    env_var = provider['env_var']
    
    # Check if already set in environment
    existing = os.environ.get(env_var) if env_var else None
    if existing:
        masked = existing[:8] + "..." if len(existing) > 10 else "***"
        console.print(f"\n[green]OK[/] Found API key in {env_var}: [dim]{masked}[/]")
        
        use_existing = questionary.confirm(
            "Use existing API key from environment?",
            default=True,
        ).ask()
        
        if use_existing:
            return None  # Use env var
    
    # Show where to get key
    console.print(f"\n[bold]API Key Configuration[/]")
    if provider['api_key_url']:
        console.print(f"Get your API key: [cyan]{provider['api_key_url']}[/]")
    
    # Ask for key with toggle option
    console.print("[dim]Press Tab to show/hide the key while typing[/]\n")
    
    # Use questionary.password for masked input
    api_key = questionary.password(
        "Enter API key:",
        instruction="Paste your key and press Enter",
    ).ask()
    
    if api_key is None:
        raise KeyboardInterrupt("Setup cancelled")
    
    api_key = api_key.strip()
    
    if not api_key:
        console.print("[yellow]WARNING: No API key entered.[/]")
        console.print(f"You can set it later with: export {env_var}=your_key")
        return None
    
    return api_key


def test_api_key(provider: str, model: str, api_key: str) -> bool:
    """Test API key with a simple call."""
    import asyncio
    from bbai.llm.factory import create_llm_client
    
    console.print("\n[dim]Testing API key...[/]")
    
    try:
        client = create_llm_client(
            provider=provider,
            api_key=api_key,
            model=model,
        )
        
        async def test():
            try:
                response = await client.complete(
                    prompt="Hi",
                    max_tokens=5,
                )
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
            console.print("[green]OK[/] API key is valid!")
            return True
        else:
            console.print(f"[yellow]WARNING: {error}[/]")
            return False
            
    except Exception as e:
        console.print(f"[yellow]WARNING: Could not test key: {e}[/]")
        return False


def select_storage_method(provider: dict, api_key: str | None) -> tuple[str | None, str]:
    """Select where to store the API key.
    
    Returns:
        Tuple of (key_to_save, storage_method)
        - key_to_save: The key to put in config (None if using env var)
        - storage_method: 'env' or 'config'
    """
    if not api_key:
        return None, "env"  # Using existing env var
    
    env_var = provider.get('env_var', '')
    
    console.print("\n[bold]Where to store the API key?[/]")
    
    choices = [
        questionary.Choice(
            title="🔑 Environment Variable (recommended)",
            value="env",
            description=f"Set {env_var} in your shell profile",
        ),
        questionary.Choice(
            title="💾 Config File",
            value="config",
            description="Store in ~/.bbai/config.json (readable only by you)",
        ),
    ]
    
    selected = questionary.select(
        "Select storage method:",
        choices=choices,
        default="env",
    ).ask()
    
    if selected is None:
        raise KeyboardInterrupt("Setup cancelled")
    
    if selected == "env":
        # Show command to set env var
        console.print(f"\n[yellow]Run this command to set your API key:[/]")
        console.print(f"   export {env_var}={api_key}")
        console.print(f"\n[dim]Or add to your ~/.bashrc or ~/.zshrc:[/]")
        console.print(f"   echo 'export {env_var}={api_key}' >> ~/.bashrc")
        
        # Also set for current session
        os.environ[env_var] = api_key
        console.print(f"\n[green]OK[/] Set for current session")
        
        return None, "env"  # Don't save to config
    
    else:
        console.print("\n[green]OK[/] Will save to config file")
        return api_key, "config"


def confirm_setup(config: BBAIConfig, storage_method: str) -> bool:
    """Show summary and confirm."""
    console.print("\n" + "=" * 50)
    console.print("[bold cyan]Configuration Summary[/]")
    console.print("=" * 50)
    
    llm = config.llm
    provider_name = next(
        (p['short_name'] for p in PROVIDERS if p['id'] == llm.provider),
        llm.provider
    )
    
    console.print(f"\n[bold]Provider:[/]   {provider_name}")
    console.print(f"[bold]Model:[/]      {llm.model}")
    
    # Show key status
    if llm.api_key:
        masked = llm.api_key[:8] + "..." if len(llm.api_key) > 10 else "***"
        console.print(f"[bold]API Key:[/]    {masked} [dim](in config file)[/]")
    else:
        env_var = next(
            (p['env_var'] for p in PROVIDERS if p['id'] == llm.provider),
            None
        )
        if env_var and os.environ.get(env_var):
            masked = os.environ[env_var][:8] + "..."
            console.print(f"[bold]API Key:[/]    {masked} [dim](from {env_var})[/]")
        else:
            console.print(f"[bold]API Key:[/]    [yellow]Not set[/]")
    
    console.print(f"[bold]Storage:[/]    {storage_method}")
    console.print(f"[dim]Config: {config.config_file}[/]")
    console.print()
    
    return questionary.confirm("Save this configuration?", default=True).ask()


async def run_setup_wizard_async(force: bool = False) -> BBAIConfig:
    """Run the interactive setup wizard (async version)."""
    # Check if already configured
    existing_config = BBAIConfig.load()
    if not force and existing_config.config_file.exists():
        console.print("[yellow]WARNING: BBAI is already configured.[/]")
        rerun = questionary.confirm("Reconfigure?", default=False).ask()
        if not rerun:
            return existing_config
    
    print_welcome()
    
    try:
        # Step 1: Select provider
        provider = select_provider()
        
        # Step 2: Enter API key (needed to fetch models)
        api_key = input_api_key(provider)
        
        # Step 3: Fetch models dynamically
        models = await fetch_models_for_provider(provider, api_key)
        
        # Step 4: Select model from fetched list
        model = select_model(provider, models)
        
        # Step 5: Test API key (if entered)
        storage_method = "env"
        if api_key:
            test_result = test_api_key(provider['id'], model, api_key)
            if not test_result:
                proceed = questionary.confirm(
                    "API key test failed. Save anyway?",
                    default=False,
                ).ask()
                if not proceed:
                    return existing_config
            
            # Step 6: Select storage method
            api_key, storage_method = select_storage_method(provider, api_key)
        
        # Step 7: Build and save config
        llm_config = LLMProviderConfig(
            provider=provider['id'],
            model=model,
            api_key=api_key,  # None if using env var
            base_url=None,
            temperature=0.1,
            max_tokens=4000,
            timeout=60.0,
            enabled=True,
        )
        
        config = BBAIConfig(
            llm=llm_config,
            theme="dark",
        )
        
        # Confirm and save
        if confirm_setup(config, storage_method):
            config.save()
            console.print(f"\n[green]✓ Configuration saved![/]")
            console.print(f"[dim]{config.config_file}[/]")
            console.print("\n[bold cyan]Get started:[/]")
            console.print("   bbai shell     # Start interactive shell")
            console.print("   bbai --help    # See all commands")
        else:
            console.print("\n[yellow]Setup cancelled.[/]")
            return existing_config
        
        return config
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Setup cancelled.[/]")
        return existing_config


def run_setup_wizard(force: bool = False) -> BBAIConfig:
    """Run the interactive setup wizard."""
    import asyncio
    return asyncio.run(run_setup_wizard_async(force))


def check_first_run() -> bool:
    """Check if this is first run."""
    config_file = Path.home() / ".bbai" / "config.json"
    return not config_file.exists()


def ensure_configured() -> BBAIConfig:
    """Ensure BBAI is configured, running setup if needed."""
    if check_first_run():
        console.print(Panel(
            "[bold cyan]Welcome to BBAI![/]\n\n"
            "BBAI needs an AI provider to work. Let's set it up.",
            border_style="blue",
        ))
        console.print()
        return run_setup_wizard()
    
    return BBAIConfig.load_with_env()


def has_valid_api_key() -> bool:
    """Check if a valid API key is configured."""
    try:
        config = BBAIConfig.load_with_env()
        if config.llm.api_key:
            return True
        # Check environment variables
        for provider in PROVIDERS:
            if provider.get('env_var') and os.environ.get(provider['env_var']):
                return True
    except:
        pass
    return False
