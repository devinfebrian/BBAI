# BBAI - Bug Bounty AI Agent

An AI-driven security testing framework that makes intelligent decisions about what to investigate and which security tools to run.

> **Status**: Functional for small targets (< 100 subdomains). Core architecture complete, needs hardening for production use.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Tools Assessment](#tools-assessment)
- [Safety & Scope](#safety--scope)
- [Future Improvements](#future-improvements)
- [Troubleshooting](#troubleshooting)

---

## Overview

BBAI is an AI-driven security testing agent that follows a **ReAct pattern** (Reasoning + Acting):

1. **THINK**: AI analyzes current findings and decides next action
2. **ACT**: Executes the chosen security tool
3. **OBSERVE**: Processes results and updates knowledge
4. **REPEAT**: Continues until investigation is complete

### Key Features

- 🤖 **AI-Driven**: LLM makes intelligent decisions about what to investigate
- 🔧 **Auto-Downloading Tools**: Security binaries downloaded on first use
- 🛡️ **Safety First**: Scope validation before every network call
- 📊 **Adaptive Strategy**: Changes approach based on findings (e.g., GraphQL detected → run GraphQL tests)
- 📝 **Structured Reports**: Markdown reports with findings summary

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ USER INTERFACE (CLI)                                                            │
│  bbai agent investigate example.com --max-iterations 30                         │
└─────────────────────────────────────────────────┬───────────────────────────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ SAFETY LAYER                                                                    │
│  • Validate target against scope rules                                          │
│  • Block private IPs (10.x.x.x, 192.168.x.x)                                    │
│  • Check rate limits                                                            │
└─────────────────────────────────────────────────┬───────────────────────────────┘
                                                  │ ALLOWED
                                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ AI AGENT LOOP                                                                   │
│                                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐       │
│  │   THINK     │───→│    ACT      │───→│  OBSERVE    │───→│   REPEAT    │       │
│  │             │    │             │    │             │    │   (or END)  │       │
│  │ LLM decides │    │ Run tool    │    │ Parse &     │    │             │       │
│  │ next action │    │ via registry│    │ update state│    │             │       │
│  └─────────────┘    └──────┬──────┘    └─────────────┘    └─────────────┘       │
│         ▲                  │                                       │            │
│         └──────────────────┴───────────────────────────────────────┘            │
│                            (Loop up to 30 iterations)                           │
│                                                                                 │
│  STATE TRACKED:                                                                 │
│  • hosts discovered (with tech stack)                                           │
│  • endpoints found (APIs, forms, etc.)                                          │
│  • vulnerabilities identified                                                   │
│  • previous actions & observations                                              │
│                                                                                 │
└─────────────────────────────────────────────────┬───────────────────────────────┘
                                                  │ ToolDecision
                                                  │ {tool_name, params}
                                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ TOOL REGISTRY                                                                   │
│  • Validates AI input against Pydantic schemas                                  │
│  • Translates AI intent → CLI commands                                          │
│  • Routes to appropriate tool wrapper                                           │
└─────────────────────────────────────────────────┬───────────────────────────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ BINARY WRAPPERS                                                                 │
│                                                                                 │
│  subfinder  →  Download from GitHub  →  Run: subfinder -d target -json          │
│  httpx      →  Download from GitHub  →  Run: httpx -u target -tech-detect       │
│  katana     →  Download from GitHub  →  Run: katana -u target -json             │
│  nuclei     →  Download from GitHub  →  Run: nuclei -u target -t templates      │
│                                                                                 │
│  Binary Location: ~/.bbai/tools/                                                │
│  Auto-downloaded on first use (~200 MB total)                                   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Three-Layer Architecture

| Layer | Purpose | Key Files |
|-------|---------|-----------|
| **AI Agent** | Decision making, state management | `src/bbai/agent/agent.py` |
| **Tool Registry** | Input validation, routing | `src/bbai/agent/tools.py` |
| **Binary Wrappers** | CLI execution, output parsing | `src/bbai/tools/wrappers/*.py` |

---

## How It Works

### For New Users

```
$ bbai

Welcome to BBAI!
1. Demo Mode      ← Try this first (no setup)
2. Quick Test     ← Try on safe target
3. Setup          ← Configure AI provider
4. Exit

→ Select Demo
→ See how AI makes decisions
→ Try a real scan
```

### Example Investigation Flow

```
$ bbai scan example.com

Starting Investigation

Progress: ████████░░░░░░░░░░░░ 40%
Strategy: deep_dive
Hosts: 15 | Endpoints: 47 | Findings: 2 (1 high)

→ Running nuclei on api.example.com

[Iteration 1] Strategy: initial_recon
AI Reasoning: "Starting fresh. Need to understand attack surface."
Action: Run subfinder(domain="example.com")
Result: Found 15 subdomains

[Iteration 2] Strategy: initial_recon  
AI Reasoning: "Good baseline. Now check which hosts are alive."
Action: Run httpx(targets=["sub1.example.com", "sub2.example.com", ...])
Result: api.example.com: 200, Express.js, [GraphQL] ← AI notices this!

[Iteration 3] Strategy: deep_dive ← Changed!
AI Reasoning: "GraphQL detected! Should run GraphQL-specific tests."
Action: Run nuclei(targets=["api.example.com"], templates=["graphql"])
Result: Found GraphQL Introspection Enabled (HIGH)

Final Report:
- 15 hosts discovered
- 47 endpoints mapped  
- 1 HIGH severity finding: GraphQL Introspection
```

---

## Installation

### Prerequisites

- Python 3.13+
- [UV](https://docs.astral.sh/uv/) package manager
- Git (for cloning)
- Internet connection (for downloading tools)

### Quick Install

```bash
# Clone the repository
git clone <repository-url>
cd bbai

# Install dependencies
uv pip install -e .

# Start BBAI (interactive menu on first run)
bbai
```

---

## Usage

### First Time? Start Here

When you run `bbai` for the first time, you'll see a welcome menu:

```bash
$ bbai

┌─────────────────────────────────────────────────────────────┐
│ Welcome to BBAI!                                            │
│ AI-powered security testing                                 │
└─────────────────────────────────────────────────────────────┘

BBAI is an AI agent that finds security vulnerabilities by
intelligently deciding which tools to run.

┌─────────────────────────────────────────────────────────────┐
│  # │ Option        │ Description                            │
├────┼───────────────┼────────────────────────────────────────┤
│  1 │ Demo Mode     │ See how it works (no setup, no API key)│
│  2 │ Quick Test    │ Scan a safe test target                │
│  3 │ Setup         │ Configure AI provider for full use     │
│  4 │ Exit          │ Close BBAI                             │
└─────────────────────────────────────────────────────────────┘

What would you like to do? [1/2/3/4]: 
```

### Option 1: Demo Mode (No Setup Required)

See how BBAI works without any configuration:

```bash
$ bbai
# Select "Demo Mode"

[THINK]     Starting fresh. Need to understand the attack surface.
[ACT]       Run subfinder to find subdomains...
[OBSERVE]   Found 15 subdomains including api.example.com
[THINK]     Good baseline. Check which hosts are alive.
[ACT]       Run httpx to probe discovered hosts...
[OBSERVE]   api.example.com is alive with GraphQL endpoint!
[THINK]     GraphQL detected! Switching to deep_dive strategy.
[ACT]       Run nuclei with GraphQL templates...
[OBSERVE]   Found: GraphQL Introspection Enabled (HIGH severity)
```

### Option 2: Quick Scan

Once configured, scanning is simple:

```bash
# Basic scan
bbai scan example.com

# Preview what will happen (no actual scan)
bbai scan example.com --preview

# Deeper investigation
bbai scan example.com --iterations 30

# Save report
bbai scan example.com -o report.md
```

### LLM Configuration

If you want full functionality, configure an AI provider:

```bash
# Run setup
bbai setup
```

**Supported Providers:**

| Provider | Cost | Setup | Best For |
|----------|------|-------|----------|
| **Ollama** | Free | Install locally | Privacy, no API keys |
| **Moonshot AI** | ~$0.05/scan | API key | Best performance |
| **OpenAI** | ~$0.10/scan | API key | Reliable |
| **Anthropic** | ~$0.08/scan | API key | Reasoning |

**Get an API key:**
- Moonshot AI: https://platform.moonshot.cn/
- OpenAI: https://platform.openai.com/api-keys
- Anthropic: https://console.anthropic.com/settings/keys

### Check Everything is Working

```bash
# Diagnose issues
bbai doctor

# Try to fix issues automatically
bbai doctor --fix
```

### Interactive Shell

```bash
# Start interactive shell
bbai shell

# Inside shell:
> scan example.com
> /status
> /help
> /exit
```

### Scope Management

```bash
# Create scope template
bbai create-scope-template ./program.yaml --name "HackerOne" --target hackerone.com

# Validate scope file
bbai validate-scope ./program.yaml

# Edit the YAML to customize:
# - scope_in: What's in scope
# - scope_out: What's out of scope  
# - rate_limit: Request throttling
```

### Tool Management

```bash
# List available tools
bbai tools list

# Check tool status
bbai tools status

# Update tool binaries
bbai tools update
```

### Configuration

```bash
# View config
bbai config --list

# Reconfigure LLM
bbai setup --force
```

---

## Tools Assessment

### Currently Available

| Tool | Status | Purpose | Download Size |
|------|--------|---------|---------------|
| **subfinder** | ✅ Working | Subdomain enumeration (passive) | 31 MB |
| **httpx** | ✅ Working | HTTP probing, tech detection | 39 MB |
| **katana** | ✅ Working | Web crawler (JS rendering) | 36 MB |
| **nuclei** | ✅ Working | Vulnerability scanning | 93 MB |

**Total Download**: ~200 MB (first use)

### Tool Details

#### subfinder
```python
# AI calls this as:
{
  "tool_name": "subfinder",
  "params": {
    "domain": "example.com",
    "sources": ["all"]  # or ["crtsh", "virustotal"]
  }
}
```
- **Passive**: No traffic to target
- **Sources**: 50+ passive sources (crt.sh, VirusTotal, etc.)
- **Output**: List of subdomains

#### httpx
```python
# AI calls this as:
{
  "tool_name": "httpx",
  "params": {
    "targets": ["sub1.example.com", "sub2.example.com"],
    "tech_detection": true
  }
}
```
- **Active**: Sends HTTP requests to target
- **Detects**: Tech stack (Wappalyzer), status codes, titles
- **Output**: Live hosts with technology fingerprinting

#### katana
```python
# AI calls this as:
{
  "tool_name": "katana",
  "params": {
    "url": "https://example.com",
    "depth": 3,
    "js_rendering": true
  }
}
```
- **Active**: Crawls target website
- **Features**: Headless browser, JS execution, form discovery
- **Output**: Discovered endpoints, API paths, forms

#### nuclei
```python
# AI calls this as:
{
  "tool_name": "nuclei",
  "params": {
    "targets": ["api.example.com"],
    "severity": ["critical", "high"],
    "templates": ["graphql", "cve"]  # AI chooses based on findings!
  }
}
```
- **Active**: Sends test payloads to target
- **Templates**: 4000+ vulnerability templates
- **Smart**: AI selects specific templates (e.g., `graphql` when GraphQL detected)

### Planned Tools (Not Yet Implemented)

| Tool | Purpose | Priority |
|------|---------|----------|
| naabu | Port scanning | Medium |
| trufflehog | Secret scanning | Medium |
| feroxbuster | Content fuzzing | Low |
| gowitness | Screenshots | Low |
| amass | Comprehensive recon | Low |

---

## Safety & Scope

### Safety Features

1. **Scope Validation** (Every request)
   - Checks against `scope_in` patterns
   - Blocks `scope_out` patterns
   - Validates before ANY network call

2. **Private IP Blocking**
   - Blocks 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
   - Prevents accidental internal scanning

3. **Rate Limiting**
   - Configurable requests per second
   - Default: 5 req/s

4. **Tool Timeouts**
   - Each tool has 5-minute timeout
   - Prevents hanging investigations

### Scope File Example

```yaml
name: my-program
platform: hackerone
scope_in:
  - pattern: "*.example.com"
    description: "All subdomains"
  - pattern: "example.com"
    description: "Main domain"
scope_out:
  - pattern: "*.internal.example.com"
    description: "Internal systems"
  - pattern: "*.corp.example.com"
    description: "Corporate network"
timing:
  timezone: "UTC"
  max_requests_per_second: 5.0
rate_limit:
  requests_per_second: 5.0
  burst_size: 10
auto_halt_on_critical: true
block_private_ips: true
```

---

## Current Limitations

### What's Working
- ✅ Core AI agent loop
- ✅ 4 security tools with auto-download
- ✅ Scope validation and safety checks
- ✅ Basic error handling with timeouts
- ✅ 112 unit tests passing

### What Needs Improvement

| Issue | Impact | Workaround |
|-------|--------|------------|
| **No state persistence** | Lose progress on crash | Restart investigation |
| **Sequential execution** | Slower on large targets | Use smaller scope |
| **Basic LLM error handling** | May fail on malformed responses | Retry command |
| **No parallel tool execution** | Tools run one at a time | None (future feature) |
| **Context window limits** | Large targets may overflow | Limit iterations |

### Production Readiness

**Status**: Functional for small targets, needs hardening for production.

**Ready for**:
- Development and testing
- Small targets (< 100 subdomains)
- Demonstrations
- Learning workflows

**Not ready for**:
- Large enterprise targets
- Unattended operation
- Critical infrastructure testing

---

## Future Improvements

### Short Term 

1. **State Persistence**
   - SQLite storage for investigation state
   - Resume interrupted investigations
   - Audit log of AI decisions

2. **Better Error Handling**
   - LLM response retry with backoff
   - Graceful degradation on tool failures
   - Better error messages to user

3. **Parallel Execution**
   - Run independent tools concurrently
   - Example: httpx + subfinder at same time

4. **More Tools**
   - naabu (port scanning)
   - trufflehog (secrets)

### Medium Term 

1. **Human-in-the-Loop**
   - Pause for approval on critical findings
   - Interactive decision override

2. **Multi-Target Support**
   - Investigate multiple related targets
   - Cross-reference findings

3. **Advanced Strategies**
   - Multi-step planning ("first X, then Y, then Z")
   - Tool result correlation
   - Confidence scoring

4. **Web UI**
   - Browser-based interface
   - Real-time progress visualization
   - Historical investigation browser

### Long Term 

1. **Custom Tool Integration**
   - Plugin system for custom tools
   - Community tool repository

2. **Learning System**
   - Remember effective strategies per target type
   - Adapt based on past investigations

3. **Team Collaboration**
   - Share investigations
   - Comment on findings
   - Assign tasks

---

## Command Reference

```bash
# Quick start
bbai scan <target>           # Simple one-command scan
bbai doctor                  # Check installation health

# Configuration
bbai setup                   # First-time setup
bbai config --list           # View configuration

# Investigation
bbai agent investigate       # Full AI-driven investigation
bbai agent demo              # Demo mode (no network)

# Utilities
bbai shell                   # Interactive shell
bbai tools status            # Check tool status
bbai validate-scope          # Validate scope file
```

## Troubleshooting

### First: Run the Doctor

```bash
bbai doctor
```

This checks:
- ✓ Configuration exists
- ✓ API key is set
- ✓ Tools directory exists
- ✓ Binary tools present
- ✓ Internet connectivity

### "Failed to download binary"

```bash
# Check internet connectivity to github.com
ping github.com

# Check if binary already exists
ls ~/.bbai/tools/

# Check doctor output
bbai doctor

# Manually install if needed
winget install ProjectDiscovery.Subfinder  # Windows
brew install subfinder                      # macOS
```

### "LLM error" or API failures

```bash
# Check API key is set
echo $MOONSHOT_API_KEY  # or $OPENAI_API_KEY

# Test connectivity
bbai config --list

# Check LLM provider status
bbai config --get llm.provider

# Reconfigure if needed
bbai setup --force
```

### "Target validation failed"

```bash
# Check scope file format
bbai validate-scope ./scope.yaml

# Common issues:
# - Pattern syntax (use * for wildcards)
# - YAML indentation
# - Missing required fields
```

### Tool timeouts

Tools have a 5-minute timeout. If a tool times out:
- Target may be too large
- Network connectivity issues
- Try reducing scope or iterations

### Tests failing

```bash
# Run tests
uv run pytest tests/unit -v

# Common issues:
# - Missing dependencies: uv pip install -e ".[dev]"
# - Python version: requires 3.13+
```

---

## Project Structure

```
bbai/
├── src/bbai/
│   ├── agent/                    # AI agent (core)
│   │   ├── agent.py              # Main agent loop
│   │   ├── tools.py              # Agent tool wrappers
│   │   └── __init__.py
│   ├── cli/                      # Command-line interface
│   │   ├── main.py               # Entry point
│   │   ├── agent_commands.py     # Agent CLI commands
│   │   ├── shell.py              # Interactive shell
│   │   ├── setup_wizard.py       # First-time setup
│   │   └── tools_commands.py     # Tool management
│   ├── core/                     # Core functionality
│   │   ├── config_models.py      # Configuration schemas
│   │   ├── safety_manager.py     # Scope validation
│   │   ├── scope_engine.py       # Scope matching
│   │   └── state_manager.py      # State persistence
│   ├── llm/                      # LLM clients
│   │   ├── factory.py            # Client factory
│   │   ├── providers.py          # Provider implementations
│   │   └── ...
│   └── tools/wrappers/           # Binary tool wrappers
│       ├── base.py               # Base wrapper class
│       ├── subfinder.py
│       ├── httpx.py
│       ├── katana.py
│       └── nuclei.py
├── tests/unit/                   # Unit tests (112 tests)
├── pyproject.toml                # Project config
└── README.md                     # This file
```

---

## License

MIT

---

## Contributing

The architecture is designed for extensibility. To add a new tool:

1. Create binary wrapper in `src/bbai/tools/wrappers/`
2. Create agent tool wrapper in `src/bbai/agent/tools.py`
3. Register in `ToolRegistry`
4. AI automatically sees it (no prompt changes needed)

See `src/bbai/tools/wrappers/base.py` for the wrapper interface.
