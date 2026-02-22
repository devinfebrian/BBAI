# BBAI - Bug Bounty AI Agent

A production-grade, interactive bug bounty automation framework featuring a **Kimi Code CLI-style interface** with **visible AI reasoning streams**.

## Features

- **Interactive Shell**: Rich UI with auto-completion and command history
- **AI Thought Streamer**: Real-time visualization of AI reasoning process
- **Immutable Scope Engine**: Legal protection through strict scope validation
- **LangGraph Orchestration**: State machine workflow for complex security tasks
- **Containerized Tools**: 8 Docker images with 25+ security tools
- **Kimi K2.5 Integration**: AI-powered analysis and false positive filtering

## Quick Start

```bash
# Install dependencies
uv pip install -e .

# Start interactive shell
bbai shell

# Or use commands directly
bbai init my-project --target example.com
bbai scan --target example.com --program myprogram
bbai config --list
```

## Project Structure

```
bbai/
├── src/bbai/
│   ├── cli/              # CLI and interactive shell
│   ├── core/             # Configuration, safety, scope engine
│   ├── llm/              # AI thought streamer and Kimi K2.5 client
│   ├── orchestration/    # LangGraph workflow nodes and state
│   ├── tools/            # Docker tool abstraction and parsers
│   └── reporting/        # Report generators
├── docker/               # 8 containerized tool images
└── tests/                # Unit and integration tests (154 tests)
```

## Development Phases

- [x] **Phase 1**: Foundation & Interactive Shell
- [x] **Phase 2**: Safety & Scope Engine  
- [x] **Phase 3**: Docker Tool Ecosystem
- [x] **Phase 4**: LangGraph Orchestration
- [x] **Phase 5**: Kimi K2.5 Integration
- [x] **Phase 6**: Reporting & Distribution

## Test Results

```
============================= 154 passed =============================
- test_config_models.py: 19 passed
- test_docker_client.py: 9 passed
- test_llm.py: 15 passed
- test_orchestration.py: 18 passed
- test_parsers.py: 15 passed
- test_rate_limiter.py: 14 passed
- test_safety_guards.py: 24 passed
- test_scope_engine.py: 26 passed
- test_state_manager.py: 14 passed
```

## Architecture

### Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: AI Orchestration (Python 3.14.3 + UV)             │
│ ├─ Interactive Shell (Rich + Prompt Toolkit)               │
│ ├─ Thought Streamer (Real-time AI reasoning display)       │
│ ├─ LangGraph State Machines                                │
│ ├─ Safety Guard Nodes (Immutable scope enforcement)        │
│ └─ Kimi K2.5 Analysis Engine                               │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Tool Abstraction API (Async FastAPI)              │
│ ├─ Docker SDK Integration                                  │
│ ├─ Output Parsers (JSON/Structured)                        │
│ ├─ Adaptive Rate Limiting (Token Bucket)                   │
│ └─ Scope Validation Proxy (Intercept all traffic)          │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Containerized Tool Ecosystem (8 Images)           │
│ ├─ recon-passive: Amass, Subfinder, Assetfinder, GAU       │
│ ├─ recon-active: Katana, Naabu, DNSx, RustScan, FFUF       │
│ ├─ content-discovery: Feroxbuster, GoSpider, Hakrawler     │
│ ├─ vulnerability-core: Nuclei + Templates                  │
│ ├─ secrets: TruffleHog, Gitleaks, JSubfinder               │
│ ├─ js-analysis: LinkFinder, Semgrep, JS-Beautify           │
│ ├─ cloud: CloudEnum, S3Scanner, ScoutURL                   │
│ └─ visual: GoWitness, Chromium headless                    │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

```yaml
# bbai.yaml - Program configuration
name: my-program
platform: hackerone
scope_in:
  - pattern: "*.example.com"
scope_out:
  - pattern: "admin.example.com"
timing:
  blocked_hours: "09:00-17:00"
rate_limit:
  requests_per_second: 5.0
```

## Environment Variables

```bash
# Required for AI analysis
export MOONSHOT_API_KEY="your-api-key"

# Optional
export MOONSHOT_MODEL="kimi-k2-5"
export BBAI_DATA_DIR="~/.bbai"
```

## License

MIT
