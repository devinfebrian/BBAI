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
│   ├── core/             # Configuration models and scope engine
│   ├── llm/              # AI thought streamer and LLM client
│   ├── orchestration/    # LangGraph workflow nodes
│   ├── tools/            # Docker tool abstraction
│   └── reporting/        # Report generators
├── docker/               # 8 containerized tool images
└── tests/                # Unit and integration tests
```

## Development Phases

- [x] **Phase 1**: Foundation & Interactive Shell
- [x] **Phase 2**: Safety & Scope Engine
- [x] **Phase 3**: Docker Tool Ecosystem
- [x] **Phase 4**: LangGraph Orchestration
- [ ] **Phase 5**: Kimi K2.5 Integration
- [ ] **Phase 6**: Reporting & Distribution

## License

MIT
