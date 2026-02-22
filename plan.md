```markdown
# BBAI (Bug Bounty AI Agent) - Master Implementation Plan
**Version**: 1.0.0  
**Python**: 3.14.3  
**Package Manager**: UV (Astral)  
**LLM**: Kimi K2.5 (Moonshot)  
**Architecture**: Containerized AI Agents with LangGraph Orchestration

---

## 1. Executive Summary

BBAI is a production-grade, interactive bug bounty automation framework featuring a **Kimi Code CLI-style interface** with **visible AI reasoning streams**. It combines 25+ containerized security tools with LangGraph state machines and Kimi K2.5 intelligent analysis, featuring immutable scope enforcement for legal protection.

**Key Innovation**: Real-time visualization of AI thinking process, showing confidence levels, decision branches, and safety validations as they happen.

---

## 2. System Architecture

### 2.1 Three-Layer Architecture

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
│ ├─ vulnerability-core: Nuclei (800MB templates)            │
│ ├─ secrets: TruffleHog, Gitleaks, JSubfinder               │
│ ├─ js-analysis: LinkFinder, Semgrep, JS-Beautify           │
│ ├─ cloud: CloudEnum, S3Scanner, ScoutURL                   │
│ └─ visual: GoWitness, Chromium headless                    │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Interactive Shell Interface

**Design Target**: Kimi Code CLI aesthetic with REPL

```bash
$ bbai shell

┌─────────────────────────────────────────────────────────────┐
│ 🎯 Welcome to BBAI Shell v1.0!                              │
│ Send /help for help information.                            │
│ Directory: ~/bugbounty/projects                             │
│ Session: 5be91838-40ef-4a34-9266-b2b6a6e75b34              │
│ Model: kimi-k2-5 (connected)                                │
│ Status: Ready                                               │
└─────────────────────────────────────────────────────────────┘
[dim]Tip: BBAI Web UI available. Type[/dim] [yellow]/web[/yellow] [dim]to switch.[/dim]

💀 bbai > scan --target robinhood.com --program robinhood
```

### 2.3 AI Thinking Visualization

Real-time reasoning display:

```
🤔 AI > Analyzing target scope for robinhood.com...
   └─ Pattern match: *.robinhood.com [ALLOWED]
   └─ Time check: 21:44 ET (Market closed ✓)
   └─ Rate limit: 5 req/s [CONFIGURED]
   Confidence: ██████████ 100%

🎯 AI > Strategy Selection
   ├─ katana [ENABLED] - JavaScript rendering required for React app
   ├─ amass [ENABLED] - Passive DNS enumeration
   ├─ nuclei [ENABLED] - Vulnerability template matching
   └─ feroxbuster [DISABLED] - Rate limit too aggressive

🔍 AI > Executing: katana -u https://robinhood.com
   ├─ Crawling...
   ├─ Found /graphql endpoint (introspection enabled?)
   └─ ✓ Complete: 47 endpoints discovered

🧠 AI > Validating findings...
   ├─ GraphQL endpoint: TRUE POSITIVE (confidence: 87%)
   │  └─ Reasoning: Introspection query returned schema
   ├─ Potential SQLi: FALSE POSITIVE (confidence: 92%)
   │  └─ Reasoning: Error message is standard 404, not SQL error
```

---

## 3. Tech Stack Specification

### 3.1 Host Environment
- **Python**: 3.14.3 (pre-release, requires `UV_PRERELEASE=allow`)
- **Package Manager**: UV 0.4.x (Rust-based, 10x faster than pip)
- **Virtual Environment**: `.venv` (UV-managed)
- **Docker**: 24.x with BuildKit
- **OS**: Linux (primary), macOS (dev), WSL2 (Windows)

### 3.2 Core Dependencies

```toml
[project]
name = "bbai"
version = "1.0.0"
requires-python = ">=3.14"
dependencies = [
    # Async & Core
    "anyio[trio]>=4.4.0",
    "asyncio-mqtt>=0.16.0",
    "aiofiles>=24.1.0",
    "aioshutil>=1.5",
    
    # CLI & Interface
    "typer[all]>=0.12.3",
    "rich>=13.7.1",
    "prompt-toolkit>=3.0.0",
    "questionary>=2.0.1",
    "textual>=0.70.0",
    
    # AI & LangChain
    "langgraph>=0.2.14",
    "langchain-core>=0.3.0",
    "langchain-moonshot>=0.1.0",
    "langgraph-checkpoint-sqlite>=1.0.0",
    
    # Data & Validation
    "pydantic>=2.8.2",
    "pydantic-settings>=2.3.4",
    "orjson>=3.10.6",
    "validators>=0.28.0",
    "publicsuffixlist>=0.10.0",
    "tldextract>=5.1.2",
    
    # Storage
    "aiosqlite>=0.20.0",
    "sqlalchemy[asyncio]>=2.0.31",
    
    # Docker & System
    "docker>=7.1.0",
    "podman-py>=4.9.0",
    
    # Security & Rate Limiting
    "aiolimiter>=1.1.0",
    "slowapi>=0.1.9",
    "cryptography>=42.0.0",
    
    # Utilities
    "pyyaml>=6.0.1",
    "pytz>=2024.1",
    "tenacity>=8.5.0",
    "structlog>=24.4.0",
    "python-dotenv>=1.0.1",
    "httpx[http2]>=0.27.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.2",
    "pytest-asyncio>=0.23.8",
    "pytest-cov>=5.0.0",
    "pytest-xdist>=3.6.1",
    "respx>=0.21.0",
    "pytest-docker>=3.1.1",
    "black>=24.8.0",
    "ruff>=0.6.0",
    "mypy>=1.11.1",
    "pre-commit>=3.8.0",
    "bandit>=1.7.9",
    "safety>=3.2.0",
]

[tool.uv]
resolution = "highest"
prerelease-mode = "allow"
generate-hashes = true

[tool.black]
line-length = 100
target-version = ['py314']

[tool.ruff]
target-version = "py314"
select = ["E", "F", "I", "N", "W", "UP", "B", "C4", "ASYNC"]
```

---

## 4. Implementation Phases

### Phase 1: Foundation & Interactive Shell (Weeks 1-2)

**Deliverables**: 
- UV project setup with Python 3.14.3
- Interactive REPL shell with Rich UI
- Thought Streamer infrastructure
- Configuration system (Pydantic v2)

**Key Components**:

```python
# src/bbai/cli/shell.py
class BBAIShell:
    def __init__(self):
        self.session_id = str(uuid.uuid4())[:8]
        self.console = Console()
        self.completer = WordCompleter([
            "/help", "/exit", "/status", "/web", "/clear",
            "scan", "recon", "analyze", "report", "config"
        ])
    
    def print_banner(self):
        # Kimi Code CLI style banner
        panel = Panel(
            f"[bold cyan]BBAI Shell v1.0[/bold cyan]\n"
            f"Session: {self.session_id}\n"
            f"Model: kimi-k2-5 (connected)",
            border_style="blue"
        )
        self.console.print(panel)

# src/bbai/llm/thought_stream.py
class AIThoughtStreamer:
    """Real-time AI reasoning visualization"""
    
    async def __aenter__(self):
        self.live = Live(
            self._render(),
            refresh_per_second=10,
            console=self.console
        )
        return self
    
    def think(self, message: str, thought_type: ThoughtType):
        self.current_thought = Thought(
            type=thought_type,
            message=message,
            details=[],
            timestamp=time.time()
        )
    
    def detail(self, message: str, confidence: Optional[float] = None):
        if self.current_thought:
            self.current_thought.details.append(message)
            self.current_thought.confidence = confidence
    
    def _render(self) -> Panel:
        # Render tree structure with confidence bars
        tree = Tree(f"🤔 AI > {self.current_thought.message}")
        for detail in self.current_thought.details:
            tree.add(f"└─ {detail}")
        return Panel(tree, title="AI Reasoning Stream")
```

**Exit Criteria**:
- Shell runs with `bbai shell`
- Commands have auto-completion
- Thought streamer renders in real-time

### Phase 2: Safety & Scope Engine (Weeks 3-4)

**Deliverables**: Immutable legal protection layer

**Implementation**:

```python
# src/bbai/core/scope_engine.py
class ScopeValidator:
    """
    CRITICAL: Every network operation MUST pass through here.
    No exceptions. Immutable rules.
    """
    
    def __init__(self, config: ProgramConfig):
        self.config = config
        self.allowed_cache: Set[str] = set()
        self.blocked_cache: Set[str] = set()
        
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Pre-flight check for EVERY HTTP request"""
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        # Layer 1: Cache check
        if hostname in self.blocked_cache:
            return False, "CACHED_BLOCKED"
        
        # Layer 2: Out-of-scope (blacklist first)
        for rule in self.config.scope_out:
            if rule.matches(hostname):
                self.blocked_cache.add(hostname)
                return False, f"BLACKLIST:{rule.pattern}"
        
        # Layer 3: In-scope validation
        for rule in self.config.scope_in:
            if rule.matches(hostname):
                self.allowed_cache.add(hostname)
                return True, "ALLOWED"
        
        # Layer 4: Private IP blocking
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private:
                return False, "PRIVATE_IP_BLOCKED"
        except ValueError:
            pass
        
        return False, "NO_SCOPE_MATCH"
    
    def validate_timing(self) -> Tuple[bool, str]:
        """Market hours protection for financial targets"""
        if not self.config.timing.blocked_hours:
            return True, "NO_RESTRICTION"
        
        tz = pytz.timezone(self.config.timing.timezone)
        now = datetime.now(tz)
        current = now.time()
        
        start, end = self.config.timing.blocked_hours.split('-')
        start_t = datetime.strptime(start, "%H:%M").time()
        end_t = datetime.strptime(end, "%H:%M").time()
        
        # Handle overnight ranges
        is_blocked = (start_t <= current <= end_t) if start_t < end_t else (current >= start_t or current <= end_t)
        
        if is_blocked:
            return False, f"MARKET_HOURS:{self.config.timing.blocked_hours}"
        return True, "TIMING_OK"

# Safety Node in LangGraph
class SafetyNode:
    async def pre_execution(self, state: AgentState) -> AgentState:
        validator = ScopeValidator(state["config"])
        
        # Check target
        valid, reason = validator.validate_url(state["target"])
        if not valid:
            return {
                **state,
                "halt_requested": True,
                "safety_events": [{"level": "CRITICAL", "reason": reason}]
            }
        
        # Check timing
        valid, reason = validator.validate_timing()
        if not valid:
            return {**state, "halt_requested": True, "safety_events": [{"reason": reason}]}
        
        return state
```

**Exit Criteria**:
- 100% unit test coverage for scope engine
- Property-based testing (Hypothesis) for URL validation
- Zero tolerance for scope violations in tests

### Phase 3: Docker Tool Ecosystem (Weeks 5-6)

**Deliverables**: 8 Production-ready container images

**Image Specifications**:

| Image | Size | Tools | Purpose |
|-------|------|-------|---------|
| `bbai-recon-passive` | 150MB | Amass, Subfinder, Assetfinder, GAU, Waybackurls | Passive intelligence |
| `bbai-recon-active` | 200MB | Katana, Naabu, DNSx, RustScan, FFUF | Active scanning |
| `bbai-content-discovery` | 180MB | Feroxbuster, GoSpider, Hakrawler, HTTPx | Hidden endpoints |
| `bbai-vulnerability-core` | 800MB | Nuclei + Templates | Vulnerability detection |
| `bbai-secrets` | 250MB | TruffleHog, Gitleaks, JSubfinder | Credential exposure |
| `bbai-js-analysis` | 300MB | LinkFinder, Semgrep, JS-Beautify | Frontend analysis |
| `bbai-cloud` | 200MB | CloudEnum, S3Scanner, ScoutURL | Cloud misconfig |
| `bbai-visual` | 500MB | GoWitness, Chromium | Screenshots |

**Docker Security Hardening**:
```dockerfile
# Example: bbai-recon-passive/Dockerfile
FROM golang:1.22-alpine AS builder
RUN go install -v github.com/OWASP/Amass/v3/...@latest
# ... other tools

FROM alpine:3.19
RUN apk add --no-cache ca-certificates bind-tools
COPY --from=builder /go/bin/* /usr/local/bin/

# Security: Non-root execution
RUN adduser -D -u 1000 scanner
USER scanner
WORKDIR /workspace

# Security: Read-only filesystem
read_only: true
tmpfs: /tmp

# Security: Resource limits
mem_limit: 512m
cpu_quota: 50000
```

**Tool Abstraction**:
```python
# src/bbai/tools/docker_client.py
class DockerToolRunner:
    async def run_tool(
        self,
        image: str,
        command: str,
        timeout: int = 300
    ) -> ToolResult:
        """Execute tool with resource constraints"""
        
        container = await self.client.containers.create(
            image=image,
            command=command,
            mem_limit="512m",
            cpu_quota=50000,
            read_only=True,
            security_opt=["no-new-privileges:true"],
            cap_drop=["ALL"],
            cap_add=["NET_RAW"]  # For DNS
        )
        
        await container.start()
        
        # Stream logs for thought visualization
        async for log in container.logs(stdout=True, stderr=True, follow=True):
            yield log.decode()
        
        result = await container.wait()
        return ToolResult(
            exit_code=result["StatusCode"],
            output=logs
        )
```

### Phase 4: LangGraph Orchestration (Weeks 7-8)

**Deliverables**: State machine with AI decision points

**State Schema**:
```python
class AgentState(TypedDict):
    # Config
    target: str
    config: ProgramConfig
    thread_id: str
    
    # Progress
    current_phase: str
    discovered_endpoints: Annotated[List[str], operator.add]
    vulnerabilities: Annotated[List[Vulnerability], operator.add]
    
    # AI Reasoning
    thoughts: List[Thought]
    next_recommended_action: Optional[str]
    
    # Safety
    halt_requested: bool
    safety_events: List[SafetyEvent]
    
    # Metadata
    start_time: str
    tool_outputs: List[ToolOutput]
```

**Graph Structure**:
```python
def build_workflow():
    workflow = StateGraph(AgentState)
    
    # Nodes
    workflow.add_node("safety_pre", SafetyNode.pre_execution)
    workflow.add_node("recon", ReconNode.subdomain_enum)
    workflow.add_node("content_discovery", ContentDiscoveryNode.run)
    workflow.add_node("secret_scan", SecretScanNode.run)
    workflow.add_node("vuln_scan", VulnScanNode.run)
    workflow.add_node("ai_analysis", AnalysisNode.analyze)
    workflow.add_node("human_review", HumanReviewNode.interrupt)
    workflow.add_node("safety_post", SafetyNode.sanitize_output)
    
    # Edges
    workflow.set_entry_point("safety_pre")
    workflow.add_conditional_edges(
        "safety_pre",
        lambda s: "halt" if s["halt_requested"] else "continue",
        {"halt": END, "continue": "recon"}
    )
    workflow.add_edge("recon", "content_discovery")
    workflow.add_edge("content_discovery", "secret_scan")
    workflow.add_edge("secret_scan", "vuln_scan")
    workflow.add_edge("vuln_scan", "ai_analysis")
    
    # Human-in-the-loop for critical findings
    workflow.add_conditional_edges(
        "ai_analysis",
        lambda s: "review" if has_critical(s) else "continue",
        {"review": "human_review", "continue": "safety_post"}
    )
    
    workflow.add_edge("safety_post", END)
    
    return workflow.compile(checkpointer=SqliteSaver())
```

**AI Analysis Node**:
```python
class AnalysisNode:
    async def analyze(self, state: AgentState) -> AgentState:
        async with AIThoughtStreamer(self.console) as thinker:
            
            thinker.think(
                f"Validating {len(state['vulnerabilities'])} findings",
                ThoughtType.ANALYZING
            )
            
            confirmed = []
            for vuln in state["vulnerabilities"]:
                thinker.detail(f"Checking {vuln['type']} on {vuln['target']}...")
                
                # Kimi K2.5 validation
                analysis = await self.llm.analyze(
                    evidence=vuln["evidence"],
                    context=f"Target: {state['target']}, Program: {state['config'].meta['name']}"
                )
                
                if analysis.is_true_positive:
                    thinker.detail(
                        f"✓ Confirmed {analysis.vulnerability_type} "
                        f"(CVSS: {analysis.cvss_score})",
                        confidence=analysis.confidence
                    )
                    confirmed.append({**vuln, **analysis.dict()})
                else:
                    thinker.detail(
                        f"✗ False positive: {analysis.reasoning}",
                        confidence=analysis.confidence
                    )
            
            thinker.complete_thood(f"Confirmed {len(confirmed)} true positives")
            
            return {**state, "vulnerabilities": confirmed}
```

### Phase 5: Kimi K2.5 Integration (Week 9)

**Deliverables**: 
- Chain-of-thought prompting
- Structured output (JSON mode)
- Confidence scoring

**Implementation**:
```python
# src/bbai/llm/client.py
class KimiClient:
    def __init__(self, api_key: str):
        self.llm = MoonshotAI(
            model="kimi-k2-5",
            temperature=0.1,  # Deterministic for security
            max_tokens=4000,
            api_key=api_key
        )
    
    async def analyze_finding(self, finding: dict) -> AnalysisResult:
        system_prompt = """You are a security analyst. Think step by step:
        
        1. TECHNICAL VALIDITY: Is the vulnerability technically real?
        2. SCOPE COMPLIANCE: Is this endpoint in the bug bounty scope?
        3. BUSINESS IMPACT: What's the severity for this specific target type?
        4. CONFIDENCE: Rate your certainty (0.0-1.0)
        
        Format:
        REASONING: <detailed step-by-step thought process>
        VERDICT: <TRUE_POSITIVE or FALSE_POSITIVE>
        TYPE: <CWE-ID or category>
        CVSS: <0.0-10.0>
        CONFIDENCE: <0.0-1.0>"""
        
        response = await self.llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=json.dumps(finding))
        ])
        
        return self._parse_structured_output(response.content)
```

### Phase 6: Reporting & Distribution (Week 10)

**Deliverables**:
- HackerOne markdown generator
- Binary distribution (PyInstaller)
- Docker Compose deployment

**Report Generation**:
```python
class HackerOneReporter:
    def generate(self, findings: List[Vulnerability]) -> str:
        report = "# Bug Bounty Report\n\n"
        for vuln in findings:
            report += f"## {vuln.type} - {vuln.severity}\n"
            report += f"**CVSS Score:** {vuln.cvss_score}\n"
            report += f"**Target:** {vuln.target}\n"
            report += f"**AI Confidence:** {vuln.confidence:.0%}\n\n"
            report += f"### Summary\n{vuln.description}\n\n"
            report += f"### Reproduction\n```\n{vuln.reproduction_steps}\n```\n\n"
            report += f"### Remediation\n{vuln.remediation}\n\n"
            report += f"### AI Reasoning\n{vuln.ai_reasoning}\n\n---\n"
        return report
```

---

## 5. Safety & Compliance Architecture

### 5.1 Four-Layer Safety Model

1. **Configuration Validation** (Startup)
   - YAML schema validation
   - Scope conflict detection
   - Pattern syntax verification

2. **Pre-Execution** (Every tool call)
   - URL scope validation
   - Timing checks (market hours)
   - Rate limit acquisition
   - Tool permission check

3. **Network Interception** (Optional)
   - MITM proxy for HTTP inspection
   - DNS interception for private IP blocking
   - Automatic kill-switch on PII detection

4. **Post-Execution**
   - Output sanitization (PII removal)
   - Finding validation (AI re-checks scope)
   - Audit logging (immutable SQLite)

### 5.2 Human-in-the-Loop Triggers

Auto-pause and request confirmation when:
- CVSS 9.0+ (Critical) vulnerability found
- Potential PII detected in response
- Tool requests to exceed rate limits
- Out-of-scope endpoint accidentally discovered
- Financial transaction endpoints detected

---

## 6. Directory Structure

```
bbai/
├── pyproject.toml              # UV configuration
├── uv.lock                     # Locked dependencies
├── .python-version             # 3.14.3
├── Makefile                    # Build automation
├── src/bbai/
│   ├── __init__.py
│   ├── __main__.py             # Entry point
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py             # Typer app
│   │   ├── shell.py            # Interactive REPL
│   │   ├── commands.py         # Scan/config commands
│   │   └── wizard.py           # Interactive setup
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config_models.py    # Pydantic schemas
│   │   ├── scope_engine.py     # Immutable validation
│   │   ├── state_manager.py    # SQLite persistence
│   │   ├── rate_limiter.py     # Token bucket
│   │   └── safety_guards.py    # PII detection
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── client.py           # Kimi K2.5 wrapper
│   │   ├── thought_stream.py   # Reasoning visualization
│   │   ├── prompts.py          # System prompts
│   │   └── schemas.py          # Output models
│   ├── orchestration/
│   │   ├── __init__.py
│   │   ├── graph.py            # LangGraph workflow
│   │   ├── state.py            # State definitions
│   │   └── nodes/              # Individual nodes
│   │       ├── safety.py
│   │       ├── recon.py
│   │       ├── scanning.py
│   │       ├── analysis.py
│   │       └── reporting.py
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── docker_client.py    # Container management
│   │   ├── interfaces.py       # Abstract interfaces
│   │   ├── registry.py         # Tool registry
│   │   └── parsers/            # Output parsers
│   │       ├── nuclei.py
│   │       ├── amass.py
│   │       └── trufflehog.py
│   └── reporting/
│       ├── __init__.py
│       ├── hackerone.py        # H1 markdown
│       └── json_export.py
├── docker/                     # 8 tool images
│   ├── recon-passive/
│   ├── recon-active/
│   ├── content-discovery/
│   ├── vulnerability-core/
│   ├── secrets/
│   ├── js-analysis/
│   ├── cloud/
│   └── visual/
├── tests/
│   ├── conftest.py
│   ├── unit/
│   ├── integration/
│   └── fixtures/
└── docs/
    ├── architecture.md
    ├── usage.md
    └── safety.md
```

---

## 7. Development Workflow

### Setup
```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Initialize project
uv init bbai --python 3.14.3
cd bbai

# Install dependencies
uv add <dependencies from pyproject.toml>
uv pip install -e ".[dev]"

# Build tool images
make build-images

# Run
uv run bbai shell
```

### Daily Commands
```bash
uv run bbai scan --target example.com --program test
uv run pytest -xvs --tb=short
uv run mypy src/bbai
uv run ruff check .
```

---

## 8. Success Metrics

- **Scope Violations**: 0 incidents
- **False Positive Rate**: <15% (AI filtered)
- **Scan Completion**: >95%
- **Tool Execution Time**: <2 hours for standard web app
- **AI Analysis Latency**: <5s per finding
- **Test Coverage**: >90%

---

## 9. Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Legal: Out-of-scope testing | Immutable ScopeValidator, mandatory checks, audit logs |
| Technical: Docker escape | Non-root, no-privileges, read-only root, resource caps |
| Financial: API costs | Token tracking, cost limits, local LLM fallback |
| Data Leakage | PII regex detection, output encryption, memory-only processing |
| Reputational: False positives | High confidence thresholds (>0.8), human confirmation for Critical |

---
