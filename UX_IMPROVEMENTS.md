# BBAI UX Improvement Analysis

## Current Pain Points

### 1. First-Time Experience
- **Problem**: User runs `bbai`, gets prompted for setup, but no context on what it is
- **Problem**: LLM configuration is technical (API keys, models, base URLs)
- **Problem**: No validation that the LLM actually works

### 2. Discovery
- **Problem**: User doesn't know what commands are available
- **Problem**: `bbai --help` shows too many options at once
- **Problem**: No "getting started" path

### 3. Investigation Flow
- **Problem**: No preview of what will happen
- **Problem**: No progress indication during long runs
- **Problem**: Can't pause/resume investigations
- **Problem**: Output is just dumped at the end

### 4. Configuration
- **Problem**: Scope files are required but complex to create
- **Problem**: No guidance on rate limits
- **Problem**: Settings scattered across files and env vars

### 5. Error Handling
- **Problem**: Technical error messages ("JSON decode error")
- **Problem**: No suggestions on how to fix issues
- **Problem**: Silent failures in some cases

---

## Proposed UX Improvements

### 1. Guided Onboarding Flow

```
$ bbai

🎯 Welcome to BBAI - Your AI Security Assistant!

BBAI uses AI to intelligently investigate targets and find 
security vulnerabilities. It makes decisions about which tools 
to run based on what it discovers.

┌─────────────────────────────────────────────────────────┐
│ Quick Start                                             │
│                                                         │
│ 1. Configure AI (one-time)                             │
│ 2. Investigate a target                                │
│ 3. View results                                        │
└─────────────────────────────────────────────────────────┘

? What would you like to do? (Use arrow keys)
❯ Configure AI Provider
  Quick Test (scanme.nmap.org)
  View Demo
  Exit
```

### 2. Simple "Just Works" Command

```bash
# Current: Too many options
bbai agent investigate example.com --max-iterations 30 --scope-file ./scope.yaml -o report.md

# Improved: Smart defaults
bbai scan example.com

# Or even simpler - interactive
bbai quickstart
```

### 3. Real-Time Progress Dashboard

```
$ bbai scan example.com

🔍 Investigating example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  60%

Current: Running nuclei on api.example.com
Strategy: deep_dive
Iteration: 12/30

Discoveries:
  ✅ 15 subdomains found
  ✅ 8 hosts alive
  🔍 3 vulnerabilities checking
  ⏳ Crawling in progress

Last Action: Found GraphQL endpoint, switching strategy...

Press Ctrl+C to stop gracefully (save progress)
```

### 4. Smart Scope Handling

```bash
# No scope file? Use safe defaults
$ bbai scan example.com
⚠️  No scope file provided. Using safe defaults:
   • Target: example.com + subdomains
   • Rate limit: 5 req/s
   • Block private IPs: Yes
   
? Continue with these settings? (Y/n)

# Auto-create scope file after first run
✓ Created scope.yaml for this target
```

### 5. Configuration Wizard

```bash
$ bbai configure

🤖 AI Provider Configuration

? Select AI Provider:
  ▸ Moonshot AI (Kimi K2.5) - Recommended
    OpenAI (GPT-4)
    Anthropic (Claude)
    Ollama (Local - Free)

? Enter API key: [hidden]

✓ Testing connection...
✓ AI responding correctly
✓ Configuration saved

Estimated cost: ~$0.05 per investigation
```

### 6. Preview Mode

```bash
$ bbai scan example.com --preview

📋 Investigation Plan

AI will perform approximately 15-25 tool executions:

Phase 1: Reconnaissance (3-5 min)
  • subfinder - Find subdomains
  • httpx - Check which are alive

Phase 2: Discovery (5-10 min)
  • katana - Crawl discovered hosts
  • nuclei - Run targeted vulnerability scans

Phase 3: Analysis (2-3 min)
  • AI analysis of findings
  • Report generation

Estimated time: 10-18 minutes
Estimated cost: $0.03-$0.08

? Start investigation? (Y/n)
```

### 7. Better Error Messages

```bash
# Before: Technical
Error: JSONDecodeError: Expecting ',' delimiter: line 1 column 235

# After: Human-friendly
⚠️  The AI had trouble understanding the response.

This usually happens when:
  • The LLM API is overloaded
  • The investigation state is very large

Try:
  1. Running again (automatic retry)
  2. Using --max-iterations 20 to limit scope
  3. Checking your LLM provider status
```

### 8. Resume Capability

```bash
$ bbai scan example.com
# ... investigation runs for 10 minutes ...
# User presses Ctrl+C

⚠️  Investigation paused at iteration 15/30

? What would you like to do?
  ▸ Resume investigation
    Save and exit
    Discard progress

# Later:
$ bbai resume example.com
✓ Resumed from iteration 15
```

### 9. Interactive Shell Improvements

```
$ bbai shell

💀 bbai [default] > 

Tip: Type 'help' or just press Tab for suggestions

💀 bbai [default] > scan ex<TAB>
Completing: example.com  (from history)

💀 bbai [default] > scan example.com
Running investigation... Press Ctrl+C to stop

💀 bbai [default] > status
Last investigation: example.com (2 hours ago)
Findings: 3 vulnerabilities (1 HIGH)
Report: ./reports/example.com-2024-02-24.md

💀 bbai [default] > tools
Available tools:
  ✅ subfinder  (v2.12.0)
  ✅ httpx      (v1.6.10)
  ✅ katana     (v1.1.2)
  ✅ nuclei     (v3.3.9)
```

### 10. Post-Investigation Summary

```
✓ Investigation Complete: example.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 Target: example.com
⏱  Duration: 14m 32s
🔧 Tools used: 4
📊 Findings: 3 vulnerabilities

🔴 HIGH: GraphQL Introspection Enabled
   Location: api.example.com/graphql
   Details: Schema can be queried without authentication
   
🟡 MEDIUM: Missing Security Headers
   Location: www.example.com
   Details: X-Frame-Options not set

🟢 LOW: Information Disclosure
   Location: dev.example.com
   Details: Server version exposed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 Full report: ./reports/example.com-2024-02-24.md

? What next?
  ▸ View full report
    Investigate another target
    Export to HackerOne format
    Exit
```

---

## Implementation Priority

### Phase 1: Critical (Week 1)
1. ✅ Simplify main command (`bbai scan` alias)
2. ✅ Better error messages with suggestions
3. ✅ Add progress indicator to agent
4. ✅ Smart defaults without scope file

### Phase 2: High (Week 2-3)
5. Interactive setup wizard
6. Preview mode (`--preview`)
7. Resume capability (save state)
8. Configuration profiles

### Phase 3: Medium (Week 4)
9. Interactive shell improvements
10. Post-investigation summary
11. Contextual help system

---

## New Command Structure

```bash
# Entry points
bbai                          # Interactive menu
bbai quickstart              # One-command test
bbai scan <target>           # Main investigation
bbai resume <target>         # Resume paused

# Configuration
bbai configure               # Setup wizard
bbai config                  # View/edit settings
bbai config --profile prod   # Switch profiles

# Utilities
bbai doctor                  # Check everything works
bbai templates               # List scope templates
bbai history                 # Past investigations
```
