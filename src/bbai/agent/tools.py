"""
Agent-callable security tools.

Each tool is a function that:
1. Takes structured input (Pydantic model)
2. Runs the external CLI tool
3. Returns structured output (Pydantic model)
4. Can be called by the AI agent
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar, TypeVar

from pydantic import BaseModel, Field

from bbai.tools.wrappers.base import BinaryToolWrapper
from bbai.tools.wrappers.subfinder import SubfinderWrapper
from bbai.tools.wrappers.katana import KatanaWrapper
from bbai.tools.wrappers.nuclei import NucleiWrapper
from bbai.tools.wrappers.httpx import HttpxWrapper


# ============================================================================
# Tool Input/Output Models
# ============================================================================

class SubfinderInput(BaseModel):
    """Input for subdomain enumeration."""
    domain: str = Field(description="Root domain to enumerate (e.g., example.com)")
    sources: list[str] = Field(
        default=["all"],
        description="Data sources to query (all, crtsh, virustotal, etc.)"
    )


class SubdomainInfo(BaseModel):
    """Information about a discovered subdomain."""
    subdomain: str
    sources: list[str] = Field(default=[], description="Which sources found this")


class SubfinderOutput(BaseModel):
    """Output from subdomain enumeration."""
    subdomains: list[SubdomainInfo]
    total_found: int
    sources_queried: int
    
    def to_observation(self) -> str:
        """Convert to natural language for AI context."""
        lines = [f"Found {self.total_found} subdomains for target:"]
        for sd in self.subdomains[:10]:  # Limit to avoid context overflow
            lines.append(f"  - {sd.subdomain}")
        if len(self.subdomains) > 10:
            lines.append(f"  ... and {len(self.subdomains) - 10} more")
        return "\n".join(lines)


class HttpxInput(BaseModel):
    """Input for HTTP probing and tech detection."""
    targets: list[str] = Field(description="List of URLs/hostnames to probe")
    tech_detection: bool = Field(
        default=True,
        description="Detect technologies (Wappalyzer)"
    )
    follow_redirects: bool = Field(default=True)


class HttpxResult(BaseModel):
    """Result for a single host."""
    url: str
    status_code: int
    title: str = ""
    tech: list[str] = Field(default=[], description="Detected technologies")
    server: str = ""
    content_type: str = ""
    response_time_ms: float = 0.0
    webserver: str = ""
    
    @property
    def is_interesting(self) -> bool:
        """Heuristic for AI to notice this result."""
        interesting_tech = ["graphql", "wordpress", "apache", "nginx", "api"]
        return (
            any(t.lower() in self.tech or t.lower() in self.title.lower() 
                for t in interesting_tech)
            or self.status_code in [200, 301, 302, 401, 403]  # Not just 404s
        )


class HttpxOutput(BaseModel):
    """Output from HTTP probing."""
    results: list[HttpxResult]
    alive_count: int
    
    def to_observation(self) -> str:
        """Convert to natural language for AI context."""
        lines = [f"Probed {len(self.results)} hosts, {self.alive_count} are alive:"]
        interesting = [r for r in self.results if r.is_interesting]
        for r in interesting[:15]:
            tech_str = f" [{', '.join(r.tech[:3])}]" if r.tech else ""
            lines.append(f"  - {r.url} → {r.status_code}{tech_str}")
        return "\n".join(lines)


class KatanaInput(BaseModel):
    """Input for web crawling."""
    url: str = Field(description="Starting URL to crawl")
    depth: int = Field(default=2, ge=1, le=5, description="Crawl depth")
    js_rendering: bool = Field(
        default=True,
        description="Use headless browser for JavaScript apps"
    )
    same_domain_only: bool = Field(
        default=True,
        description="Don't crawl external domains"
    )


class EndpointInfo(BaseModel):
    """Discovered endpoint."""
    url: str
    method: str = "GET"
    status_code: int = 0
    parameters: list[str] = Field(default=[], description="URL parameters found")
    is_form: bool = False
    
    @property
    def is_api_endpoint(self) -> bool:
        """Detect if this looks like an API endpoint."""
        api_indicators = ["/api/", "/graphql", "/v1/", "/v2/", ".json", "/rest/"]
        return any(ind in self.url.lower() for ind in api_indicators)


class KatanaOutput(BaseModel):
    """Output from web crawling."""
    endpoints: list[EndpointInfo]
    total_discovered: int
    forms_found: int
    api_endpoints: list[str] = Field(default=[])
    
    def model_post_init(self, __context: Any) -> None:
        """Extract API endpoints after initialization."""
        self.api_endpoints = [
            e.url for e in self.endpoints 
            if e.is_api_endpoint
        ]
    
    def to_observation(self) -> str:
        """Convert to natural language for AI context."""
        lines = [f"Crawled {self.total_discovered} endpoints:"]
        
        if self.api_endpoints:
            lines.append(f"\n  API endpoints found ({len(self.api_endpoints)}):")
            for url in self.api_endpoints[:10]:
                lines.append(f"    - {url}")
        
        if self.forms_found:
            lines.append(f"\n  Forms found: {self.forms_found}")
        
        # Show interesting paths
        interesting_paths = [
            e for e in self.endpoints 
            if any(x in e.url.lower() for x in ["admin", "login", "config", "api", "internal"])
        ]
        if interesting_paths:
            lines.append(f"\n  Interesting paths:")
            for e in interesting_paths[:10]:
                lines.append(f"    - {e.url}")
        
        return "\n".join(lines)


class NucleiSeverity(str):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NucleiInput(BaseModel):
    """Input for vulnerability scanning."""
    targets: list[str] = Field(description="URLs to scan")
    severity: list[str] = Field(
        default=["critical", "high"],
        description="Severity levels to check"
    )
    templates: list[str] = Field(
        default=[],
        description="Specific template categories (graphql, cve, exposed-panels, etc.)"
    )
    rate_limit: int = Field(
        default=100,
        description="Max requests per second"
    )


class VulnerabilityFinding(BaseModel):
    """A vulnerability finding."""
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    reference: list[str] = []
    
    @property
    def is_confirmed(self) -> bool:
        """Whether this is a confirmed (not potential) vulnerability."""
        return self.severity in ["critical", "high"]


class NucleiOutput(BaseModel):
    """Output from vulnerability scanning."""
    findings: list[VulnerabilityFinding]
    templates_executed: int
    scan_duration_seconds: float
    
    def to_observation(self) -> str:
        """Convert to natural language for AI context."""
        if not self.findings:
            return f"No vulnerabilities found (scanned {self.templates_executed} templates)"
        
        lines = [f"Found {len(self.findings)} vulnerabilities:"]
        
        # Group by severity
        by_severity: dict[str, list[VulnerabilityFinding]] = {}
        for f in self.findings:
            by_severity.setdefault(f.severity, []).append(f)
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                lines.append(f"\n  {sev.upper()} ({len(by_severity[sev])}):")
                for f in by_severity[sev][:5]:
                    lines.append(f"    - {f.name} on {f.host}")
                if len(by_severity[sev]) > 5:
                    lines.append(f"    ... and {len(by_severity[sev]) - 5} more")
        
        return "\n".join(lines)


# ============================================================================
# Tool Base Class
# ============================================================================

InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


class AgentTool(ABC, BaseModel):
    """Base class for tools the AI agent can call."""
    
    name: ClassVar[str]
    description: ClassVar[str]
    input_model: ClassVar[type[BaseModel]]
    output_model: ClassVar[type[BaseModel]]
    
    @abstractmethod
    async def run(self, input_data: InputT) -> OutputT:
        """Execute the tool and return structured output."""
        pass
    
    def get_schema(self) -> dict:
        """Get JSON schema for LLM tool calling."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.input_model.model_json_schema()
        }


# ============================================================================
# Concrete Tool Implementations
# ============================================================================

class SubfinderTool(AgentTool):
    """Find subdomains using passive sources."""
    
    name = "subfinder"
    description = "Enumerate subdomains using passive DNS sources (crt.sh, VirusTotal, etc.). Does not send traffic to target."
    input_model = SubfinderInput
    output_model = SubfinderOutput
    
    def __init__(self):
        super().__init__()
        self.wrapper = SubfinderWrapper()
    
    async def run(self, input_data: SubfinderInput) -> SubfinderOutput:
        """Run subfinder and parse output."""
        await self.wrapper.ensure_installed()
        
        # Build command
        sources_arg = "-all" if "all" in input_data.sources else f"-sources {','.join(input_data.sources)}"
        cmd = f"-d {input_data.domain} {sources_arg} -json"
        
        # Execute
        result = await self.wrapper.run(input_data.domain, options={"sources": input_data.sources})
        
        # Parse results
        subdomains = []
        for finding in result.findings:
            subdomains.append(SubdomainInfo(
                subdomain=finding.get("host", ""),
                sources=finding.get("source", []).split(",") if isinstance(finding.get("source"), str) else []
            ))
        
        return SubfinderOutput(
            subdomains=subdomains,
            total_found=len(subdomains),
            sources_queried=len(input_data.sources)
        )


class HttpxTool(AgentTool):
    """Probe HTTP services and detect technologies."""
    
    name = "httpx"
    description = "Probe URLs to check if they're alive, detect tech stack (Wappalyzer), extract titles, response codes."
    input_model = HttpxInput
    output_model = HttpxOutput
    
    def __init__(self):
        super().__init__()
        self.wrapper = HttpxWrapper()
    
    async def run(self, input_data: HttpxInput) -> HttpxOutput:
        """Run httpx and parse output."""
        await self.wrapper.ensure_installed()
        
        # Create temp file with targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for target in input_data.targets:
                f.write(f"{target}\n")
            target_file = f.name
        
        try:
            # Build command - use JSON output for parsing
            tech_flag = "-tech-detect" if input_data.tech_detection else ""
            follow_flag = "-follow-redirects" if input_data.follow_redirects else ""
            
            cmd = f"-l {target_file} {tech_flag} {follow_flag} -json"
            
            # Execute (use first target as the main target param)
            result = await self.wrapper.run(
                input_data.targets[0] if input_data.targets else "",
                options={
                    "list": target_file,
                    "tech_detect": input_data.tech_detection,
                    "follow_redirects": input_data.follow_redirects
                }
            )
            
            # Parse JSON output
            results = []
            for line in result.raw_output.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    results.append(HttpxResult(
                        url=data.get("url", ""),
                        status_code=data.get("status_code", 0),
                        title=data.get("title", ""),
                        tech=data.get("tech", []),
                        server=data.get("webserver", ""),
                        content_type=data.get("content_type", ""),
                        response_time_ms=data.get("response_time", 0)
                    ))
                except json.JSONDecodeError:
                    continue
            
            alive = [r for r in results if r.status_code > 0]
            
            return HttpxOutput(
                results=results,
                alive_count=len(alive)
            )
        finally:
            Path(target_file).unlink(missing_ok=True)


class KatanaTool(AgentTool):
    """Crawl websites to discover endpoints."""
    
    name = "katana"
    description = "Crawl websites using headless browser. Discovers links, forms, JavaScript endpoints. Good for SPAs (React, Vue, Angular)."
    input_model = KatanaInput
    output_model = KatanaOutput
    
    def __init__(self):
        super().__init__()
        self.wrapper = KatanaWrapper()
    
    async def run(self, input_data: KatanaInput) -> KatanaOutput:
        """Run katana crawler."""
        await self.wrapper.ensure_installed()
        
        options = {
            "depth": input_data.depth,
            "js_crawl": input_data.js_rendering,
            "same_domain": input_data.same_domain_only
        }
        
        result = await self.wrapper.run(input_data.url, options=options)
        
        # Parse findings into endpoints
        endpoints = []
        forms = 0
        
        for finding in result.findings:
            url = finding.get("url", "")
            endpoint = EndpointInfo(
                url=url,
                method=finding.get("method", "GET"),
                status_code=finding.get("status_code", 0)
            )
            
            if finding.get("is_form"):
                endpoint.is_form = True
                forms += 1
            
            # Extract parameters from URL
            if "?" in url:
                endpoint.parameters = [
                    p.split("=")[0] for p in url.split("?")[1].split("&")
                    if "=" in p
                ]
            
            endpoints.append(endpoint)
        
        return KatanaOutput(
            endpoints=endpoints,
            total_discovered=len(endpoints),
            forms_found=forms
        )


class NucleiTool(AgentTool):
    """Run vulnerability scans using Nuclei templates."""
    
    name = "nuclei"
    description = "Scan for vulnerabilities using 4000+ templates. Can target specific categories (graphql, cve, exposed-panels) or severity levels."
    input_model = NucleiInput
    output_model = NucleiOutput
    
    def __init__(self):
        super().__init__()
        self.wrapper = NucleiWrapper()
    
    async def run(self, input_data: NucleiInput) -> NucleiOutput:
        """Run nuclei scan."""
        await self.wrapper.ensure_installed()
        
        # Build options
        options = {
            "severity": ",".join(input_data.severity),
            "rate_limit": input_data.rate_limit
        }
        
        if input_data.templates:
            options["tags"] = ",".join(input_data.templates)
        
        # Create target file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for target in input_data.targets:
                f.write(f"{target}\n")
            target_file = f.name
        
        options["list"] = target_file
        
        try:
            import time
            start = time.time()
            
            result = await self.wrapper.run(
                input_data.targets[0] if input_data.targets else "",
                options=options
            )
            
            duration = time.time() - start
            
            # Parse findings
            findings = []
            for f in result.findings:
                findings.append(VulnerabilityFinding(
                    template_id=f.get("template_id", "unknown"),
                    name=f.get("info", {}).get("name", "Unknown"),
                    severity=f.get("info", {}).get("severity", "unknown"),
                    host=f.get("host", ""),
                    matched_at=f.get("matched-at", ""),
                    description=f.get("info", {}).get("description", ""),
                    reference=f.get("info", {}).get("reference", [])
                ))
            
            # Estimate templates executed (rough)
            templates_count = len(input_data.severity) * 500  # rough estimate
            
            return NucleiOutput(
                findings=findings,
                templates_executed=templates_count,
                scan_duration_seconds=duration
            )
        finally:
            Path(target_file).unlink(missing_ok=True)


# ============================================================================
# Tool Registry
# ============================================================================

class ToolRegistry:
    """Registry of all available tools for the agent."""
    
    def __init__(self):
        self._tools: dict[str, AgentTool] = {}
        self._register_defaults()
    
    def _register_defaults(self):
        """Register default security tools."""
        self.register(SubfinderTool())
        self.register(HttpxTool())
        self.register(KatanaTool())
        self.register(NucleiTool())
    
    def register(self, tool: AgentTool):
        """Register a tool."""
        self._tools[tool.name] = tool
    
    def get(self, name: str) -> AgentTool | None:
        """Get a tool by name."""
        return self._tools.get(name)
    
    def list_tools(self) -> list[dict]:
        """List all available tools with schemas."""
        return [tool.get_schema() for tool in self._tools.values()]
    
    async def execute(self, tool_name: str, params: dict) -> BaseModel:
        """Execute a tool by name with params."""
        tool = self.get(tool_name)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        # Parse params into input model
        input_data = tool.input_model.model_validate(params)
        
        # Run tool
        return await tool.run(input_data)


# Global registry instance
_tool_registry: ToolRegistry | None = None


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry."""
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
    return _tool_registry
