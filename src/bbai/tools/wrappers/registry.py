"""Tool registry for managing all security tools."""

from __future__ import annotations

from typing import Type

from bbai.tools.wrappers.base import ToolResult, ToolWrapper
from bbai.tools.wrappers.httpx import HttpxWrapper
from bbai.tools.wrappers.katana import KatanaWrapper
from bbai.tools.wrappers.nuclei import NucleiWrapper
from bbai.tools.wrappers.python_httpx import PythonHttpx
from bbai.tools.wrappers.python_portscan import PythonPortScanner
from bbai.tools.wrappers.python_subdomain import PythonSubdomainEnum
from bbai.tools.wrappers.python_vulnscan import PythonVulnScanner
from bbai.tools.wrappers.python_webcrawl import PythonWebCrawler
from bbai.tools.wrappers.subfinder import SubfinderWrapper


class ToolRegistry:
    """Registry of all available security tools.
    
    Manages both Python-native tools and binary wrappers,
    providing a unified interface for the scanner.
    """

    def __init__(self):
        """Initialize registry with all tools."""
        self._tools: dict[str, list[ToolWrapper]] = {
            # Subdomain enumeration - Binary tools first (preferred), Python fallback
            "subdomain_enum": [
                SubfinderWrapper(),     # Binary (primary - 50+ passive sources)
                PythonSubdomainEnum(),  # Pure Python (fallback)
            ],
            
            # Port scanning
            "port_scan": [
                PythonPortScanner(),  # Pure Python
            ],
            
            # Content discovery
            "content_discovery": [
                KatanaWrapper(),     # Binary (primary - headless JS crawling)
                PythonWebCrawler(),  # Pure Python (fallback)
            ],
            
            # Vulnerability scanning - Binary tools first, Python fallback
            "vuln_scan": [
                NucleiWrapper(),      # Binary wrapper (primary)
                PythonVulnScanner(),  # Pure Python (fallback)
            ],
            
            # Web crawling
            "web_crawl": [
                KatanaWrapper(),     # Binary (headless browser)
                PythonWebCrawler(),  # Pure Python (static)
            ],
            
            # Technology fingerprinting
            "tech_detect": [
                HttpxWrapper(),      # Binary (primary)
                PythonWebCrawler(),  # Pure Python (fallback)
            ],
            
            # HTTP probing (find live hosts) - Binary tools first, Python fallback
            "http_probe": [
                HttpxWrapper(),  # Binary (primary)
                PythonHttpx(),   # Pure Python (fallback)
            ],
            

        }

    def get_tools(self, category: str) -> list[ToolWrapper]:
        """Get all tools for a category.
        
        Args:
            category: Tool category name
            
        Returns:
            List of tools in that category
        """
        return self._tools.get(category, [])

    async def run_tool(
        self,
        category: str,
        target: str,
        options: dict | None = None,
        tool_name: str | None = None
    ) -> ToolResult:
        """Run a tool from a category.
        
        Args:
            category: Tool category
            target: Target to scan
            options: Tool options
            tool_name: Specific tool to use (or first available)
            
        Returns:
            Tool execution result
        """
        tools = self.get_tools(category)
        
        if not tools:
            return ToolResult(
                success=False,
                tool_name="none",
                target=target,
                error_message=f"No tools available for category: {category}"
            )
        
        # Find specific tool or first available
        tool = None
        if tool_name:
            for t in tools:
                if t.name == tool_name:
                    tool = t
                    break
        
        if not tool:
            # Find first available tool
            for t in tools:
                if await t.is_available():
                    tool = t
                    break
        
        if not tool:
            # Try to install first binary tool
            for t in tools:
                if hasattr(t, 'ensure_installed'):
                    try:
                        await t.ensure_installed()
                        tool = t
                        break
                    except Exception:
                        continue
        
        if not tool:
            return ToolResult(
                success=False,
                tool_name="none",
                target=target,
                error_message=f"No available tools for category: {category}"
            )
        
        # Run the tool
        return await tool.run(target, options)

    async def run_category(
        self,
        category: str,
        target: str,
        options: dict | None = None
    ) -> list[ToolResult]:
        """Run all available tools in a category.
        
        Args:
            category: Tool category
            target: Target to scan
            options: Tool options
            
        Returns:
            List of results from all tools
        """
        tools = self.get_tools(category)
        results = []
        
        for tool in tools:
            if await tool.is_available():
                result = await tool.run(target, options)
                results.append(result)
        
        return results

    def list_categories(self) -> list[str]:
        """List all available tool categories."""
        return list(self._tools.keys())

    def list_tools(self, category: str | None = None) -> list[dict]:
        """List tools with their availability status.
        
        Args:
            category: Optional category filter
            
        Returns:
            List of tool information dictionaries
        """
        tools_info = []
        
        categories = [category] if category else self._tools.keys()
        
        for cat in categories:
            for tool in self._tools.get(cat, []):
                tools_info.append({
                    "name": tool.name,
                    "category": cat,
                    "description": tool.description,
                    "type": "binary" if hasattr(tool, 'binary_path') else "python",
                })
        
        return tools_info


# Global registry instance
_registry: ToolRegistry | None = None


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
