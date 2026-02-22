"""Tool Registry - Central registry for all security tools.

Manages tool discovery, registration, and execution.
"""

from __future__ import annotations

import importlib
import inspect
import logging
from typing import Any, Type

from bbai.core.config_models import ToolConfig
from bbai.tools.interfaces import BaseTool, ToolCategory, ToolMetadata, ToolPriority

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Central registry for security tools.
    
    Provides:
    - Tool registration and discovery
    - Category-based grouping
    - Priority-based ordering
    - Configuration management
    
    Usage:
        registry = ToolRegistry()
        
        # Register a tool
        registry.register(NucleiTool)
        
        # Get tool instance
        tool = registry.get_tool("nuclei")
        
        # Get tools by category
        recon_tools = registry.get_by_category(ToolCategory.RECON_PASSIVE)
        
        # Get execution order
        ordered = registry.get_execution_order()
    """

    def __init__(self):
        self._tools: dict[str, Type[BaseTool]] = {}
        self._configs: dict[str, ToolConfig] = {}
        self._instances: dict[str, BaseTool] = {}

    def register(
        self,
        tool_class: Type[BaseTool],
        config: ToolConfig | None = None,
    ) -> None:
        """Register a tool class.
        
        Args:
            tool_class: Tool class to register
            config: Optional tool configuration
        """
        # Create temporary instance to get metadata
        temp_instance = tool_class()
        name = temp_instance.metadata.name
        
        self._tools[name] = tool_class
        self._configs[name] = config or ToolConfig(
            name=name,
            image=f"bbai-{temp_instance.metadata.category.value}:latest",
        )
        
        logger.debug(f"Registered tool: {name}")

    def unregister(self, name: str) -> None:
        """Unregister a tool.
        
        Args:
            name: Tool name to unregister
        """
        if name in self._tools:
            del self._tools[name]
            del self._configs[name]
            if name in self._instances:
                del self._instances[name]
            logger.debug(f"Unregistered tool: {name}")

    def get_tool(self, name: str) -> BaseTool | None:
        """Get a tool instance by name.
        
        Args:
            name: Tool name
            
        Returns:
            Tool instance or None if not found
        """
        if name not in self._tools:
            return None
        
        # Return cached instance or create new
        if name not in self._instances:
            tool_class = self._tools[name]
            config = self._configs.get(name)
            self._instances[name] = tool_class(config)
        
        return self._instances[name]

    def get_metadata(self, name: str) -> ToolMetadata | None:
        """Get tool metadata by name.
        
        Args:
            name: Tool name
            
        Returns:
            Tool metadata or None
        """
        tool = self.get_tool(name)
        if tool:
            return tool.metadata
        return None

    def get_by_category(self, category: ToolCategory) -> list[BaseTool]:
        """Get all tools in a category.
        
        Args:
            category: Tool category
            
        Returns:
            List of tool instances
        """
        tools = []
        for name, tool_class in self._tools.items():
            temp = tool_class()
            if temp.metadata.category == category:
                tools.append(self.get_tool(name))
        return tools

    def get_by_priority(self, priority: ToolPriority) -> list[BaseTool]:
        """Get all tools with a specific priority.
        
        Args:
            priority: Tool priority
            
        Returns:
            List of tool instances
        """
        tools = []
        for name, tool_class in self._tools.items():
            temp = tool_class()
            if temp.metadata.priority == priority:
                tools.append(self.get_tool(name))
        return tools

    def get_execution_order(self) -> list[BaseTool]:
        """Get tools sorted by execution priority.
        
        Returns:
            List of tool instances sorted by priority
        """
        tool_info = []
        for name, tool_class in self._tools.items():
            temp = tool_class()
            tool_info.append((temp.metadata.priority, name))
        
        # Sort by priority (lower = higher priority)
        tool_info.sort(key=lambda x: x[0].value)
        
        return [self.get_tool(name) for _, name in tool_info]

    def list_tools(self) -> list[str]:
        """List all registered tool names.
        
        Returns:
            List of tool names
        """
        return list(self._tools.keys())

    def list_by_category(self) -> dict[ToolCategory, list[str]]:
        """List tools grouped by category.
        
        Returns:
            Dictionary mapping categories to tool names
        """
        result: dict[ToolCategory, list[str]] = {}
        for name, tool_class in self._tools.items():
            temp = tool_class()
            category = temp.metadata.category
            if category not in result:
                result[category] = []
            result[category].append(name)
        return result

    def is_registered(self, name: str) -> bool:
        """Check if a tool is registered.
        
        Args:
            name: Tool name
            
        Returns:
            True if registered
        """
        return name in self._tools

    def update_config(self, name: str, config: ToolConfig) -> bool:
        """Update tool configuration.
        
        Args:
            name: Tool name
            config: New configuration
            
        Returns:
            True if updated successfully
        """
        if name not in self._tools:
            return False
        
        self._configs[name] = config
        # Clear cached instance
        if name in self._instances:
            del self._instances[name]
        
        return True

    def get_config(self, name: str) -> ToolConfig | None:
        """Get tool configuration.
        
        Args:
            name: Tool name
            
        Returns:
            Tool configuration or None
        """
        return self._configs.get(name)

    def clear(self) -> None:
        """Clear all registered tools."""
        self._tools.clear()
        self._configs.clear()
        self._instances.clear()

    def auto_discover(self, module_path: str = "bbai.tools.plugins") -> int:
        """Auto-discover and register tools from a module.
        
        Scans the module for classes inheriting from BaseTool
        and registers them automatically.
        
        Args:
            module_path: Python module path to scan
            
        Returns:
            Number of tools registered
        """
        count = 0
        try:
            module = importlib.import_module(module_path)
            for name in dir(module):
                obj = getattr(module, name)
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, BaseTool)
                    and obj is not BaseTool
                    and not inspect.isabstract(obj)
                ):
                    self.register(obj)
                    count += 1
        except ImportError as e:
            logger.warning(f"Could not import module {module_path}: {e}")
        
        return count

    def get_stats(self) -> dict[str, Any]:
        """Get registry statistics.
        
        Returns:
            Dictionary with statistics
        """
        by_category = self.list_by_category()
        return {
            "total_tools": len(self._tools),
            "by_category": {
                cat.value: len(tools) for cat, tools in by_category.items()
            },
            "tools": self.list_tools(),
        }


# Global registry instance
_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Get the global tool registry.
    
    Returns:
        Global ToolRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


def register_tool(
    tool_class: Type[BaseTool],
    config: ToolConfig | None = None,
) -> None:
    """Register a tool in the global registry.
    
    Args:
        tool_class: Tool class to register
        config: Optional tool configuration
    """
    get_registry().register(tool_class, config)


def get_tool(name: str) -> BaseTool | None:
    """Get a tool from the global registry.
    
    Args:
        name: Tool name
        
    Returns:
        Tool instance or None
    """
    return get_registry().get_tool(name)
