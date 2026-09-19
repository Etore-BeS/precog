from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Tool:
    name: str
    description: str
    category: str
    risk: str
    handler: Callable[..., dict[str, Any]]
    requires_confirm: bool = False


@dataclass
class ToolRegistry:
    tools: dict[str, Tool] = field(default_factory=dict)

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def list(self) -> list[Tool]:
        return list(self.tools.values())

    def get(self, name: str) -> Tool:
        if name not in self.tools:
            raise KeyError(name)
        return self.tools[name]


def default_registry() -> ToolRegistry:
    from agent.tools import builtin

    reg = ToolRegistry()
    for t in builtin.all_tools():
        reg.register(t)
    return reg
