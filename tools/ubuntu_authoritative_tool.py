
from __future__ import annotations

from typing import Any, Dict

from tools.common import command_only_parameters, parse_exact_command_arguments


TOOL_NAME = "emit_authoritative_terminal_output"


def tool_definition(command: str) -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": TOOL_NAME,
            "description": (
                "Return the authoritative Ubuntu terminal output for the current command. "
                "Use this tool instead of generating or correcting terminal text yourself."
            ),
            "parameters": command_only_parameters(command),
            "strict": True,
        },
    }


def execute_tool_call(
    tool_name: str,
    arguments: str,
    original_command: str,
    authoritative_output: str,
) -> str:
    if tool_name != TOOL_NAME:
        raise ValueError(f"unknown tool: {tool_name}")
    parse_exact_command_arguments(arguments, original_command)
    if not isinstance(authoritative_output, str):
        raise ValueError("authoritative output must be text")
    return authoritative_output
