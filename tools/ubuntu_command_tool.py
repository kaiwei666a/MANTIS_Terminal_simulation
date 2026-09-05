
from __future__ import annotations

from typing import Any, Dict

from tools.common import parse_exact_command_arguments


TOOL_NAME = "execute_ubuntu_command"


_MUTATION_PROPERTIES: Dict[str, Any] = {
    "op": {
        "type": "string",
        "enum": [
            "write_file",
            "touch_path",
            "remove_path",
            "make_directory",
            "move_path",
            "copy_path",
            "change_mode",
            "change_owner",
            "set_cwd",
            "set_service",
            "set_listener",
            "set_package",
            "set_environment",
            "set_process",
        ],
    },
    "path": {"type": "string"},
    "source": {"type": "string"},
    "destination": {"type": "string"},
    "content": {"type": "string"},
    "append": {"type": "boolean"},
    "mode": {"type": "string"},
    "create": {"type": "boolean"},
    "access_time": {"type": "boolean"},
    "modification_time": {"type": "boolean"},
    "timestamp": {"type": "string"},
    "atime": {"type": "string"},
    "mtime": {"type": "string"},
    "recursive": {"type": "boolean"},
    "parents": {"type": "boolean"},
    "user": {"type": "string"},
    "group": {"type": "string"},
    "name": {"type": "string"},
    "enabled": {"type": "boolean"},
    "port": {"type": "integer"},
    "protocol": {"type": "string", "enum": ["tcp", "udp"]},
    "process": {"type": "string"},
    "present": {"type": "boolean"},
    "version": {"type": "string"},
    "installed": {"type": "boolean"},
    "commands": {"type": "array", "items": {"type": "string"}},
    "value": {"type": "string"},
    "pid": {"type": "integer"},
    "command": {"type": "string"},
    "state": {"type": "string"},
}


def tool_definition(command: str) -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": TOOL_NAME,
            "description": (
                "Execute the exact command using Ubuntu 22.04/GNU utility semantics. Parse all short, "
                "combined-short, long, attached-value and -- option forms before identifying operands. "
                "Return realistic terminal output plus every persistent state mutation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "enum": [command],
                        "description": "The original terminal command, byte-for-byte unchanged.",
                    },
                    "terminal_output": {
                        "type": "string",
                        "description": "Raw Ubuntu terminal output without a prompt or Markdown.",
                    },
                    "exit_status": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 255,
                    },
                    "mutations": {
                        "type": "array",
                        "description": "All successful persistent effects, in execution order.",
                        "items": {
                            "type": "object",
                            "properties": _MUTATION_PROPERTIES,
                            "required": ["op"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["command", "terminal_output", "exit_status", "mutations"],
                "additionalProperties": False,
            },
        },
    }
def execute_tool_call(tool_name: str, arguments: str, original_command: str) -> Dict[str, Any]:
    if tool_name != TOOL_NAME:
        raise ValueError(f"unknown tool: {tool_name}")
    parsed = parse_exact_command_arguments(
        arguments,
        original_command,
        ("command", "terminal_output", "exit_status", "mutations"),
    )
    return {
        "terminal_output": parsed["terminal_output"],
        "exit_status": parsed["exit_status"],
        "mutations": parsed["mutations"],
    }
