
from __future__ import annotations

import shlex
from typing import List, Optional


SUPPORTED = "supported"
DEFER_TO_LLM = "defer_to_llm"


_LOCAL_WRITE_COMMANDS = {
    "cd",
    "chmod",
    "chown",
    "cp",
    "curl",
    "echo",
    "git",
    "mkdir",
    "mv",
    "python",
    "python3",
    "rm",
    "rmdir",
    "su",
    "sudo",
    "systemctl",
    "touch",
    "wget",
}


def _contains_shell_syntax(command: str) -> bool:
    single = False
    double = False
    escaped = False
    for char in command:
        if escaped:
            escaped = False
            continue
        if char == "\\" and not single:
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
            continue
        if char == '"' and not single:
            double = not double
            continue
        if not single and not double and char in ";|&<>":
            return True
    return False


def _has_option(tokens: List[str], start: int = 1) -> bool:
    for token in tokens[start:]:
        if token == "--":
            return True
        if token.startswith("-") and token != "-":
            return True
    return False


def local_write_capability(command: str) -> Optional[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return DEFER_TO_LLM
    if not tokens or tokens[0] not in _LOCAL_WRITE_COMMANDS:
        return None
    if _contains_shell_syntax(command):
        return DEFER_TO_LLM

    tool = tokens[0]

    if tool == "touch":
        return DEFER_TO_LLM

    if tool == "cd":
        if len(tokens) == 1:
            return SUPPORTED
        if len(tokens) == 2 and (tokens[1] == "-" or not tokens[1].startswith("-")):
            return SUPPORTED
        return DEFER_TO_LLM

    if tool == "mkdir":
        return DEFER_TO_LLM

    if tool in {"rm", "rmdir"}:
        return DEFER_TO_LLM

    if tool == "mv":
        return SUPPORTED if len(tokens) == 3 and not _has_option(tokens) else DEFER_TO_LLM

    if tool == "cp":
        if len(tokens) == 3 and not _has_option(tokens):
            return SUPPORTED
        if len(tokens) == 4 and tokens[1] == "-r":
            return SUPPORTED
        return DEFER_TO_LLM

    if tool == "chmod":
        return DEFER_TO_LLM

    if tool == "chown":
        return DEFER_TO_LLM

    if tool == "systemctl":
        if len(tokens) == 3 and tokens[1] in {"enable", "disable"} and not tokens[2].startswith("-"):
            return SUPPORTED
        return DEFER_TO_LLM

    if tool in {"python", "python3"}:
        if len(tokens) in {3, 4} and tokens[1:3] == ["-m", "http.server"]:
            if len(tokens) == 3 or tokens[3].isdigit():
                return SUPPORTED
        return DEFER_TO_LLM

    if tool == "git":
        if len(tokens) in {3, 4} and tokens[1] == "clone" and not tokens[2].startswith("-"):
            return SUPPORTED
        return DEFER_TO_LLM

    if tool == "wget":
        return SUPPORTED if len(tokens) == 2 and not tokens[1].startswith("-") else DEFER_TO_LLM

    if tool in {"curl", "echo"}:
        return DEFER_TO_LLM

    if tool == "sudo":
        return SUPPORTED if len(tokens) == 2 and tokens[1] in {"-i", "-s", "--login", "--shell", "su"} else DEFER_TO_LLM

    if tool == "su":
        return SUPPORTED if len(tokens) <= 2 and not _has_option(tokens) else DEFER_TO_LLM

    return DEFER_TO_LLM
