
from __future__ import annotations

import shlex
import re
from typing import Any, Dict, List, Optional

from tools.ubuntu_ls import resolve_path_entry


SUPPORTED_COMMANDS = {"chmod", "chown", "mkdir", "rm", "rmdir"}


def is_deterministic_fs_write(command: str, system_log: Optional[Dict[str, Any]] = None) -> bool:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    if not tokens:
        return False
    if tokens[0] in SUPPORTED_COMMANDS:
        return True
    if tokens[0] == "echo" and any(token in {">", ">>"} for token in tokens[1:]):
        return True
    if tokens[0] in {"apt", "apt-get"} and system_log is not None:
        identity = system_log.get("identity") or {}
        return int(identity.get("euid", identity.get("uid", 1000)) or 0) != 0
    return False


def _result(output: List[str], mutations: List[Dict[str, Any]], failed: bool) -> Dict[str, Any]:
    return {
        "terminal_output": "\n".join(output),
        "exit_status": 1 if failed else 0,
        "mutations": mutations,
    }


def _plan_rm(tokens: List[str], system_log: Dict[str, Any]) -> Dict[str, Any]:
    recursive = False
    force = False
    operands: List[str] = []
    parsing_options = True
    for token in tokens[1:]:
        if parsing_options and token == "--":
            parsing_options = False
            continue
        if parsing_options and token.startswith("--"):
            if token == "--recursive":
                recursive = True
            elif token == "--force":
                force = True
            elif token in {"--help", "--version"}:
                return {
                    "terminal_output": "Usage: rm [OPTION]... [FILE]..." if token == "--help" else "rm (GNU coreutils) 8.32",
                    "exit_status": 0,
                    "mutations": [],
                }
            else:
                return _result([f"rm: unrecognized option '{token}'", "Try 'rm --help' for more information."], [], True)
            continue
        if parsing_options and token.startswith("-") and token != "-":
            for flag in token[1:]:
                if flag in {"r", "R"}:
                    recursive = True
                elif flag == "f":
                    force = True
                else:
                    return _result([f"rm: invalid option -- '{flag}'", "Try 'rm --help' for more information."], [], True)
            continue
        operands.append(token)

    if not operands:
        if force:
            return _result([], [], False)
        return _result(["rm: missing operand", "Try 'rm --help' for more information."], [], True)

    output: List[str] = []
    mutations: List[Dict[str, Any]] = []
    failed = False
    for operand in operands:
        absolute, kind, _, _ = resolve_path_entry(system_log, operand)
        if kind == "missing":
            if not force:
                output.append(f"rm: cannot remove '{operand}': No such file or directory")
                failed = True
            continue
        if kind == "dir" and not recursive:
            output.append(f"rm: cannot remove '{operand}': Is a directory")
            failed = True
            continue
        mutations.append({"op": "remove_path", "path": absolute, "recursive": kind == "dir"})
    return _result(output, mutations, failed)


def _plan_mkdir(tokens: List[str], system_log: Dict[str, Any]) -> Dict[str, Any]:
    parents = False
    operands: List[str] = []
    parsing_options = True
    for token in tokens[1:]:
        if parsing_options and token == "--":
            parsing_options = False
            continue
        if parsing_options and token in {"-p", "--parents"}:
            parents = True
            continue
        if parsing_options and token == "--help":
            return {"terminal_output": "Usage: mkdir [OPTION]... DIRECTORY...", "exit_status": 0, "mutations": []}
        if parsing_options and token == "--version":
            return {"terminal_output": "mkdir (GNU coreutils) 8.32", "exit_status": 0, "mutations": []}
        if parsing_options and token.startswith("-") and token != "-":
            if token.startswith("--"):
                return _result([f"mkdir: unrecognized option '{token}'", "Try 'mkdir --help' for more information."], [], True)
            return _result([f"mkdir: invalid option -- '{token[1:2]}'", "Try 'mkdir --help' for more information."], [], True)
        operands.append(token)
    if not operands:
        return _result(["mkdir: missing operand", "Try 'mkdir --help' for more information."], [], True)

    output: List[str] = []
    mutations: List[Dict[str, Any]] = []
    failed = False
    for operand in operands:
        absolute, kind, _, _ = resolve_path_entry(system_log, operand)
        if kind != "missing":
            if not parents:
                output.append(f"mkdir: cannot create directory ‘{operand}’: File exists")
                failed = True
            continue
        parent = absolute.rsplit("/", 1)[0] or "/"
        _, parent_kind, _, _ = resolve_path_entry(system_log, parent)
        if not parents and parent_kind != "dir":
            output.append(f"mkdir: cannot create directory ‘{operand}’: No such file or directory")
            failed = True
            continue
        mutations.append({"op": "make_directory", "path": absolute, "parents": parents})
    return _result(output, mutations, failed)


def _plan_rmdir(tokens: List[str], system_log: Dict[str, Any]) -> Dict[str, Any]:
    ignore_nonempty = False
    operands: List[str] = []
    parsing_options = True
    for token in tokens[1:]:
        if parsing_options and token == "--":
            parsing_options = False
            continue
        if parsing_options and token.startswith("--"):
            if token == "--ignore-fail-on-non-empty":
                ignore_nonempty = True
            elif token == "--help":
                return {"terminal_output": "Usage: rmdir [OPTION]... DIRECTORY...", "exit_status": 0, "mutations": []}
            elif token == "--version":
                return {"terminal_output": "rmdir (GNU coreutils) 8.32", "exit_status": 0, "mutations": []}
            else:
                return _result([f"rmdir: unrecognized option '{token}'", "Try 'rmdir --help' for more information."], [], True)
            continue
        if parsing_options and token.startswith("-") and token != "-":
            flag = token[1:2] or token
            return _result([f"rmdir: invalid option -- '{flag}'", "Try 'rmdir --help' for more information."], [], True)
        operands.append(token)

    if not operands:
        return _result(["rmdir: missing operand", "Try 'rmdir --help' for more information."], [], True)
    output: List[str] = []
    mutations: List[Dict[str, Any]] = []
    failed = False
    for operand in operands:
        absolute, kind, node, _ = resolve_path_entry(system_log, operand)
        if kind == "missing":
            output.append(f"rmdir: failed to remove '{operand}': No such file or directory")
            failed = True
        elif kind == "file":
            output.append(f"rmdir: failed to remove '{operand}': Not a directory")
            failed = True
        elif (node or {}).get("files") or (node or {}).get("folders"):
            if not ignore_nonempty:
                output.append(f"rmdir: failed to remove '{operand}': Directory not empty")
                failed = True
        else:
            mutations.append({"op": "remove_path", "path": absolute, "recursive": False})
    return _result(output, mutations, failed)


def _plan_chown(tokens: List[str], system_log: Dict[str, Any]) -> Dict[str, Any]:
    if len(tokens) < 2:
        return _result(["chown: missing operand", "Try 'chown --help' for more information."], [], True)
    if len(tokens) < 3:
        return _result([f"chown: missing operand after ‘{tokens[1]}’", "Try 'chown --help' for more information."], [], True)
    if any(token.startswith("-") for token in tokens[1:]):
        bad = next(token for token in tokens[1:] if token.startswith("-"))
        return _result([f"chown: invalid option -- '{bad.lstrip('-')[:1]}'", "Try 'chown --help' for more information."], [], True)

    owner_spec = tokens[1]
    user, separator, group = owner_spec.partition(":")
    identity = system_log.get("identity") or {}
    active_user = str(identity.get("user") or "user")
    euid = int(identity.get("euid", identity.get("uid", 1000)) or 0)
    valid_users = {"root", active_user}
    if user not in valid_users:
        return _result([f"chown: invalid user: ‘{owner_spec}’"], [], True)

    output: List[str] = []
    mutations: List[Dict[str, Any]] = []
    failed = False
    for operand in tokens[2:]:
        absolute, kind, _, _ = resolve_path_entry(system_log, operand)
        if kind == "missing":
            output.append(f"chown: cannot access '{operand}': No such file or directory")
            failed = True
            continue
        requested_group: Optional[str] = group if separator else None
        if euid != 0 and (user != active_user or requested_group not in {None, active_user}):
            output.append(f"chown: changing ownership of '{operand}': Operation not permitted")
            failed = True
            continue
        mutations.append({"op": "change_owner", "path": absolute, "user": user, "group": requested_group})
    return _result(output, mutations, failed)


def _plan_chmod(tokens: List[str], system_log: Dict[str, Any]) -> Dict[str, Any]:
    if len(tokens) < 2:
        return _result(["chmod: missing operand", "Try 'chmod --help' for more information."], [], True)
    if len(tokens) < 3:
        return _result([f"chmod: missing operand after ‘{tokens[1]}’", "Try 'chmod --help' for more information."], [], True)
    mode = tokens[1]
    if not re.fullmatch(r"(?:[0-7]{3,4}|[ugoa]*[+\-=][rwxXst]+(?:,[ugoa]*[+\-=][rwxXst]+)*)", mode):
        if mode.startswith("-"):
            return _result([f"chmod: invalid option -- '{mode[1:2]}'", "Try 'chmod --help' for more information."], [], True)
        return _result([f"chmod: invalid mode: ‘{mode}’", "Try 'chmod --help' for more information."], [], True)
    output: List[str] = []
    mutations: List[Dict[str, Any]] = []
    failed = False
    for operand in tokens[2:]:
        if operand.startswith("-"):
            return _result([f"chmod: invalid option -- '{operand[1:2]}'", "Try 'chmod --help' for more information."], [], True)
        absolute, kind, _, _ = resolve_path_entry(system_log, operand)
        if kind == "missing":
            output.append(f"chmod: cannot access '{operand}': No such file or directory")
            failed = True
            continue
        mutations.append({"op": "change_mode", "path": absolute, "mode": mode})
    return _result(output, mutations, failed)


def _plan_echo_redirect(tokens: List[str], system_log: Dict[str, Any]) -> Dict[str, Any]:
    operators = [index for index, token in enumerate(tokens) if token in {">", ">>"}]
    if len(operators) != 1:
        raise ValueError("unsupported echo redirection")
    index = operators[0]
    if index + 2 != len(tokens):
        raise ValueError("unsupported echo redirection")
    target = tokens[index + 1]
    absolute, kind, _, _ = resolve_path_entry(system_log, target)
    if kind == "dir":
        return _result([f"bash: {target}: Is a directory"], [], True)
    parent = absolute.rsplit("/", 1)[0] or "/"
    _, parent_kind, _, _ = resolve_path_entry(system_log, parent)
    if parent_kind != "dir":
        return _result([f"bash: {target}: No such file or directory"], [], True)
    content = " ".join(tokens[1:index]) + "\n"
    return {
        "terminal_output": "",
        "exit_status": 0,
        "mutations": [{
            "op": "write_file",
            "path": absolute,
            "content": content,
            "append": tokens[index] == ">>",
        }],
    }


def plan_deterministic_fs_write(command: str, system_log: Dict[str, Any]) -> Dict[str, Any]:
    background = re.fullmatch(r"\s*mkdir\s*&\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*", command)
    if background:
        following = background.group(1)
        return _result(
            [
                "[1] 2001",
                f"bash: {following}: command not found",
                "mkdir: missing operand",
                "Try 'mkdir --help' for more information.",
                "[1]+  Exit 1                  mkdir",
            ],
            [],
            True,
        )
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        return _result([f"bash: syntax error: {exc}"], [], True)
    if not tokens:
        raise ValueError("unsupported deterministic filesystem command")
    if tokens[0] == "echo":
        return _plan_echo_redirect(tokens, system_log)
    if tokens[0] in {"apt", "apt-get"}:
        identity = system_log.get("identity") or {}
        if int(identity.get("euid", identity.get("uid", 1000)) or 0) == 0:
            raise ValueError("root package command belongs to the general command planner")
        return _result(
            [
                "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)",
                "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?",
            ],
            [],
            True,
        )
    if tokens[0] not in SUPPORTED_COMMANDS:
        raise ValueError("unsupported deterministic filesystem command")
    if tokens[0] == "mkdir":
        return _plan_mkdir(tokens, system_log)
    if tokens[0] == "chmod":
        return _plan_chmod(tokens, system_log)
    if tokens[0] == "rm":
        return _plan_rm(tokens, system_log)
    if tokens[0] == "rmdir":
        return _plan_rmdir(tokens, system_log)
    return _plan_chown(tokens, system_log)
