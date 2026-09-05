
from __future__ import annotations

import shlex
from typing import Any, Dict, Optional

from tools.common import now_eastern


def render_uname(command: str, hostname: str) -> Optional[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens or tokens[0] != "uname":
        return None
    fields = {
        "s": "Linux",
        "n": hostname,
        "r": "5.15.0-84-generic",
        "v": "#93-Ubuntu SMP Tue Sep 5 17:01:00 UTC 2023",
        "m": "x86_64",
        "p": "x86_64",
        "i": "x86_64",
        "o": "GNU/Linux",
    }
    if len(tokens) == 1:
        return fields["s"]
    flags = "".join(token[1:] for token in tokens[1:] if token.startswith("-"))
    if "a" in flags:
        flags = "snrvmpio"
    order = "snrvmpio"
    selected = [fields[key] for key in order if key in flags]
    if not selected:
        bad = tokens[1]
        return f"uname: extra operand ‘{bad}’\nTry 'uname --help' for more information."
    return " ".join(selected)


def render_date_now() -> str:
    now = now_eastern()
    day = f"{now.day:2d}"
    return f"{now:%a %b} {day} {now:%H:%M:%S %Z %Y}"


def format_shell_prompt(
    login_username: str,
    hostname: str,
    current_path: str,
    identity: Dict[str, Any],
) -> str:
    active_user = str(identity.get("user") or login_username)
    euid = int(identity.get("euid", identity.get("uid", 1000)) or 0)
    home_path = str(identity.get("home") or ("/root" if active_user == "root" else f"/home/{active_user}"))
    if current_path == home_path:
        display_path = "~"
    elif current_path.startswith(home_path + "/"):
        display_path = "~" + current_path[len(home_path):]
    else:
        display_path = current_path
    prompt_char = "#" if euid == 0 else "$"
    return f"{active_user}@{hostname}:{display_path}{prompt_char} "
