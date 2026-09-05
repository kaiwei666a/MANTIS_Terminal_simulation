
from __future__ import annotations

import re
import shlex
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Tuple

from tools.ubuntu_ls import resolve_path_entry
from tools.ubuntu_sysinfo_tools import render_uname, render_date_now
from tools.ubuntu_top_tool import render_ps_aux


def _identity(system_log: Dict[str, Any]) -> Tuple[str, int, int, str]:
    identity = system_log.get("identity") or {}
    username = str(identity.get("user") or "user")
    uid = int(identity.get("uid", 1000) or 0)
    gid = int(identity.get("gid", 1000) or 0)
    home = str(identity.get("home") or ("/root" if uid == 0 else f"/home/{username}"))
    return username, uid, gid, home


def _passwd(system_log: Dict[str, Any]) -> str:
    username, uid, gid, home = _identity(system_log)
    rows = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "sync:x:4:65534:sync:/bin:/bin/sync",
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
    ]
    if username != "root":
        rows.append(f"{username}:x:{uid}:{gid}:{username}:{home}:/bin/bash")
    return "\n".join(rows) + "\n"


def _group(system_log: Dict[str, Any]) -> str:
    username, _, gid, _ = _identity(system_log)
    rows = [
        "root:x:0:",
        "daemon:x:1:",
        "bin:x:2:",
        "sys:x:3:",
        "adm:x:4:",
        "tty:x:5:",
        "disk:x:6:",
        "lp:x:7:",
        "mail:x:8:",
        "sudo:x:27:",
        "nogroup:x:65534:",
    ]
    if username != "root" and str(gid) not in {"0", "27"}:
        rows.append(f"{username}:x:{gid}:")
    return "\n".join(rows) + "\n"


def _hosts(system_log: Dict[str, Any]) -> str:
    identity = system_log.get("identity") or {}
    hostname = str(identity.get("hostname") or "localhost")
    return (
        "127.0.0.1 localhost\n"
        f"127.0.1.1 {hostname}\n\n"
        "# The following lines are desirable for IPv6 capable hosts\n"
        "::1     ip6-localhost ip6-loopback\n"
        "fe00::0 ip6-localnet\n"
        "ff00::0 ip6-mcastprefix\n"
        "ff02::1 ip6-allnodes\n"
        "ff02::2 ip6-allrouters\n"
    )


def _resolv_conf() -> str:
    return (
        "# This file is managed by man:systemd-resolved(8). Do not edit.\n"
        "#\n"
        "# This is a dynamic resolv.conf file for connecting local clients to the\n"
        "# internal DNS stub resolver of systemd-resolved. This file lists all\n"
        "# configured search domains.\n"
        "#\n"
        "# Run \"resolvectl status\" to see details about the uplink DNS servers\n"
        "# currently in use.\n"
        "#\n"
        "# Third party programs should typically not access this file directly, but\n"
        "# only through the symlink at /etc/resolv.conf. To manage man:resolv.conf(5)\n"
        "# in a different way, replace this symlink by a static file or a different\n"
        "# symlink.\n"
        "nameserver 127.0.0.53\n"
        "options edns0 trust-ad\n"
    )


_ROOT_ONLY_ETC_FILES = {"/etc/shadow", "/etc/sudoers", "/etc/gshadow"}


def _read_file(system_log: Dict[str, Any], target: str) -> Tuple[Optional[str], Optional[str]]:
    if target == "/etc/passwd":
        return _passwd(system_log), None
    if target == "/etc/group":
        return _group(system_log), None
    if target == "/etc/hosts":
        return _hosts(system_log), None
    if target == "/etc/resolv.conf":
        return _resolv_conf(), None
    if target in _ROOT_ONLY_ETC_FILES:
        _, uid, _, _ = _identity(system_log)
        if uid != 0:
            return None, "Permission denied"
    _, kind, metadata, parent = resolve_path_entry(system_log, target)
    if kind == "missing":
        return None, "No such file or directory"
    if kind == "dir":
        return None, "Is a directory"
    name = PurePosixPath(target).name
    contents = (parent or {}).get("file_contents") or {}
    if name in contents:
        return str(contents.get(name) or ""), None
    size = int((metadata or {}).get("size", 0) or 0)
    return ("\x00" * min(size, 4096)), None


def _render_cat(tokens: List[str], system_log: Dict[str, Any]) -> Optional[str]:
    args = tokens[1:]
    if not args or any(arg.startswith("-") and arg != "--" for arg in args):
        return None
    if args and args[0] == "--":
        args = args[1:]
    outputs: List[str] = []
    errors: List[str] = []
    for target in args:
        content, error = _read_file(system_log, target)
        if error:
            errors.append(f"cat: {target}: {error}")
        else:
            outputs.append(content or "")
    return "\n".join(errors) + (("\n" if errors and outputs else "") + "".join(outputs)).rstrip("\n")


def _render_grep(tokens: List[str], system_log: Dict[str, Any]) -> Optional[str]:
    ignore_case = False
    line_numbers = False
    invert = False
    fixed = False
    index = 1
    while index < len(tokens) and tokens[index].startswith("-") and tokens[index] != "-":
        token = tokens[index]
        if token == "--":
            index += 1
            break
        for flag in token[1:]:
            if flag == "i":
                ignore_case = True
            elif flag == "n":
                line_numbers = True
            elif flag == "v":
                invert = True
            elif flag == "F":
                fixed = True
            elif flag == "E":
                pass
            else:
                return None
        index += 1
    if index >= len(tokens):
        return "grep: missing search pattern"
    pattern = tokens[index]
    files = tokens[index + 1:]
    if not files:
        return None
    flags = re.IGNORECASE if ignore_case else 0
    try:
        matcher = re.compile(re.escape(pattern) if fixed else pattern, flags)
    except re.error as exc:
        return f"grep: {exc}"

    output: List[str] = []
    multiple = len(files) > 1
    for target in files:
        content, error = _read_file(system_log, target)
        if error:
            output.append(f"grep: {target}: {error}")
            continue
        for number, line in enumerate((content or "").splitlines(), 1):
            matched = matcher.search(line) is not None
            if matched == invert:
                continue
            prefix = f"{target}:" if multiple else ""
            if line_numbers:
                prefix += f"{number}:"
            output.append(prefix + line)
    return "\n".join(output)


def _display_child(display: str, name: str) -> str:
    base = display.rstrip("/")
    if base in {"", "."}:
        return f"./{name}"
    if base == "/":
        return f"/{name}"
    return f"{base}/{name}"


def _walk_empty(node: Dict[str, Any], display: str) -> List[str]:
    rows: List[str] = []
    files = list(node.get("files") or [])
    folders = node.get("folders") or {}
    meta = node.get("file_meta") or {}
    contents = node.get("file_contents") or {}
    for name in files:
        size = int((meta.get(name) or {}).get("size", len(str(contents.get(name, "")).encode("utf-8"))) or 0)
        if size == 0:
            rows.append(_display_child(display, name))
    for name, child in folders.items():
        if not isinstance(child, dict):
            continue
        child_display = _display_child(display, name)
        rows.extend(_walk_empty(child, child_display))
        if not (child.get("files") or []) and not (child.get("folders") or {}):
            rows.append(child_display)
    if not files and not folders:
        rows.append(display)
    return list(dict.fromkeys(rows))


def _render_find(tokens: List[str], system_log: Dict[str, Any]) -> Optional[str]:
    if len(tokens) != 3 or tokens[2] != "-empty":
        return None
    target = tokens[1]
    _, kind, node, _ = resolve_path_entry(system_log, target)
    if kind == "missing":
        return f"find: ‘{target}’: No such file or directory"
    if kind == "file":
        size = int((node or {}).get("size", 0) or 0)
        return target if size == 0 else ""
    return "\n".join(_walk_empty(node or {}, target.rstrip("/") or "/"))


def _file_kib(meta: Dict[str, Any]) -> int:
    blocks = int(meta.get("blocks", 0) or 0)
    if blocks:
        return (blocks * 512 + 1023) // 1024
    return 4 if int(meta.get("size", 0) or 0) > 0 else 0


def _du_directory(node: Dict[str, Any], display: str, include_files: bool) -> Tuple[int, List[Tuple[int, str]]]:
    total = 4
    rows: List[Tuple[int, str]] = []
    meta = node.get("file_meta") or {}
    for name in node.get("files") or []:
        size = _file_kib(meta.get(name) or {})
        total += size
        if include_files:
            rows.append((size, _display_child(display, name)))
    for name, child in (node.get("folders") or {}).items():
        if not isinstance(child, dict):
            continue
        child_display = _display_child(display, name)
        child_total, child_rows = _du_directory(child, child_display, include_files)
        total += child_total
        rows.extend(child_rows)
        rows.append((child_total, child_display))
    return total, rows


def _human_kib(value: int) -> str:
    if value < 1024:
        return f"{value}K"
    amount = value / 1024.0
    return f"{amount:.1f}M" if amount < 10 and not amount.is_integer() else f"{amount:.0f}M"


def _render_du(tokens: List[str], system_log: Dict[str, Any]) -> Optional[str]:
    include_files = False
    summarize = False
    human = False
    targets: List[str] = []
    for token in tokens[1:]:
        if token.startswith("-") and token != "-":
            for flag in token[1:]:
                if flag == "a":
                    include_files = True
                elif flag == "s":
                    summarize = True
                elif flag == "h":
                    human = True
                else:
                    return None
        else:
            targets.append(token)
    targets = targets or ["."]
    rendered: List[str] = []
    for target in targets:
        _, kind, node, _ = resolve_path_entry(system_log, target)
        if kind == "missing":
            rendered.append(f"du: cannot access '{target}': No such file or directory")
            continue
        if kind == "file":
            total = _file_kib(node or {})
            rows = [(total, target)]
        else:
            total, rows = _du_directory(node or {}, target.rstrip("/") or "/", include_files)
            if summarize:
                rows = [(total, target)]
            else:
                rows.append((total, target))
        for size, name in rows:
            rendered.append(f"{_human_kib(size) if human else size}\t{name}")
    return "\n".join(rendered)


_ROOT_TOTAL_KIB = 20 * 1024 * 1024
_ROOT_BASE_USED_KIB = 3_145_728
_BOOT_EFI_TOTAL_KIB = 104_856
_BOOT_EFI_USED_KIB = 6_248


def _filesystem_used_kib(system_log: Dict[str, Any]) -> int:
    filesystem = system_log.get("filesystem") or {}
    total = 0
    for path, node in filesystem.items():
        if not isinstance(node, dict):
            continue
        node_total, _ = _du_directory(node, path, include_files=False)
        total += node_total
    return total


def _tmpfs_total_kib(system_log: Dict[str, Any]) -> int:
    mem = system_log.get("memory") or {}
    total_mib = float(mem.get("total_mib", 0.0) or 0.0)
    if total_mib <= 0:
        total_mib = 3200.0
    return int(total_mib * 1024 / 2)


def _disk_mounts(system_log: Dict[str, Any]) -> List[Dict[str, Any]]:
    used_kib = min(_ROOT_BASE_USED_KIB + _filesystem_used_kib(system_log), _ROOT_TOTAL_KIB - 1024)
    tmpfs_total = _tmpfs_total_kib(system_log)
    run_total = max(1024, tmpfs_total // 5)
    return [
        {"device": "udev", "fstype": "devtmpfs", "mount": "/dev", "total": tmpfs_total, "used": 0, "opts": "rw,nosuid,relatime,size=" + str(tmpfs_total) + "k"},
        {"device": "tmpfs", "fstype": "tmpfs", "mount": "/run", "total": run_total, "used": 1900, "opts": "rw,nosuid,nodev,noexec,relatime,mode=755"},
        {"device": "/dev/sda1", "fstype": "ext4", "mount": "/", "total": _ROOT_TOTAL_KIB, "used": used_kib, "opts": "rw,relatime,errors=remount-ro"},
        {"device": "tmpfs", "fstype": "tmpfs", "mount": "/dev/shm", "total": tmpfs_total, "used": 0, "opts": "rw,nosuid,nodev"},
        {"device": "tmpfs", "fstype": "tmpfs", "mount": "/run/lock", "total": 5120, "used": 0, "opts": "rw,nosuid,nodev,noexec,relatime,size=5120k"},
        {"device": "/dev/sda15", "fstype": "vfat", "mount": "/boot/efi", "total": _BOOT_EFI_TOTAL_KIB, "used": _BOOT_EFI_USED_KIB, "opts": "rw,relatime,fmask=0077,dmask=0077"},
        {"device": "tmpfs", "fstype": "tmpfs", "mount": "/run/user/1000", "total": run_total, "used": 0, "opts": "rw,nosuid,nodev,relatime,size=" + str(run_total) + "k,uid=1000,gid=1000"},
    ]


def _human_kib_df(kib: int) -> str:
    gib = kib / (1024.0 * 1024.0)
    if gib >= 1:
        return f"{gib:.1f}G"
    mib = kib / 1024.0
    if mib >= 1:
        return f"{mib:.0f}M"
    return f"{kib}K"


def _render_df(tokens: List[str], system_log: Dict[str, Any]) -> Optional[str]:
    human = False
    for token in tokens[1:]:
        if token in ("-h", "--human-readable"):
            human = True
        else:
            return None
    mounts = _disk_mounts(system_log)
    if human:
        lines = ["Filesystem      Size  Used Avail Use% Mounted on"]
        for m in mounts:
            avail = m["total"] - m["used"]
            pct = f"{round(m['used'] * 100.0 / m['total']) if m['total'] else 0}%"
            lines.append(
                f"{m['device']:<15} {_human_kib_df(m['total']):>4} {_human_kib_df(m['used']):>5} "
                f"{_human_kib_df(avail):>5} {pct:>4} {m['mount']}"
            )
        return "\n".join(lines)
    lines = ["Filesystem     1K-blocks     Used Available Use% Mounted on"]
    for m in mounts:
        avail = m["total"] - m["used"]
        pct = f"{round(m['used'] * 100.0 / m['total']) if m['total'] else 0}%"
        lines.append(
            f"{m['device']:<15} {m['total']:>9} {m['used']:>8} {avail:>9} {pct:>4} {m['mount']}"
        )
    return "\n".join(lines)


def _render_mount(tokens: List[str], system_log: Dict[str, Any]) -> Optional[str]:
    if len(tokens) != 1:
        return None
    lines = []
    for m in _disk_mounts(system_log):
        lines.append(f"{m['device']} on {m['mount']} type {m['fstype']} ({m['opts']})")
    return "\n".join(lines)


def render_ps(command: str, system_log: Dict[str, Any], processes: List[Dict[str, Any]]) -> Optional[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not tokens or tokens[0] != "ps" or tokens[1:] not in (["-a"], ["-f"]):
        return None
    username, _, _, _ = _identity(system_log)
    shell = next((p for p in processes if str(p.get("cmd") or "").endswith("bash")), None)
    shell_pid = int((shell or {}).get("pid", 613) or 613)
    ps_pid = max([shell_pid, *(int(p.get("pid", 0) or 0) for p in processes)]) + 1
    if tokens[1] == "-a":
        return "\n".join([
            "    PID TTY          TIME CMD",
            f"{ps_pid:7d} pts/0    00:00:00 ps",
        ])
    now = datetime.now()
    return "\n".join([
        "UID          PID    PPID  C STIME TTY          TIME CMD",
        f"{username:<8} {shell_pid:7d}     123  0 {now:%H:%M} pts/0    00:00:00 -bash",
        f"{username:<8} {ps_pid:7d} {shell_pid:7d}  0 {now:%H:%M} pts/0    00:00:00 ps -f",
    ])


def _render_ssh(tokens: List[str]) -> Optional[str]:
    if len(tokens) != 2 or tokens[0] != "ssh":
        return None
    destination = tokens[1]
    host = destination.rsplit("@", 1)[-1]
    if host not in {"127.0.0.1", "localhost"}:
        return None
    return f"ssh: connect to host {host} port 22: Connection refused"


def _render_ss(tokens: List[str], system_log: Dict[str, Any]) -> Optional[str]:
    if len(tokens) != 2 or tokens[0] != "ss" or tokens[1] not in {"-tulpn", "-lntup", "-tunlp"}:
        return None
    lines = ["Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process"]
    listeners = ((system_log.get("network") or {}).get("listening_ports") or [])
    for item in listeners:
        if not isinstance(item, dict):
            continue
        protocol = str(item.get("proto") or "tcp")
        address = str(item.get("ip") or "0.0.0.0")
        port = int(item.get("port", 0) or 0)
        process = str(item.get("process") or "unknown")
        pid = int(item.get("pid", 0) or 0)
        lines.append(
            f"{protocol:<5} LISTEN 0      128    {address}:{port:<10} 0.0.0.0:*         "
            f'users:(("{process}",pid={pid},fd=3))'
        )
    return "\n".join(lines)


def render_stateful_read(command: str, system_log: Dict[str, Any]) -> Optional[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        return f"bash: syntax error: {exc}"
    if not tokens:
        return ""
    if tokens[0] == "cat":
        return _render_cat(tokens, system_log)
    if tokens[0] == "grep":
        return _render_grep(tokens, system_log)
    if tokens[0] == "find":
        return _render_find(tokens, system_log)
    if tokens[0] == "du":
        return _render_du(tokens, system_log)
    if tokens[0] == "df":
        return _render_df(tokens, system_log)
    if tokens[0] == "mount":
        return _render_mount(tokens, system_log)
    if tokens[0] == "ssh":
        return _render_ssh(tokens)
    if tokens[0] == "ss":
        return _render_ss(tokens, system_log)
    if tokens == ["python3", "--version"]:
        return "Python 3.11.2"
    return None


def render_authoritative_shell_output(
    command: str,
    prior_status: int,
    system_log: Dict[str, Any],
    current_path: str,
    login_username: str,
    hostname: str,
    history: List[str],
    get_processes: Callable[[], List[Dict[str, Any]]],
) -> Optional[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return ""
    tool = tokens[0]
    identity = system_log.get("identity", {}) or {}
    active_user = str(identity.get("user") or login_username)
    uid = int(identity.get("uid", 1000) or 0)
    gid = int(identity.get("gid", 1000) or 0)

    if command == "pwd":
        return current_path
    if command == "whoami":
        return active_user
    if command == "id":
        return f"uid={uid}({active_user}) gid={gid}({active_user}) groups={gid}({active_user})"
    if command == "hostname":
        return hostname
    if tool == "uname":
        return render_uname(command, hostname)
    if command == "date":
        return render_date_now()
    if command in ("ps aux", "ps -aux"):
        return render_ps_aux(get_processes())
    if tool == "ps":
        rendered_ps = render_ps(command, system_log, get_processes())
        if rendered_ps is not None:
            return rendered_ps
    if command == "history":
        return "\n".join(f"{index:5d}  {entry}" for index, entry in enumerate(history, 1))
    if command in ("true", "false", "clear"):
        return ""
    if tool == "echo" and len(tokens) == 2:
        variables = {
            "$?": str(prior_status),
            "$HOME": str(identity.get("home") or "/home/user"),
            "$USER": active_user,
            "$LOGNAME": active_user,
            "$SHELL": str(identity.get("shell") or "/bin/bash"),
            "$PWD": current_path,
            "$OLDPWD": str(system_log.get("oldpwd") or ""),
        }
        for name, value in (system_log.get("environment") or {}).items():
            if isinstance(name, str):
                variables[f"${name}"] = str(value)
        if tokens[1] in variables:
            return variables[tokens[1]]
    return None


def command_exit_status(command: str, output: str, classification: str, system_log: Dict[str, Any]) -> int:
    if command == "false":
        return 1
    if command == "true" or command == "clear" or command == "history":
        return 0
    if classification == "rejection":
        return 127
    if command == "ip" or output.startswith("Option \"") or output.startswith("Object \""):
        return 255
    if re.match(r"^\s*cd(?:\s|$)", command):
        return 1 if str(system_log.get("last_output") or "") else 0
    if re.match(r"^\s*rmdir(?:\s|$)", command):
        return 1 if str(system_log.get("last_output") or "") else 0
    if output.startswith("ls: ") or ": command not found" in output:
        return 2 if output.startswith("ls: ") else 127
    if re.search(r"(?:No such file or directory|Not a directory|Permission denied)", output):
        return 1
    return 0
