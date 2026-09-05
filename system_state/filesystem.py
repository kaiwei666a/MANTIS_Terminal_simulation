
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple


ALLOWED_FS_ROOTS = {"/home/user", "/root", "/tmp", "/upload"}
DEFAULT_HOME = "/home/user"
EXT4_BLOCK_BYTES = 4096
STAT_BLOCK_BYTES = 512

CRITICAL_CONFIG_PATHS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/resolv.conf",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_file_mtime() -> str:
    return utc_now_iso()


def is_under_allowed_fs_roots(abs_path: str) -> bool:
    if any(
        abs_path == root or abs_path.startswith(root + "/") for root in ALLOWED_FS_ROOTS
    ):
        return True
    return re.match(r"^/home/[A-Za-z_][A-Za-z0-9_-]*(?:/|$)", abs_path) is not None


def normalize_path(cwd: str, target: str, home: str = DEFAULT_HOME) -> str:
    if not target or target == "~":
        return home
    if target.startswith("~/"):
        target = home.rstrip("/") + target[1:]
    abs_base = target if target.startswith("/") else f"{cwd.rstrip('/')}/{target}"
    p = PurePosixPath(abs_base)
    stack: List[str] = []
    for part in p.parts:
        if part in ("", "/"):
            continue
        if part == ".":
            continue
        if part == "..":
            if stack:
                stack.pop()
            continue
        stack.append(part)
    norm = "/" + "/".join(stack)
    if len(norm) > 1 and norm.endswith("/"):
        norm = norm.rstrip("/")
    return norm


def split_parent_child(abs_path: str) -> Tuple[str, str]:
    p = PurePosixPath(abs_path)
    parent = str(p.parent) if str(p.parent) != "." else "/"
    return parent, p.name


def ensure_dir_node(node: Dict[str, Any]) -> None:
    node.setdefault("files", [])
    node.setdefault("folders", {})
    node.setdefault("file_contents", {})
    node.setdefault("file_meta", {})
    node.setdefault("dir_mode", "drwxr-xr-x")
    node.setdefault("dir_mtime", "1970-01-01T00:00:00Z")
    node.setdefault("dir_uid", 1000)
    node.setdefault("dir_gid", 1000)
    node.setdefault("dir_size", EXT4_BLOCK_BYTES)
    node.setdefault("dir_blocks", EXT4_BLOCK_BYTES // STAT_BLOCK_BYTES)


def allocated_blocks_512(size: int) -> int:
    size = max(0, int(size))
    if size == 0:
        return 0
    return ((size + EXT4_BLOCK_BYTES - 1) // EXT4_BLOCK_BYTES) * (
        EXT4_BLOCK_BYTES // STAT_BLOCK_BYTES
    )


def ensure_file_meta(meta: Dict[str, Any]) -> None:
    meta.setdefault("mode", "-rw-r--r--")
    meta.setdefault("mode_octal", "0644")
    meta.setdefault("uid", 1000)
    meta.setdefault("gid", 1000)
    meta.setdefault("mtime", now_file_mtime())
    meta.setdefault("size", 0)
    meta.setdefault("blocks", allocated_blocks_512(int(meta.get("size", 0))))
    meta.setdefault("nlink", 1)
    meta.setdefault("hash", "")


def mode_string_from_octal(mode_octal: str, is_dir: bool = False) -> str:
    digits = re.sub(r"\D", "", mode_octal)[-3:].zfill(3)
    chars = ["d" if is_dir else "-"]
    for digit in digits:
        value = int(digit)
        chars.append("r" if value & 4 else "-")
        chars.append("w" if value & 2 else "-")
        chars.append("x" if value & 1 else "-")
    return "".join(chars)


def octal_from_mode_string(mode: str) -> str:
    perm = mode[1:10] if len(mode) >= 10 else mode.ljust(9, "-")
    digits = []
    for i in range(0, 9, 3):
        triplet = perm[i : i + 3]
        value = 0
        if len(triplet) > 0 and triplet[0] == "r":
            value += 4
        if len(triplet) > 1 and triplet[1] == "w":
            value += 2
        if len(triplet) > 2 and triplet[2] in ("x", "s", "t"):
            value += 1
        digits.append(str(value))
    return "0" + "".join(digits)


SYMBOLIC_CHMOD_CLAUSE = re.compile(r"^([ugoa]*)([+\-=])([rwxXst]*)$")


def apply_symbolic_chmod(mode: str, expr: str, is_dir: bool = False) -> str:
    if len(mode) < 10:
        mode = ("d" if is_dir else "-") + "-" * 9
    chars = list(mode)
    for clause in expr.split(","):
        clause = clause.strip()
        match = SYMBOLIC_CHMOD_CLAUSE.match(clause)
        if not match:
            continue
        who, op, perms = match.groups()
        who = who or "a"
        blocks = []
        if "u" in who or "a" in who:
            blocks.append(0)
        if "g" in who or "a" in who:
            blocks.append(1)
        if "o" in who or "a" in who:
            blocks.append(2)
        wants_exec = "x" in perms or "X" in perms
        for block in blocks:
            base = 1 + block * 3
            for offset, letter in enumerate("rwx"):
                idx = base + offset
                grant = letter == "r" and "r" in perms
                grant = grant or (letter == "w" and "w" in perms)
                grant = grant or (letter == "x" and wants_exec)
                if op == "+" and grant:
                    chars[idx] = letter
                elif op == "-" and grant:
                    chars[idx] = "-"
                elif op == "=":
                    chars[idx] = letter if grant else "-"
    return "".join(chars)


def resolve_dir(
    filesystem: Dict[str, Any], abs_dir: str, create: bool = False
) -> Optional[Dict[str, Any]]:
    if abs_dir in filesystem:
        ensure_dir_node(filesystem[abs_dir])
        return filesystem[abs_dir]

    dynamic_roots = {
        key
        for key in filesystem
        if isinstance(key, str) and is_under_allowed_fs_roots(key)
    }
    dynamic_roots.update(ALLOWED_FS_ROOTS)
    for root in sorted(dynamic_roots, key=len, reverse=True):
        if abs_dir == root:
            if create and root not in filesystem:
                filesystem[root] = {}
            node = filesystem.get(root)
            if node is None:
                return None
            ensure_dir_node(node)
            return node

        if abs_dir.startswith(root + "/"):
            if root not in filesystem:
                if not create:
                    return None
                filesystem[root] = {}
            node = filesystem[root]
            ensure_dir_node(node)
            parts = PurePosixPath(abs_dir[len(root) :].lstrip("/")).parts
            for part in parts:
                ensure_dir_node(node)
                folders = node["folders"]
                if part not in folders:
                    if not create:
                        return None
                    folders[part] = {}
                node = folders[part]
            ensure_dir_node(node)
            return node

    return None
