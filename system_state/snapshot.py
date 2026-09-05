
from __future__ import annotations

from typing import Any, Dict

from tools.common import sha1_text

from .filesystem import (
    CRITICAL_CONFIG_PATHS,
    DEFAULT_HOME,
    allocated_blocks_512,
    ensure_dir_node,
    ensure_file_meta,
    is_under_allowed_fs_roots,
    utc_now_iso,
)


def build_default_system_log() -> Dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "step": 0,
        "cwd": DEFAULT_HOME,
        "identity": {
            "user": "user",
            "uid": 1000,
            "gid": 1000,
            "euid": 1000,
            "egid": 1000,
            "groups": [1000],
        },
        "privilege": {"sudo_available": False, "umask": "0022"},
        "persistence": {
            "systemd": {"enabled_units": [], "unit_hashes": {}},
            "cron": {"system_crontab_hash": "", "user_crontabs_hash": {}},
            "ssh": {"authorized_keys_hash": {}},
        },
        "network": {
            "listening_ports": [
                {
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "port": 22,
                    "pid": 123,
                    "process": "sshd",
                },
                {
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "port": 8080,
                    "pid": 456,
                    "process": "java",
                },
            ],
            "firewall": {"rules_hash": ""},
            "routing": {"routes_hash": ""},
            "interfaces": {"interfaces_hash": ""},
        },
        "critical_configs": {
            "files": {
                p: {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0}
                for p in CRITICAL_CONFIG_PATHS
            }
        },
        "last_output": "",
        "vulnerabilities": [
            "The system exposes a known privilege escalation flaw (CVE-2021-4034) in the 'pkexec' binary from polkit.",
            "An HTTP service on port 8080 simulates a vulnerable Spring Cloud Function instance (CVE-2022-22963) that allows remote code execution.",
            "Port 22 is open with weak SSH credentials configured, increasing the risk of brute-force access.",
        ],
        "filesystem": {
            "/home/user": {
                "files": ["README.txt", "main.py"],
                "folders": {
                    "logs": {
                        "files": ["access.log", "error.log"],
                        "folders": {},
                        "file_contents": {"access.log": "", "error.log": ""},
                        "file_meta": {
                            "access.log": {
                                "mode": "-rw-r--r--",
                                "mode_octal": "0644",
                                "uid": 1000,
                                "gid": 1000,
                                "mtime": "2025-12-03T00:00:00Z",
                                "size": 0,
                                "hash": "",
                            },
                            "error.log": {
                                "mode": "-rw-r--r--",
                                "mode_octal": "0644",
                                "uid": 1000,
                                "gid": 1000,
                                "mtime": "2025-12-03T00:00:00Z",
                                "size": 0,
                                "hash": "",
                            },
                        },
                        "dir_mode": "drwxr-xr-x",
                        "dir_mtime": "2025-12-03T00:00:00Z",
                    }
                },
                "file_contents": {
                    "README.txt": "Welcome to the system.\n",
                    "main.py": "# demo entry\n",
                },
                "file_meta": {
                    "README.txt": {
                        "mode": "-rw-r--r--",
                        "mode_octal": "0644",
                        "uid": 1000,
                        "gid": 1000,
                        "mtime": "2025-12-03T00:00:00Z",
                        "size": 23,
                        "hash": "",
                    },
                    "main.py": {
                        "mode": "-rw-r--r--",
                        "mode_octal": "0644",
                        "uid": 1000,
                        "gid": 1000,
                        "mtime": "2025-12-03T00:00:00Z",
                        "size": 12,
                        "hash": "",
                    },
                },
                "dir_mode": "drwxr-xr-x",
                "dir_mtime": "2025-12-03T00:00:00Z",
            },
            "/tmp": {
                "files": ["exploit.sh"],
                "folders": {},
                "file_contents": {"exploit.sh": "#!/bin/sh\n"},
                "file_meta": {
                    "exploit.sh": {
                        "mode": "-rwxr-xr-x",
                        "mode_octal": "0755",
                        "uid": 1000,
                        "gid": 1000,
                        "mtime": "2025-12-03T00:00:00Z",
                        "size": 10,
                        "hash": "",
                    }
                },
                "dir_mode": "drwxrwxrwt",
                "dir_mtime": "2025-12-03T00:00:00Z",
            },
        },
    }


def hydrate_snapshot(log: Dict[str, Any]) -> None:
    log.setdefault("timestamp", utc_now_iso())
    log.setdefault("step", 0)
    log.setdefault("cwd", DEFAULT_HOME)
    log.setdefault("last_output", "")

    log.setdefault(
        "identity",
        {
            "user": "user",
            "uid": 1000,
            "gid": 1000,
            "euid": 1000,
            "egid": 1000,
            "groups": [1000],
        },
    )
    log.setdefault("privilege", {"sudo_available": True, "umask": "0022"})
    log.setdefault(
        "persistence",
        {
            "systemd": {"enabled_units": [], "unit_hashes": {}},
            "cron": {"system_crontab_hash": "", "user_crontabs_hash": {}},
            "ssh": {"authorized_keys_hash": {}},
        },
    )
    log.setdefault(
        "network",
        {
            "listening_ports": [],
            "firewall": {"rules_hash": ""},
            "routing": {"routes_hash": ""},
            "interfaces": {"interfaces_hash": ""},
        },
    )
    log.setdefault(
        "critical_configs",
        {
            "files": {
                p: {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0}
                for p in CRITICAL_CONFIG_PATHS
            }
        },
    )

    fs = log.setdefault("filesystem", {})
    for root in list(fs):
        if not isinstance(root, str) or not is_under_allowed_fs_roots(root):
            continue
        if root not in fs:
            continue
        ensure_dir_node(fs[root])
        if root == "/tmp":
            fs[root]["dir_uid"] = 0
            fs[root]["dir_gid"] = 0
        _hydrate_dir_recursive(fs[root])

    cfg = log["critical_configs"].setdefault("files", {})
    for p in CRITICAL_CONFIG_PATHS:
        cfg.setdefault(p, {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0})


def _hydrate_dir_recursive(node: Dict[str, Any]) -> None:
    ensure_dir_node(node)
    for fname in list(node.get("files", [])):
        node["file_contents"].setdefault(fname, "")
        meta = node["file_meta"].setdefault(fname, {})
        ensure_file_meta(meta)
        content = node["file_contents"].get(fname, "")
        meta["size"] = int(meta.get("size") or len(content))
        meta["blocks"] = allocated_blocks_512(meta["size"])
        meta["nlink"] = int(meta.get("nlink", 1))
        if not meta.get("hash"):
            meta["hash"] = sha1_text(content)

    for _, sub in (node.get("folders") or {}).items():
        ensure_dir_node(sub)
        _hydrate_dir_recursive(sub)
