from __future__ import annotations

import os
import json
import traceback
import re
import shlex
import hashlib
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Dict, Optional, Tuple, List

try:
    import requests
except Exception:
    requests = None

SYSTEM_LOG_PATH = "./system_log.json"


_ALLOWED_FS_ROOTS = {"/home/user", "/tmp"}
_DEFAULT_HOME = "/home/user"

_CRITICAL_CFG_WHITELIST = {
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

def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

def now_file_mtime() -> str:
    return utc_now_iso()

def is_under_allowed_fs_roots(abs_path: str) -> bool:
    return any(abs_path == root or abs_path.startswith(root + "/") for root in _ALLOWED_FS_ROOTS)

def normalize_path(cwd: str, target: str) -> str:
    if not target or target == "~":
        return _DEFAULT_HOME
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

def ensure_file_meta(meta: Dict[str, Any]) -> None:
    meta.setdefault("mode", "-rw-r--r--")
    meta.setdefault("mode_octal", "0644")
    meta.setdefault("uid", 1000)
    meta.setdefault("gid", 1000)
    meta.setdefault("mtime", now_file_mtime())
    meta.setdefault("size", 0)
    meta.setdefault("hash", "")

def resolve_dir(filesystem: Dict[str, Any], abs_dir: str, create: bool = False) -> Optional[Dict[str, Any]]:

    # root direct hit
    if abs_dir in filesystem:
        ensure_dir_node(filesystem[abs_dir])
        return filesystem[abs_dir]

    for root in _ALLOWED_FS_ROOTS:
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
            parts = PurePosixPath(abs_dir[len(root):].lstrip("/")).parts
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



_COMPLEX_PATTERNS = [
    r"\|",         # pipe
    r"\&\&",       # &&
    r"\|\|",       # ||
    r";",          # multiple commands
    r"\$\(",       # command substitution
    r"`",          # backticks
    r"\{|\}",      # braces
    r"\(|\)",      # parentheses
    r"<<",         # heredoc
]

def is_complex_command(cmd: str) -> bool:
    s = cmd.strip()
    if not s:
        return False

    try:
        toks = shlex.split(s)
        if len(toks) > 20:
            return True
    except Exception:
        return True

    for pat in _COMPLEX_PATTERNS:
        if re.search(pat, s):
            return True

    if len(re.findall(r"(>>|>|<)", s)) >= 2 and not s.strip().startswith("echo "):
        return True
    return False




class VulnerabilityAgentLLM:
    def __init__(
        self,
        cve_list: Optional[List[str]] = None,
        llm_config: Optional[Dict[str, Any]] = None,
        system_log_path: str = SYSTEM_LOG_PATH
    ):
        self.system_log_path = system_log_path
        self.llm_config = llm_config or {"use_llm": False}

        log = self.load_system_log()
        if not log:
            log = self.default_system_log()
        if cve_list is not None:
            log["vulnerabilities"] = list(cve_list)

        self.system_log: Dict[str, Any] = log
        self._hydrate_snapshot(self.system_log)
        self.save_system_log(self.system_log)


    def default_system_log(self) -> Dict[str, Any]:
        return {
            "timestamp": utc_now_iso(),
            "step": 0,
            "cwd": _DEFAULT_HOME,


            "identity": {
                "user": "user",
                "uid": 1000, "gid": 1000,
                "euid": 1000, "egid": 1000,
                "groups": [1000]
            },
            "privilege": {
                "sudo_available": True,
                "umask": "0022"
            },


            "persistence": {
                "systemd": {"enabled_units": [], "unit_hashes": {}},
                "cron": {"system_crontab_hash": "", "user_crontabs_hash": {}},
                "ssh": {"authorized_keys_hash": {}}
            },


            "network": {
                "listening_ports": [
                    {"proto": "tcp", "ip": "0.0.0.0", "port": 22, "pid": 123, "process": "sshd"},
                    {"proto": "tcp", "ip": "0.0.0.0", "port": 8080, "pid": 456, "process": "java"},
                ],
                "firewall": {"rules_hash": ""},
                "routing": {"routes_hash": ""},
                "interfaces": {"interfaces_hash": ""}
            },


            "critical_configs": {
                "files": {p: {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0} for p in _CRITICAL_CFG_WHITELIST}
            },

            "last_output": "",

            "vulnerabilities": [
                "The system exposes a known privilege escalation flaw (CVE-2021-4034) in the 'pkexec' binary from polkit.",
                "An HTTP service on port 8080 simulates a vulnerable Spring Cloud Function instance (CVE-2022-22963) that allows remote code execution.",
                "Port 22 is open with weak SSH credentials configured, increasing the risk of brute-force access."
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
                                "access.log": {"mode": "-rw-r--r--", "mode_octal": "0644", "uid": 1000, "gid": 1000, "mtime": "2025-12-03T00:00:00Z", "size": 0, "hash": ""},
                                "error.log":  {"mode": "-rw-r--r--", "mode_octal": "0644", "uid": 1000, "gid": 1000, "mtime": "2025-12-03T00:00:00Z", "size": 0, "hash": ""},
                            },
                            "dir_mode": "drwxr-xr-x",
                            "dir_mtime": "2025-12-03T00:00:00Z"
                        }
                    },
                    "file_contents": {"README.txt": "Welcome to the system.\n", "main.py": "# demo entry\n"},
                    "file_meta": {
                        "README.txt": {"mode": "-rw-r--r--", "mode_octal": "0644", "uid": 1000, "gid": 1000, "mtime": "2025-12-03T00:00:00Z", "size": 23, "hash": ""},
                        "main.py":   {"mode": "-rw-r--r--", "mode_octal": "0644", "uid": 1000, "gid": 1000, "mtime": "2025-12-03T00:00:00Z", "size": 12, "hash": ""},
                    },
                    "dir_mode": "drwxr-xr-x",
                    "dir_mtime": "2025-12-03T00:00:00Z"
                },
                "/tmp": {
                    "files": ["exploit.sh"],
                    "folders": {},
                    "file_contents": {"exploit.sh": "#!/bin/sh\n"},
                    "file_meta": {
                        "exploit.sh": {"mode": "-rwxr-xr-x", "mode_octal": "0755", "uid": 1000, "gid": 1000, "mtime": "2025-12-03T00:00:00Z", "size": 10, "hash": ""}
                    },
                    "dir_mode": "drwxrwxrwt",
                    "dir_mtime": "2025-12-03T00:00:00Z"
                }
            }
        }

    def _hydrate_snapshot(self, log: Dict[str, Any]) -> None:
        log.setdefault("timestamp", utc_now_iso())
        log.setdefault("step", 0)
        log.setdefault("cwd", _DEFAULT_HOME)
        log.setdefault("last_output", "")

        log.setdefault("identity", {"user": "user", "uid": 1000, "gid": 1000, "euid": 1000, "egid": 1000, "groups": [1000]})
        log.setdefault("privilege", {"sudo_available": True, "umask": "0022"})
        log.setdefault("persistence", {"systemd": {"enabled_units": [], "unit_hashes": {}}, "cron": {"system_crontab_hash": "", "user_crontabs_hash": {}}, "ssh": {"authorized_keys_hash": {}}})
        log.setdefault("network", {"listening_ports": [], "firewall": {"rules_hash": ""}, "routing": {"routes_hash": ""}, "interfaces": {"interfaces_hash": ""}})
        log.setdefault("critical_configs", {"files": {p: {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0} for p in _CRITICAL_CFG_WHITELIST}})

        fs = log.setdefault("filesystem", {})
        for root in list(_ALLOWED_FS_ROOTS):
            if root not in fs:
                continue
            ensure_dir_node(fs[root])
            self._hydrate_dir_recursive(fs[root])

        cfg = log["critical_configs"].setdefault("files", {})
        for p in _CRITICAL_CFG_WHITELIST:
            cfg.setdefault(p, {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0})

    def _hydrate_dir_recursive(self, node: Dict[str, Any]) -> None:
        ensure_dir_node(node)
        for fname in list(node.get("files", [])):
            node["file_contents"].setdefault(fname, "")
            meta = node["file_meta"].setdefault(fname, {})
            ensure_file_meta(meta)
            content = node["file_contents"].get(fname, "")
            meta["size"] = int(meta.get("size") or len(content))
            if not meta.get("hash"):
                meta["hash"] = sha1_text(content)

        for _, sub in (node.get("folders") or {}).items():
            ensure_dir_node(sub)
            self._hydrate_dir_recursive(sub)
    def load_system_log(self) -> Optional[Dict[str, Any]]:
        try:
            if not os.path.exists(self.system_log_path):
                return None
            with open(self.system_log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def save_system_log(self, log_data: Dict[str, Any]) -> None:
        try:
            with open(self.system_log_path, "w", encoding="utf-8") as f:
                json.dump(log_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Failed to save system log: {e}")
            traceback.print_exc()

    def _emit(self, msg: str) -> None:
        self.system_log["last_output"] = msg



    def build_llm_prompt(self, command: str, current_log: Dict[str, Any]) -> str:
        instr = (
            "You are a deterministic system-state manager for a Linux terminal simulator.\n"
            "Update the given JSON snapshot according to APPLY_COMMAND.\n"
            "Rules:\n"
            "1) Output ONLY the updated snapshot as pure JSON (no markdown, no prose).\n"
            "2) Preserve schema keys: timestamp, step, cwd, identity, privilege, persistence, network, critical_configs, filesystem, vulnerabilities, last_output.\n"
            "3) You may modify filesystem ONLY under /home/user and /tmp.\n"
            "4) For writes to critical config whitelist paths (e.g., /etc/ssh/sshd_config), update critical_configs.files[path].hash and metadata, but do NOT create real filesystem entries outside allowed roots.\n"
            "5) Keep snapshot consistent: file_meta.hash=size=mtime should match file_contents.\n"
            "6) If command is read-only, return snapshot unchanged except timestamp/step/last_output.\n"
        )
        return (
            f"{instr}\n\nCURRENT_SNAPSHOT_JSON:\n"
            f"{json.dumps(current_log, ensure_ascii=False, indent=2)}\n\n"
            f"APPLY_COMMAND: {command}\n\n"
            f"Return only JSON."
        )

    def call_openai(self, prompt: str, cfg: Dict[str, Any]) -> Optional[str]:
        if requests is None:
            return None
        try:
            api_key = cfg.get("api_key") or os.getenv("OPENAI_API_KEY")
            if not api_key:
                return None
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            body = {
                "model": cfg.get("model", "gpt-4o-mini"),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": int(cfg.get("max_tokens", 1800)),
                "response_format": {"type": "json_object"},
            }
            r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=body, timeout=45)
            if r.status_code == 200:
                data = r.json()
                if data.get("choices"):
                    return data["choices"][0]["message"]["content"].strip()
            return None
        except Exception:
            return None

    def invoke_openai_for_snapshot(self, command: str) -> Optional[Dict[str, Any]]:
        cfg = (self.llm_config or {}).get("openai", {})
        prompt = self.build_llm_prompt(command, self.system_log)
        raw = self.call_openai(prompt, cfg)
        if not raw:
            return None
        cand = None
        try:
            cand = json.loads(raw)
        except Exception:
            m = re.search(r"(\{(?:.|\s)*\})", raw)
            if m:
                try:
                    cand = json.loads(m.group(1))
                except Exception:
                    cand = None
        if not isinstance(cand, dict):
            return None

        required = {"timestamp", "step", "cwd", "identity", "privilege", "persistence", "network", "critical_configs", "filesystem", "vulnerabilities", "last_output"}
        if not required.issubset(cand.keys()):
            return None

        fs = cand.get("filesystem", {})
        safe_fs = {}
        if isinstance(fs, dict):
            for root in _ALLOWED_FS_ROOTS:
                if root in fs and isinstance(fs[root], dict):
                    safe_fs[root] = fs[root]
        cand["filesystem"] = safe_fs

        if not is_under_allowed_fs_roots(cand.get("cwd", _DEFAULT_HOME)):
            cand["cwd"] = _DEFAULT_HOME

        cand["timestamp"] = utc_now_iso()
        self._hydrate_snapshot(cand)
        return cand


    def process_safe_fs(self, command: str) -> str:
        """
        If command is NOT handled by local deterministic handlers, return immediately to caller (run.py).
        No OpenAI fallback is used here for unmatched commands.
        """
        cmd = command.strip()
        self.system_log["timestamp"] = utc_now_iso()
        self.system_log["last_output"] = ""

        self.system_log["step"] = int(self.system_log.get("step", 0)) + 1
        t = int(self.system_log["step"])

        handled = False
        try:
            handled = self.apply_command_local(cmd, step=t)
        except Exception:
            traceback.print_exc()
            handled = False

        self.last_handled_local = bool(handled)
        self.last_unhandled_command = "" if handled else cmd

        try:
            self.system_log["timestamp"] = utc_now_iso()
            self._hydrate_snapshot(self.system_log)
            self.save_system_log(self.system_log)
        except Exception:
            traceback.print_exc()

        return json.dumps(self.system_log, ensure_ascii=False, indent=2)




    def apply_command_local(self, cmd: str, step: int) -> bool:
        """
        Returns True if handled locally; False otherwise.
        Local handlers update snapshot deterministically.
        """
        if re.match(r"^\s*(pwd|whoami|id|ls|cat|head|tail|grep|find)\b", cmd):

            return True

        try:
            tokens = shlex.split(cmd)
        except Exception:
            tokens = cmd.split()
        if not tokens:
            return True

        # Handle sudo -i / su changes identity (persisted in snapshot)
        if tokens[0] == "sudo" and len(tokens) >= 2 and tokens[1] in ("-i", "su"):
            self.system_log["identity"]["user"] = "root"
            self.system_log["identity"]["euid"] = 0
            self.system_log["identity"]["egid"] = 0
            self._emit("root shell started\n")
            return True

        if tokens[0] == "su":
            # su [user]
            user = tokens[1] if len(tokens) >= 2 else "root"
            self.system_log["identity"]["user"] = user
            # naive uid mapping: root->0 else 1000
            if user == "root":
                self.system_log["identity"]["euid"] = 0
                self.system_log["identity"]["egid"] = 0
            else:
                self.system_log["identity"]["euid"] = 1000
                self.system_log["identity"]["egid"] = 1000
            self._emit(f"switched user to {user}\n")
            return True

        # cd
        m = re.match(r"^\s*cd\s*$", cmd)
        if m:
            self.apply_cd("~"); return True
        m = re.match(r"^\s*cd\s+(.+)$", cmd)
        if m:
            self.apply_cd(m.group(1).strip()); return True

        # mkdir
        m = re.match(r"^\s*mkdir\s+(-p\s+)?(.+)$", cmd)
        if m:
            for t in m.group(2).strip().split():
                self.apply_mkdir(t)
            return True

        # rmdir
        m = re.match(r"^\s*rmdir\s+(.+)$", cmd)
        if m:
            self.apply_rmdir(m.group(1).strip()); return True

        # rm / rm -r
        m = re.match(r"^\s*rm\s+(.+)$", cmd)
        if m:
            args = m.group(1).strip().split()
            if args and args[0].startswith("-r"):
                flags = args[0]
                force = "f" in flags
                targets = args[1:] if len(args) > 1 else []
                for t in targets:
                    self.apply_rm_recursive(t, force=force)
            else:
                for t in args:
                    self.apply_rm(t)
            return True

        # touch
        m = re.match(r"^\s*touch\s+(.+)$", cmd)
        if m:
            for t in m.group(1).strip().split():
                self.apply_touch(t)
            return True

        # echo > / >>
        m = re.match(r"^\s*echo\s+(.+?)\s*(>>|>)\s*(.+)$", cmd)
        if m:
            text_expr = m.group(1).strip()
            op = m.group(2)
            target = m.group(3).strip()
            self.apply_echo_write(text_expr, op, target)
            return True

        # mv
        m = re.match(r"^\s*mv\s+(.+?)\s+(.+)$", cmd)
        if m:
            self.apply_mv(m.group(1).strip(), m.group(2).strip()); return True

        # cp -r / cp
        m = re.match(r"^\s*cp\s+-r\s+(.+?)\s+(.+)$", cmd)
        if m:
            self.apply_cp_r(m.group(1).strip(), m.group(2).strip()); return True
        m = re.match(r"^\s*cp\s+(.+?)\s+(.+)$", cmd)
        if m:
            self.apply_cp(m.group(1).strip(), m.group(2).strip()); return True

        # chmod/chown (perm)
        m = re.match(r"^\s*chmod\s+([0-7]{3,4})\s+(.+)$", cmd)
        if m:
            mode_octal = m.group(1)
            for path in m.group(2).strip().split():
                self.apply_chmod(mode_octal, path)
            return True

        m = re.match(r"^\s*chown\s+([^:\s]+)(?::([^:\s]+))?\s+(.+)$", cmd)
        if m:
            user = m.group(1)
            group = m.group(2)
            for path in m.group(3).strip().split():
                self.apply_chown(user, group, path)
            return True

        # systemctl enable/disable (persist)
        m = re.match(r"^\s*systemctl\s+(enable|disable)\s+(\S+)\s*$", cmd)
        if m:
            act = m.group(1)
            unit = m.group(2)
            self.apply_systemctl(act, unit)
            return True

        # python -m http.server (net exposure)
        m = re.match(r"^\s*python3?\s+-m\s+http\.server(?:\s+(\d+))?\s*$", cmd)
        if m:
            port = int(m.group(1) or "8000")
            self.apply_open_port(port, process="python-http.server")
            self._emit(f"Serving HTTP on 0.0.0.0 port {port} ...\n")
            return True


        if len(tokens) >= 2 and tokens[0] == "git" and tokens[1] == "clone":
            self.apply_git_clone(tokens)
            return True

        return False 



    def apply_cd(self, target: str) -> None:
        new_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), target)
        if not is_under_allowed_fs_roots(new_path):
            return
        fs = self.system_log["filesystem"]
        node = resolve_dir(fs, new_path, create=False)
        if node is not None:
            self.system_log["cwd"] = new_path

    def apply_mkdir(self, path: str) -> None:
        abs_dir = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)
        if not is_under_allowed_fs_roots(abs_dir):
            return
        fs = self.system_log["filesystem"]
        node = resolve_dir(fs, abs_dir, create=True)
        if node is not None:
            node["dir_mtime"] = now_file_mtime()

    def apply_touch(self, path: str) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)

        if abs_path in _CRITICAL_CFG_WHITELIST and not is_under_allowed_fs_roots(abs_path):
            self.touch_critical_cfg(abs_path)
            return

        if not is_under_allowed_fs_roots(abs_path):
            return
        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        parent_node = resolve_dir(fs, parent, create=True)
        if parent_node is None or not name:
            return
        ensure_dir_node(parent_node)
        if name not in parent_node["files"]:
            parent_node["files"].append(name)
        parent_node["file_contents"].setdefault(name, "")

        meta = parent_node["file_meta"].setdefault(name, {})
        ensure_file_meta(meta)
        meta["mtime"] = now_file_mtime()
        content = parent_node["file_contents"].get(name, "")
        meta["size"] = len(content)
        meta["hash"] = sha1_text(content)

    def apply_rm(self, path: str) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)

        if abs_path in _CRITICAL_CFG_WHITELIST and not is_under_allowed_fs_roots(abs_path):
            # deleting a critical cfg -> model as empty content hash change
            self.update_critical_cfg(abs_path, "")
            return

        if not is_under_allowed_fs_roots(abs_path):
            return
        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        node = resolve_dir(fs, parent, create=False)
        if node is None:
            return
        ensure_dir_node(node)
        if name in node["files"]:
            node["files"].remove(name)
        node.get("file_contents", {}).pop(name, None)
        node.get("file_meta", {}).pop(name, None)

    def apply_rm_recursive(self, path: str, force: bool = False) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)
        if not is_under_allowed_fs_roots(abs_path):
            return
        if abs_path in _ALLOWED_FS_ROOTS:
            return
        fs = self.system_log["filesystem"]
        parent, name = split_parent_child(abs_path)
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is None or not name:
            return
        ensure_dir_node(parent_node)
        if name in parent_node["folders"]:
            del parent_node["folders"][name]
            return
        if name in parent_node.get("files", []):
            parent_node["files"].remove(name)
            parent_node.get("file_contents", {}).pop(name, None)
            parent_node.get("file_meta", {}).pop(name, None)

    def apply_rmdir(self, path: str) -> None:
        abs_dir = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)
        if not is_under_allowed_fs_roots(abs_dir):
            return
        if abs_dir in _ALLOWED_FS_ROOTS:
            return
        fs = self.system_log["filesystem"]
        parent, name = split_parent_child(abs_dir)
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is None or not name:
            return
        ensure_dir_node(parent_node)
        sub = parent_node["folders"].get(name)
        if sub is None:
            return
        ensure_dir_node(sub)
        if not sub["folders"] and not sub["files"]:
            del parent_node["folders"][name]

    def apply_mv(self, src: str, dst: str) -> None:
        src_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), src)
        dst_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), dst)
        if not (is_under_allowed_fs_roots(src_abs) and is_under_allowed_fs_roots(dst_abs)):
            return
        src_parent, src_name = split_parent_child(src_abs)
        dst_parent, dst_name = split_parent_child(dst_abs)
        fs = self.system_log["filesystem"]
        src_parent_node = resolve_dir(fs, src_parent, create=False)
        dst_parent_node = resolve_dir(fs, dst_parent, create=True)
        if src_parent_node is None or dst_parent_node is None:
            return
        ensure_dir_node(src_parent_node)
        ensure_dir_node(dst_parent_node)


        if src_name in src_parent_node["files"]:
            content = src_parent_node["file_contents"].pop(src_name, "")
            meta = src_parent_node["file_meta"].pop(src_name, None)

            src_parent_node["files"].remove(src_name)


            if dst_name in dst_parent_node["files"]:
                dst_parent_node["files"].remove(dst_name)
                dst_parent_node["file_contents"].pop(dst_name, None)
                dst_parent_node["file_meta"].pop(dst_name, None)

            dst_parent_node["files"].append(dst_name)
            dst_parent_node["file_contents"][dst_name] = content
            if meta is None:
                meta = {}
            ensure_file_meta(meta)
            meta["mtime"] = now_file_mtime()
            meta["size"] = len(content)
            meta["hash"] = sha1_text(content)
            dst_parent_node["file_meta"][dst_name] = meta
            return


        if src_name in src_parent_node["folders"]:
            if dst_name in dst_parent_node["folders"]:
                del dst_parent_node["folders"][dst_name]
            dst_parent_node["folders"][dst_name] = src_parent_node["folders"].pop(src_name)

    def apply_cp(self, src: str, dst: str) -> None:
        src_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), src)
        dst_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), dst)
        if not (is_under_allowed_fs_roots(src_abs) and is_under_allowed_fs_roots(dst_abs)):
            return
        src_parent, src_name = split_parent_child(src_abs)
        dst_parent, dst_name = split_parent_child(dst_abs)
        fs = self.system_log["filesystem"]
        src_parent_node = resolve_dir(fs, src_parent, create=False)
        dst_parent_node = resolve_dir(fs, dst_parent, create=True)
        if src_parent_node is None or dst_parent_node is None:
            return
        ensure_dir_node(src_parent_node)
        ensure_dir_node(dst_parent_node)
        if src_name in src_parent_node["files"]:
            content = src_parent_node["file_contents"].get(src_name, "")
            if dst_name not in dst_parent_node["files"]:
                dst_parent_node["files"].append(dst_name)
            dst_parent_node["file_contents"][dst_name] = content
            meta = dst_parent_node["file_meta"].setdefault(dst_name, {})
            ensure_file_meta(meta)
            meta["mtime"] = now_file_mtime()
            meta["size"] = len(content)
            meta["hash"] = sha1_text(content)

    def apply_cp_r(self, src: str, dst: str) -> None:
        src_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), src)
        dst_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), dst)
        if not (is_under_allowed_fs_roots(src_abs) and is_under_allowed_fs_roots(dst_abs)):
            return
        fs = self.system_log["filesystem"]
        src_parent, src_name = split_parent_child(src_abs)
        dst_parent, dst_name = split_parent_child(dst_abs)
        src_parent_node = resolve_dir(fs, src_parent, create=False)
        dst_parent_node = resolve_dir(fs, dst_parent, create=True)
        if src_parent_node is None or dst_parent_node is None:
            return
        ensure_dir_node(src_parent_node)
        ensure_dir_node(dst_parent_node)
        if src_name in src_parent_node["folders"]:
            if dst_name not in dst_parent_node["folders"]:
                dst_parent_node["folders"][dst_name] = {}
            dst_dir = dst_parent_node["folders"][dst_name]
            ensure_dir_node(dst_dir)
            self.copy_dir_recursive(src_parent_node["folders"][src_name], dst_dir)
            return
        self.apply_cp(src, dst)

    def copy_dir_recursive(self, src_dir: Dict[str, Any], dst_dir: Dict[str, Any]) -> None:
        ensure_dir_node(src_dir)
        ensure_dir_node(dst_dir)
        for fname in src_dir.get("files", []):
            if fname not in dst_dir["files"]:
                dst_dir["files"].append(fname)
            content = src_dir.get("file_contents", {}).get(fname, "")
            dst_dir["file_contents"][fname] = content
            meta = dst_dir["file_meta"].setdefault(fname, {})
            ensure_file_meta(meta)
            meta["mtime"] = now_file_mtime()
            meta["size"] = len(content)
            meta["hash"] = sha1_text(content)

        for subname, subnode in src_dir.get("folders", {}).items():
            if subname not in dst_dir["folders"]:
                dst_dir["folders"][subname] = {}
            self.copy_dir_recursive(subnode, dst_dir["folders"][subname])

    def parse_echo_text(self, expr: str) -> str:
        s = expr.strip()
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            s = s[1:-1]
        s = s.replace(r"\n", "\n").replace(r"\t", "\t").replace(r"\\", "\\").replace(r"\"", "\"").replace(r"\'", "'")
        s = s + "\n"
        return s

    def apply_echo_write(self, text_expr: str, op: str, target: str) -> None:
        text = self.parse_echo_text(text_expr)
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), target)

        if abs_path in _CRITICAL_CFG_WHITELIST and not is_under_allowed_fs_roots(abs_path):
            prev = self.system_log["critical_configs"]["files"].get(abs_path, {}).get("hash", "")
            new_hash = sha1_text(text if op == ">" else (prev + text))
            self.system_log["critical_configs"]["files"][abs_path] = {
                "hash": new_hash, "mode_octal": "0644", "uid": 0, "gid": 0
            }
            self._emit(f"(simulated) wrote critical config: {abs_path}\n")
            return

        if not is_under_allowed_fs_roots(abs_path):
            return

        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        parent_node = resolve_dir(fs, parent, create=True)
        if parent_node is None or not name:
            return

        ensure_dir_node(parent_node)
        if name not in parent_node["files"]:
            parent_node["files"].append(name)
            parent_node["file_contents"].setdefault(name, "")

        if op == ">":
            parent_node["file_contents"][name] = text
        else:
            parent_node["file_contents"][name] = parent_node["file_contents"].get(name, "") + text

        content = parent_node["file_contents"][name]
        meta = parent_node["file_meta"].setdefault(name, {})
        ensure_file_meta(meta)
        meta["mtime"] = now_file_mtime()
        meta["size"] = len(content)
        meta["hash"] = sha1_text(content)

    def apply_chmod(self, mode_octal: str, path: str) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)

        # critical cfg outside allowed roots
        if abs_path in _CRITICAL_CFG_WHITELIST and not is_under_allowed_fs_roots(abs_path):
            cfg = self.system_log["critical_configs"]["files"].setdefault(abs_path, {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0})
            cfg["mode_octal"] = mode_octal
            self._emit(f"(simulated) chmod {mode_octal} {abs_path}\n")
            return

        if not is_under_allowed_fs_roots(abs_path):
            return
        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is None:
            return
        ensure_dir_node(parent_node)
        if name not in parent_node["files"]:
            return
        meta = parent_node["file_meta"].setdefault(name, {})
        ensure_file_meta(meta)
        meta["mode_octal"] = mode_octal
        meta["mtime"] = now_file_mtime()

    def apply_chown(self, user: str, group: Optional[str], path: str) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)


        uid = 0 if user == "root" else 1000
        gid = 0 if (group == "root") else 1000


        if abs_path in _CRITICAL_CFG_WHITELIST and not is_under_allowed_fs_roots(abs_path):
            cfg = self.system_log["critical_configs"]["files"].setdefault(abs_path, {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0})
            cfg["uid"] = uid
            cfg["gid"] = gid
            self._emit(f"(simulated) chown {user}:{group or ''} {abs_path}\n")
            return

        if not is_under_allowed_fs_roots(abs_path):
            return
        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is None:
            return
        ensure_dir_node(parent_node)
        if name not in parent_node["files"]:
            return
        meta = parent_node["file_meta"].setdefault(name, {})
        ensure_file_meta(meta)
        meta["uid"] = uid
        meta["gid"] = gid
        meta["mtime"] = now_file_mtime()

    def apply_systemctl(self, action: str, unit: str) -> None:
        enabled = self.system_log["persistence"]["systemd"].setdefault("enabled_units", [])
        if action == "enable":
            if unit not in enabled:
                enabled.append(unit)
            self._emit(f"Created symlink /etc/systemd/system/multi-user.target.wants/{unit}.\n")
        else:
            if unit in enabled:
                enabled.remove(unit)
            self._emit(f"Removed symlink for {unit}.\n")

    def apply_open_port(self, port: int, process: str = "unknown") -> None:
        ports = self.system_log["network"].setdefault("listening_ports", [])

        for p in ports:
            if int(p.get("port", -1)) == port and p.get("proto") == "tcp":
                return
        ports.append({"proto": "tcp", "ip": "0.0.0.0", "port": port, "pid": 9999, "process": process})

    def touch_critical_cfg(self, path: str) -> None:
        self.update_critical_cfg(path, "")

    def update_critical_cfg(self, path: str, content: str) -> None:
        files = self.system_log["critical_configs"].setdefault("files", {})
        files[path] = {"hash": sha1_text(content), "mode_octal": "0644", "uid": 0, "gid": 0}

    def apply_git_clone(self, tokens: List[str]) -> None:
        cwd = self.system_log.get("cwd", _DEFAULT_HOME)
        url = None
        dst_dir = None

        nonopts: List[str] = []
        for t in tokens[2:]:
            if t.startswith("-"):
                continue
            nonopts.append(t)
        if nonopts:
            url = nonopts[0]
            if len(nonopts) >= 2:
                dst_dir = nonopts[1]
        if not url:
            return

        if not dst_dir:
            base = PurePosixPath(url).name or "repo"
            if base.endswith(".git"):
                base = base[:-4] or "repo"
            dst_dir = base

        repo_abs = normalize_path(cwd, dst_dir)
        if not is_under_allowed_fs_roots(repo_abs):
            return

        repo_node = resolve_dir(self.system_log["filesystem"], repo_abs, create=True)
        if repo_node is None:
            return
        ensure_dir_node(repo_node)

        if "README.md" not in repo_node["files"]:
            repo_node["files"].append("README.md")
        repo_node["file_contents"]["README.md"] = f"# Simulated clone\n\nCloned from: {url}\nTime: {utc_now_iso()}\n"
        repo_node["file_meta"].setdefault("README.md", {})
        ensure_file_meta(repo_node["file_meta"]["README.md"])
        repo_node["file_meta"]["README.md"]["mtime"] = now_file_mtime()
        repo_node["file_meta"]["README.md"]["size"] = len(repo_node["file_contents"]["README.md"])
        repo_node["file_meta"]["README.md"]["hash"] = sha1_text(repo_node["file_contents"]["README.md"])

        if "main.py" not in repo_node["files"]:
            repo_node["files"].append("main.py")
        repo_node["file_contents"]["main.py"] = 'print("hello from cloned repo")\n'
        repo_node["file_meta"].setdefault("main.py", {})
        ensure_file_meta(repo_node["file_meta"]["main.py"])
        repo_node["file_meta"]["main.py"]["mtime"] = now_file_mtime()
        repo_node["file_meta"]["main.py"]["size"] = len(repo_node["file_contents"]["main.py"])
        repo_node["file_meta"]["main.py"]["hash"] = sha1_text(repo_node["file_contents"]["main.py"])

        # fake .git
        if ".git" not in repo_node["folders"]:
            repo_node["folders"][".git"] = {"files": [], "folders": {}, "file_contents": {}, "file_meta": {}, "dir_mode": "drwxr-xr-x", "dir_mtime": now_file_mtime()}
        git_dir = repo_node["folders"][".git"]
        ensure_dir_node(git_dir)

        if "HEAD" not in git_dir["files"]:
            git_dir["files"].append("HEAD")
        git_dir["file_contents"]["HEAD"] = "ref: refs/heads/main\n"
        git_dir["file_meta"].setdefault("HEAD", {})
        ensure_file_meta(git_dir["file_meta"]["HEAD"])
        git_dir["file_meta"]["HEAD"]["mtime"] = now_file_mtime()
        git_dir["file_meta"]["HEAD"]["size"] = len(git_dir["file_contents"]["HEAD"])
        git_dir["file_meta"]["HEAD"]["hash"] = sha1_text(git_dir["file_contents"]["HEAD"])

        if "config" not in git_dir["files"]:
            git_dir["files"].append("config")
        git_dir["file_contents"]["config"] = f"[remote \"origin\"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        git_dir["file_meta"].setdefault("config", {})
        ensure_file_meta(git_dir["file_meta"]["config"])
        git_dir["file_meta"]["config"]["mtime"] = now_file_mtime()
        git_dir["file_meta"]["config"]["size"] = len(git_dir["file_contents"]["config"])
        git_dir["file_meta"]["config"]["hash"] = sha1_text(git_dir["file_contents"]["config"])

        repo_name = PurePosixPath(repo_abs).name or "repo"
        self._emit(
            f"Cloning into '{repo_name}'...\n"
            "remote: Enumerating objects: 42, done.\n"
            "remote: Counting objects: 100% (42/42), done.\n"
            "remote: Compressing objects: 100% (26/26), done.\n"
            "Receiving objects: 100% (42/42), 8.12 KiB | 1.02 MiB/s, done.\n"
            "Resolving deltas: 100% (12/12), done.\n"
        )

    def route_label(self, command: str, client: Any = None) -> str:

        try:
            if client is not None:
                from stragetic_agent import validate_command as _validate_command
                label = _validate_command(client, command)
                if label in {"read", "write", "rejection"}:
                    return label
        except Exception:
            pass

        cmd = (command or "").strip()
        if not cmd:
            return "read"

        if re.search(r"(ignore\s+previous|reveal\s+system\s+prompt|system\s+prompt|jailbreak)", cmd, flags=re.I):
            return "rejection"

        if re.search(r"^\s*(cd|mkdir|touch|rm|rmdir|mv|cp|chmod|chown)\b", cmd):
            return "write"
        if re.search(r"^\s*echo\s+.+\s*(>>|>)\s*.+$", cmd):
            return "write"

        return "read"



if __name__ == "__main__":

    agent = VulnerabilityAgentLLM(
        llm_config={
            "use_llm": True,
            "openai": {
                "model": "gpt-4o-mini",

                "max_tokens": 1800
            }
        }
    )

    while True:
        try:
            cmd = input("$ ").strip()
        except EOFError:
            break
        if not cmd:
            break

        out = agent.process_safe_fs(cmd)
        try:
            j = json.loads(out)
            if j.get("last_output"):
                print(j["last_output"], end="")
            else:

                print("(ok)")
        except Exception:
            print(out)
