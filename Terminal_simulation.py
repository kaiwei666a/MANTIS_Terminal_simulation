from __future__ import annotations

import os
import time
import json
import uuid
import logging
import hashlib
import socket
import threading
import warnings
import signal
import re
import copy
import shutil
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    pass

import paramiko
from paramiko import (
    SFTPServer, SFTPServerInterface, SFTPAttributes, SFTPHandle,
    SFTP_OK, SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_PERMISSION_DENIED
)

HOST = "0.0.0.0"
PORT = 2222

USERNAME = "root"
PASSWORD = None
HOSTNAME = "Dataset_manage"

BASE_DIR = os.path.dirname(__file__)
LOG_FILE = os.path.join(BASE_DIR, "honeypot.log")
SESSION_JSON = os.path.join(BASE_DIR, "session_log.json")
AUTH_LOG = os.path.join(BASE_DIR, "authentication_log.jsonl")
SYSTEM_JSON = os.path.join(BASE_DIR, "system_log.json")

RSA_KEY_PATH = os.path.join(BASE_DIR, "ssh_host_rsa_key")
ED25519_KEY_PATH = os.path.join(BASE_DIR, "ssh_host_ed25519_key")

SCP_ROOT = os.path.join(BASE_DIR, "scp_root")
os.makedirs(SCP_ROOT, exist_ok=True)

DOCKER_UPLOAD_CONTAINER = os.environ.get("DOCKER_UPLOAD_CONTAINER", "terminal_sftp")
DOCKER_UPLOAD_PATH = os.environ.get("DOCKER_UPLOAD_PATH", "/home/sftpuser/upload")
DOCKER_DELETE_LOCAL_AFTER_COPY = os.environ.get("DOCKER_DELETE_LOCAL_AFTER_COPY", "0").strip().lower() in {"1", "true", "yes", "on"}
UPLOAD_AUDIT_JSONL = os.path.join(BASE_DIR, "upload_audit.jsonl")
UPLOAD_QUARANTINE_DIR = os.path.join(SCP_ROOT, "_quarantine")

LOAD_SESSION_FROM_FILE = True
LOAD_SYSTEM_FROM_FILE = True
PERSIST_SYSTEM_TO_FILE = False

TOP_REFRESH_SEC = 4.0

from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

EASTERN_TZ_NAME = "America/New_York"

def now_eastern() -> datetime:
    if ZoneInfo is not None:
        return datetime.now(tz=ZoneInfo(EASTERN_TZ_NAME))
    return datetime.now().astimezone()

def fmt_eastern(fmt: str) -> str:
    return now_eastern().strftime(fmt)

def ts_utc_isoz() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

from arbiter_agent import VulnerabilityAgentLLM

try:
    from stragetic_agent import init_client, validate_command, plan_terminal_response, PlanningRuntime
    client = init_client()
except Exception as e:
    print(f"[stragetic_agent import failed] {type(e).__name__}: {e}")
    client = None

    def validate_command(_client, command: str) -> str:
        cmd = command.strip()
        if re.search(r"\b(rm\s+-rf\s+/|mkfs|iptables|dd\s+if=|mount|umount)\b", cmd):
            return "rejection"
        if re.search(r"\b(mkdir|touch|rm|mv|cp|cd|chmod|chown)\b", cmd) or re.search(r"^\s*echo\s+.+\s*(>>|>)\s*.+$", cmd):
            return "write"
        return "read"

    def plan_terminal_response(_client, command: str, current_path: str, file_tree: Dict[str, Any],
                              session_log: List[Dict[str, Any]], system_log: Dict[str, Any]) -> str:
        if command.strip().split()[:1] == ["top"] and isinstance(system_log.get("_top_state"), dict):
            return _top_render_from_state_fallback(system_log["_top_state"])
        tool = (command.split() or ["cmd"])[0]
        return f"bash: {tool}: command not found"

    class PlanningRuntime:
        def __init__(self, K: int = 30):
            self.K = K
        def get_pruned_history(self):
            return []
        def step(self, command: str, response: str, pre_snapshot: Dict[str, Any], post_snapshot: Dict[str, Any]) -> None:
            return

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ],
)
# Reduce noisy Paramiko handshake tracebacks from internet scanners.
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

def log_attack(message: str, level: str = "info"):
    if level == "warn":
        logging.warning(message)
    elif level == "error":
        logging.error(message)
    else:
        logging.info(message)


def append_auth_log(event: str,
                    session_id: str = "",
                    username: str = "",
                    hostname: str = "",
                    remote_addr: str = "",
                    success: bool = True,
                    note: str = "",
                    proto: str = "ssh",
                    local_port: int = PORT,
                    **extra):
    try:
        now = now_eastern()
        ts = now.strftime("%Y-%m-%d %H:%M:%S")

        rip = ""
        rport = ""
        if remote_addr:
            if ":" in remote_addr:
                rip, rport = remote_addr.rsplit(":", 1)
            else:
                rip = remote_addr

        rec = {
            "timestamp": ts,
            "timestamp_iso": now.isoformat(),
            "event": event,
            "proto": proto,
            "local_port": int(local_port),
            "session_id": session_id or "",
            "username": username or "",
            "hostname": hostname or "",
            "remote_addr": remote_addr or "",
            "remote_ip": rip,
            "remote_port": str(rport) if rport != "" else "",
            "success": bool(success),
            "note": note or "",
        }
        if extra:
            rec.update(extra)

        with open(AUTH_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass

def load_json_file(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def save_json_file(path: str, obj: Any):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def load_session_log() -> List[Dict[str, Any]]:
    data = load_json_file(SESSION_JSON)
    if isinstance(data, list):
        return data
    return []

def save_session_log(session_log: List[Dict[str, Any]]):
    save_json_file(SESSION_JSON, session_log)

def record_session(session_log: List[Dict[str, Any]], cmd: str, output: str, classification: str):
    session_log.append({
        "ts": ts_utc_isoz(),
        "command": cmd,
        "output": output,
        "classification": classification,
    })
    save_session_log(session_log)

def load_system_log(path: str) -> Optional[Dict[str, Any]]:
    data = load_json_file(path)
    if isinstance(data, dict):
        return data
    return None

def refresh_system_log_for_planning(system_log: Dict[str, Any], vuln_agent: VulnerabilityAgentLLM) -> Dict[str, Any]:
    system_log["timestamp"] = ts_utc_isoz()
    vuln_agent.system_log = system_log
    if PERSIST_SYSTEM_TO_FILE:
        try:
            vuln_agent.save_system_log(system_log)
        except Exception:
            pass
    return system_log

def render_response(cmd: str, plan_text: str, session_log: List[Dict[str, Any]], system_log: Dict[str, Any]) -> str:
    """Dispatch to Response Agent if available; otherwise return plan_text."""
    try:
        from response_agent import render_response as _render
        return _render(cmd, plan_text, session_log, system_log)
    except Exception:
        return plan_text

# class HoneypotServer(paramiko.ServerInterface):
#     def __init__(self, session_id: str, remote_addr: str, local_port: int):
#         super().__init__()
#         self._session_id = session_id
#         self._remote_addr = remote_addr
#         self._local_port = local_port
#         self.event = threading.Event()
#         self.exec_command: Optional[str] = None
#         self.shell_requested: bool = False

#     def check_auth_password(self, username, password):
#         ok = (username == USERNAME and password == PASSWORD)
#         append_auth_log(
#             event="ssh_auth_attempt",
#             session_id=self._session_id,
#             username=username,
#             hostname=HOSTNAME,
#             remote_addr=self._remote_addr,
#             success=bool(ok),
#             note="password accepted" if ok else "password rejected",
#             method="password",
#             password=str(password),
#             proto="ssh",
#             local_port=self._local_port,
#         )
#         return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, session_id: str, remote_addr: str, local_port: int):
        super().__init__()
        self._session_id = session_id
        self._remote_addr = remote_addr
        self._local_port = local_port
        self.event = threading.Event()
        self.exec_command: Optional[str] = None
        self.shell_requested: bool = False

    def get_allowed_auths(self, username):
        return "none,password"

    # def check_auth_none(self, username):
    #     append_auth_log(
    #         event="ssh_auth_attempt",
    #         session_id=self._session_id,
    #         username=username,
    #         hostname=HOSTNAME,
    #         remote_addr=self._remote_addr,
    #         success=True,
    #         note="none auth accepted",
    #         method="none",
    #         proto="ssh",
    #         local_port=self._local_port,
    #     )
    #     return paramiko.AUTH_SUCCESSFUL


    def check_auth_password(self, username, password):
        append_auth_log(
            event="ssh_auth_attempt",
            session_id=self._session_id,
            username=username,
            hostname=HOSTNAME,
            remote_addr=self._remote_addr,
            success=True,
            note="password auth accepted (ignored)",
            method="password",
            password=str(password),
            proto="ssh",
            local_port=self._local_port,
        )
        return paramiko.AUTH_SUCCESSFUL

    # def get_allowed_auths(self, username):
    #     return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_requested = True
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        try:
            self.exec_command = command.decode("utf-8", errors="ignore") if isinstance(command, (bytes, bytearray)) else str(command)
        except Exception:
            self.exec_command = str(command)
        self.event.set()
        return True

SERVER_KEY_RSA = None
SERVER_KEY_ED25519 = None

try:
    if os.path.exists(RSA_KEY_PATH):
        SERVER_KEY_RSA = paramiko.RSAKey.from_private_key_file(RSA_KEY_PATH)
    else:
        k = paramiko.RSAKey.generate(2048)
        k.write_private_key_file(RSA_KEY_PATH)
        try:
            os.chmod(RSA_KEY_PATH, 0o600)
        except Exception:
            pass
        SERVER_KEY_RSA = paramiko.RSAKey.from_private_key_file(RSA_KEY_PATH)
except Exception:
    SERVER_KEY_RSA = None

try:
    if os.path.exists(ED25519_KEY_PATH):
        SERVER_KEY_ED25519 = paramiko.Ed25519Key.from_private_key_file(ED25519_KEY_PATH)
    else:
        try:
            k = paramiko.Ed25519Key.generate()
            k.write_private_key_file(ED25519_KEY_PATH)
            try:
                os.chmod(ED25519_KEY_PATH, 0o600)
            except Exception:
                pass
            SERVER_KEY_ED25519 = paramiko.Ed25519Key.from_private_key_file(ED25519_KEY_PATH)
        except Exception:
            SERVER_KEY_ED25519 = None
except Exception:
    SERVER_KEY_ED25519 = None

def _safe_send(chan, s: str | bytes) -> None:
    try:
        if isinstance(s, str):
            chan.send(s)
        else:
            chan.sendall(s)
    except Exception:
        pass

def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _record_upload_audit(**rec):
    try:
        rec.setdefault("timestamp", ts_utc_isoz())
        with open(UPLOAD_AUDIT_JSONL, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass

def _enforce_non_executable(path: str):
    # Uploaded payloads should be treated as data artifacts, not runnable binaries/scripts.
    try:
        os.chmod(path, 0o644)
    except Exception:
        pass

def _record_uploaded_file_in_system_log(
    local_path: str,
    docker_path: str,
    size: int,
    sha256: str,
    proto: str,
    av_status: str,
):
    try:
        log = load_system_log(SYSTEM_JSON)
        if not isinstance(log, dict):
            log = {}

        now_iso = ts_utc_isoz()
        rec = {
            "timestamp": now_iso,
            "file_name": os.path.basename(local_path),
            "local_path": local_path,
            "docker_path": docker_path,
            "size": int(size),
            "sha256": sha256,
            "proto": proto,
            "av_status": av_status,
        }

        uploaded = log.setdefault("uploaded_files", [])
        if not isinstance(uploaded, list):
            uploaded = []
            log["uploaded_files"] = uploaded
        uploaded = [
            x for x in uploaded
            if not (
                isinstance(x, dict)
                and (
                    x.get("local_path") == local_path
                    or (docker_path and x.get("docker_path") == docker_path)
                )
            )
        ]
        uploaded.append(rec)
        log["uploaded_files"] = uploaded[-500:]

        fs = log.setdefault("filesystem", {})
        if not isinstance(fs, dict):
            fs = {}
            log["filesystem"] = fs
        upload_node = fs.setdefault("/upload", {
            "files": [],
            "folders": {},
            "file_contents": {},
            "file_meta": {},
            "dir_mode": "drwxr-xr-x",
            "dir_mtime": now_iso,
        })
        if not isinstance(upload_node, dict):
            upload_node = {}
            fs["/upload"] = upload_node
        files = upload_node.setdefault("files", [])
        if not isinstance(files, list):
            files = []
            upload_node["files"] = files
        fname = os.path.basename(local_path)
        if fname not in files:
            files.append(fname)

        # Explicitly avoid storing uploaded file content in system_log.
        fc = upload_node.setdefault("file_contents", {})
        if isinstance(fc, dict) and fname in fc:
            fc.pop(fname, None)

        fm = upload_node.setdefault("file_meta", {})
        if isinstance(fm, dict):
            fm[fname] = {
                "mode_octal": "0644",
                "size": int(size),
                "hash": sha256,
                "mtime": now_iso,
                "source_proto": proto,
                "av_status": av_status,
            }

        upload_node["dir_mtime"] = now_iso
        log["timestamp"] = now_iso
        save_json_file(SYSTEM_JSON, log)
    except Exception as e:
        log_attack(f"[system_log] upload record failed for {local_path}: {e}", "warn")

def _scan_uploaded_file(path: str) -> Tuple[str, str, str]:
    """
    Returns: (engine, status, detail)
    status in {"clean", "infected", "error", "not_available"}
    """
    try:
        import subprocess
    except Exception as e:
        return "none", "error", f"subprocess unavailable: {e}"

    clamscan = shutil.which("clamscan")
    if clamscan:
        try:
            p = subprocess.run([clamscan, "--no-summary", path], capture_output=True, text=True, check=False)
            out = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
            if p.returncode == 0:
                return "clamav", "clean", out[:300]
            if p.returncode == 1:
                return "clamav", "infected", out[:300]
            return "clamav", "error", f"rc={p.returncode}; {out[:220]}"
        except Exception as e:
            return "clamav", "error", str(e)

    defender_candidates = [
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender", "Platform"),
    ]

    defender_exe = None
    for c in defender_candidates:
        if c.lower().endswith(".exe") and os.path.exists(c):
            defender_exe = c
            break
        if os.path.isdir(c):
            try:
                subs = sorted(os.listdir(c), reverse=True)
                for sub in subs:
                    exe = os.path.join(c, sub, "MpCmdRun.exe")
                    if os.path.exists(exe):
                        defender_exe = exe
                        break
                if defender_exe:
                    break
            except Exception:
                pass

    if defender_exe:
        try:
            p = subprocess.run(
                [defender_exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"],
                capture_output=True,
                text=True,
                check=False,
            )
            out = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
            if p.returncode == 0:
                return "defender", "clean", out[:300]
            if p.returncode == 2:
                return "defender", "infected", out[:300]
            return "defender", "error", f"rc={p.returncode}; {out[:220]}"
        except Exception as e:
            return "defender", "error", str(e)

    return "none", "not_available", "no scanner found (clamav/defender)"

def _copy_to_docker_and_delete(
    local_path: str,
    source_proto: str = "sftp",
    session_id: str = "",
    remote_addr: str = "",
):
    if not DOCKER_UPLOAD_CONTAINER:
        return
    try:
        import subprocess

        root = os.path.abspath(SCP_ROOT)
        abs_local = os.path.abspath(local_path)

        if not (abs_local == root or abs_local.startswith(root + os.sep)):
            log_attack(f"[docker] skip non-root file {abs_local}")
            return

        size = 0
        try:
            size = os.path.getsize(abs_local)
        except Exception:
            pass
        sha256 = ""
        try:
            sha256 = _file_sha256(abs_local)
        except Exception as e:
            log_attack(f"[upload] hash failed for {abs_local}: {e}", "warn")

        _enforce_non_executable(abs_local)
        av_engine, av_status, av_detail = _scan_uploaded_file(abs_local)

        rel = os.path.relpath(abs_local, root).replace("\\", "/")
        container_root = DOCKER_UPLOAD_PATH.rstrip("/")
        rel_parts = [p for p in rel.split("/") if p]
        container_parts = [p for p in container_root.split("/") if p]
        if container_parts and rel_parts[:len(container_parts)] == container_parts:
            rel_parts = rel_parts[len(container_parts):]
        else:
            container_leaf = os.path.basename(container_root)
            if rel_parts and container_leaf and rel_parts[0] == container_leaf:
                rel_parts = rel_parts[1:]
        rel = "/".join(rel_parts) if rel_parts else os.path.basename(abs_local)
        container_dst = f"{container_root}/{rel}"

        if av_status == "infected":
            os.makedirs(UPLOAD_QUARANTINE_DIR, exist_ok=True)
            quarantine_dst = os.path.join(UPLOAD_QUARANTINE_DIR, os.path.basename(abs_local))
            try:
                os.replace(abs_local, quarantine_dst)
            except Exception:
                quarantine_dst = abs_local
            log_attack(f"[upload] blocked infected file; quarantined at {quarantine_dst}; sha256={sha256}", "warn")
            _record_upload_audit(
                local_path=abs_local,
                size=size,
                sha256=sha256,
                av_engine=av_engine,
                av_status=av_status,
                av_detail=av_detail,
                copied_to_docker=False,
                docker_container=DOCKER_UPLOAD_CONTAINER,
                docker_path="",
                quarantined_path=quarantine_dst,
            )
            _record_uploaded_file_in_system_log(
                local_path=quarantine_dst,
                docker_path="",
                size=size,
                sha256=sha256,
                proto=source_proto,
                av_status=av_status,
            )
            return

        subprocess.run(
            ["docker", "exec", DOCKER_UPLOAD_CONTAINER, "mkdir", "-p", os.path.dirname(container_dst)],
            check=False
        )
        subprocess.run(
            ["docker", "cp", abs_local, f"{DOCKER_UPLOAD_CONTAINER}:{container_dst}"],
            check=True
        )
        subprocess.run(
            ["docker", "exec", DOCKER_UPLOAD_CONTAINER, "chmod", "0644", container_dst],
            check=False,
        )

        log_attack(f"[docker] copied {abs_local} -> {DOCKER_UPLOAD_CONTAINER}:{container_dst}")
        _record_upload_audit(
            local_path=abs_local,
            size=size,
            sha256=sha256,
            av_engine=av_engine,
            av_status=av_status,
            av_detail=av_detail,
            copied_to_docker=True,
            docker_container=DOCKER_UPLOAD_CONTAINER,
            docker_path=container_dst,
            quarantined_path="",
        )
        if source_proto == "sftp":
            append_auth_log(
                event="sftp_upload",
                session_id=session_id,
                username=USERNAME,
                hostname=HOSTNAME,
                remote_addr=remote_addr,
                success=True,
                note=f"uploaded file={os.path.basename(abs_local)} local={abs_local} docker={container_dst} ({size} bytes)",
                proto="ssh",
                local_port=PORT,
            )
        _record_uploaded_file_in_system_log(
            local_path=abs_local,
            docker_path=container_dst,
            size=size,
            sha256=sha256,
            proto=source_proto,
            av_status=av_status,
        )

        if DOCKER_DELETE_LOCAL_AFTER_COPY:
            try:
                os.remove(abs_local)
                log_attack(f"[docker] removed local {abs_local}")
            except Exception as e:
                log_attack(f"[docker] remove local failed {abs_local}: {e}", "warn")

    except Exception as e:
        log_attack(f"[docker] copy failed for {local_path}: {e}", "warn")

def _normalize_under_root(path: str) -> str:
    root = os.path.abspath(SCP_ROOT)
    abs_path = os.path.abspath(path)
    if abs_path == root or abs_path.startswith(root + os.sep):
        return abs_path

    if path.startswith("/"):
        path = path[1:]

    safe_parts: List[str] = []
    for p in path.split("/"):
        if not p or p == ".":
            continue
        if p == "..":
            if safe_parts:
                safe_parts.pop()
        else:
            safe_parts.append(p)

    local_path = os.path.abspath(os.path.join(root, *safe_parts)) if safe_parts else root

    if os.name == "nt":
        r = root.lower()
        lp = local_path.lower()
        if lp == r or lp.startswith(r + os.sep):
            return local_path
        return root
    else:
        if local_path == root or local_path.startswith(root + os.sep):
            return local_path
        return root

class RootedSFTPHandle(SFTPHandle):
    def __init__(self, flags, filename=None, session_id: str = "", remote_addr: str = ""):
        super().__init__(flags)
        self.filename = filename
        self.session_id = session_id
        self.remote_addr = remote_addr
        self.readfile = None
        self.writefile = None

    def read(self, offset, length):
        if not self.readfile:
            return SFTP_FAILURE
        try:
            self.readfile.seek(offset)
            return self.readfile.read(length)
        except Exception:
            return SFTP_FAILURE

    def write(self, offset, data):
        if not self.writefile:
            return SFTP_FAILURE
        try:
            self.writefile.seek(offset)
            self.writefile.write(data)
            return SFTP_OK
        except Exception:
            return SFTP_FAILURE

    def close(self):
        try:
            file_path = self.filename
            wrote = self.writefile is not None

            if self.readfile:
                self.readfile.close()
            if self.writefile:
                self.writefile.close()

            if wrote and file_path:
                _copy_to_docker_and_delete(
                    file_path,
                    source_proto="sftp",
                    session_id=self.session_id,
                    remote_addr=self.remote_addr,
                )

            return SFTP_OK
        except Exception:
            return SFTP_FAILURE

class RootedSFTP(SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server)
        self.root = os.path.abspath(SCP_ROOT)
        self.session_id = getattr(server, "_session_id", "")
        self.remote_addr = getattr(server, "_remote_addr", "")
        try:
            os.makedirs(self.root, exist_ok=True)
        except Exception:
            pass

    def _to_local(self, path: str) -> str:
        if not path:
            path = "/"
        if path.startswith("/"):
            path = path[1:]
        parts = []
        for p in path.split("/"):
            if p in ("", "."):
                continue
            if p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        local = os.path.abspath(os.path.join(self.root, *parts)) if parts else self.root
        r = self.root.lower() if os.name == "nt" else self.root
        l = local.lower() if os.name == "nt" else local
        if l == r or l.startswith(r + os.sep):
            return local
        return self.root

    def list_folder(self, path):
        try:
            local = self._to_local(path)
            if not os.path.isdir(local):
                return SFTP_NO_SUCH_FILE
            out = []
            for name in os.listdir(local):
                full = os.path.join(local, name)
                try:
                    st = os.stat(full)
                except Exception:
                    continue
                attr = SFTPAttributes.from_stat(st)
                attr.filename = name
                out.append(attr)
            return out
        except Exception:
            return SFTP_FAILURE

    def stat(self, path):
        try:
            local = self._to_local(path)
            st = os.stat(local)
            return SFTPAttributes.from_stat(st)
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception:
            return SFTP_FAILURE

    lstat = stat

    def open(self, path, flags, attr):
        try:
            local = self._to_local(path)
            os_flags = _convert_sftp_pflags_to_os(flags)
            write_requested = bool(os_flags & (os.O_WRONLY | os.O_RDWR))
            read_requested = bool(os_flags & os.O_RDWR) or not bool(os_flags & os.O_WRONLY)
            wants_create = bool(os_flags & os.O_CREAT)
            wants_append = bool(os_flags & os.O_APPEND)
            wants_trunc = bool(os_flags & os.O_TRUNC)

            if write_requested:
                parent = os.path.dirname(local)
                if parent and not os.path.exists(parent):
                    os.makedirs(parent, exist_ok=True)


            if write_requested and read_requested:
                if wants_append:
                    py_mode = "a+b"
                elif wants_trunc:
                    py_mode = "w+b"
                else:
                    py_mode = "r+b"
                    if wants_create and not os.path.exists(local):
                        py_mode = "w+b"
            elif write_requested:
                py_mode = "ab" if wants_append else "wb"
            else:
                py_mode = "rb"

            fobj = open(local, py_mode)

            if attr and attr.st_mode is not None and write_requested:
                try:
                    os.chmod(local, attr.st_mode & 0o777)
                except Exception:
                    pass

            h = RootedSFTPHandle(
                flags,
                filename=local,
                session_id=self.session_id,
                remote_addr=self.remote_addr,
            )
            if "r" in py_mode:
                h.readfile = fobj
            if "w" in py_mode or "+" in py_mode or "a" in py_mode:
                h.writefile = fobj
            return h
        except PermissionError:
            return SFTP_PERMISSION_DENIED
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception as e:
            log_attack(f"[sftp] open failed path={path!r} local={locals().get('local', '')!r}: {e}", "warn")
            return SFTP_FAILURE

    def remove(self, path):
        try:
            local = self._to_local(path)
            os.remove(local)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception:
            return SFTP_FAILURE

    def mkdir(self, path, attr):
        try:
            local = self._to_local(path)
            os.makedirs(local, exist_ok=True)
            return SFTP_OK
        except Exception:
            return SFTP_FAILURE

    def rmdir(self, path):
        try:
            local = self._to_local(path)
            os.rmdir(local)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception:
            return SFTP_FAILURE

    def rename(self, oldpath, newpath):
        try:
            src = self._to_local(oldpath)
            dst = self._to_local(newpath)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(src, dst)
            return SFTP_OK
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except Exception:
            return SFTP_FAILURE

def _scp_read_ack(chan) -> int:
    try:
        b = chan.recv(1)
        if not b:
            return -1
        return b[0]
    except Exception:
        return -1

def _scp_send_ack(chan):
    _safe_send(chan, b"\x00")

def _scp_send_error(chan, msg: str, fatal: bool = False):
    try:
        b = (msg + "\n").encode("utf-8", errors="ignore")
        _safe_send(chan, b"\x01" + b)
    except Exception:
        pass
    if fatal:
        try:
            chan.close()
        except Exception:
            pass

def _scp_read_line(chan) -> bytes:
    buf = b""
    while True:
        b = chan.recv(1)
        if not b:
            return b""
        buf += b
        if b == b"\n":
            return buf

def _scp_read_exact(chan, size: int) -> bytes:
    out = b""
    remaining = size
    while remaining > 0:
        chunk = chan.recv(min(32768, remaining))
        if not chunk:
            break
        out += chunk
        remaining -= len(chunk)
    return out

def _ensure_parent(path: str):
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

def _convert_sftp_pflags_to_os(pflags: int) -> int:

    if int(pflags) & ~0x3F:
        return int(pflags)


    P_READ = 0x01
    P_WRITE = 0x02
    P_APPEND = 0x04
    P_CREAT = 0x08
    P_TRUNC = 0x10
    P_EXCL = 0x20

    read_requested = bool(pflags & P_READ)
    write_requested = bool(pflags & P_WRITE)

    if read_requested and write_requested:
        os_flags = os.O_RDWR
    elif write_requested:
        os_flags = os.O_WRONLY
    else:
        os_flags = os.O_RDONLY

    if pflags & P_APPEND:
        os_flags |= os.O_APPEND
    if pflags & P_CREAT:
        os_flags |= os.O_CREAT
    if pflags & P_TRUNC:
        os_flags |= os.O_TRUNC
    if pflags & P_EXCL:
        os_flags |= os.O_EXCL

    return os_flags

_SCPEXEC_RE = re.compile(r"scp(\.exe)?$", re.IGNORECASE)

def _parse_scp_exec(exec_cmd: str) -> Tuple[Optional[str], Optional[str]]:
    if not exec_cmd:
        return None, None
    args = exec_cmd.strip().split()
    if not args:
        return None, None

    cmd0 = os.path.basename(args[0])
    if not _SCPEXEC_RE.fullmatch(cmd0):
        i = 0
        while i < len(args) and not _SCPEXEC_RE.fullmatch(os.path.basename(args[i])):
            i += 1
        if i >= len(args):
            return None, None
        args = args[i:]

    args = args[1:]
    if not args:
        return None, None

    opts, rest = [], []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            rest.extend(args[i + 1:])
            break
        elif a.startswith("-"):
            opts.append(a)
        else:
            rest.append(a)
        i += 1

    optstr = " ".join(opts).lower()
    mode = None
    if re.search(r'(^|\s)-t(\s|$)', optstr):
        mode = "upload"
    elif re.search(r'(^|\s)-f(\s|$)', optstr):
        mode = "download"
    else:
        return None, None

    target = rest[0] if rest else "/"
    return mode, target

def scp_serve_download(chan, remote_path: str, session_id: str, remote_addr: str):
    req_path = remote_path.strip()
    local_path = _normalize_under_root(req_path)
    base = os.path.basename(local_path)

    append_auth_log(event="scp_download", session_id=session_id, username=USERNAME,
                    hostname=HOSTNAME, remote_addr=remote_addr, success=False,
                    note=f"request_path={req_path}, local_path={local_path}")

    if not (os.path.exists(local_path) and os.path.isfile(local_path)):
        _scp_send_error(chan, f"not found: {req_path}")
        try:
            chan.send_exit_status(1)
        except Exception:
            pass
        log_attack(f"[{session_id}] SCP file not found: {local_path}", "warn")
        return

    try:
        size = os.path.getsize(local_path)
        mode = 0o644

        ack = _scp_read_ack(chan)
        if ack != 0:
            _scp_send_error(chan, "Client not ready")
            return

        header = f"C{mode:04o} {size} {base}\n".encode("utf-8")
        _safe_send(chan, header)
        _scp_read_ack(chan)

        with open(local_path, "rb") as f:
            while True:
                chunk = f.read(32768)
                if not chunk:
                    break
                _safe_send(chan, chunk)

        _scp_send_ack(chan)
        _scp_read_ack(chan)

        try:
            chan.send_exit_status(0)
        except Exception:
            pass

        append_auth_log(event="scp_download", session_id=session_id, username=USERNAME,
                        hostname=HOSTNAME, remote_addr=remote_addr, success=True,
                        note=f"ok {base} ({size} bytes)")
        log_attack(f"[{session_id}] SCP sent: {base} ({size} bytes)")
    except Exception as e:
        _scp_send_error(chan, f"error: {e}", fatal=True)
        try:
            chan.send_exit_status(2)
        except Exception:
            pass

def scp_serve_upload(chan, target_path: str, session_id: str, remote_addr: str):
    base_target = _normalize_under_root(target_path.strip())
    root_dir = (
        base_target if os.path.isdir(base_target) or target_path.endswith("/")
        else os.path.dirname(base_target)
    )
    if not os.path.isdir(root_dir):
        os.makedirs(root_dir, exist_ok=True)

    dir_stack: List[str] = [root_dir]

    def _cwd() -> str:
        return dir_stack[-1]

    def _enter_dir(name: str):
        d = os.path.join(_cwd(), name)
        d = _normalize_under_root(d)
        os.makedirs(d, exist_ok=True)
        dir_stack.append(d)

    def _leave_dir():
        if len(dir_stack) > 1:
            dir_stack.pop()

    def _write_file(mode: int, size: int, name: str):
        dst = os.path.join(_cwd(), name)
        dst = _normalize_under_root(dst)
        _ensure_parent(dst)

        data = _scp_read_exact(chan, size)
        with open(dst, "wb") as f:
            f.write(data)

        _ = _scp_read_ack(chan)
        _scp_send_ack(chan)

        try:
            os.chmod(dst, mode & 0o777)
        except Exception:
            pass

        _copy_to_docker_and_delete(dst, source_proto="scp")

        append_auth_log(
            event="scp_upload",
            session_id=session_id,
            username=USERNAME,
            hostname=HOSTNAME,
            remote_addr=remote_addr,
            success=True,
            note=f"upload to docker from {dst} ({size} bytes)"
        )
        log_attack(f"[{session_id}] SCP received to docker: {dst} ({size} bytes)")

    try:
        _scp_send_ack(chan)
        log_attack(f"[{session_id}] SCP upload ready, target: {target_path}")

        while True:
            line = _scp_read_line(chan)
            if line == b"":
                break
            s = line.rstrip(b"\r\n")
            if not s:
                _scp_send_ack(chan)
                continue

            tag = s[:1]
            rest = s[1:].decode("utf-8", "ignore").strip()

            if tag == b"C":
                mode_str, size_str, name = rest.split(" ", 2)
                mode = int(mode_str, 8)
                size = int(size_str)
                _scp_send_ack(chan)
                _write_file(mode, size, name)

            elif tag == b"D":
                mode_str, _zero, name = rest.split(" ", 2)
                _enter_dir(name)
                try:
                    os.chmod(_cwd(), int(mode_str, 8) & 0o777)
                except Exception:
                    pass
                _scp_send_ack(chan)

            elif tag == b"E":
                _leave_dir()
                _scp_send_ack(chan)

            elif tag == b"T":
                _scp_send_ack(chan)

            elif tag in (b"\x00",):
                _scp_send_ack(chan)

            else:
                _scp_send_error(chan, f"unsupported header: {line!r}", fatal=True)
                return
    except Exception as e:
        _scp_send_error(chan, f"upload error: {e}", fatal=True)
        log_attack(f"[{session_id}] SCP upload error: {e}", "error")
    else:
        try:
            chan.send_exit_status(0)
        except Exception:
            pass

def send_response_lines_shell(chan, text: str, prompt: str, chunk_size: int = 1024):
    if text is None:
        text = ""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    for line in lines:
        if line == "":
            _safe_send(chan, "\r\n")
            continue
        b = line.encode("utf-8", errors="ignore")
        for i in range(0, len(b), chunk_size):
            chunk = b[i:i+chunk_size].decode("utf-8", errors="ignore")
            _safe_send(chan, chunk)
        _safe_send(chan, "\r\n")
    _safe_send(chan, "\r\n")
    _safe_send(chan, prompt)

def _format_uptime(seconds: float) -> str:
    s = int(max(0, seconds))
    days = s // 86400
    s %= 86400
    hours = s // 3600
    s %= 3600
    mins = s // 60
    if days > 0:
        return f"up {days} day{'s' if days != 1 else ''},  {hours:2d}:{mins:02d}"
    return f"up  {hours:2d}:{mins:02d}"

def _top_render_from_state_fallback(state: Dict[str, Any]) -> str:
    now_hms = fmt_eastern("%H:%M:%S")
    up = state.get("uptime_str") or _format_uptime(float(state.get("uptime_sec", 0.0)))
    users = int(state.get("users", 1))
    la = state.get("loadavg") or [0.06, 0.08, 0.10]
    la1, la5, la15 = float(la[0]), float(la[1]), float(la[2])

    tasks_total = int(state.get("tasks_total", 0))
    tasks_running = int(state.get("tasks_running", 1))
    tasks_sleeping = int(state.get("tasks_sleeping", max(0, tasks_total - tasks_running)))
    tasks_stopped = int(state.get("tasks_stopped", 0))
    tasks_zombie = int(state.get("tasks_zombie", 0))

    cpu = state.get("cpu") or {"us": 0.7, "sy": 0.3, "ni": 0.0, "id": 98.7, "wa": 0.2, "hi": 0.0, "si": 0.1, "st": 0.0}
    mem = state.get("memory") or {"total_mib": 2048.0, "free_mib": 812.4, "used_mib": 531.8, "buff_cache_mib": 703.8}
    sw  = state.get("swap") or {"total_mib": 1024.0, "free_mib": 1024.0, "used_mib": 0.0}
    swap_avail = float(mem.get("free_mib", 0.0)) + float(mem.get("buff_cache_mib", 0.0))

    procs = state.get("processes") or []

    lines: List[str] = []
    lines.append(f"top - {now_hms} {up},  {users} user,  load average: {la1:.2f}, {la5:.2f}, {la15:.2f}")
    lines.append(f"Tasks: {tasks_total:3d} total,   {tasks_running:1d} running, {tasks_sleeping:3d} sleeping,   {tasks_stopped:1d} stopped,   {tasks_zombie:1d} zombie")
    lines.append(f"%Cpu(s):  {float(cpu.get('us',0.0)):3.1f} us,  {float(cpu.get('sy',0.0)):3.1f} sy,  {float(cpu.get('ni',0.0)):3.1f} ni, {float(cpu.get('id',0.0)):3.1f} id,  {float(cpu.get('wa',0.0)):3.1f} wa,  {float(cpu.get('hi',0.0)):3.1f} hi,  {float(cpu.get('si',0.0)):3.1f} si,  {float(cpu.get('st',0.0)):3.1f} st")
    lines.append(f"MiB Mem : {float(mem.get('total_mib',0.0)):7.1f} total, {float(mem.get('free_mib',0.0)):7.1f} free, {float(mem.get('used_mib',0.0)):7.1f} used, {float(mem.get('buff_cache_mib',0.0)):7.1f} buff/cache")
    lines.append(f"MiB Swap: {float(sw.get('total_mib',0.0)):7.1f} total, {float(sw.get('free_mib',0.0)):7.1f} free, {float(sw.get('used_mib',0.0)):7.1f} used. {swap_avail:7.1f} avail Mem")
    lines.append("")
    lines.append("  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND")

    for p in procs[:25]:
        lines.append(
            f"{int(p.get('pid', 0)):5d} {str(p.get('user','root')):<8} {int(p.get('pr',20)):2d} {int(p.get('ni',0)):3d} "
            f"{str(p.get('virt','0m')):>7} {str(p.get('res','0m')):>6} {str(p.get('shr','0m')):>6} {str(p.get('state','S')):<1} "
            f"{float(p.get('%cpu',0.0)):5.1f} {float(p.get('%mem',0.0)):4.1f} {str(p.get('time_plus','0:00.00')):>9} {str(p.get('cmd','-'))}"
        )

    lines.append("")
    lines.append("q: Quit")
    return "\n".join(lines)

def run_agent_shell(chan, session_id: str, remote_addr: str):
    vuln_agent = VulnerabilityAgentLLM()

    session_log: List[Dict[str, Any]] = load_session_log() if LOAD_SESSION_FROM_FILE else []
    save_session_log(session_log)

    file_syslog = load_system_log(SYSTEM_JSON) if LOAD_SYSTEM_FROM_FILE else None
    if isinstance(file_syslog, dict):
        system_log: Dict[str, Any] = file_syslog
    else:
        system_log = vuln_agent.get_system_log()

    system_log["cwd"] = system_log.get("cwd") or "/home/user"
    system_log["timestamp"] = ts_utc_isoz()
    vuln_agent.system_log = system_log

    current_path = system_log.get("cwd", "/home/user")
    file_tree = system_log.get("filesystem", {})

    CSI = "\x1b["

    planner = PlanningRuntime(K=30)

    def _prompt() -> str:
        return f"{USERNAME}@{HOSTNAME}:{current_path}$ "

    def _redraw_line(buffer: List[str], cursor: int):
        _safe_send(chan, "\r")
        line = _prompt() + "".join(buffer)
        _safe_send(chan, line)
        _safe_send(chan, "\x1b[K")
        back = len(buffer) - cursor
        if back > 0:
            _safe_send(chan, f"{CSI}{back}D")
    def _ensure_dir(abs_dir: str) -> Dict[str, Any]:
        fs = system_log.setdefault("filesystem", {})
        if abs_dir not in fs:
            fs[abs_dir] = {"files": [], "folders": {}, "file_contents": {}, "file_meta": {}}
        node = fs[abs_dir]
        node.setdefault("files", [])
        node.setdefault("folders", {})
        node.setdefault("file_contents", {})
        node.setdefault("file_meta", {})
        return node

    def _get_dir(abs_dir: str) -> Optional[Dict[str, Any]]:
        fs = system_log.get("filesystem", {})
        if isinstance(fs, dict) and abs_dir in fs and isinstance(fs[abs_dir], dict):
            return fs[abs_dir]
        return None

    def _resolve_path(p: str) -> str:
        p = (p or "").strip()
        if not p:
            return current_path
        if p.startswith("/"):
            out = p
        else:
            base = current_path.rstrip("/") or "/"
            out = (base + "/" + p).replace("//", "/")
        # normalize .. and .
        parts = []
        for seg in out.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(seg)
        return "/" + "/".join(parts) if parts else "/"

    def _read_file(abs_path: str) -> str:
        d = os.path.dirname(abs_path).replace("\\", "/")
        b = os.path.basename(abs_path)
        node = _get_dir(d)
        if not node:
            return ""
        fc = node.get("file_contents", {})
        if isinstance(fc, dict):
            return str(fc.get(b, ""))
        return ""

    def _write_file(abs_path: str, content: str):
        ident = system_log.get("identity", {}) or {}
        euid = int(ident.get("euid", ident.get("uid", 1000)) or 1000)
        if abs_path.startswith("/etc/") and euid != 0:
            raise PermissionError("Permission denied")

        d = os.path.dirname(abs_path).replace("\\", "/")
        b = os.path.basename(abs_path)
        node = _ensure_dir(d)
        node["file_contents"][b] = content
        if b not in node["files"]:
            node["files"].append(b)
        meta = node.setdefault("file_meta", {})
        meta[b] = {
            "mode": "-rw-r--r--",
            "mode_octal": "0644",
            "uid": int(ident.get("uid", 1000) or 1000),
            "gid": int(ident.get("gid", 1000) or 1000),
            "mtime": ts_utc_isoz(),
            "size": len(content.encode("utf-8", errors="ignore")),
            "hash": meta.get(b, {}).get("hash", "")
        }
        vuln_agent.system_log = system_log
        if PERSIST_SYSTEM_TO_FILE:
            try:
                vuln_agent.save_system_log(system_log)
            except Exception:
                pass

    _top_session_start = time.time()
    _top_cpu_time_by_pid: Dict[int, float] = {}
    _top_last_frame_time = 0.0

    def _derive_processes_from_system_log(syslog: Dict[str, Any]) -> List[Dict[str, Any]]:

        if isinstance(syslog.get("processes"), list):
            out = []
            for p in syslog["processes"]:
                if isinstance(p, dict) and "pid" in p:
                    out.append(p)
            if out:
                return out

        procs: List[Dict[str, Any]] = []


        procs.append({
            "pid": 1, "user": "root", "pr": 20, "ni": 0,
            "virt": "168m", "res": "  7m", "shr": "  5m", "state": "S",
            "%cpu": 0.0, "%mem": 0.3, "time_plus": "0:00.16", "cmd": "/sbin/init"
        })

        ports = (((syslog.get("network") or {}).get("listening_ports")) or [])
        seen: set[int] = set()
        for ent in ports:
            if not isinstance(ent, dict):
                continue
            pid = int(ent.get("pid", 0) or 0)
            name = str(ent.get("process") or "unknown")
            if pid <= 0 or pid in seen:
                continue
            seen.add(pid)

            proc_user = "root" if name in ("sshd", "java", "nginx", "apache2") else str((syslog.get("identity", {}) or {}).get("user", "user"))

            if name == "java":
                virt, res, shr, cpu, mem = " 512m", " 96m", " 12m", 0.3, 4.5
            elif name == "sshd":
                virt, res, shr, cpu, mem = "  85m", " 14m", "  8m", 0.0, 0.7
            else:
                virt, res, shr, cpu, mem = " 128m", " 18m", "  6m", 0.0, 0.6

            procs.append({
                "pid": pid, "user": proc_user, "pr": 20, "ni": 0,
                "virt": virt, "res": res, "shr": shr, "state": "S",
                "%cpu": cpu, "%mem": mem, "time_plus": "0:00.00", "cmd": name
            })

        # session bash (stable pseudo pid)
        user_name = str((syslog.get("identity", {}) or {}).get("user", "user"))
        procs.append({
            "pid": 613, "user": user_name, "pr": 20, "ni": 0,
            "virt": "  12m", "res": "  5m", "shr": "  4m", "state": "R",
            "%cpu": 0.1, "%mem": 0.2, "time_plus": "0:00.01", "cmd": "bash"
        })

        procs.sort(key=lambda x: (-float(x.get("%cpu", 0.0)), int(x.get("pid", 0))))
        return procs

    def _update_time_plus(procs: List[Dict[str, Any]], delta: float) -> None:
        for p in procs:
            pid = int(p.get("pid", 0) or 0)
            cpu = float(p.get("%cpu", 0.0) or 0.0)
            prev = float(_top_cpu_time_by_pid.get(pid, 0.0))
            inc = max(0.0, min(1.0, cpu / 100.0)) * max(0.0, delta) * 4.0
            cur = prev + inc
            _top_cpu_time_by_pid[pid] = cur

            mm = int(cur // 60)
            ss = cur % 60
            p["time_plus"] = f"{mm}:{ss:05.2f}"

    def _build_top_state(syslog: Dict[str, Any]) -> Dict[str, Any]:
        uptime_sec = float(syslog.get("uptime_sec") or 0.0)
        if uptime_sec <= 0:
            uptime_sec = time.time() - _top_session_start
            syslog["uptime_sec"] = uptime_sec

        la = syslog.get("loadavg")
        if not (isinstance(la, list) and len(la) >= 3):
            t = int(time.time())
            base = 0.05 + ((t // 2) % 40) / 1000.0
            la = [base, base + 0.01, base + 0.02]
            syslog["loadavg"] = la

        users = int(syslog.get("users") or 1)

        cpu = syslog.get("cpu")
        if not isinstance(cpu, dict):
            cpu = {"us": 0.7, "sy": 0.3, "ni": 0.0, "id": 98.7, "wa": 0.2, "hi": 0.0, "si": 0.1, "st": 0.0}
            syslog["cpu"] = cpu

        mem = syslog.get("memory")
        if not isinstance(mem, dict):
            mem = {"total_mib": 2048.0, "free_mib": 812.4, "used_mib": 531.8, "buff_cache_mib": 703.8}
            syslog["memory"] = mem

        sw = syslog.get("swap")
        if not isinstance(sw, dict):
            sw = {"total_mib": 1024.0, "free_mib": 1024.0, "used_mib": 0.0}
            syslog["swap"] = sw

        procs = _derive_processes_from_system_log(syslog)
        tasks_total = len(procs)
        tasks_running = sum(1 for p in procs if str(p.get("state", "S")) == "R")
        tasks_sleeping = max(0, tasks_total - tasks_running)

        return {
            "uptime_sec": uptime_sec,
            "uptime_str": _format_uptime(uptime_sec),
            "users": users,
            "loadavg": [float(la[0]), float(la[1]), float(la[2])],
            "tasks_total": tasks_total,
            "tasks_running": tasks_running if tasks_running > 0 else 1,
            "tasks_sleeping": tasks_sleeping,
            "tasks_stopped": 0,
            "tasks_zombie": 0,
            "cpu": cpu,
            "memory": mem,
            "swap": sw,
            "processes": procs,
        }

    def _top_frame_via_llm() -> str:
        nonlocal _top_last_frame_time

        refresh_system_log_for_planning(system_log, vuln_agent)

        now = time.time()
        delta = now - _top_last_frame_time if _top_last_frame_time > 0 else TOP_REFRESH_SEC
        _top_last_frame_time = now

        state = _build_top_state(system_log)
        _update_time_plus(state["processes"], delta)

        system_log["_top_state"] = state
        try:
            if client is None:
                raise RuntimeError("LLM client not available")

            txt = plan_terminal_response(client, "top", current_path, file_tree, session_log, system_log)

            if not isinstance(txt, str) or ("load average" not in txt) or ("PID" not in txt):
                raise RuntimeError("LLM top frame invalid")

            return txt
        except Exception:
            return _top_render_from_state_fallback(state)
        finally:
            system_log.pop("_top_state", None)

    def _run_top_interactive(interval: float = TOP_REFRESH_SEC):
        old_timeout = None
        try:
            try:
                old_timeout = chan.gettimeout()
            except Exception:
                old_timeout = None

            try:
                chan.settimeout(0.0)  
            except Exception:
                pass

            _safe_send(chan, "\x1b[?25l") 
            last_render = 0.0

            while True:
                now = time.time()
                if now - last_render >= interval:
                    frame = _top_frame_via_llm().replace("\n", "\r\n")
                    _safe_send(chan, "\x1b[H\x1b[2J")
                    _safe_send(chan, frame + "\r\n")
                    last_render = now

                if chan.recv_ready():
                    data = chan.recv(1024)
                    if not data:
                        return
                    if b"q" in data or b"Q" in data or b"\x03" in data:
                        return

                time.sleep(0.05)
        finally:
            _safe_send(chan, "\x1b[?25h") 
            _safe_send(chan, "\x1b[H\x1b[2J")
            try:
                chan.settimeout(old_timeout)
            except Exception:
                pass

    def _nano_clear():
        _safe_send(chan, "\x1b[H\x1b[2J")

    def _nano_hide_cursor():
        _safe_send(chan, "\x1b[?25l")

    def _nano_show_cursor():
        _safe_send(chan, "\x1b[?25h")

    def _nano_move_cursor(row: int, col: int):
        _safe_send(chan, f"{CSI}{row};{col}H")

    def _clip(n: int, lo: int, hi: int) -> int:
        return max(lo, min(hi, n))

    def _recv_key_blocking() -> str:
        """
        Read one key:
        - printable char
        - Enter, Backspace
        - Ctrl+O, Ctrl+X
        - Arrow keys (ESC [ A/B/C/D)
        """
        b = chan.recv(1)
        if not b:
            return ""
        ch = b.decode("utf-8", errors="ignore")
        if ch != "\x1b":
            return ch

        # escape sequence
        b2 = chan.recv(1)
        if not b2:
            return "\x1b"
        ch2 = b2.decode("utf-8", errors="ignore")
        if ch2 != "[":
            return "\x1b" + ch2

        b3 = chan.recv(1)
        if not b3:
            return "\x1b["
        ch3 = b3.decode("utf-8", errors="ignore")
        return "\x1b[" + ch3 

    def _render_nano(filename: str, lines: List[str], cy: int, cx: int, msg: str, dirty: bool,
                     rows: int = 24, cols: int = 80):

        text_rows = max(1, rows - 3) 
        top = 0
        if cy >= top + text_rows:
            top = cy - text_rows + 1
        if cy < top:
            top = cy

        _nano_clear()

        head = f"  GNU nano  {filename}"
        if dirty:
            head += "  [Modified]"
        _safe_send(chan, head[:cols].ljust(cols) + "\r\n")

        for r in range(text_rows):
            li = top + r
            s = lines[li] if li < len(lines) else ""
            _safe_send(chan, s[:cols].ljust(cols) + "\r\n")

        help_line = "^O WriteOut   ^X Exit"
        _safe_send(chan, help_line[:cols].ljust(cols) + "\r\n")

        _safe_send(chan, (msg or "")[:cols].ljust(cols))

        vy = 2 + (cy - top)  
        vx = 1 + cx
        vy = _clip(vy, 2, rows - 2)
        vx = _clip(vx, 1, cols)
        _nano_move_cursor(vy, vx)

    def _run_nano_interactive(abs_path: str):

        old_timeout = None
        try:
            try:
                old_timeout = chan.gettimeout()
            except Exception:
                old_timeout = None
            try:
                chan.settimeout(None)
            except Exception:
                pass

            filename = abs_path
            content = _read_file(abs_path)
            lines = content.split("\n")
            if not lines:
                lines = [""]

            cy, cx = 0, 0
            dirty = False
            msg = ""

            _nano_hide_cursor()
            _render_nano(filename, lines, cy, cx, msg, dirty)

            while True:
                k = _recv_key_blocking()
                if k == "":
                    break

                if k == "\x18":
                    if not dirty:
                        msg = "Exit"
                        _render_nano(filename, lines, cy, cx, msg, dirty)
                        break

                    msg = "Save modified buffer? (y/n)"
                    _render_nano(filename, lines, cy, cx, msg, dirty)
                    while True:
                        kk = _recv_key_blocking().lower()
                        if kk in ("y", "n"):
                            if kk == "y":
                                try:
                                    _write_file(abs_path, "\n".join(lines))
                                    dirty = False
                                    msg = "Wrote file"
                                except PermissionError:
                                    msg = "Error writing file: Permission denied"
                                except Exception as e:
                                    msg = f"Error writing file: {e}"
                            else:
                                msg = "Discarded changes"
                            _render_nano(filename, lines, cy, cx, msg, dirty)
                            break
                    break

                if k == "\x0f":
                    try:
                        _write_file(abs_path, "\n".join(lines))
                        dirty = False
                        msg = "Wrote file"
                    except PermissionError:
                        msg = "Error writing file: Permission denied"
                    except Exception as e:
                        msg = f"Error writing file: {e}"
                    _render_nano(filename, lines, cy, cx, msg, dirty)
                    continue

                if k == "\x1b[A":  # up
                    cy = _clip(cy - 1, 0, len(lines) - 1)
                    cx = _clip(cx, 0, len(lines[cy]))
                    _render_nano(filename, lines, cy, cx, "", dirty)
                    continue
                if k == "\x1b[B":  # down
                    cy = _clip(cy + 1, 0, len(lines) - 1)
                    cx = _clip(cx, 0, len(lines[cy]))
                    _render_nano(filename, lines, cy, cx, "", dirty)
                    continue
                if k == "\x1b[C":  # right
                    cx = _clip(cx + 1, 0, len(lines[cy]))
                    _render_nano(filename, lines, cy, cx, "", dirty)
                    continue
                if k == "\x1b[D":  # left
                    cx = _clip(cx - 1, 0, len(lines[cy]))
                    _render_nano(filename, lines, cy, cx, "", dirty)
                    continue

                if k in ("\r", "\n"):
                    left = lines[cy][:cx]
                    right = lines[cy][cx:]
                    lines[cy] = left
                    lines.insert(cy + 1, right)
                    cy += 1
                    cx = 0
                    dirty = True
                    _render_nano(filename, lines, cy, cx, "", dirty)
                    continue


                if k == "\x7f":
                    if cx > 0:
                        s = lines[cy]
                        lines[cy] = s[:cx - 1] + s[cx:]
                        cx -= 1
                        dirty = True
                    elif cy > 0:
                        prev = lines[cy - 1]
                        cur = lines[cy]
                        cx = len(prev)
                        lines[cy - 1] = prev + cur
                        del lines[cy]
                        cy -= 1
                        dirty = True
                    _render_nano(filename, lines, cy, cx, "", dirty)
                    continue

                if len(k) == 1 and (" " <= k <= "~"):
                    s = lines[cy]
                    lines[cy] = s[:cx] + k + s[cx:]
                    cx += 1
                    dirty = True
                    _render_nano(filename, lines, cy, cx, "", dirty)
                    continue


        finally:
            _nano_show_cursor()
            _safe_send(chan, "\r\n")
            try:
                chan.settimeout(old_timeout)
            except Exception:
                pass

    buffer: List[str] = []
    cursor: int = 0
    history: List[str] = []
    hist_idx: int = 0

    _safe_send(chan, "\r\n")
    _safe_send(chan, "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-84-generic x86_64)\r\n")
    _safe_send(chan, f"Last login: {fmt_eastern('%a %b %d %H:%M:%S %Y')} from {remote_addr.split(':')[0]}\r\n")
    _safe_send(chan, _prompt())

    esc_mode = False
    esc_buf = ""




    

    def _accept_line():
        nonlocal buffer, cursor, history, hist_idx, system_log, current_path, file_tree
        cmd = "".join(buffer).strip()
        log_attack(f"[{session_id}] Command received: {cmd}")
        _safe_send(chan, "\r\n")

        if cmd == "":
            _safe_send(chan, _prompt())
            buffer.clear()
            cursor = 0
            hist_idx = len(history)
            return None

        if cmd.lower() == "exit":
            _safe_send(chan, "logout\r\n")
            append_auth_log(event="disconnect", session_id=session_id, username=USERNAME,
                            hostname=HOSTNAME, remote_addr=remote_addr, success=True, note="session closed", proto="ssh", local_port=PORT)
            try:
                chan.close()
            except Exception:
                pass
            return "EXIT"

        history.append(cmd)
        hist_idx = len(history)

        if cmd == "top" or cmd.startswith("top "):
            try:
                args = cmd.split()[1:]
                batch = ("-b" in args) or ("--batch" in args)

                iters = 1
                for i, a in enumerate(args):
                    if a in ("-n", "--iterations") and i + 1 < len(args) and args[i + 1].isdigit():
                        iters = max(1, int(args[i + 1]))
                        break

                if batch:
                    frames: List[str] = []
                    for _ in range(iters):
                        frames.append(_top_frame_via_llm())
                    out_text = "\n\n".join(frames)
                    send_response_lines_shell(chan, out_text, _prompt())
                    record_session(session_log, cmd, out_text, "read")
                else:
                    record_session(session_log, cmd, "<interactive top>", "read")
                    _run_top_interactive(interval=TOP_REFRESH_SEC)
                    _safe_send(chan, _prompt())

            except Exception as e:
                send_response_lines_shell(chan, f"top: {e}", _prompt())
                record_session(session_log, cmd, f"top: {e}", "read")

            buffer.clear()
            cursor = 0
            hist_idx = len(history)
            return None

        if cmd == "nano" or cmd.startswith("nano "):
            try:
                parts = cmd.split(maxsplit=1)
                if len(parts) < 2 or not parts[1].strip():
                    out = "nano: missing file operand"
                    send_response_lines_shell(chan, out, _prompt())
                    record_session(session_log, cmd, out, "read")
                else:
                    rel = parts[1].strip()
                    abs_path = _resolve_path(rel)
                    record_session(session_log, cmd, "<interactive nano>", "read")
                    _run_nano_interactive(abs_path)
                    _safe_send(chan, _prompt())
            except Exception as e:
                out = f"nano: {e}"
                send_response_lines_shell(chan, out, _prompt())
                record_session(session_log, cmd, out, "read")

            buffer.clear()
            cursor = 0
            hist_idx = len(history)
            return None


        try:
            if hasattr(vuln_agent, "route_label"):
                classification = vuln_agent.route_label(cmd, client=client)
            else:
                classification = validate_command(client, cmd)
        except Exception as e:
            log_attack(f"[{session_id}] classify error: {e}", "warn")
            classification = "rejection"


        pruned_history = planner.get_pruned_history() if planner is not None else []

        if classification == "rejection":
            tool = (cmd.split() or ["cmd"])[0]
            output = f"bash: {tool}: command not found"
            send_response_lines_shell(chan, output, _prompt())
            record_session(session_log, cmd, output, classification)
            try:
                pre_snapshot = copy.deepcopy(system_log)
                post_snapshot = copy.deepcopy(system_log)
                planner.step(cmd, output, pre_snapshot, post_snapshot)
            except Exception:
                pass

        elif classification == "write":
            try:
                pre_snapshot = copy.deepcopy(system_log)

                state_json = vuln_agent.process_safe_fs(cmd)
                system_log = json.loads(state_json)
                current_path = system_log.get("cwd", current_path)
                file_tree = system_log.get("filesystem", file_tree)

                post_snapshot = copy.deepcopy(system_log)
                system_ctx = copy.deepcopy(post_snapshot)
                system_ctx["pre_snapshot"] = pre_snapshot

                plan_text = plan_terminal_response(
                    client,
                    cmd,
                    current_path,
                    file_tree,
                    pruned_history=pruned_history,
                    pre_snapshot=pre_snapshot,
                    post_snapshot=post_snapshot,
                )
                rendered = render_response(cmd, plan_text, pruned_history, system_ctx)

                send_response_lines_shell(chan, rendered, _prompt())
                record_session(session_log, cmd, rendered, classification)
                planner.step(cmd, rendered, pre_snapshot, post_snapshot)

            except Exception as e:
                tool = (cmd.split() or ["cmd"])[0]
                err = f"{tool}: {e}"
                send_response_lines_shell(chan, err, _prompt())
                record_session(session_log, cmd, err, classification)
                try:
                    pre_snapshot = copy.deepcopy(system_log)
                    post_snapshot = copy.deepcopy(system_log)
                    planner.step(cmd, err, pre_snapshot, post_snapshot)
                except Exception:
                    pass

        else:
            try:
                system_log = refresh_system_log_for_planning(system_log, vuln_agent)
                current_path = system_log.get("cwd", current_path)
                file_tree = system_log.get("filesystem", file_tree)

                pre_snapshot = copy.deepcopy(system_log)
                post_snapshot = copy.deepcopy(system_log)
                system_ctx = copy.deepcopy(post_snapshot)
                system_ctx["pre_snapshot"] = pre_snapshot

                plan_text = plan_terminal_response(
                    client,
                    cmd,
                    current_path,
                    file_tree,
                    pruned_history=pruned_history,
                    pre_snapshot=pre_snapshot,
                    post_snapshot=post_snapshot,
                )
                rendered = render_response(cmd, plan_text, pruned_history, system_ctx)

            except Exception as e:
                log_attack(f"[{session_id}] plan/render error: {e}", "warn")
                tool = (cmd.split() or ["cmd"])[0]
                rendered = f"bash: {tool}: command not found"
                try:
                    pre_snapshot = copy.deepcopy(system_log)
                    post_snapshot = copy.deepcopy(system_log)
                except Exception:
                    pre_snapshot, post_snapshot = {}, {}

            send_response_lines_shell(chan, rendered, _prompt())
            record_session(session_log, cmd, rendered, classification)
            try:
                planner.step(cmd, rendered, pre_snapshot, post_snapshot)  #
            except Exception:
                pass
        buffer.clear()
        cursor = 0
        return None

    while True:
        data = chan.recv(1024)
        if not data:
            break
        chunk = data.decode("utf-8", errors="ignore")

        i = 0
        while i < len(chunk):
            ch = chunk[i]
            i += 1

            if esc_mode:
                esc_buf += ch
                if ch.isalpha() or ch == "~":
                    seq = esc_buf
                    esc_mode = False
                    esc_buf = ""

                    if seq in ("[C", "OC"):
                        if cursor < len(buffer):
                            cursor += 1
                            _safe_send(chan, CSI + "1C")
                    elif seq in ("[D", "OD"):
                        if cursor > 0:
                            cursor -= 1
                            _safe_send(chan, CSI + "1D")
                    elif seq in ("[A",):
                        if history:
                            if hist_idx > 0:
                                hist_idx -= 1
                            buffer = list(history[hist_idx])
                            cursor = len(buffer)
                            _redraw_line(buffer, cursor)
                    elif seq in ("[B",):
                        if history:
                            if hist_idx < len(history) - 1:
                                hist_idx += 1
                                buffer = list(history[hist_idx])
                            else:
                                hist_idx = len(history)
                                buffer = []
                            cursor = len(buffer)
                            _redraw_line(buffer, cursor)
                    elif seq in ("[3~",):
                        if cursor < len(buffer):
                            del buffer[cursor]
                            _redraw_line(buffer, cursor)
                    elif seq in ("[H", "[1~", "OH"):
                        cursor = 0
                        _redraw_line(buffer, cursor)
                    elif seq in ("[F", "[4~", "OF"):
                        cursor = len(buffer)
                        _redraw_line(buffer, cursor)
                continue

            if ch == "\x1b":
                esc_mode = True
                esc_buf = ""
                continue

            if ch in ("\r", "\n"):
                r = _accept_line()
                if r == "EXIT":
                    return
                continue

            if ch == "\x7f":  # backspace
                if cursor > 0:
                    cursor -= 1
                    del buffer[cursor]
                    _redraw_line(buffer, cursor)
                continue

            buffer.insert(cursor, ch)
            cursor += 1
            _redraw_line(buffer, cursor)

stop_event = threading.Event()
server_sock = None

def handle_exec_command_once(chan, session_id: str, remote_addr: str, exec_cmd: str):
    """
    Handle non-interactive SSH exec requests: `ssh host "cmd"`.
    Record command/output into SESSION_JSON even when no PTY/shell is opened.
    """
    vuln_agent = VulnerabilityAgentLLM()

    # load logs
    session_log: List[Dict[str, Any]] = load_session_log() if LOAD_SESSION_FROM_FILE else []
    save_session_log(session_log)

    file_syslog = load_system_log(SYSTEM_JSON) if LOAD_SYSTEM_FROM_FILE else None
    if isinstance(file_syslog, dict):
        system_log: Dict[str, Any] = file_syslog
    else:
        system_log = vuln_agent.get_system_log()

    system_log["cwd"] = system_log.get("cwd") or "/home/user"
    system_log["timestamp"] = ts_utc_isoz()
    vuln_agent.system_log = system_log

    current_path = system_log.get("cwd", "/home/user")
    file_tree = system_log.get("filesystem", {})

    cmd = (exec_cmd or "").strip()
    log_attack(f"[{session_id}] EXEC received (no-pty): {cmd}")

    if not cmd:
        try:
            chan.send_exit_status(0)
        except Exception:
            pass
        return

    # classify (keep same labels as your shell loop: rejection/write/read)
    try:
        if hasattr(vuln_agent, "route_label"):
            classification = vuln_agent.route_label(cmd, client=client)
        else:
            classification = validate_command(client, cmd)
    except Exception as e:
        log_attack(f"[{session_id}] exec classify error: {e}", "warn")
        classification = "rejection"

    # run according to label
    if classification == "rejection":
        tool = (cmd.split() or ["cmd"])[0]
        output = f"bash: {tool}: command not found\n"
        _safe_send(chan, output.replace("\n", "\r\n"))
        record_session(session_log, cmd, output, classification)
        try:
            chan.send_exit_status(127)
        except Exception:
            pass
        return

    if classification == "write":
        try:
            pre_snapshot = copy.deepcopy(system_log)

            state_json = vuln_agent.process_safe_fs(cmd)
            system_log = json.loads(state_json)
            current_path = system_log.get("cwd", current_path)
            file_tree = system_log.get("filesystem", file_tree)

            post_snapshot = copy.deepcopy(system_log)
            system_ctx = copy.deepcopy(post_snapshot)
            system_ctx["pre_snapshot"] = pre_snapshot

            plan_text = plan_terminal_response(
                client,
                cmd,
                current_path,
                file_tree,
                pruned_history=[],       
                pre_snapshot=pre_snapshot,
                post_snapshot=post_snapshot,
            )
            rendered = render_response(cmd, plan_text, [], system_ctx)
            if not rendered.endswith("\n"):
                rendered += "\n"

            _safe_send(chan, rendered.replace("\n", "\r\n"))
            record_session(session_log, cmd, rendered, classification)
            try:
                chan.send_exit_status(0)
            except Exception:
                pass
            return
        except Exception as e:
            tool = (cmd.split() or ["cmd"])[0]
            err = f"{tool}: {e}\n"
            _safe_send(chan, err.replace("\n", "\r\n"))
            record_session(session_log, cmd, err, classification)
            try:
                chan.send_exit_status(1)
            except Exception:
                pass
            return

    try:
        system_log = refresh_system_log_for_planning(system_log, vuln_agent)
        current_path = system_log.get("cwd", current_path)
        file_tree = system_log.get("filesystem", file_tree)

        pre_snapshot = copy.deepcopy(system_log)
        post_snapshot = copy.deepcopy(system_log)
        system_ctx = copy.deepcopy(post_snapshot)
        system_ctx["pre_snapshot"] = pre_snapshot

        plan_text = plan_terminal_response(
            client,
            cmd,
            current_path,
            file_tree,
            pruned_history=[],
            pre_snapshot=pre_snapshot,
            post_snapshot=post_snapshot,
        )
        rendered = render_response(cmd, plan_text, [], system_ctx)
        if not rendered.endswith("\n"):
            rendered += "\n"
    except Exception as e:
        log_attack(f"[{session_id}] exec plan/render error: {e}", "warn")
        tool = (cmd.split() or ["cmd"])[0]
        rendered = f"bash: {tool}: command not found\n"

    _safe_send(chan, rendered.replace("\n", "\r\n"))
    record_session(session_log, cmd, rendered, classification)
    try:
        chan.send_exit_status(0)
    except Exception:
        pass


def handle_connection(client_sock, addr):
    session_id = str(uuid.uuid4())
    remote_addr = f"{addr[0]}:{addr[1]}"
    append_auth_log(event="connect", session_id=session_id, username=USERNAME,
                    hostname=HOSTNAME, remote_addr=remote_addr, success=True, note="session opened", proto="ssh", local_port=PORT)
    log_attack(f"[*] New connection from {remote_addr}, session={session_id}")

    transport = None
    chan = None
    try:
        client_sock.settimeout(15.0)
        transport = paramiko.Transport(client_sock)
        if SERVER_KEY_ED25519 is not None:
            transport.add_server_key(SERVER_KEY_ED25519)
        if SERVER_KEY_RSA is not None:
            transport.add_server_key(SERVER_KEY_RSA)

        try:
            sec = transport.get_security_options()
            # sec.ciphers = ("aes128-ctr", "aes192-ctr", "aes256-ctr",
            #                "aes128-gcm@openssh.com", "aes256-gcm@openssh.com")
            # sec.kex = ("curve25519-sha256", "diffie-hellman-group-exchange-sha256")
            # sec.macs = ("hmac-sha2-256", "hmac-sha2-512")
        except Exception:
            pass

        server = HoneypotServer(session_id=session_id, remote_addr=remote_addr, local_port=PORT)
        transport.set_subsystem_handler('sftp', SFTPServer, RootedSFTP)

        transport.start_server(server=server)
        append_auth_log(event="ssh_session_open", session_id=session_id, username=USERNAME,
                        hostname=HOSTNAME, remote_addr=remote_addr, success=True,
                        note="ssh session opened", proto="ssh", local_port=PORT)
        chan = transport.accept(20)
        if chan is None:
            log_attack(f"[{session_id}] No channel, closing")
            return

        for _ in range(40):
            if server.exec_command is not None or server.shell_requested:
                break
            time.sleep(0.05)

        exec_cmd = server.exec_command
        if exec_cmd:
            mode, raw_path = _parse_scp_exec(exec_cmd)
            if mode == "download":
                log_attack(f"[{session_id}] Handling SCP -f {raw_path}")
                scp_serve_download(chan, raw_path, session_id, remote_addr)
                try:
                    chan.close()
                except Exception:
                    pass
                return
            elif mode == "upload":
                log_attack(f"[{session_id}] Handling SCP -t {raw_path}")
                scp_serve_upload(chan, raw_path, session_id, remote_addr)
                try:
                    chan.close()
                except Exception:
                    pass
                return

            handle_exec_command_once(chan, session_id, remote_addr, exec_cmd)
            try:
                chan.close()
            except Exception:
                pass
            return


        if server.shell_requested:
            run_agent_shell(chan, session_id, remote_addr)
            try:
                chan.close()
            except Exception:
                pass
            return

        while transport.is_active() and not chan.closed:
            time.sleep(0.1)

    except Exception as e:
        err_msg = str(e)
        if isinstance(e, (paramiko.SSHException, EOFError, socket.timeout)) and "Error reading SSH protocol banner" in err_msg:
            log_attack(f"[{session_id}] pre-auth disconnect/banner read failed from {remote_addr}: {err_msg}", "warn")
        else:
            log_attack(f"[{session_id}] connection error: {e}", "error")
    finally:
        try:
            if chan:
                chan.close()
        except Exception:
            pass
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass
        append_auth_log(event="disconnect", session_id=session_id, username=USERNAME,
                        hostname=HOSTNAME, remote_addr=remote_addr, success=True,
                        note="session closed", proto="ssh", local_port=PORT)
        log_attack(f"[*] Connection handler finished for session {session_id}")

def start_ssh_server(host: str = HOST, port: int = PORT):
    global server_sock
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(100)
    server_sock.settimeout(1.0)
    log_attack(f"[*] Fake SSH server listening on {host}:{port}")

    try:
        while not stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
                remote_addr = f"{addr[0]}:{addr[1]}"
                append_auth_log(event="tcp_connect", session_id="", username="", hostname=HOSTNAME,
                                remote_addr=remote_addr, success=True, note=f"SSH({port})",
                                proto="ssh", local_port=port)
            except socket.timeout:
                continue
            t = threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True)
            t.start()
    finally:
        try:
            server_sock.close()
        except Exception:
            pass
        log_attack("[*] SSH server stopped")

def _handle_shutdown(signum, frame):
    log_attack("[*] Shutdown signal received, stopping server.", "warn")
    stop_event.set()
    try:
        if server_sock:
            server_sock.close()
    except Exception:
        pass

signal.signal(signal.SIGINT, _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)

if __name__ == "__main__":
    try:
        start_ssh_server()
    except KeyboardInterrupt:
        log_attack("Shutting down (keyboard interrupt)")
