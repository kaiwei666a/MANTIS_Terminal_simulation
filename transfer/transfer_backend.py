from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from storage.session_store import append_auth_log, log_attack
from terminal_config import (
    DOCKER_DELETE_LOCAL_AFTER_COPY,
    DOCKER_DOWNLOAD_CONTAINER,
    DOCKER_DOWNLOAD_PATH,
    DOCKER_UPLOAD_CONTAINER,
    DOCKER_UPLOAD_PATH,
    DOWNLOAD_MAX_BYTES,
    DOWNLOAD_TIMEOUT_SEC,
    HOSTNAME,
    PORT,
    SCP_ROOT,
    SYSTEM_JSON,
    UPLOAD_AUDIT_JSONL,
    UPLOAD_QUARANTINE_DIR,
)
from tools.common import ts_utc_isoz
from tools.ubuntu_fs_session import record_uploaded_file_in_system_log


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
    try:
        os.chmod(path, 0o644)
    except Exception:
        pass

def _scan_uploaded_file(path: str) -> Tuple[str, str, str]:

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


def _safe_download_name(name: str) -> str:
    base = PurePosixPath(name or "").name
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".") or "download"
    return base[:200]


def _docker_download_exec(args: List[str], timeout: int, workdir: Optional[str] = None) -> Tuple[int, str, str]:
    import subprocess
    docker_args = ["docker", "exec"]
    if workdir:
        docker_args += ["-w", workdir]
    docker_args += [DOCKER_DOWNLOAD_CONTAINER, *args]
    try:
        p = subprocess.run(
            docker_args,
            capture_output=True, timeout=timeout, check=False,
        )
        return p.returncode, p.stdout.decode("utf-8", errors="replace"), p.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except Exception as e:
        return -1, "", str(e)


def docker_fetch_file(tool: str, url: str, filename: str, session_id: str) -> Optional[Dict[str, Any]]:

    if not DOCKER_DOWNLOAD_CONTAINER or not re.match(r"^https?://", url, re.I):
        return None

    safe_name = _safe_download_name(filename)
    dest_dir = f"{DOCKER_DOWNLOAD_PATH}/{session_id}"
    dest_path = f"{dest_dir}/{safe_name}"

    rc, _, _ = _docker_download_exec(["mkdir", "-p", dest_dir], timeout=10)
    if rc != 0:
        log_attack(f"[download] container {DOCKER_DOWNLOAD_CONTAINER} unavailable (mkdir rc={rc})", "warn")
        return None

    if tool == "wget":
        fetch_cmd = [
            "wget", f"--timeout={DOWNLOAD_TIMEOUT_SEC}", "--tries=1", "-q",
            f"--quota={DOWNLOAD_MAX_BYTES}", "-O", dest_path, "--", url,
        ]
    else:
        fetch_cmd = [
            "curl", "-fsSL", "--max-time", str(DOWNLOAD_TIMEOUT_SEC),
            "--max-filesize", str(DOWNLOAD_MAX_BYTES), "-o", dest_path, "--", url,
        ]

    rc, _, err = _docker_download_exec(fetch_cmd, timeout=DOWNLOAD_TIMEOUT_SEC + 5)
    if rc != 0:
        _docker_download_exec(["rm", "-f", dest_path], timeout=10)
        log_attack(f"[download] {tool} failed for {url!r}: rc={rc} err={err[:200]}", "warn")
        return None

    rc, size_out, _ = _docker_download_exec(["stat", "-c%s", dest_path], timeout=10)
    if rc != 0:
        return None
    rc, hash_out, _ = _docker_download_exec(["sha256sum", dest_path], timeout=10)
    if rc != 0:
        return None
    try:
        size = int(size_out.strip())
    except ValueError:
        return None
    digest = hash_out.strip().split()[0] if hash_out.strip() else ""
    return {"name": safe_name, "size": size, "hash": digest, "container_path": dest_path}


def docker_fetch_git_clone(url: str, dst_dir_name: str, session_id: str) -> Optional[Dict[str, Any]]:
    if not DOCKER_DOWNLOAD_CONTAINER or not re.match(r"^https?://", url, re.I):
        return None

    safe_name = _safe_download_name(dst_dir_name)
    session_root = f"{DOCKER_DOWNLOAD_PATH}/{session_id}"
    repo_path = f"{session_root}/{safe_name}"

    _docker_download_exec(["rm", "-rf", repo_path], timeout=10)
    rc, _, _ = _docker_download_exec(["mkdir", "-p", session_root], timeout=10)
    if rc != 0:
        log_attack(f"[download] container {DOCKER_DOWNLOAD_CONTAINER} unavailable (mkdir rc={rc})", "warn")
        return None


    rc, _, err = _docker_download_exec(
        ["timeout", str(DOWNLOAD_TIMEOUT_SEC), "git", "clone", "--progress", "--depth", "1", "--", url, safe_name],
        timeout=DOWNLOAD_TIMEOUT_SEC + 5,
        workdir=session_root,
    )
    if rc != 0:
        _docker_download_exec(["rm", "-rf", repo_path], timeout=10)
        log_attack(f"[download] git clone failed for {url!r}: rc={rc} err={err[:200]}", "warn")
        return None

    rc, out, _ = _docker_download_exec(
        ["find", repo_path, "-mindepth", "1", "-maxdepth", "1", "-printf", "%y\t%s\t%f\n"],
        timeout=10,
    )
    if rc != 0:
        _docker_download_exec(["rm", "-rf", repo_path], timeout=10)
        return None

    entries: List[Dict[str, Any]] = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        type_char, size_str, entry_name = parts
        if not entry_name:
            continue
        try:
            size_val = int(size_str)
        except ValueError:
            size_val = 0
        entries.append({"name": entry_name, "size": size_val, "is_dir": type_char == "d"})

    return {"name": safe_name, "entries": entries, "container_path": repo_path, "clone_output": err}


def _copy_to_docker_and_delete(
    local_path: str,
    source_proto: str = "sftp",
    session_id: str = "",
    remote_addr: str = "",
    login_username: str = "",
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
            record_uploaded_file_in_system_log(
                local_path=quarantine_dst,
                docker_path="",
                size=size,
                sha256=sha256,
                proto=source_proto,
                av_status=av_status,
                login_username=login_username,
                system_log_path=SYSTEM_JSON,
                on_error=lambda msg: log_attack(msg, "warn"),
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
                username=login_username,
                hostname=HOSTNAME,
                remote_addr=remote_addr,
                success=True,
                note=f"uploaded file={os.path.basename(abs_local)} local={abs_local} docker={container_dst} ({size} bytes)",
                proto="ssh",
                local_port=PORT,
            )
        record_uploaded_file_in_system_log(
            local_path=abs_local,
            docker_path=container_dst,
            size=size,
            sha256=sha256,
            proto=source_proto,
            av_status=av_status,
            login_username=login_username,
            system_log_path=SYSTEM_JSON,
            on_error=lambda msg: log_attack(msg, "warn"),
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
