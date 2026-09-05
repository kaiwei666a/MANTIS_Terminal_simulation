
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from typing import Any, Callable, Dict, Optional, Tuple

from system_state import ensure_dir_node, resolve_dir
from tools.common import ts_utc_isoz
from tools.ubuntu_ls import allocated_blocks_512


def simulated_account_details(login_username: str) -> Tuple[str, str, int]:
    safe_account = login_username if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", login_username or "") else "user"
    is_root = safe_account == "root"
    return safe_account, ("/root" if is_root else f"/home/{safe_account}"), (0 if is_root else 1000)


def ensure_user_upload_directory(
    system_log: Dict[str, Any],
    login_username: str,
) -> Tuple[str, Dict[str, Any]]:
    _, home_path, numeric_id = simulated_account_details(login_username)
    filesystem = system_log.setdefault("filesystem", {})
    home_node = filesystem.setdefault(home_path, {})
    home_node.setdefault("files", [])
    folders = home_node.setdefault("folders", {})
    home_node.setdefault("file_contents", {})
    home_node.setdefault("file_meta", {})
    home_node.setdefault("dir_mode", "drwx------" if numeric_id == 0 else "drwxr-x---")
    home_node.setdefault("dir_mtime", ts_utc_isoz())
    home_node.setdefault("dir_uid", numeric_id)
    home_node.setdefault("dir_gid", numeric_id)
    home_node.setdefault("dir_size", 4096)
    home_node.setdefault("dir_blocks", 8)

    upload_node = folders.setdefault("upload", {})
    upload_node.setdefault("files", [])
    upload_node.setdefault("folders", {})
    upload_node.setdefault("file_contents", {})
    upload_node.setdefault("file_meta", {})
    upload_node.setdefault("dir_mode", "drwxr-xr-x")
    upload_node.setdefault("dir_mtime", ts_utc_isoz())
    upload_node["dir_uid"] = numeric_id
    upload_node["dir_gid"] = numeric_id
    upload_node.setdefault("dir_size", 4096)
    upload_node.setdefault("dir_blocks", 8)
    return f"{home_path}/upload", upload_node


def apply_login_identity(system_log: Dict[str, Any], login_username: str, hostname: str) -> None:
    if not login_username:
        raise ValueError("authenticated SSH username is required")

    safe_account, home_path, numeric_id = simulated_account_details(login_username)
    is_root = safe_account == "root"
    identity = system_log.setdefault("identity", {})
    identity.update({
        "user": login_username,
        "uid": numeric_id,
        "gid": numeric_id,
        "euid": numeric_id,
        "egid": numeric_id,
        "groups": [numeric_id],
        "home": home_path,
        "shell": "/bin/bash",
        "hostname": hostname,
    })

    filesystem = system_log.setdefault("filesystem", {})
    if home_path not in filesystem:
        if not is_root and isinstance(filesystem.get("/home/user"), dict):
            filesystem[home_path] = copy.deepcopy(filesystem["/home/user"])
        else:
            filesystem[home_path] = {
                "files": [],
                "folders": {},
                "file_contents": {},
                "file_meta": {},
                "dir_mode": "drwx------" if is_root else "drwxr-x---",
                "dir_mtime": ts_utc_isoz(),
                "dir_uid": numeric_id,
                "dir_gid": numeric_id,
                "dir_size": 4096,
                "dir_blocks": 8,
            }
    home_node = filesystem[home_path]
    if isinstance(home_node, dict):
        home_node["dir_uid"] = numeric_id
        home_node["dir_gid"] = numeric_id

    _, upload_node = ensure_user_upload_directory(system_log, safe_account)
    legacy_upload = filesystem.pop("/upload", None)
    if isinstance(legacy_upload, dict):
        for name in legacy_upload.get("files", []) or []:
            if name not in upload_node["files"]:
                upload_node["files"].append(name)
        upload_node["folders"].update(legacy_upload.get("folders", {}) or {})
        upload_node["file_contents"].update(legacy_upload.get("file_contents", {}) or {})
        upload_node["file_meta"].update(legacy_upload.get("file_meta", {}) or {})
        upload_node["dir_mtime"] = legacy_upload.get("dir_mtime") or ts_utc_isoz()
    if system_log.get("oldpwd") == "/upload":
        system_log["oldpwd"] = home_path


def resolve_session_path(raw_path: str, current_path: str, home_path: str) -> str:
    p = (raw_path or "").strip()
    if not p:
        return current_path
    if p == "~":
        out = home_path
    elif p.startswith("~/"):
        out = home_path.rstrip("/") + p[1:]
    elif p.startswith("/"):
        out = p
    else:
        base = current_path.rstrip("/") or "/"
        out = (base + "/" + p).replace("//", "/")
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


def get_dir_node(abs_dir: str, system_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    fs = system_log.get("filesystem", {})
    return resolve_dir(fs, abs_dir, create=False) if isinstance(fs, dict) else None


def ensure_dir_node_at(abs_dir: str, system_log: Dict[str, Any]) -> Dict[str, Any]:
    fs = system_log.setdefault("filesystem", {})
    node = resolve_dir(fs, abs_dir, create=True)
    if node is None:
        raise PermissionError("Permission denied")
    ensure_dir_node(node)
    return node


def read_session_file(abs_path: str, system_log: Dict[str, Any]) -> str:
    d = os.path.dirname(abs_path).replace("\\", "/")
    b = os.path.basename(abs_path)
    node = get_dir_node(d, system_log)
    if not node:
        return ""
    fc = node.get("file_contents", {})
    if isinstance(fc, dict):
        return str(fc.get(b, ""))
    return ""


def write_session_file(abs_path: str, content: str, system_log: Dict[str, Any]) -> None:
    ident = system_log.get("identity", {}) or {}
    euid = int(ident.get("euid", ident.get("uid", 1000)) or 1000)
    if abs_path.startswith("/etc/") and euid != 0:
        raise PermissionError("Permission denied")

    d = os.path.dirname(abs_path).replace("\\", "/")
    b = os.path.basename(abs_path)
    node = ensure_dir_node_at(d, system_log)
    created = b not in node["files"]
    node["file_contents"][b] = content
    if created:
        node["files"].append(b)
    meta = node.setdefault("file_meta", {})
    meta[b] = {
        "mode": "-rw-r--r--",
        "mode_octal": "0644",
        "uid": int(ident.get("uid", 1000) or 1000),
        "gid": int(ident.get("gid", 1000) or 1000),
        "mtime": ts_utc_isoz(),
        "size": len(content.encode("utf-8", errors="ignore")),
        "blocks": allocated_blocks_512(len(content.encode("utf-8", errors="ignore"))),
        "nlink": 1,
        "hash": hashlib.sha1(content.encode("utf-8", errors="ignore")).hexdigest()
    }
    if created:
        node["dir_mtime"] = meta[b]["mtime"]


def record_uploaded_file_in_system_log(
    local_path: str,
    docker_path: str,
    size: int,
    sha256: str,
    proto: str,
    av_status: str,
    login_username: str,
    system_log_path: str,
    on_error: Optional[Callable[[str], None]] = None,
) -> None:
    try:
        log: Dict[str, Any] = {}
        if os.path.exists(system_log_path):
            try:
                with open(system_log_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    log = loaded
            except Exception:
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
            "username": login_username,
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

        upload_path, upload_node = ensure_user_upload_directory(log, login_username)
        rec["simulated_path"] = f"{upload_path}/{os.path.basename(local_path)}"
        files = upload_node.setdefault("files", [])
        if not isinstance(files, list):
            files = []
            upload_node["files"] = files
        fname = os.path.basename(local_path)
        if fname not in files:
            files.append(fname)

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
        with open(system_log_path, "w", encoding="utf-8") as f:
            json.dump(log, f, ensure_ascii=False, indent=2)
    except Exception as e:
        if on_error is not None:
            on_error(f"[system_log] upload record failed for {local_path}: {e}")
