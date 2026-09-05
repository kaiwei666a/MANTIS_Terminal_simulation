from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

from terminal_config import AUTH_LOG, LOG_FILE, PORT, SESSION_JSON
from tools.common import now_eastern, ts_utc_isoz


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
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

