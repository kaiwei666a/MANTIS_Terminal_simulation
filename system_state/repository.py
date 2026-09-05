
from __future__ import annotations

import json
import os
import traceback
from typing import Any, Dict, Optional

def load_system_log(path: str) -> Optional[Dict[str, Any]]:
    try:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def save_system_log(path: str, log_data: Dict[str, Any]) -> None:
    try:
        data_to_save = {
            key: value for key, value in log_data.items() if key != "login_history"
        }
        with open(path, "w", encoding="utf-8") as file:
            json.dump(data_to_save, file, ensure_ascii=False, indent=2)
    except Exception as exc:
        print(f"Failed to save system log: {exc}")
        traceback.print_exc()
