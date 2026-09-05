
from __future__ import annotations

import shlex
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    import psutil
except Exception:
    psutil = None

try:
    from zoneinfo import ZoneInfo
    _SEED_TZ = ZoneInfo("America/New_York")
except Exception:
    _SEED_TZ = None


_SEED_LOGIN_TEMPLATES = (
    (60, "root", "tty1", "", 7, 18, 12, 2068, "seed-01-maintenance"),
    (57, "ubuntu", "pts/0", "192.168.129.24", 9, 3, 27, 5004, "seed-02-ubuntu"),
    (54, "user", "pts/1", "131.247.90.41", 13, 44, 9, 2004, "seed-03-user"),
    (51, "kai", "pts/0", "192.168.56.102", 18, 21, 54, 6024, "seed-04-kai"),
    (48, "admin", "pts/2", "10.18.4.27", 8, 37, 16, 2066, "seed-05-admin"),
    (45, "user", "pts/0", "131.247.90.77", 11, 29, 5, 4772, "seed-06-user"),
    (42, "backup", "pts/3", "192.168.129.18", 2, 14, 31, 755, "seed-07-backup"),
    (39, "kai", "pts/1", "192.168.56.101", 15, 6, 48, 8723, "seed-08-kai"),
    (36, "root", "pts/0", "10.18.4.10", 6, 51, 22, 1057, "seed-09-root"),
    (33, "user", "pts/2", "131.247.91.36", 10, 42, 14, 4394, "seed-10-user"),
    (30, "ubuntu", "pts/0", "192.168.129.32", 12, 17, 3, 2683, "seed-11-ubuntu"),
    (27, "admin", "pts/1", "10.18.4.29", 9, 26, 38, 2559, "seed-12-admin"),
    (24, "kai", "pts/0", "192.168.56.104", 14, 33, 52, 7888, "seed-13-kai"),
    (21, "user", "pts/3", "131.247.90.64", 17, 58, 41, 2248, "seed-14-user"),
    (18, "root", "tty1", "", 7, 12, 25, 1648, "seed-15-root"),
    (15, "ubuntu", "pts/1", "192.168.129.24", 11, 4, 36, 4652, "seed-16-ubuntu"),
    (12, "user", "pts/2", "131.247.91.18", 13, 49, 17, 5068, "seed-17-user"),
    (8, "root", "tty1", "", 8, 11, 2, 2117, "seed-console-root"),
    (4, "kai", "pts/1", "192.168.56.101", 16, 22, 31, 6193, "seed-kai-lab"),
    (1, "user", "pts/0", "131.247.90.83", 10, 14, 7, 5599, "seed-user-campus"),
)


def _generate_seed_login_history() -> List[Dict[str, Any]]:
    now = datetime.now(_SEED_TZ) if _SEED_TZ is not None else datetime.now().astimezone()
    seeds: List[Dict[str, Any]] = []
    for days_ago, username, tty, host, hour, minute, second, duration_sec, session_id in _SEED_LOGIN_TEMPLATES:
        login_at = (now - timedelta(days=days_ago)).replace(hour=hour, minute=minute, second=second, microsecond=0)
        logout_at = login_at + timedelta(seconds=duration_sec)
        seeds.append({
            "session_id": session_id,
            "username": username,
            "tty": tty,
            "host": host,
            "login_at": login_at.isoformat(),
            "logout_at": logout_at.isoformat(),
        })
    return seeds


def ensure_login_history(system_log: Dict[str, Any]) -> List[Dict[str, Any]]:
    existing = system_log.get("login_history")
    history = [item for item in existing if isinstance(item, dict)] if isinstance(existing, list) else []
    known_ids = {str(item.get("session_id") or "") for item in history}
    seeds = [item for item in _generate_seed_login_history() if item["session_id"] not in known_ids]
    if seeds:
        history = seeds + history
    system_log["login_history"] = history
    return history


def record_login_session(
    system_log: Dict[str, Any],
    username: str,
    remote_addr: str,
    login_time: datetime,
    session_id: str,
    tty: str = "pts/0",
) -> None:
    history = ensure_login_history(system_log)
    if session_id and any(str(item.get("session_id") or "") == session_id for item in history):
        return
    history.append(
        {
            "session_id": session_id,
            "username": str(username or "user"),
            "tty": str(tty or "pts/0"),
            "host": _remote_host(remote_addr),
            "login_at": login_time.isoformat(),
            "logout_at": None,
        }
    )
    if len(history) > 100:
        del history[:-100]


def record_logout_session(
    system_log: Dict[str, Any],
    session_id: str,
    logout_time: datetime,
) -> None:
    history = ensure_login_history(system_log)
    for item in reversed(history):
        if str(item.get("session_id") or "") == session_id:
            if not item.get("logout_at"):
                item["logout_at"] = logout_time.isoformat()
            return


def _remote_host(remote_addr: str) -> str:
    value = str(remote_addr or "").strip()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value or "-"


def _load_average(system_log: Dict[str, Any]) -> tuple[float, float, float]:
    configured = system_log.get("load_average")
    if isinstance(configured, (list, tuple)) and len(configured) >= 3:
        try:
            return float(configured[0]), float(configured[1]), float(configured[2])
        except (TypeError, ValueError):
            pass
    if isinstance(configured, dict):
        try:
            return (
                float(configured.get("1m", configured.get("1", 0.0))),
                float(configured.get("5m", configured.get("5", 0.0))),
                float(configured.get("15m", configured.get("15", 0.0))),
            )
        except (TypeError, ValueError):
            pass
    if psutil is not None:
        try:
            one, five, fifteen = psutil.getloadavg()
            return float(one), float(five), float(fifteen)
        except Exception:
            pass
    return 0.00, 0.01, 0.05


def _uptime_seconds(system_log: Dict[str, Any], now: datetime) -> int:
    configured = system_log.get("uptime_seconds")
    try:
        if configured is not None:
            return max(0, int(float(configured)))
    except (TypeError, ValueError):
        pass
    if psutil is not None:
        try:
            return max(0, int(now.timestamp() - float(psutil.boot_time())))
        except Exception:
            pass
    return 0


def _format_uptime(seconds: int) -> str:
    days, remainder = divmod(max(0, int(seconds)), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        day_word = "day" if days == 1 else "days"
        return f"{days} {day_word},  {hours}:{minutes:02d}"
    if hours:
        return f"{hours}:{minutes:02d}"
    return f"{minutes} min"


def _format_idle(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}.00s"
    if seconds < 3600:
        return f"{seconds // 60}:{seconds % 60:02d}"
    hours, remainder = divmod(seconds, 3600)
    return f"{hours}:{remainder // 60:02d}m"


def _parse_history_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _last_login_stamp(value: datetime) -> str:
    return f"{value:%a %b} {value.day:2d} {value:%H:%M}"


def _last_duration(start: datetime, end: datetime) -> str:
    total_minutes = max(0, int((end - start).total_seconds()) // 60)
    days, remainder = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(remainder, 60)
    if days:
        return f"({days}+{hours:02d}:{minutes:02d})"
    return f"({hours:02d}:{minutes:02d})"


def _render_last(system_log: Dict[str, Any]) -> str:
    history = ensure_login_history(system_log)
    rows: List[tuple[datetime, str]] = []
    for item in history:
        login_at = _parse_history_time(item.get("login_at"))
        if login_at is None:
            continue
        username = str(item.get("username") or "user")[:32]
        tty = str(item.get("tty") or "pts/0")[:12]
        host = str(item.get("host") or "")[:16]
        prefix = f"{username:<8} {tty:<12} {host:<16} {_last_login_stamp(login_at)}"
        logout_at = _parse_history_time(item.get("logout_at"))
        if logout_at is None:
            suffix = "   still logged in"
        else:
            suffix = f" - {logout_at:%H:%M}  {_last_duration(login_at, logout_at)}"
        rows.append((login_at, prefix.rstrip() + suffix))

    rows.sort(key=lambda pair: pair[0].timestamp(), reverse=True)
    lines = [line for _, line in rows]
    if rows:
        oldest = min(pair[0] for pair in rows)
        lines.extend(
            [
                "",
                f"wtmp begins {oldest:%a %b} {oldest.day:2d} {oldest:%H:%M:%S %Y}",
            ]
        )
    return "\n".join(lines)


def _render_lastlog(system_log: Dict[str, Any]) -> str:
    history = ensure_login_history(system_log)
    latest: Dict[str, tuple[datetime, Dict[str, Any]]] = {}
    for item in history:
        login_at = _parse_history_time(item.get("login_at"))
        if login_at is None:
            continue
        username = str(item.get("username") or "user")[:16]
        previous = latest.get(username)
        if previous is None or login_at > previous[0]:
            latest[username] = (login_at, item)

    identity_user = str((system_log.get("identity") or {}).get("user") or "user")
    preferred = ["root", identity_user]
    usernames = sorted(latest)
    usernames.sort(key=lambda name: (preferred.index(name) if name in preferred else len(preferred), name))
    lines = ["Username         Port     From                 Latest"]
    for username in usernames:
        login_at, item = latest[username]
        tty = str(item.get("tty") or "")[:8]
        host = str(item.get("host") or "")[:20]
        stamp = f"{login_at:%a %b} {login_at.day:2d} {login_at:%H:%M:%S %z %Y}"
        lines.append(f"{username:<16} {tty:<8} {host:<20} {stamp}".rstrip())
    return "\n".join(lines)


def render_user_session_command(
    command: str,
    system_log: Dict[str, Any],
    login_username: str,
    remote_addr: str,
    login_time: datetime,
    *,
    now: Optional[datetime] = None,
    idle_seconds: int = 0,
) -> Optional[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not tokens or tokens[0] not in {"who", "users", "w", "last", "lastlog"}:
        return None

    tool = tokens[0]
    args = tokens[1:]
    username = str(login_username or "user")
    host = _remote_host(remote_addr)
    current = now or datetime.now(tz=login_time.tzinfo)

    if tool == "last":
        if args:
            return None
        return _render_last(system_log)

    if tool == "lastlog":
        if args:
            return None
        return _render_lastlog(system_log)

    if tool == "who":
        if args:
            bad = next((arg for arg in args if arg.startswith("-")), None)
            if bad is not None:
                option = bad[1:2] or bad
                return f"who: invalid option -- '{option}'\nTry 'who --help' for more information."
            return f"who: extra operand '{args[0]}'\nTry 'who --help' for more information."
        return f"{username:<8} pts/0        {login_time:%Y-%m-%d %H:%M} ({host})"

    if tool == "users":
        if args:
            return f"users: extra operand '{args[0]}'\nTry 'users --help' for more information."
        return username

    if args:
        bad = next((arg for arg in args if arg.startswith("-")), args[0])
        option = bad[1:2] if bad.startswith("-") else bad
        return f"w: invalid option -- '{option}'\nUsage:\n w [options]"

    load1, load5, load15 = _load_average(system_log)
    uptime = _format_uptime(_uptime_seconds(system_log, current))
    user_count = int(system_log.get("users", 1) or 1)
    login_at = login_time.strftime("%H:%M")
    idle = _format_idle(idle_seconds)
    what = "w"
    return "\n".join(
        [
            f" {current:%H:%M:%S} up {uptime},  {user_count} user,  load average: "
            f"{load1:.2f}, {load5:.2f}, {load15:.2f}",
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT",
            f"{username:<8} pts/0    {host:<16} {login_at:>5}   {idle:>6}  0.01s  0.00s {what}",
        ]
    )
