from __future__ import annotations


def _safe_send(channel, data: str | bytes) -> None:
    try:
        if isinstance(data, str):
            channel.send(data)
        else:
            channel.sendall(data)
    except Exception:
        pass
