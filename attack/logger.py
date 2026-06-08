"""Persistência de capturas, cliques e campanha (sem passwords)."""

import json
import os
import threading
import uuid
from datetime import datetime, timezone

_lock = threading.Lock()

LOG_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "logs"))
CAPTURES_PATH = os.path.join(LOG_DIR, "captures.json")
CLICKS_PATH = os.path.join(LOG_DIR, "clicks.json")
CAMPAIGN_PATH = os.path.join(LOG_DIR, "campaign.json")


def _append(path: str, entry: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _lock:
        records: list = []
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                try:
                    records = json.load(fh)
                except (json.JSONDecodeError, ValueError):
                    records = []
        records.append(entry)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, ensure_ascii=False)


def log_capture(
    email: str,
    ip: str,
    user_agent: str,
    track_token: str = "",
    geo: dict | None = None,
) -> str:
    victim_id = str(uuid.uuid4())
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "email": email,
        "ip": ip,
        "user_agent": user_agent,
        "track_token": track_token or None,
        "victim_id": victim_id,
        "geo": geo or {},
    }
    _append(CAPTURES_PATH, entry)
    return victim_id


def log_click(token: str, ip: str, user_agent: str) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "token": token,
        "ip": ip,
        "user_agent": user_agent,
    }
    _append(CLICKS_PATH, entry)
