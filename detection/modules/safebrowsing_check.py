"""Comparação com a Google Safe Browsing Lookup API v4.

Não entra no score heurístico — serve para validar/comparar o veredito
do nosso scanner com a base de dados de ameaças da Google.

Requer a variável de ambiente SAFE_BROWSING_KEY (chave gratuita via
Google Cloud Console → APIs & Services → Credenciais).
"""

import os

import requests

from .utils import normalize_url

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
REQUEST_TIMEOUT = 10

THREAT_TYPES = [
    "SOCIAL_ENGINEERING",   # phishing
    "MALWARE",
    "UNWANTED_SOFTWARE",
]


def query(url: str) -> dict:
    api_key = os.environ.get("SAFE_BROWSING_KEY", "").strip()
    if not api_key:
        return {"available": False, "reason": "SAFE_BROWSING_KEY não configurada"}

    normalized = normalize_url(url)

    payload = {
        "client": {"clientId": "phishing-detector-segred", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalized}],
        },
    }

    try:
        resp = requests.post(
            API_URL,
            params={"key": api_key},
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        return {"available": False, "reason": f"Erro de ligação ao Safe Browsing: {exc}"}

    if resp.status_code == 400:
        return {"available": False, "reason": "Pedido inválido — verifica a SAFE_BROWSING_KEY"}
    if resp.status_code == 403:
        return {"available": False, "reason": "SAFE_BROWSING_KEY inválida ou API não ativada"}
    if resp.status_code != 200:
        return {"available": False, "reason": f"Google Safe Browsing devolveu HTTP {resp.status_code}"}

    data = resp.json()
    matches = data.get("matches", [])

    if not matches:
        return {
            "available": True,
            "flagged": False,
            "threat_types": [],
            "verdict": "SEGURA",
        }

    threat_types = list({m["threatType"] for m in matches})
    return {
        "available": True,
        "flagged": True,
        "threat_types": threat_types,
        "verdict": "PHISHING" if "SOCIAL_ENGINEERING" in threat_types else "MALWARE/OUTRO",
    }
