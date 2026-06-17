"""Comparação com o VirusTotal — não entra no score heurístico, serve apenas
para validar/comparar o veredito do nosso scanner com motores de terceiros.

Requer a variável de ambiente VT_API_KEY (chave gratuita em virustotal.com).
Sem chave configurada, devolve available=False e o resto do scanner continua
a funcionar normalmente.
"""

import base64
import os
import time

import requests

from .utils import normalize_url

API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15
POLL_ATTEMPTS = 3
POLL_DELAY_SECONDS = 5


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _headers() -> dict:
    return {"x-apikey": os.environ.get("VT_API_KEY", "")}


def _stats_to_result(url: str, attributes: dict) -> dict:
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    return {
        "available": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "total_engines": total,
        "stats": stats,
        "permalink": f"https://www.virustotal.com/gui/url/{_url_id(url)}",
    }


def query(url: str) -> dict:
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "reason": "VT_API_KEY não configurada"}

    normalized = normalize_url(url)
    url_id = _url_id(normalized)

    try:
        resp = requests.get(
            f"{API_BASE}/urls/{url_id}", headers=_headers(), timeout=REQUEST_TIMEOUT
        )
    except requests.exceptions.RequestException as exc:
        return {"available": False, "reason": f"Erro de ligação ao VirusTotal: {exc}"}

    if resp.status_code == 200:
        attributes = resp.json().get("data", {}).get("attributes", {})
        return _stats_to_result(normalized, attributes)

    if resp.status_code == 404:
        return _submit_and_poll(normalized)

    if resp.status_code == 401:
        return {"available": False, "reason": "VT_API_KEY inválida"}

    return {"available": False, "reason": f"VirusTotal devolveu HTTP {resp.status_code}"}


def _submit_and_poll(url: str) -> dict:
    try:
        submit = requests.post(
            f"{API_BASE}/urls",
            headers=_headers(),
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        return {"available": False, "reason": f"Erro ao submeter URL ao VirusTotal: {exc}"}

    if submit.status_code != 200:
        return {"available": False, "reason": f"Falha ao submeter URL (HTTP {submit.status_code})"}

    analysis_id = submit.json().get("data", {}).get("id", "")
    if not analysis_id:
        return {"available": False, "reason": "VirusTotal não devolveu ID de análise"}

    for _ in range(POLL_ATTEMPTS):
        time.sleep(POLL_DELAY_SECONDS)
        try:
            check = requests.get(
                f"{API_BASE}/analyses/{analysis_id}", headers=_headers(), timeout=REQUEST_TIMEOUT
            )
        except requests.exceptions.RequestException:
            continue

        if check.status_code != 200:
            continue

        data = check.json().get("data", {})
        if data.get("attributes", {}).get("status") == "completed":
            return _stats_to_result(url, data["attributes"])

    return {"available": False, "reason": "Análise ainda em curso no VirusTotal — tenta novamente em breve"}
