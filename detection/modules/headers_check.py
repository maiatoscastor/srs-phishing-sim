"""Análise de cabeçalhos HTTP de segurança."""

import requests

from .utils import normalize_url

SECURITY_HEADERS: dict[str, int] = {
    "Strict-Transport-Security": 15,
    "Content-Security-Policy": 10,
    "X-Frame-Options": 10,
    "X-Content-Type-Options": 5,
    "Referrer-Policy": 5,
    "Permissions-Policy": 5,
}

REQUEST_TIMEOUT = 8


def analyze(url: str) -> dict:
    normalized = normalize_url(url)
    flags: list[str] = []
    score = 0
    details: dict = {"url": normalized, "headers_present": [], "headers_missing": []}

    try:
        resp = requests.get(
            normalized,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishDetect/1.0)"},
        )
    except requests.exceptions.ConnectionError as exc:
        return {
            "module": "headers",
            "score": 20,
            "flags": [f"Não foi possível ligar ao servidor: {exc}"],
            "details": details,
        }
    except requests.exceptions.Timeout:
        return {
            "module": "headers",
            "score": 10,
            "flags": ["Timeout ao ligar ao servidor"],
            "details": details,
        }
    except Exception as exc:
        return {
            "module": "headers",
            "score": 10,
            "flags": [f"Erro ao obter headers: {exc}"],
            "details": details,
        }

    details["status_code"] = resp.status_code
    response_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header, penalty in SECURITY_HEADERS.items():
        if header.lower() in response_headers_lower:
            details["headers_present"].append(header)
        else:
            details["headers_missing"].append(header)
            flags.append(f"Header de segurança em falta: {header}")
            score += penalty

    return {
        "module": "headers",
        "score": min(score, 100),
        "flags": flags,
        "details": details,
    }
