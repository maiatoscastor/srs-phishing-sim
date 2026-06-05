"""Análise WHOIS — idade do domínio, registar, país."""

from datetime import datetime, timezone

import whois

from .utils import get_hostname

SCORE_DOMAIN_VERY_NEW = 30   # < 30 dias
SCORE_DOMAIN_NEW = 15        # < 6 meses
SCORE_EXPIRING_SOON = 10     # expira em < 30 dias
SCORE_NO_WHOIS = 10          # sem informação pública


def _earliest(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, list):
        dates = [d for d in value if isinstance(d, datetime)]
        return min(dates) if dates else None
    if isinstance(value, datetime):
        return value
    return None


def analyze(url: str) -> dict:
    hostname = get_hostname(url)
    flags: list[str] = []
    score = 0
    details: dict = {"hostname": hostname}

    try:
        w = whois.whois(hostname)
    except Exception as exc:
        return {
            "module": "whois",
            "score": SCORE_NO_WHOIS,
            "flags": [f"Sem dados WHOIS ({exc})"],
            "details": details,
        }

    creation = _earliest(w.creation_date)
    expiration = _earliest(w.expiration_date)
    now = datetime.now(timezone.utc)

    details["registrar"] = w.registrar
    details["country"] = w.country
    details["creation_date"] = creation.isoformat() if creation else None
    details["expiration_date"] = expiration.isoformat() if expiration else None

    if creation is None:
        flags.append("Data de criação do domínio não disponível (privacidade WHOIS)")
        score += SCORE_NO_WHOIS
    else:
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (now - creation).days
        details["domain_age_days"] = age_days
        if age_days < 30:
            flags.append(f"Domínio registado há {age_days} dias (muito recente)")
            score += SCORE_DOMAIN_VERY_NEW
        elif age_days < 180:
            flags.append(f"Domínio registado há {age_days} dias (recente)")
            score += SCORE_DOMAIN_NEW

    if expiration is not None:
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        days_left = (expiration - now).days
        if 0 < days_left < 30:
            flags.append(f"Domínio expira em {days_left} dias")
            score += SCORE_EXPIRING_SOON

    return {
        "module": "whois",
        "score": min(score, 100),
        "flags": flags,
        "details": details,
    }
