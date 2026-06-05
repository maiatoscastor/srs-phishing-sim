"""Análise heurística de domínio e URL."""

import ipaddress
import re
from urllib.parse import urlparse

# Palavras frequentes em URLs de phishing
SUSPICIOUS_KEYWORDS = ("login", "secure", "verify", "account", "update", "signin")

# Domínios de encurtadores conhecidos
URL_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co")

# Pontuação por tipo de alerta
SCORE_URL_LONG = 15
SCORE_IP_HOST = 25
SCORE_KEYWORD = 10
SCORE_MANY_DOTS = 15
SCORE_SHORTENER = 20
SCORE_AT_SYMBOL = 25


def _normalize_url(url: str) -> str:
    # Garantir esquema http/https para parsing
    url = url.strip()
    if not url:
        raise ValueError("URL vazia")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url


def _hostname_is_ip(hostname: str) -> bool:
    # Verificar se o hostname é IPv4 ou IPv6
    hostname = hostname.strip("[]")
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _count_domain_dots(hostname: str) -> int:
    # Contar pontos no hostname (ignorar porta)
    host = hostname.split(":")[0].lower()
    return host.count(".")


def _is_shortener(hostname: str) -> bool:
    host = hostname.lower().split(":")[0]
    return any(host == s or host.endswith("." + s) for s in URL_SHORTENERS)


def _find_keywords(url_lower: str) -> list[str]:
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]


def analyze(url: str) -> dict:
    """Analisar URL e devolver score, flags e detalhes."""
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)

    if not parsed.netloc:
        raise ValueError("URL inválida ou sem domínio")

    hostname = parsed.hostname or ""
    if not hostname or " " in hostname:
        raise ValueError("URL inválida ou sem domínio")
    if not _hostname_is_ip(hostname) and not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        raise ValueError("URL inválida ou sem domínio")
    url_lower = normalized.lower()
    flags: list[str] = []
    details: dict = {
        "url": normalized,
        "hostname": hostname,
        "url_length": len(normalized),
        "dot_count": _count_domain_dots(hostname),
        "keywords_found": [],
    }

    score = 0

    # Comprimento excessivo da URL
    if len(normalized) > 75:
        flags.append("URL com mais de 75 caracteres")
        score += SCORE_URL_LONG

    # IP em vez de domínio
    if _hostname_is_ip(hostname):
        flags.append("Hostname é um endereço IP")
        score += SCORE_IP_HOST

    # Palavras-chave suspeitas
    keywords = _find_keywords(url_lower)
    details["keywords_found"] = keywords
    for kw in keywords:
        flags.append(f"Palavra-chave suspeita: {kw}")
        score += SCORE_KEYWORD

    # Demasiados subdomínios
    if _count_domain_dots(hostname) > 3:
        flags.append("Domínio com mais de 3 pontos")
        score += SCORE_MANY_DOTS

    # Encurtador de URL
    if _is_shortener(hostname):
        flags.append("Encurtador de URL detectado")
        score += SCORE_SHORTENER

    # Símbolo @ (técnica de ofuscação)
    if "@" in normalized:
        flags.append("Símbolo @ presente na URL")
        score += SCORE_AT_SYMBOL

    score = min(score, 100)

    return {
        "module": "domain",
        "score": score,
        "flags": flags,
        "details": details,
    }
