"""Análise heurística de domínio e URL."""

import ipaddress
import re
from urllib.parse import urlparse

from .utils import normalize_url

# Palavras frequentes em URLs de phishing que raramente aparecem em sites legítimos
SUSPICIOUS_KEYWORDS = ("login", "secure", "verify", "account", "update", "signin")

# Serviços de encurtamento de URL — ocultam o destino real da ligação
URL_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co")

SCORE_URL_LONG      = 15   # URLs muito longas são comuns em phishing para esconder o domínio real
SCORE_IP_HOST       = 25   # IP em vez de domínio indica falta de registo legítimo
SCORE_KEYWORD       = 10   # por palavra-chave suspeita encontrada
SCORE_MANY_DOTS     = 15   # muitos subdomínios sugerem spoofing (ex: paypal.secure.login.com.evil.com)
SCORE_SHORTENER     = 20   # encurtador oculta o destino — impossível avaliar sem seguir
SCORE_AT_SYMBOL     = 25   # o browser ignora tudo antes do @ na URL (técnica de ofuscação)


def _hostname_is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _count_domain_dots(hostname: str) -> int:
    return hostname.split(":")[0].lower().count(".")


def _is_shortener(hostname: str) -> bool:
    host = hostname.lower().split(":")[0]
    return any(host == s or host.endswith("." + s) for s in URL_SHORTENERS)


def _find_keywords(url_lower: str) -> list[str]:
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]


def analyze(url: str) -> dict:
    normalized = normalize_url(url)
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
    score = 0
    details: dict = {
        "url": normalized,
        "hostname": hostname,
        "url_length": len(normalized),
        "dot_count": _count_domain_dots(hostname),
        "keywords_found": [],
    }

    if len(normalized) > 75:
        flags.append("URL com mais de 75 caracteres")
        score += SCORE_URL_LONG

    if _hostname_is_ip(hostname):
        flags.append("Hostname é um endereço IP")
        score += SCORE_IP_HOST

    keywords = _find_keywords(url_lower)
    details["keywords_found"] = keywords
    for kw in keywords:
        flags.append(f"Palavra-chave suspeita: {kw}")
        score += SCORE_KEYWORD

    if _count_domain_dots(hostname) > 3:
        flags.append("Domínio com mais de 3 pontos")
        score += SCORE_MANY_DOTS

    if _is_shortener(hostname):
        flags.append("Encurtador de URL detectado")
        score += SCORE_SHORTENER

    if "@" in normalized:
        flags.append("Símbolo @ presente na URL")
        score += SCORE_AT_SYMBOL

    return {
        "module": "domain",
        "score": min(score, 100),
        "flags": flags,
        "details": details,
    }
