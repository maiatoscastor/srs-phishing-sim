"""Análise DNS — registos A, MX, NS."""

import dns.exception
import dns.resolver

from .utils import get_hostname

SCORE_NO_A = 35      # domínio não resolve
SCORE_NO_MX = 10     # sem registo MX
SCORE_NO_NS = 15     # sem servidores de nomes


def _query(hostname: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(hostname, record_type, lifetime=5)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return []
    except Exception:
        return []


def analyze(url: str) -> dict:
    hostname = get_hostname(url)
    flags: list[str] = []
    score = 0

    a_records = _query(hostname, "A")
    mx_records = _query(hostname, "MX")
    ns_records = _query(hostname, "NS")

    details = {
        "hostname": hostname,
        "a_records": a_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
    }

    if not a_records:
        flags.append("Domínio sem registo A (não resolve para nenhum IP)")
        score += SCORE_NO_A

    if not mx_records:
        flags.append("Sem registos MX (domínio não recebe email)")
        score += SCORE_NO_MX

    if not ns_records:
        flags.append("Sem registos NS (servidores de nomes em falta)")
        score += SCORE_NO_NS

    return {
        "module": "dns",
        "score": min(score, 100),
        "flags": flags,
        "details": details,
    }
