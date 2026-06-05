"""Análise TLS/SSL — validade, emissor, idade do certificado."""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from OpenSSL import crypto

from .utils import normalize_url

SCORE_NO_TLS = 30
SCORE_SELF_SIGNED = 25
SCORE_CERT_VERY_NEW = 20   # emitido há < 7 dias
SCORE_CERT_NEW = 10        # emitido há < 30 dias
SCORE_CERT_EXPIRING = 10   # expira em < 30 dias
SCORE_CERT_EXPIRED = 30


def _fetch_cert(hostname: str, port: int = 443) -> crypto.X509:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return crypto.load_certificate(crypto.FILETYPE_ASN1, der)


def _parse_cert_date(b: bytes) -> datetime:
    return datetime.strptime(b.decode(), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def analyze(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""
    details: dict = {"hostname": hostname}

    if parsed.scheme == "http":
        return {
            "module": "tls",
            "score": SCORE_NO_TLS,
            "flags": ["Ligação sem TLS (HTTP puro)"],
            "details": {**details, "tls": False},
        }

    port = parsed.port or 443
    flags: list[str] = []
    score = 0

    try:
        x509 = _fetch_cert(hostname, port)
    except Exception as exc:
        return {
            "module": "tls",
            "score": SCORE_NO_TLS,
            "flags": [f"Não foi possível obter certificado TLS: {exc}"],
            "details": {**details, "tls": False},
        }

    now = datetime.now(timezone.utc)
    not_before = _parse_cert_date(x509.get_notBefore())
    not_after = _parse_cert_date(x509.get_notAfter())
    issuer_cn = x509.get_issuer().CN or ""
    subject_cn = x509.get_subject().CN or ""
    days_old = (now - not_before).days
    days_remaining = (not_after - now).days

    details.update({
        "tls": True,
        "issuer_cn": issuer_cn,
        "subject_cn": subject_cn,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_old": days_old,
        "days_remaining": days_remaining,
    })

    # Self-signed: issuer e subject são iguais
    if issuer_cn and issuer_cn == subject_cn:
        flags.append("Certificado auto-assinado")
        score += SCORE_SELF_SIGNED

    if days_remaining <= 0:
        flags.append("Certificado expirado")
        score += SCORE_CERT_EXPIRED
    elif days_remaining < 30:
        flags.append(f"Certificado expira em {days_remaining} dias")
        score += SCORE_CERT_EXPIRING

    if days_old < 7:
        flags.append(f"Certificado emitido há apenas {days_old} dias")
        score += SCORE_CERT_VERY_NEW
    elif days_old < 30:
        flags.append(f"Certificado emitido há {days_old} dias (recente)")
        score += SCORE_CERT_NEW

    return {
        "module": "tls",
        "score": min(score, 100),
        "flags": flags,
        "details": details,
    }
