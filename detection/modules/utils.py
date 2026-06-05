"""Utilitários partilhados pelos módulos de deteção."""

import re
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL vazia")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url


def get_hostname(url: str) -> str:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("URL sem domínio válido")
    return hostname
