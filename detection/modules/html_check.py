"""Análise da estrutura HTML — formulários, links externos, brand spoofing, JS ofuscado."""

import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .utils import normalize_url

# Marcas conhecidas — detetar quando aparecem no conteúdo mas não no domínio
KNOWN_BRANDS = (
    "microsoft", "google", "apple", "facebook", "amazon",
    "paypal", "netflix", "instagram", "linkedin", "twitter",
)

# Padrões comuns em JavaScript ofuscado para esconder código malicioso
OBFUSCATION_PATTERNS = re.compile(
    r"eval\s*\(|document\.write\s*\(|unescape\s*\(|String\.fromCharCode",
    re.IGNORECASE,
)

# Domínios de widgets legítimos que usam iframes ocultos (reCAPTCHA, analytics, pagamentos)
LEGITIMATE_IFRAME_DOMAINS = (
    "google.com", "gstatic.com", "recaptcha.net", "googletagmanager.com",
    "googleadservices.com", "doubleclick.net", "facebook.com", "youtube.com",
    "stripe.com", "paypal.com",
)

# Tags cujo conteúdo não é texto visível ao utilizador — excluídas da análise de brand spoofing
_NON_VISIBLE_TAGS = {"script", "style", "noscript", "meta", "link", "head"}

SCORE_PASSWORD_FIELD       = 20
SCORE_EXTERNAL_FORM_ACTION = 25
SCORE_BRAND_SPOOFING       = 20
SCORE_HIDDEN_IFRAME        = 15
SCORE_OBFUSCATED_JS        = 15
SCORE_HIGH_EXTERNAL_RATIO  = 10
SCORE_REDIRECT_MISMATCH    = 15

REQUEST_TIMEOUT = 8


def _base_domain(hostname: str) -> str:
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


def _visible_text(soup: BeautifulSoup) -> str:
    # Recolhe apenas texto de nós cujo elemento pai é visível no browser
    return " ".join(
        str(node) for node in soup.find_all(string=True)
        if node.parent.name not in _NON_VISIBLE_TAGS
    ).lower()


def _iframe_is_known_widget(iframe) -> bool:
    src = iframe.get("src", "")
    host = (urlparse(src).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in LEGITIMATE_IFRAME_DOMAINS)


def analyze(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    base = _base_domain(parsed.hostname or "")

    flags: list[str] = []
    score = 0
    details: dict = {
        "url": normalized,
        "final_url": normalized,
        "password_fields": 0,
        "forms": [],
        "total_links": 0,
        "external_links": 0,
        "brands_detected": [],
        "hidden_iframes": 0,
        "obfuscated_js": False,
    }

    try:
        resp = requests.get(
            normalized,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )
    except requests.exceptions.ConnectionError as exc:
        return {"module": "html", "score": 0, "flags": [f"Não foi possível ligar ao servidor: {exc}"], "details": details}
    except requests.exceptions.Timeout:
        return {"module": "html", "score": 0, "flags": ["Timeout ao ligar ao servidor"], "details": details}
    except Exception as exc:
        return {"module": "html", "score": 0, "flags": [f"Erro ao obter página: {exc}"], "details": details}

    # Redireccionamento para um domínio diferente do original é um indicador de phishing
    final_url = resp.url
    details["final_url"] = final_url
    final_domain = _base_domain(urlparse(final_url).hostname or "")
    if final_domain and final_domain != base:
        flags.append(f"Redireccionamento para domínio diferente: {final_domain}")
        score += SCORE_REDIRECT_MISMATCH

    soup = BeautifulSoup(resp.text, "html.parser")

    # Campos de password indicam que a página tenta capturar credenciais
    pw_fields = soup.find_all("input", attrs={"type": "password"})
    details["password_fields"] = len(pw_fields)
    if pw_fields:
        flags.append(f"Página contém {len(pw_fields)} campo(s) de password")
        score += SCORE_PASSWORD_FIELD

    # Análise de formulários — verificar se submetem dados para domínios externos
    form_details = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        has_pw = bool(form.find("input", attrs={"type": "password"}))

        if action:
            action_url = urljoin(normalized, action)
            action_domain = _base_domain(urlparse(action_url).hostname or "")
            is_external = bool(action_domain) and action_domain != base
        else:
            action_url = ""
            is_external = False

        form_details.append({
            "action": action_url or "(vazia)",
            "method": method,
            "has_password": has_pw,
            "external_action": is_external,
        })

        if is_external and has_pw:
            flags.append(f"Formulário de password envia dados para domínio externo: {action_domain}")
            score += SCORE_EXTERNAL_FORM_ACTION

    details["forms"] = form_details

    # Brand spoofing e iframes ocultos só são relevantes em páginas com campo de password.
    # Em sites de conteúdo, referências a marcas (botões SSO) e iframes ocultos (anúncios,
    # reCAPTCHA) são normais e não indicam phishing.
    is_login_page = bool(pw_fields)

    visible_text = _visible_text(soup)
    detected = [b for b in KNOWN_BRANDS if b in visible_text]
    details["brands_detected"] = detected
    # Phishing foca-se numa única marca; sites legítimos com SSO mencionam várias em simultâneo
    if is_login_page and detected and len(detected) <= 2 and not any(b in base for b in detected):
        flags.append(f"Marca(s) detectada(s) no conteúdo mas não no domínio: {', '.join(detected)}")
        score += SCORE_BRAND_SPOOFING

    hidden_iframes = [
        f for f in soup.find_all("iframe")
        if (
            "display:none" in (f.get("style", "").replace(" ", "").lower())
            or "visibility:hidden" in (f.get("style", "").replace(" ", "").lower())
            or f.get("hidden") is not None
        )
        and not _iframe_is_known_widget(f)
    ]
    details["hidden_iframes"] = len(hidden_iframes)
    if is_login_page and hidden_iframes:
        flags.append(f"{len(hidden_iframes)} iframe(s) oculto(s) detectado(s) (não-widget conhecido)")
        score += SCORE_HIDDEN_IFRAME

    # JavaScript ofuscado pode esconder redirecionamentos ou exfiltração de dados
    obfuscated = any(
        OBFUSCATION_PATTERNS.search(script.string or "")
        for script in soup.find_all("script")
    )
    details["obfuscated_js"] = obfuscated
    if obfuscated:
        flags.append("JavaScript potencialmente ofuscado detectado (eval/document.write/unescape)")
        score += SCORE_OBFUSCATED_JS

    # Rácio elevado de links externos sugere página clonada com recursos do site original
    all_links = soup.find_all("a", href=True)
    external_count = sum(
        1 for a in all_links
        if a["href"].startswith("http")
        and _base_domain(urlparse(a["href"]).hostname or "") != base
    )
    details["total_links"] = len(all_links)
    details["external_links"] = external_count
    if len(all_links) > 5 and external_count / len(all_links) > 0.7:
        flags.append(f"{external_count}/{len(all_links)} links apontam para domínios externos (>70%)")
        score += SCORE_HIGH_EXTERNAL_RATIO

    return {
        "module": "html",
        "score": min(score, 100),
        "flags": flags,
        "details": details,
    }
