"""
Análise forense pós-ataque.

Lê os logs gerados pelo módulo attack (campaign, clicks, captures, fingerprints)
e produz um relatório agregado: funil de conversão, origens geográficas,
timeline de atividade, browsers mais comuns, latência clique→submissão e
dispositivos reutilizados entre submissões diferentes.

Uso:
    python forensics.py
"""

import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

from colorama import Fore, Style, init

LOG_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "logs"))
CAPTURES_PATH = os.path.join(LOG_DIR, "captures.json")
CLICKS_PATH = os.path.join(LOG_DIR, "clicks.json")
CAMPAIGN_PATH = os.path.join(LOG_DIR, "campaign.json")
FINGERPRINTS_PATH = os.path.join(LOG_DIR, "fingerprints.json")


def _read_json(path: str) -> list:
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except (json.JSONDecodeError, ValueError):
            return []


def _pct(num: int, den: int) -> float:
    return round(num / den * 100, 1) if den else 0.0


def _funnel(campaign: list, clicks: list, captures: list) -> dict:
    sent = sum(1 for c in campaign if c.get("sent"))
    clicked_tokens = {c["token"] for c in clicks if c.get("token")}
    captured_tokens = {c["track_token"] for c in captures if c.get("track_token")}
    return {
        "enviados": sent,
        "clicaram": len(clicked_tokens),
        "submeteram_credenciais": len(captured_tokens),
        "taxa_clique": _pct(len(clicked_tokens), sent),
        "taxa_conversao": _pct(len(captured_tokens), sent),
        "abandono_pos_clique": len(clicked_tokens - captured_tokens),
    }


def _geo_breakdown(captures: list) -> dict:
    countries, cities, isps = Counter(), Counter(), Counter()
    for c in captures:
        geo = c.get("geo") or {}
        countries[geo.get("country", "Desconhecido")] += 1
        if geo.get("city") and geo["city"] != "—":
            cities[geo["city"]] += 1
        if geo.get("isp") and geo["isp"] != "—":
            isps[geo["isp"]] += 1
    return {
        "por_pais": countries.most_common(),
        "por_cidade": cities.most_common(10),
        "por_isp": isps.most_common(10),
    }


def _timeline(clicks: list, captures: list) -> dict:
    click_h, cap_h, by_day = Counter(), Counter(), Counter()
    for c in clicks:
        ts = c.get("timestamp")
        if ts:
            dt = datetime.fromisoformat(ts)
            click_h[dt.hour] += 1
    for c in captures:
        ts = c.get("timestamp")
        if ts:
            dt = datetime.fromisoformat(ts)
            cap_h[dt.hour] += 1
            by_day[dt.date().isoformat()] += 1
    return {
        "cliques_por_hora": sorted(click_h.items()),
        "capturas_por_hora": sorted(cap_h.items()),
        "por_dia": sorted(by_day.items()),
    }


def _parse_ua(ua: str) -> str:
    """Converte um User-Agent completo numa string legível: Browser Versão / OS."""
    ua = ua or ""

    # OS
    if "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Windows NT" in ua:
        os_name = "Windows"
    elif "Mac OS X" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Outro"

    # Browser (ordem importa: Edge e browsers derivados antes do Chrome)
    m = re.search(r"Edg/(\d+)", ua)
    if m:
        return f"Edge {m.group(1)} / {os_name}"

    if "Mobile" in ua:
        m = re.search(r"Chrome/(\d+)", ua)
        if m:
            return f"Chrome {m.group(1)} Mobile / {os_name}"

    m = re.search(r"Chrome/(\d+)", ua)
    if m:
        return f"Chrome {m.group(1)} / {os_name}"

    m = re.search(r"Firefox/(\d+)", ua)
    if m:
        return f"Firefox {m.group(1)} / {os_name}"

    m = re.search(r"Safari/(\d+)", ua)
    if m:
        return f"Safari / {os_name}"

    return ua[:60]


def _user_agent_breakdown(captures: list) -> list:
    parsed = [_parse_ua(c.get("user_agent", "Desconhecido")) for c in captures]
    return Counter(parsed).most_common(10)


def _reused_devices(captures: list) -> dict:
    # Mesmo fp_token com emails diferentes indica dispositivo partilhado ou automação
    by_fp: dict[str, set] = {}
    for c in captures:
        fp = c.get("fp_token")
        if not fp:
            continue
        by_fp.setdefault(fp, set()).add(c.get("email", ""))
    return {fp: sorted(emails) for fp, emails in by_fp.items() if len(emails) > 1}


def _click_to_capture_latency(clicks: list, captures: list) -> dict:
    # Latências < 2s sugerem automação; valores muito elevados indicam desistência
    click_times = {c["token"]: c["timestamp"] for c in clicks if c.get("token")}
    deltas = []
    for cap in captures:
        token = cap.get("track_token")
        if token and token in click_times:
            t_click = datetime.fromisoformat(click_times[token])
            t_capture = datetime.fromisoformat(cap["timestamp"])
            deltas.append((t_capture - t_click).total_seconds())
    if not deltas:
        return {"amostras": 0}
    return {
        "amostras": len(deltas),
        "media_segundos": round(sum(deltas) / len(deltas), 1),
        "minimo_segundos": round(min(deltas), 1),
        "maximo_segundos": round(max(deltas), 1),
    }


def _print_report(report: dict) -> None:
    print(f"\n{Fore.CYAN}=== Relatório Forense Pós-Ataque ==={Style.RESET_ALL}")

    f = report["funil"]
    print(f"\n{Fore.YELLOW}Funil de conversão{Style.RESET_ALL}")
    print(f"  Emails enviados        : {f['enviados']}")
    print(f"  Cliques únicos         : {f['clicaram']} ({f['taxa_clique']}%)")
    print(f"  Credenciais submetidas : {f['submeteram_credenciais']} ({f['taxa_conversao']}%)")
    print(f"  Clicaram mas não submeteram: {f['abandono_pos_clique']}")

    geo = report["geografia"]
    print(f"\n{Fore.YELLOW}Origem geográfica{Style.RESET_ALL}")
    for country, count in geo["por_pais"]:
        print(f"  {country:<20} {count}")
    if geo["por_isp"]:
        print(f"\n  ISPs mais comuns:")
        for isp, count in geo["por_isp"][:5]:
            isp_short = isp[:28] + ".." if len(isp) > 30 else isp
            print(f"    {isp_short:<30} {count}")

    tl = report["timeline"]
    print(f"\n{Fore.YELLOW}Timeline de atividade{Style.RESET_ALL}")
    click_h = dict(tl.get("cliques_por_hora", []))
    cap_h   = dict(tl.get("capturas_por_hora", []))
    all_hours = sorted(set(click_h) | set(cap_h))
    if all_hours:
        max_c = max(click_h.values(), default=1)
        for h in all_hours:
            nc = click_h.get(h, 0)
            ns = cap_h.get(h, 0)
            bar = "#" * round(nc / max_c * 12)
            submissoes = f"  ({'submeteram' if ns > 1 else 'submeteu'} {ns})" if ns else ""
            print(f"  {h:02d}h  {bar:<14} {nc} clique{'s' if nc != 1 else ''}{submissoes}")

    print(f"\n{Fore.YELLOW}Browsers mais comuns{Style.RESET_ALL}")
    for ua, count in report["user_agents"][:5]:
        print(f"  [{count}] {ua}")

    lat = report["latencia_clique_submissao"]
    print(f"\n{Fore.YELLOW}Latência clique -> submissão{Style.RESET_ALL}")
    if lat["amostras"]:
        print(f"  Amostras: {lat['amostras']}")
        print(f"  Média: {lat['media_segundos']}s | Mín: {lat['minimo_segundos']}s | Máx: {lat['maximo_segundos']}s")
    else:
        print("  Sem dados suficientes (nenhum par clique->submissão encontrado)")

    reused = report["dispositivos_reutilizados"]
    print(f"\n{Fore.YELLOW}Dispositivos reutilizados (mesmo fingerprint, emails diferentes){Style.RESET_ALL}")
    if reused:
        for fp, emails in reused.items():
            print(f"  {Fore.RED}{fp[:12]}...{Style.RESET_ALL} -> {', '.join(emails)}")
    else:
        print("  Nenhum detectado")


def generate_report() -> dict:
    campaign = _read_json(CAMPAIGN_PATH)
    clicks = _read_json(CLICKS_PATH)
    captures = _read_json(CAPTURES_PATH)
    fingerprints = _read_json(FINGERPRINTS_PATH)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "totais": {
            "campanha": len(campaign),
            "cliques": len(clicks),
            "capturas": len(captures),
            "fingerprints": len(fingerprints),
        },
        "funil": _funnel(campaign, clicks, captures),
        "geografia": _geo_breakdown(captures),
        "timeline": _timeline(clicks, captures),
        "user_agents": _user_agent_breakdown(captures),
        "latencia_clique_submissao": _click_to_capture_latency(clicks, captures),
        "dispositivos_reutilizados": _reused_devices(captures),
    }


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    init(autoreset=True)
    report = generate_report()

    if report["totais"]["capturas"] == 0:
        print(f"{Fore.RED}Sem dados em {CAPTURES_PATH} — corre uma simulação primeiro.{Style.RESET_ALL}")
        return

    _print_report(report)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = os.path.join(LOG_DIR, f"forensic_report_{timestamp}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(f"\n  Relatório guardado em: data/logs/forensic_report_{timestamp}.json")


if __name__ == "__main__":
    main()
