"""
Ponto de entrada do scanner de deteção de phishing.
Executa todos os módulos de análise e agrega os resultados.
"""

import json
import os
import sys
from datetime import datetime, timezone

from colorama import Fore, Style, init

from modules.domain_check import analyze as analyze_domain
from modules.dns_check import analyze as analyze_dns
from modules.headers_check import analyze as analyze_headers
from modules.html_check import analyze as analyze_html
from modules.safebrowsing_check import query as query_safebrowsing
from modules.tls_check import analyze as analyze_tls
from modules.virustotal_check import query as query_virustotal
from modules.whois_check import analyze as analyze_whois

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

MODULES = [
    analyze_domain,
    analyze_whois,
    analyze_dns,
    analyze_tls,
    analyze_headers,
    analyze_html,
]


def _ensure_reports_dir() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _run_modules(url: str) -> list[dict]:
    results = []
    for fn in MODULES:
        try:
            results.append(fn(url))
        except Exception as exc:
            module_name = fn.__module__.split(".")[-1].replace("_check", "")
            results.append({
                "module": module_name,
                "score": 0,
                "flags": [f"Erro no módulo: {exc}"],
                "details": {},
            })
    return results


def _aggregate_score(results: list[dict]) -> int:
    # Score final = máximo entre todos os módulos (indicador mais grave prevalece)
    return max((r["score"] for r in results), default=0)


def _verdict_label(score: int) -> str:
    if score <= 30:
        return f"{Fore.GREEN}SEGURO{Style.RESET_ALL}"
    if score <= 60:
        return f"{Fore.YELLOW}SUSPEITO{Style.RESET_ALL}"
    return f"{Fore.RED}PHISHING{Style.RESET_ALL}"


def _print_results(url: str, results: list[dict], final_score: int) -> None:
    print()
    print(f"URL analisada : {url}")
    print(f"Score final   : {final_score}/100")
    print(f"Veredito      : {_verdict_label(final_score)}")

    for result in results:
        module = result.get("module", "?").upper()
        score = result.get("score", 0)
        flags = result.get("flags", [])

        color = Fore.GREEN if score <= 30 else (Fore.YELLOW if score <= 60 else Fore.RED)
        print()
        print(f"  [{color}{module}{Style.RESET_ALL}] Score: {score}/100")
        if flags:
            for flag in flags:
                print(f"    - {flag}")
        else:
            print(f"    - Sem alertas")


def _print_virustotal(vt: dict) -> None:
    print(f"\n{Fore.CYAN}Comparação com VirusTotal{Style.RESET_ALL}")
    if not vt.get("available"):
        print(f"  Indisponível: {vt.get('reason', 'desconhecido')}")
        return

    malicious = vt["malicious"]
    suspicious = vt["suspicious"]
    total = vt["total_engines"]
    color = Fore.GREEN if malicious == 0 and suspicious == 0 else (Fore.YELLOW if malicious == 0 else Fore.RED)
    print(f"  {color}{malicious + suspicious}/{total} motores assinalaram esta URL{Style.RESET_ALL}")
    print(f"    Maliciosos: {malicious} | Suspeitos: {suspicious}")
    print(f"    Detalhes: {vt['permalink']}")


def _print_safebrowsing(gsb: dict) -> None:
    print(f"\n{Fore.CYAN}Comparação com Google Safe Browsing{Style.RESET_ALL}")
    if not gsb.get("available"):
        print(f"  Indisponível: {gsb.get('reason', 'desconhecido')}")
        return

    if gsb["flagged"]:
        tipos = ", ".join(gsb["threat_types"])
        print(f"  {Fore.RED}URL ASSINALADA — {gsb['verdict']}{Style.RESET_ALL}")
        print(f"    Tipos de ameaça: {tipos}")
    else:
        print(f"  {Fore.GREEN}URL não assinalada pela Google{Style.RESET_ALL}")


def _save_report(url: str, results: list[dict], final_score: int, virustotal: dict, safebrowsing: dict) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"scan_{timestamp}.json"
    path = os.path.join(REPORTS_DIR, filename)

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "final_score": final_score,
        "verdict": "SEGURO" if final_score <= 30 else ("SUSPEITO" if final_score <= 60 else "PHISHING"),
        "results": results,
        "virustotal": virustotal,
        "safebrowsing": safebrowsing,
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    print(f"\n  Relatório guardado em: reports/{filename}")


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    init(autoreset=True)
    _ensure_reports_dir()

    if len(sys.argv) < 2:
        print(f"{Fore.RED}Erro: URL em falta.{Style.RESET_ALL}")
        print("Uso: python scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1].strip()

    print(f"\nA analisar: {url}")
    print("A executar módulos...", end="", flush=True)

    try:
        results = _run_modules(url)
    except ValueError as exc:
        print(f"\n{Fore.RED}Erro: {exc}{Style.RESET_ALL}")
        sys.exit(1)

    final_score = _aggregate_score(results)
    print(" concluído.")

    _print_results(url, results, final_score)

    try:
        virustotal = query_virustotal(url)
    except Exception as exc:
        virustotal = {"available": False, "reason": f"Erro inesperado: {exc}"}
    _print_virustotal(virustotal)

    try:
        safebrowsing = query_safebrowsing(url)
    except Exception as exc:
        safebrowsing = {"available": False, "reason": f"Erro inesperado: {exc}"}
    _print_safebrowsing(safebrowsing)

    try:
        _save_report(url, results, final_score, virustotal, safebrowsing)
    except OSError as exc:
        print(f"{Fore.YELLOW}Aviso: não foi possível guardar relatório — {exc}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
