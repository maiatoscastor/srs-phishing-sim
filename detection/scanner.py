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
from modules.tls_check import analyze as analyze_tls
from modules.whois_check import analyze as analyze_whois

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

MODULES = [
    analyze_domain,
    analyze_whois,
    analyze_dns,
    analyze_tls,
    analyze_headers,
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


def _save_report(url: str, results: list[dict], final_score: int) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"scan_{timestamp}.json"
    path = os.path.join(REPORTS_DIR, filename)

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "final_score": final_score,
        "verdict": "SEGURO" if final_score <= 30 else ("SUSPEITO" if final_score <= 60 else "PHISHING"),
        "results": results,
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    print(f"\n  Relatório guardado em: reports/{filename}")


def main() -> None:
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
        _save_report(url, results, final_score)
    except OSError as exc:
        print(f"{Fore.YELLOW}Aviso: não foi possível guardar relatório — {exc}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
