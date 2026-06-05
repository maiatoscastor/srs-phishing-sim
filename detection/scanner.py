"""
Ponto de entrada do scanner de deteção de phishing.
Executa análise de domínio e mostra resultado no terminal.
"""

import json
import os
import sys
from datetime import datetime, timezone

from colorama import Fore, Style, init

from modules.domain_check import analyze

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


def _ensure_reports_dir() -> None:
    # Criar pasta de relatórios se não existir
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _verdict_label(score: int) -> str:
    if score <= 30:
        return f"{Fore.GREEN}SEGURO{Style.RESET_ALL}"
    if score <= 60:
        return f"{Fore.YELLOW}SUSPEITO{Style.RESET_ALL}"
    return f"{Fore.RED}PHISHING{Style.RESET_ALL}"


def _print_result(url: str, result: dict) -> None:
    score = result["score"]
    print()
    print(f"URL analisada: {url}")
    print(f"Score: {score}/100")
    print(f"Veredito: {_verdict_label(score)}")
    print()

    flags = result.get("flags", [])
    if flags:
        print("Alertas:")
        for flag in flags:
            print(f"  - {flag}")
    else:
        print("Alertas: nenhum")


def _save_report(url: str, result: dict) -> None:
    # Guardar resultado em JSON na pasta reports
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"scan_{timestamp}.json"
    path = os.path.join(REPORTS_DIR, filename)

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "results": [result],
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def main() -> None:
    init(autoreset=True)
    _ensure_reports_dir()

    if len(sys.argv) < 2:
        print(f"{Fore.RED}Erro: URL em falta.{Style.RESET_ALL}")
        print("Uso: python scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1].strip()

    try:
        result = analyze(url)
    except ValueError as exc:
        print(f"{Fore.RED}Erro: {exc}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as exc:
        print(f"{Fore.RED}Erro inesperado: {exc}{Style.RESET_ALL}")
        sys.exit(1)

    _print_result(url, result)

    try:
        _save_report(url, result)
    except OSError as exc:
        print(f"{Fore.YELLOW}Aviso: não foi possível guardar relatório — {exc}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
