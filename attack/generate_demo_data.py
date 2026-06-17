"""
Gera dados sintéticos realistas para demonstração forense.

Cenário: Empresa X lançou uma campanha de phishing interno em 2026-06-10
para avaliar a resistência dos colaboradores. 10 funcionários fictícios,
emails enviados às 9h (Lisboa), respostas distribuídas ao longo do dia.

Uso:
    python generate_demo_data.py
"""

import json
import os
from datetime import datetime, timedelta, timezone

LOG_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)

# Dia da campanha simulada
BASE = datetime(2026, 6, 10, 8, 0, 0, tzinfo=timezone.utc)  # 09:00 Lisboa


def t(h=0, m=0, s=0):
    return (BASE + timedelta(hours=h, minutes=m, seconds=s)).isoformat()


UA_CHROME  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
UA_EDGE    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
UA_FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"
UA_MOBILE  = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"

GEO_LIS_NOS = {"country": "Portugal", "countryCode": "PT", "regionName": "Lisboa",
                "city": "Lisboa", "isp": "NOS SGPS SA", "lat": 38.7169, "lon": -9.1395,
                "timezone": "Europe/Lisbon"}
GEO_PRT_MEO = {"country": "Portugal", "countryCode": "PT", "regionName": "Porto",
                "city": "Porto", "isp": "MEO - Servicos de Comunicacoes e Multimedia SA",
                "lat": 41.1579, "lon": -8.6291, "timezone": "Europe/Lisbon"}
GEO_BRG_VOD = {"country": "Portugal", "countryCode": "PT", "regionName": "Braga",
                "city": "Braga", "isp": "Vodafone Portugal", "lat": 41.5454, "lon": -8.4265,
                "timezone": "Europe/Lisbon"}

# ── Campanha enviada (10 funcionários) ───────────────────────────────────────
campaign = [
    {"timestamp": t(0,  0), "name": "Ana Silva",        "email": "ana.silva@empresax.pt",       "token": "tok-ana",    "sent": True, "error": None},
    {"timestamp": t(0,  3), "name": "João Ferreira",    "email": "joao.ferreira@empresax.pt",   "token": "tok-joao",   "sent": True, "error": None},
    {"timestamp": t(0,  6), "name": "Maria Santos",     "email": "maria.santos@empresax.pt",    "token": "tok-maria",  "sent": True, "error": None},
    {"timestamp": t(0,  9), "name": "Pedro Costa",      "email": "pedro.costa@empresax.pt",     "token": "tok-pedro",  "sent": True, "error": None},
    {"timestamp": t(0, 12), "name": "Rita Oliveira",    "email": "rita.oliveira@empresax.pt",   "token": "tok-rita",   "sent": True, "error": None},
    {"timestamp": t(0, 15), "name": "Carlos Rodrigues", "email": "carlos.rodrigues@empresax.pt","token": "tok-carlos", "sent": True, "error": None},
    {"timestamp": t(0, 18), "name": "Sofia Martins",    "email": "sofia.martins@empresax.pt",   "token": "tok-sofia",  "sent": True, "error": None},
    {"timestamp": t(0, 21), "name": "Miguel Pereira",   "email": "miguel.pereira@empresax.pt",  "token": "tok-miguel", "sent": True, "error": None},
    {"timestamp": t(0, 24), "name": "Inês Carvalho",    "email": "ines.carvalho@empresax.pt",   "token": "tok-ines",   "sent": True, "error": None},
    {"timestamp": t(0, 27), "name": "Rui Gomes",        "email": "rui.gomes@empresax.pt",       "token": "tok-rui",    "sent": True, "error": None},
]

# ── Cliques (7 de 10 — 70% taxa de clique) ───────────────────────────────────
# Ana e Maria partilham o mesmo IP (computador de receção partilhado)
clicks = [
    {"timestamp": t(0, 42),     "token": "tok-ana",    "ip": "188.37.12.45",  "user_agent": UA_CHROME},
    {"timestamp": t(1, 15),     "token": "tok-joao",   "ip": "213.13.54.211", "user_agent": UA_EDGE},
    {"timestamp": t(0, 58),     "token": "tok-maria",  "ip": "188.37.12.45",  "user_agent": UA_CHROME},   # mesmo IP que Ana
    {"timestamp": t(3, 33),     "token": "tok-pedro",  "ip": "62.48.201.77",  "user_agent": UA_MOBILE},   # mobile
    {"timestamp": t(2,  7),     "token": "tok-rita",   "ip": "188.37.98.123", "user_agent": UA_FIREFOX},
    {"timestamp": t(4, 52),     "token": "tok-carlos", "ip": "213.13.87.44",  "user_agent": UA_CHROME},
    {"timestamp": t(6, 18),     "token": "tok-sofia",  "ip": "188.37.55.201", "user_agent": UA_EDGE},
    # tok-miguel, tok-ines, tok-rui: não clicaram
]

# ── Capturas (4 de 10 — 40% taxa de conversão) ───────────────────────────────
# Ana e Maria: mesmo fp_token (computador partilhado na receção)
# Pedro: latência de 1 segundo → possível automação / teste do próprio atacante
captures = [
    {
        "timestamp": t(0, 45, 12),   # Ana: clique às 08:42, captura às 08:45:12 → 192s
        "email": "ana.silva@empresax.pt",
        "ip": "188.37.12.45",
        "user_agent": UA_CHROME,
        "track_token": "tok-ana",
        "fp_token": "fp-rececao-001",
        "victim_id": "vic-001",
        "geo": GEO_LIS_NOS,
    },
    {
        "timestamp": t(1, 18, 44),   # João: clique às 09:15, captura às 09:18:44 → 224s
        "email": "joao.ferreira@empresax.pt",
        "ip": "213.13.54.211",
        "user_agent": UA_EDGE,
        "track_token": "tok-joao",
        "fp_token": "fp-joao-b3c4",
        "victim_id": "vic-002",
        "geo": GEO_PRT_MEO,
    },
    {
        "timestamp": t(1, 2, 31),    # Maria: clique às 08:58, captura às 09:02:31 → 271s
        "email": "maria.santos@empresax.pt",
        "ip": "188.37.12.45",
        "user_agent": UA_CHROME,
        "track_token": "tok-maria",
        "fp_token": "fp-rececao-001",  # mesmo fp que Ana → dispositivo reutilizado!
        "victim_id": "vic-003",
        "geo": GEO_LIS_NOS,
    },
    {
        "timestamp": t(3, 33, 1),    # Pedro: clique às 11:33:00, captura às 11:33:01 → 1s (bot!)
        "email": "pedro.costa@empresax.pt",
        "ip": "62.48.201.77",
        "user_agent": UA_MOBILE,
        "track_token": "tok-pedro",
        "fp_token": "fp-pedro-d5e6",
        "victim_id": "vic-004",
        "geo": GEO_BRG_VOD,
    },
]

# ── Fingerprints (dos 7 que clicaram) ────────────────────────────────────────
FP_BASE = {"screen": {"width": 1920, "height": 1080, "colorDepth": 24, "pixelRatio": 1},
           "timezone": "Europe/Lisbon", "language": "pt-PT", "platform": "Win32", "cores": 8}

fingerprints = [
    {**FP_BASE, "timestamp": t(0, 42,  2), "ip": "188.37.12.45",  "fp_token": "fp-rececao-001"},
    {**FP_BASE, "timestamp": t(1, 15,  1), "ip": "213.13.54.211", "fp_token": "fp-joao-b3c4"},
    {**FP_BASE, "timestamp": t(0, 58,  3), "ip": "188.37.12.45",  "fp_token": "fp-rececao-001"},
    {**FP_BASE, "timestamp": t(3, 33,  0), "ip": "62.48.201.77",  "fp_token": "fp-pedro-d5e6",
     "screen": {"width": 412, "height": 915, "colorDepth": 24, "pixelRatio": 2.6},  # mobile
     "platform": "Linux armv8l"},
    {**FP_BASE, "timestamp": t(2,  7,  1), "ip": "188.37.98.123", "fp_token": "fp-rita-f7a8"},
    {**FP_BASE, "timestamp": t(4, 52,  2), "ip": "213.13.87.44",  "fp_token": "fp-carlos-b9c0"},
    {**FP_BASE, "timestamp": t(6, 18,  1), "ip": "188.37.55.201", "fp_token": "fp-sofia-d1e2"},
]


def save(filename, data):
    path = os.path.join(LOG_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  {filename:<25} {len(data)} entradas")


print("A apagar dados anteriores e a gerar dados de demo...\n")
for fname in ["campaign.json", "clicks.json", "captures.json", "fingerprints.json"]:
    path = os.path.join(LOG_DIR, fname)
    if os.path.isfile(path):
        os.remove(path)

save("campaign.json",    campaign)
save("clicks.json",      clicks)
save("captures.json",    captures)
save("fingerprints.json", fingerprints)

print("\nCenário:")
print(f"  Emails enviados    : {len(campaign)}")
print(f"  Clicaram           : {len(clicks)} ({len(clicks)/len(campaign)*100:.0f}%)")
print(f"  Submeteram creds   : {len(captures)} ({len(captures)/len(campaign)*100:.0f}%)")
print(f"  Dispositivo partilhado: Ana + Maria (fp-rececao-001)")
print(f"  Latencia suspeita  : Pedro Costa -> 1 segundo (possivel bot)")
print(f"\nCorre agora: python forensics.py")
