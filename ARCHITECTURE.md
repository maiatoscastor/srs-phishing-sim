# Arquitectura — Simulação e Deteção de Phishing

Diogo Sá (31378) · Diogo Monteiro (32428)

---

## Visão geral

```
  Módulo attack                          Módulo detection
  ─────────────────────────────          ─────────────────────────────────────
  app.py  ←── login.html                scanner.py  ←── URL (argumento)
     │              │                       │
     ├── clicks.json                        ├── domain_check.py
     ├── captures.json                      ├── whois_check.py
     ├── fingerprints.json                  ├── dns_check.py
     └── campaign.json                      ├── tls_check.py
                                            ├── headers_check.py
  forensics.py ←── logs acima              ├── html_check.py
     └── relatório forense                  ├── virustotal_check.py  (comparação)
                                            ├── safebrowsing_check.py (comparação)
                                            └── reports/scan_*.json
```

| Módulo        | Stack principal                                       |
|---------------|-------------------------------------------------------|
| **attack**    | Python, Flask, HTML/CSS, JSON                         |
| **detection** | Python, requests, dnspython, pyOpenSSL, python-whois  |

---

## Módulo attack — fluxo

1. **GET /** — Flask serve `login.html` (clone visual Microsoft 365).
2. **POST /capture** — Recebe `username` e `password`; a password não é escrita em disco.
3. **logger.py** — Regista o clique em `clicks.json` (via token de rastreamento) e a submissão em `captures.json`.
4. **Redirect /warning** — Serve `warning.html` com explicação e boas práticas de segurança.

### Dados registados — captures.json

```json
{
  "timestamp": "2026-06-10T08:45:12+00:00",
  "email": "utilizador@empresa.pt",
  "ip": "192.168.1.10",
  "user_agent": "Mozilla/5.0 ...",
  "track_token": "tok-ana",
  "fp_token": "fp-rececao-001",
  "geo": { "country": "Portugal", "city": "Lisboa", "isp": "NOS" }
}
```

| Campo          | Descrição                                               |
|----------------|---------------------------------------------------------|
| `timestamp`    | Data/hora UTC (ISO 8601)                                |
| `email`        | Identificador submetido no formulário                   |
| `ip`           | Endereço do cliente                                     |
| `track_token`  | Liga a submissão ao clique original (funil forense)     |
| `fp_token`     | Hash do fingerprint do browser (deteção de dispositivo) |
| `geo`          | País, cidade e ISP (via ip-api.com)                     |

### Rotas

| Método | Rota           | Resposta                             |
|--------|----------------|--------------------------------------|
| GET    | `/`            | `login.html` (com token na query)    |
| GET    | `/track`       | Regista clique em `clicks.json`      |
| POST   | `/capture`     | Log + redirect `/warning`            |
| GET    | `/warning`     | `warning.html`                       |
| GET    | `/dashboard`   | Painel de campanha em tempo real     |

---

## Módulo detection — módulos de análise

Cada módulo devolve `{ "module": "...", "score": 0-100, "flags": [...], "details": {...} }`.  
O score final é o máximo entre todos os módulos (o indicador mais grave prevalece).

| Módulo              | Sinal analisado                                      | Score máximo |
|---------------------|------------------------------------------------------|--------------|
| `domain_check`      | Comprimento da URL, IP em hostname, keywords, @      | 100          |
| `whois_check`       | Idade do domínio, data de expiração                  | 30           |
| `dns_check`         | Presença de registos A, MX, NS                       | 60           |
| `tls_check`         | HTTP puro, auto-assinado, cadeia TLS, idade do cert  | 100          |
| `headers_check`     | Headers HTTP de segurança em falta                   | ~29          |
| `html_check`        | Campos de password, formulários externos, iframes    | 100          |

### Vereditos

| Score  | Veredito  |
|--------|-----------|
| 0–30   | SEGURO    |
| 31–60  | SUSPEITO  |
| >60    | PHISHING  |

### Comparação com terceiros (não entra no score)

- **VirusTotal** (`virustotal_check.py`) — consulta 90+ motores antivírus. Requer `VT_API_KEY`.
- **Google Safe Browsing** (`safebrowsing_check.py`) — base de dados de phishing/malware da Google. Requer `SAFE_BROWSING_KEY`.

---

## Considerações de segurança

- Execução apenas em ambiente de laboratório isolado.
- Passwords não são persistidas em disco.
- Página `warning.html` informa os participantes após a simulação.
- Sem hardening de produção (HTTPS, rate limiting) — não adequado a ambientes reais.
