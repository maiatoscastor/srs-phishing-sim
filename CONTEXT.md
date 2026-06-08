# Contexto do Projeto — Simulação e Deteção de Phishing

**Disciplina:** Segurança de Redes e Sistemas (SEGRED)
**Autores:** Diogo Sá (31378) · Diogo Monteiro (32428)
**Repositório:** https://github.com/DM1205/srs-phishing-sim

---

## O que é o projeto

Sistema académico de simulação e deteção de phishing com dois módulos independentes:

- **attack** — servidor Flask que simula uma página falsa de login Microsoft, regista metadados dos participantes e redireciona para uma página educativa
- **detection** — scanner de URLs que analisa indicadores de phishing e gera relatórios JSON

O objetivo é demonstrar o ciclo completo: como um ataque de phishing funciona tecnicamente, que dados expõe uma vítima, e como um sistema de deteção identifica URLs maliciosas.

---

## Estado atual

### Módulo attack — Funcional

**Ficheiros:**
- `attack/app.py` — servidor Flask em `0.0.0.0:5000`, três rotas:
  - `GET /` → serve `login.html`
  - `POST /capture` → regista metadados, redireciona para `/warning`
  - `GET /warning` → serve `warning.html`
- `attack/logger.py` — persiste entradas em `data/logs/captures.json`
- `attack/templates/login.html` — clone visual da página de login Microsoft 365 (dois passos: email → password)
- `attack/templates/warning.html` — página educativa em português, explica o ataque, 5 dicas anti-phishing, link para CNCS

**Decisões de design importantes:**
- A **password não é guardada em disco** — só email, IP, user-agent e um UUID por submissão
- Redireciona para `/warning` (página própria) e não para a Microsoft real — mais ético e educativo
- Cada submissão tem um `victim_id` UUID único para identificação sem depender do IP
- Headers `no-cache` em todas as respostas HTML
- Campo de email usa `type="text"` (não `type="email"`) para aceitar formatos corporativos
- Extração de IP trata `X-Forwarded-For` com split por vírgula (compatível com proxies)

**Dados registados por submissão:**
```json
{
  "timestamp": "2026-06-05T07:06:23.536862+00:00",
  "email": "utilizador@empresa.pt",
  "ip": "127.0.0.1",
  "user_agent": "Mozilla/5.0 ...",
  "victim_id": "8453aaf2-5015-4dca-8d85-aee249eb8df8"
}
```

**Testado:** 3 submissões reais em `data/logs/captures.json` durante desenvolvimento.

---

### Módulo detection — Parcialmente funcional

**Ficheiros:**
- `detection/scanner.py` — ponto de entrada CLI, recebe URL como argumento, imprime resultado com cores (colorama), guarda relatório JSON em `detection/reports/`
- `detection/modules/domain_check.py` — análise heurística de URL

**O que o scanner já faz (heurísticas implementadas):**

| Indicador | Pontuação |
|-----------|-----------|
| URL com mais de 75 caracteres | +15 |
| Hostname é endereço IP | +25 |
| Palavras-chave suspeitas (login, secure, verify, account, update, signin) | +10 cada |
| Mais de 3 subdomínios (pontos no hostname) | +15 |
| Encurtador de URL (bit.ly, tinyurl.com, t.co) | +20 |
| Símbolo @ na URL (técnica de ofuscação) | +25 |

**Vereditos:** 0–30 = SEGURO, 31–60 = SUSPEITO, 61–100 = PHISHING

**Exemplo de relatório gerado** (`detection/reports/scan_*.json`):
```json
{
  "timestamp": "2026-06-05T10:14:17Z",
  "url": "http://login.secure@192.168.1.1/verify",
  "results": [{
    "module": "domain",
    "score": 80,
    "flags": ["Hostname é um endereço IP", "Palavra-chave suspeita: login", "Símbolo @ presente na URL"]
  }]
}
```

**O que está em falta no detection** (planeado em ARCHITECTURE.md mas não implementado):
- WHOIS — data de registo do domínio, registar, país
- DNS — registos A, MX, NS; verificar se o domínio existe
- TLS/SSL — validade do certificado, emissor, idade do certificado
- Cabeçalhos HTTP de segurança — presença de HSTS, X-Frame-Options, CSP

Os pacotes `python-whois`, `dnspython`, `pyopenssl` e `requests` já estão no `requirements.txt` mas não são usados.

---

## Infraestrutura e deployment

**Stack:**
- Python 3.13
- Flask (attack)
- colorama, rich (detection terminal output)
- JSON como base de dados (sem dependência de servidor de BD)

**Requirements:**
```
flask, requests, python-whois, dnspython, pyopenssl, rich, python-dateutil, colorama
```

**Deployment planeado — VMs em rede local:**

| VM | Papel | O que corre |
|----|-------|-------------|
| VM1 (Linux/Kali) | Atacante | `attack/app.py` |
| VM2 (qualquer OS) | Vítima | Browser |
| VM3 (opcional) | Defensor | `detection/scanner.py` |

A vítima navega para o IP da VM atacante (`http://<IP_VM1>:5000`). Qualquer dispositivo na mesma rede pode ser vítima simultaneamente — não há limite de vítimas.

**Para acesso externo (fora da rede local):** usar ngrok (`ngrok http 5000`) para obter URL público temporário sem necessidade de VPS.

---

## Problemas conhecidos (a corrigir)

1. **Race condition no `logger.py`** — padrão read→append→write sem lock de ficheiro. Em submissões simultâneas pode perder entradas.
2. **`captures.json` não está no `.gitignore`** — ficheiro com dados de teste está a ser rastreado pelo git.

---

## Melhorias planeadas (próximas tarefas)

### Fase A — Correções e debt técnico
1. **Corrigir race condition no `logger.py`** — padrão read→append→write sem lock. Em submissões simultâneas pode perder entradas. Solução: `fcntl.flock` (Linux) ou `threading.Lock` global.
2. **Adicionar `captures.json` ao `.gitignore`** — ficheiro com dados de teste está a ser rastreado pelo git.

### Fase B — Três melhorias principais (por ordem de implementação)

#### B1 — Geolocalização OSINT automática das capturas *(~meio dia)*
- Cada `POST /capture` faz chamada à **ip-api.com** (gratuita, sem API key) com o IP da vítima
- Enriquece o registo com: país, cidade, ISP, ASN, coordenadas (lat/lon)
- Dashboard mostra bandeira do país e operador de cada vítima
- Adicionar `countryCode`, `city`, `isp` ao schema de `captures.json`

#### B2 — Browser fingerprinting silencioso na página de ataque *(~1-2 dias)*
- JavaScript injetado na `login.html` que corre **antes** de qualquer interação da vítima
- Dados recolhidos silenciosamente (sem qualquer popup ou permissão):
  - Resolução do ecrã, color depth, timezone, idioma do browser
  - Lista de dispositivos de media disponíveis (câmara/microfone — só detecção, não acesso)
  - Canvas fingerprint (hash único derivado do browser + GPU)
  - WebGL renderer e vendor (identifica o hardware)
  - Plugins e fonts disponíveis
  - `navigator.platform`, `hardwareConcurrency`, `deviceMemory`
- **Nota técnica sobre câmara:** acesso silencioso ao stream de vídeo/áudio é bloqueado pelos browsers sem permissão explícita do utilizador. O que é possível silenciosamente é apenas detetar a *presença* dos dispositivos via `enumerateDevices()`. Para acesso real ao stream seria necessário social engineering (página pedir permissão com pretexto falso) — demonstrar e explicar este mecanismo ao stor como exemplo de técnica de evasão.
- Dados enviados via `fetch` em background para `/fingerprint` antes do submit do formulário
- Guardados em `data/logs/fingerprints.json` e associados ao `victim_id`

#### B3 — Machine Learning no módulo de deteção *(~3-4 dias)*
- Dataset: **PhishTank** (URLs de phishing confirmadas, download gratuito em CSV) + **Majestic Million** (URLs legítimas)
- Feature engineering: extrair as mesmas features já implementadas em `domain_check.py` + novas (entropia do domínio, ratio consoantes/vogais, n-gramas de caracteres)
- Modelo: **Random Forest** com scikit-learn (robusto, interpretável, sem necessidade de GPU)
- Script `detection/train.py`: treina, avalia e guarda o modelo em `detection/model.pkl`
- Integração em `scanner.py` como módulo adicional: além do score heurístico, o modelo ML dá uma probabilidade (ex: "94% probabilidade de phishing")
- Relatório de avaliação: accuracy, precision, recall, F1, confusion matrix (visualizado com rich ou matplotlib)
- **Argumento principal:** comparar heurísticas vs ML — mostrar onde um falha e o outro acerta

---

## Estrutura de ficheiros atual

```
srs-phishing-sim/
├── attack/
│   ├── app.py
│   ├── logger.py
│   └── templates/
│       ├── login.html
│       └── warning.html
├── data/
│   ├── logs/
│   │   ├── .gitkeep
│   │   └── captures.json
│   └── reports/
│       └── .gitkeep
├── detection/
│   ├── modules/
│   │   ├── __init__.py
│   │   └── domain_check.py
│   ├── reports/
│   │   └── scan_*.json
│   └── scanner.py
├── ARCHITECTURE.md
├── CONTEXT.md          ← este ficheiro
├── README.md
└── requirements.txt
```
