# Contexto do Projeto — Simulação e Deteção de Phishing

**Disciplina:** Segurança de Redes e Sistemas (SEGRED)  
**Autores:** Diogo Sá (31378) · Diogo Monteiro (32428)  
**Entrega:** 18 de Junho de 2026  
**Repositório:** https://github.com/DM1205/srs-phishing-sim

---

## Narrativa do projeto (usar no relatório)

> A Empresa X contratou-nos para simular uma campanha de phishing interno e avaliar a resistência dos seus colaboradores. Enviámos emails falsos a 10 funcionários fictícios, registámos quem clicou e quem expôs credenciais, e usámos as nossas ferramentas de deteção para mostrar como um SOC identificaria o ataque.

Este enquadramento une os dois módulos do projeto (ataque + deteção) e responde à questão central da disciplina: **"Como medir e reduzir o risco humano numa organização?"**

---

## Arquitetura — Cenário de 3 VMs

```
VM1 — Kali Linux (Atacante)          VM2 — Debian/Ubuntu (Vítima)
┌──────────────────────────┐          ┌──────────────────────────┐
│  python app.py           │◄─────────│  Browser                 │
│  Flask em 0.0.0.0:5000   │  HTTP    │  Acede http://IP-VM1:5000│
│  Envia emails (mailer)   │          │  Preenche formulário      │
└──────────────┬───────────┘          └──────────────────────────┘
               │ data/logs/*.json
               ▼
VM3 — Windows/Ubuntu (Defensor/SOC)
┌──────────────────────────────────────┐
│  python scanner.py <url>             │
│  python forensics.py                 │
│  Dashboard: localhost:5000/dashboard │
└──────────────────────────────────────┘
```

**Fluxo completo do ataque:**
1. Atacante envia email com link para `http://IP-VM1:5000/track/<token>`
2. Vítima clica → Flask regista o clique (`clicks.json`) e redireciona para `/`
3. Vítima preenche email + password na página falsa → POST `/capture`
4. Flask regista metadados em `captures.json` (sem guardar password) + faz fingerprinting
5. Vítima é redirecionada para `/verify` (câmara) e depois `/warning` (página educativa)
6. Defensor abre dashboard, corre forensics.py e corre o scanner sobre a URL do ataque

**Para acesso externo (sem VMs em rede local):** `ngrok http 5000` gera URL público.

---

## O que está implementado — Estado real

### Módulo attack/

#### app.py — Servidor Flask
- Corre em `0.0.0.0:5000` (aceita ligações de qualquer VM na rede)
- Rotas:
  - `GET /` → página de login falsa Microsoft 365 (2 passos: email → password)
  - `GET /track/<token>` → regista clique, redireciona para `/?token=<token>`
  - `POST /capture` → regista metadados, redireciona para `/verify`
  - `GET /verify` → página de "verificação biométrica" que pede acesso à câmara
  - `POST /frame` → recebe frames JPEG da câmara em base64 e guarda em `data/logs/photos/`
  - `GET /live/<fp_token>` → serve o frame mais recente de uma vítima
  - `GET /livefeed/<fp_token>` → HTML com live feed da câmara
  - `POST /fingerprint` → recebe dados de fingerprinting do browser (silencioso)
  - `GET /warning` → página educativa com dicas anti-phishing
  - `GET /dashboard` → dashboard com todas as capturas, estatísticas e live feeds

#### login.html — Página de phishing
- Clone visual da página de login Microsoft 365
- JavaScript silencioso de fingerprinting (canvas hash, WebGL, resolução, timezone, cores CPU, memória)
- Campo oculto `fp_token` (UUID gerado no browser) que liga o fingerprint à captura
- Campo oculto `track_token` que liga à entrada em `clicks.json`

#### logger.py — Persistência em JSON
- Guarda em `data/logs/`:
  - `campaign.json` — emails enviados (name, email, token, sent, timestamp)
  - `clicks.json` — cliques no link (token, ip, user_agent, timestamp)
  - `captures.json` — credenciais submetidas (email, ip, user_agent, track_token, fp_token, geo, victim_id)
  - `fingerprints.json` — dados do browser (canvas_hash, webgl, screen, timezone, platform, cores, etc.)
- **Password NÃO é guardada** — só email e metadados (decisão ética explícita)
- Threading lock para evitar race condition em submissões simultâneas

#### forensics.py — Análise forense pós-ataque
Script CLI (`python forensics.py`) que lê os 4 ficheiros de log e produz:

| Análise | O que mostra |
|---------|-------------|
| Funil de conversão | Enviados → Clicaram (%) → Submeteram (%) → Abandonaram após clicar |
| Origem geográfica | País, cidade, ISP (via ip-api.com) |
| Timeline | Cliques e submissões por hora do dia (barras ASCII) |
| Browsers | User-agent parseado para "Chrome 125 / Windows" etc. |
| Latência clique→submissão | Média/min/máx em segundos; <2s indica automação/bot |
| Dispositivos reutilizados | Mesmo fp_token com emails diferentes (computador partilhado ou atacante a testar) |

**Dados de demo gerados** (ficheiro `generate_demo_data.py`):
- 10 funcionários fictícios da "Empresa X", campanha em 2026-06-10
- 7 clicaram (70%), 4 submeteram credenciais (40%)
- Ana Silva + Maria Santos: mesmo computador de receção (fp_token partilhado → detetado)
- Pedro Costa: latência de 1 segundo → assinalado como possível automação
- ISPs: NOS, MEO, Vodafone (Portugal)

---

### Módulo detection/

#### scanner.py — Ponto de entrada CLI

```bash
python scanner.py "https://exemplo.com"
```

Corre 6 módulos de análise em sequência, agrega o score, imprime resultado colorido e guarda JSON em `reports/scan_*.json`. Também chama VirusTotal e Google Safe Browsing como comparação (não entram no score heurístico).

**Estratégia de agregação:** `score_final = max(scores_dos_modulos)` — o indicador mais grave prevalece. Fácil de explicar: um único sinal muito forte (domínio com 1 dia, HTTP puro) é suficiente para suspeitar.

**Vereditos:** ≤30 = SEGURO (verde), 31–60 = SUSPEITO (amarelo), >60 = PHISHING (vermelho)

#### Módulos de análise heurística

| Módulo | Ficheiro | O que analisa | Score máx. relevante |
|--------|----------|---------------|----------------------|
| Domain | domain_check.py | URL longa, IP em vez de domínio, palavras-chave (login/secure/verify), subdomínios excessivos, encurtadores, símbolo @ | 80 |
| WHOIS | whois_check.py | Idade do domínio (<30 dias = 30pts, <6 meses = 15pts), sem dados WHOIS | 30 |
| DNS | dns_check.py | Sem registo A (35), sem MX (10), sem NS (15). MX/NS consultados no domínio apex, não no subdomínio | 35 |
| TLS | tls_check.py | HTTP puro (40), certificado auto-assinado (25), cadeia não confiável (25), cert muito novo <7 dias (20), cert expirado (30) | 40 |
| Headers | headers_check.py | Headers de segurança em falta: HSTS (10), CSP (5), X-Frame-Options (5), X-Content-Type-Options (3), Referrer-Policy (3), Permissions-Policy (3) | 29 |
| HTML | html_check.py | Campo de password (20), formulário envia para domínio externo (25), brand spoofing no texto visível (20, só se tiver password field), iframes ocultos não-widget (15, só se tiver password field), JS ofuscado (15), >70% links externos (10), redirect para domínio diferente (15) | 80 |

**Decisões de calibração importantes (para o relatório):**
- Headers limitado a 29 máximo para não cruzar o limiar de SEGURO/SUSPEITO sozinho
- Brand spoofing e iframes ocultos só contam se a página tiver campo de password (`is_login_page`) — evita falsos positivos em sites de conteúdo com botões SSO/Google Ads
- Brand spoofing só conta se ≤2 marcas detectadas — phishing foca-se numa; site legítimo menciona muitas (Google, Facebook, Instagram... via SDKs)
- Texto visível apenas (exclui script/style/meta/noscript/head) — evita detetar marcas mencionadas em SDKs JavaScript
- `_chain_is_trusted()` no módulo TLS verifica a cadeia separadamente do `_fetch_cert()` que usa `CERT_NONE` por design
- `SCORE_NO_TLS = 40` (era 30) — corrigido após teste com phishing real que ficou em 30/100

#### Módulos de comparação (não entram no score)

| Módulo | Ficheiro | API | Variável de ambiente |
|--------|----------|-----|----------------------|
| VirusTotal | virustotal_check.py | VT API v3 — GET /urls/{id}, POST /urls + polling | `VT_API_KEY` |
| Google Safe Browsing | safebrowsing_check.py | Lookup API v4 — POST threatMatches:find | `SAFE_BROWSING_KEY` |

Ambos falham graciosamente se a chave não estiver configurada.

---

## Testes com phishing real (resultados para o relatório)

### Sites legítimos (sem falsos positivos)

| Site | Score | Veredito |
|------|-------|---------|
| google.com | 24 | SEGURO |
| instagram.com | 10 | SEGURO |
| dn.pt | 20 | SEGURO |
| playvalorant.com | 23 | SEGURO |

### URLs de phishing ativo (OpenPhish public feed, 2026-06-16)

| URL | Nosso scanner | VirusTotal | Google Safe Browsing |
|-----|--------------|------------|----------------------|
| imagorad.com.br/prot/ | SEGURO (30) ⚠️ | 10/92 maliciosos | Não assinalou |
| klausfhepp.com/ino | SUSPEITO (35) | 5/92 maliciosos | Não assinalou |
| robiox.com.gr/.../profile | SUSPEITO (35) | 20/92 maliciosos | Não assinalou |
| allegrolokalnie.vsj1gdgzcs.biz | SUSPEITO (40) | 6/92 maliciosos | Não assinalou |

**Conclusão para o relatório:** URLs de phishing muito recentes (registadas no próprio dia) são difíceis de detetar para todos — o nosso scanner e o VirusTotal/GSB. O nosso scanner apanha sinais estruturais (HTTP, domínio recente, cadeia TLS inválida) mesmo antes de a URL entrar nas blacklists de reputação. Os dois abordagens são complementares.

### Bugs encontrados e corrigidos durante os testes (mostrar no relatório como processo iterativo)

1. **DNS false positive** — módulo consultava MX/NS no hostname completo (www.google.com) em vez do domínio apex (google.com). Corrigido com `_base_domain()`.
2. **Headers over-penalization** — pesos somavam 50 pontos possíveis só por headers em falta, cruzando o limiar de SEGURO/SUSPEITO. Recalibrado para máximo 29.
3. **Brand spoofing em sites legítimos** — texto de scripts/SDKs mencionava "google"/"facebook" disparando a deteção. Corrigido com `_visible_text()` e gating por `is_login_page`.
4. **TLS chain trust** — `_fetch_cert()` usa `CERT_NONE` por design (para ler metadados de certs inválidos), mas nunca verificava se a cadeia seria aceite por um cliente normal. Adicionado `_chain_is_trusted()` com `ssl.create_default_context()` separado.
5. **SCORE_NO_TLS = 30 → 40** — HTTP puro ficava exatamente no limiar 30 (SEGURO). Em 2026, todos os sites legítimos usam HTTPS; site HTTP é genuinamente mais suspeito.
6. **Encoding Windows cp1252** — caracteres acentuados e setas Unicode causavam crash. Corrigido com `sys.stdout.reconfigure(encoding="utf-8")` no início de `main()` em scanner.py e forensics.py.

---

## Pesquisa de casos reais (Semana 1)

Ficheiro: `research/pesquisa-casos-reais.md`

4 casos documentados com fontes verificadas:
1. **Microsoft 365 OAuth/device-code bypass** — campanha que contorna MFA usando o fluxo de autorização de dispositivo
2. **PhishTank** — plataforma de verificação colaborativa de URLs de phishing
3. **Chave Móvel Digital** — campanha de phishing em Portugal (CNCS)
4. **PayPal via Microsoft 365 legítimo** — abuso de infraestrutura legítima para enviar phishing

---

## Estrutura de ficheiros atual (real)

```
srs-phishing-sim/
├── attack/
│   ├── app.py                    # Servidor Flask, todas as rotas
│   ├── logger.py                 # Persistência JSON com threading lock
│   ├── forensics.py              # Análise forense pós-ataque
│   ├── generate_demo_data.py     # Gera dados sintéticos para demo
│   ├── mailer.py                 # Envio de emails de phishing simulado
│   └── templates/
│       ├── login.html            # Página falsa Microsoft 365 + fingerprinting JS
│       ├── verify.html           # Página de "verificação biométrica" (câmara)
│       ├── warning.html          # Página educativa pós-captura
│       ├── dashboard.html        # Dashboard do atacante
│       └── livefeed.html         # Live feed câmara vítima
├── data/
│   ├── logs/                     # campaign/clicks/captures/fingerprints.json (git-ignored)
│   └── reports/                  # git-ignored
├── detection/
│   ├── modules/
│   │   ├── domain_check.py       # Heurísticas de URL
│   │   ├── whois_check.py        # Idade do domínio
│   │   ├── dns_check.py          # Registos A, MX, NS
│   │   ├── tls_check.py          # Certificado TLS/SSL
│   │   ├── headers_check.py      # Cabeçalhos HTTP de segurança
│   │   ├── html_check.py         # Estrutura HTML, brand spoofing, iframes
│   │   ├── virustotal_check.py   # Comparação com VirusTotal API v3
│   │   ├── safebrowsing_check.py # Comparação com Google Safe Browsing API v4
│   │   └── utils.py              # normalize_url, get_hostname
│   ├── reports/                  # scan_*.json (git-ignored)
│   └── scanner.py                # CLI principal, agrega módulos, imprime resultado
├── research/
│   └── pesquisa-casos-reais.md   # 4 casos reais com fontes verificadas
├── ARCHITECTURE.md               # desatualizado
├── CONTEXT.md                    # este ficheiro
├── README.md                     # parcialmente atualizado
└── requirements.txt              # flask, requests, python-whois, dnspython, pyopenssl,
                                  # rich, python-dateutil, colorama, beautifulsoup4
```

---

## Guião para o relatório técnico

### Estrutura recomendada

#### 1. Introdução (½ pág)
- Phishing como vetor dominante de comprometimento organizacional (citar APWG)
- Objetivo: demonstrar o ciclo completo ataque→deteção em laboratório controlado
- Enquadramento: "Como medir e reduzir o risco humano?" em vez de só "Como detetar URLs?"

#### 2. Arquitetura do Sistema (1 pág)
- Diagrama das 3 VMs (Kali atacante / Debian vítima / Defensor SOC)
- Fluxo: email → clique → credenciais → dashboard → scanner → alerta
- Tecnologias: Python 3.13, Flask, BeautifulSoup4, dnspython, pyOpenSSL, colorama

#### 3. Módulo de Ataque (1 pág)
- Página falsa Microsoft 365 (design, dois passos email→password)
- O que é capturado e porquê: email, IP, user-agent, timestamp, geo, fingerprint
- O que NÃO é guardado e porquê: password (decisão ética explícita)
- Fingerprinting silencioso: canvas hash, WebGL, resolução, timezone
- Câmara: `/verify` pede acesso, frames enviados para `/frame`, visíveis em `/livefeed`
- Screenshot: página de login + página de aviso + dashboard

#### 4. Análise Forense Pós-Ataque (1 pág)
- Output do `forensics.py` com dados da campanha simulada (Empresa X, 2026-06-10)
- Tabela: 10 enviados → 7 clicaram (70%) → 4 submeteram (40%) → 3 abandonaram
- Frase de impacto: "Se esta fosse uma campanha real, 40% dos colaboradores teria exposto credenciais"
- Latência: Pedro Costa 1 segundo → possível automação/bot vs média humana de 172s
- Dispositivo partilhado: Ana Silva + Maria Santos no mesmo computador de receção
- Screenshot do output completo do forensics.py

#### 5. Scanner de Deteção (2 pág)
- Arquitetura modular: 6 módulos independentes + 2 de comparação
- Explicar cada módulo brevemente com a pontuação e o porquê
- Lógica de agregação: max-of-modules — o indicador mais grave prevalece (fácil de explicar)
- Vereditos: SEGURO/SUSPEITO/PHISHING com limiares
- Screenshot do scanner a analisar a página de phishing do projeto → deve dar PHISHING
- Processo iterativo: bugs encontrados e corrigidos durante testes com sites reais

#### 6. Comparação com Ferramentas Externas (1 pág)
- Tabela com 4+ URLs testadas: nosso scanner vs VirusTotal vs Google Safe Browsing
- Discussão: VT/GSB usam reputação histórica + ML → superiores para URLs conhecidas
- O nosso scanner usa heurísticas estruturais → apanha sinais mesmo em URLs muito recentes
- Os dois são complementares, não concorrentes
- Limitação honesta: imagorad.com.br confirmado phishing pelo VT, nós demos SEGURO (30)

#### 7. Limitações e Discussão (½ pág)
- Falso negativo documentado: phishing sem TLS inválido + sem marca conhecida passa no nosso scanner
- "HTTPS não implica legitimidade" — muitos sites de phishing já usam Let's Encrypt
- "Domínio antigo pode ser comprometido" — WHOIS analisa criação mas não comprometimento
- "Deteção baseada em regras tem teto" — ML e feeds de threat intel seriam o próximo passo
- A deteção por reputação (VT/GSB) falha igualmente em URLs muito recentes

#### 8. Conclusão (¼ pág)
- Construímos um laboratório completo de phishing, deteção e resposta a incidentes
- Demonstrámos o ciclo completo do ponto de vista do atacante E do defensor
- A comparação com ferramentas comerciais mostrou onde as heurísticas locais chegam e onde ficam aquém

---

## Screenshots a tirar para o relatório

| # | O quê | Como |
|---|-------|------|
| 1 | Página de login falsa | `http://localhost:5000` ou URL ngrok |
| 2 | Página de verificação (câmara) | Depois de submeter credenciais → `/verify` |
| 3 | Página de aviso educativa | `/warning` |
| 4 | Dashboard com capturas | `/dashboard` |
| 5 | Output do forensics.py | `python forensics.py` |
| 6 | Scanner → PHISHING na nossa página | `python scanner.py http://localhost:5000` |
| 7 | Scanner → SEGURO num site legítimo | `python scanner.py https://google.com` |
| 8 | Comparação VT+GSB numa URL de phishing real | `python scanner.py https://klausfhepp.com/ino` |
| 9 | Diagrama de arquitetura (fazer à mão ou draw.io) | — |

---

## Extras implementados além do PDF

O PDF listava VirusTotal como **bónus da Semana 5 "se houver tempo"**. Implementámos:
- VirusTotal API v3 (bónus do PDF) ✅
- Google Safe Browsing API v4 (estava nos objetivos mas não nos checkpoints) ✅
- Fingerprinting de browser (canvas, WebGL, hardware) ✅
- Câmara (stream JPEG via `/verify` e `/livefeed`) ✅
- Análise forense completa com 6 métricas (`forensics.py`) ✅
- Deteção de cadeia TLS não confiável (`_chain_is_trusted`) ✅
- Dados sintéticos de demo realistas para campanha simulada ✅
