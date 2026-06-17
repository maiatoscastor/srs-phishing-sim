# Simulação e Deteção de Phishing

Projeto universitário da disciplina **Segurança de Redes e Sistemas (SEGRED)**.

**Autores:** Diogo Sá (31378) · Diogo Monteiro (32428)  
**Repositório:** https://github.com/DM1205/srs-phishing-sim

---

## Descrição

Sistema completo de simulação e deteção de phishing para fins educativos em ambiente controlado.

- **Módulo attack** — envia emails de phishing simulado, serve uma página falsa de login Microsoft 365, regista metadados dos utilizadores (sem guardar passwords) e apresenta uma página de consciencialização.
- **Módulo detection** — analisa URLs suspeitas com 6 módulos heurísticos e compara com VirusTotal e Google Safe Browsing.

---

## Estrutura do projeto

```
srs-phishing-sim/
├── attack/
│   ├── app.py                    # Servidor Flask — todas as rotas
│   ├── logger.py                 # Persistência em JSON (sem passwords)
│   ├── mailer.py                 # Envio de emails com tracking por token
│   ├── forensics.py              # Análise forense pós-campanha
│   ├── generate_demo_data.py     # Gera dados sintéticos para demonstração
│   └── templates/
│       ├── login.html            # Página falsa Microsoft 365
│       ├── verify.html           # Página de verificação (pede câmara)
│       ├── warning.html          # Página educativa pós-captura
│       └── dashboard.html        # Painel de campanha em tempo real
├── data/
│   ├── logs/                     # Logs em runtime — git-ignored
│   └── targets.json              # Lista de alvos para o mailer
├── detection/
│   ├── modules/
│   │   ├── domain_check.py       # URL, subdomínios, palavras-chave
│   │   ├── whois_check.py        # Idade e registar do domínio
│   │   ├── dns_check.py          # Registos A, MX, NS
│   │   ├── tls_check.py          # Certificado TLS/SSL
│   │   ├── headers_check.py      # Cabeçalhos HTTP de segurança
│   │   ├── html_check.py         # Formulários, brand spoofing, iframes
│   │   ├── virustotal_check.py   # Comparação com VirusTotal (opcional)
│   │   ├── safebrowsing_check.py # Comparação com Google Safe Browsing (opcional)
│   │   └── utils.py              # Funções partilhadas
│   ├── reports/                  # Relatórios JSON — git-ignored
│   └── scanner.py                # CLI principal do scanner
├── research/
│   └── pesquisa-casos-reais.md   # 4 casos reais documentados
├── ARCHITECTURE.md
├── CONTEXT.md
├── requirements.txt
└── README.md
```

---

## Instalação

Requer Python 3.10+.

```powershell
pip install -r requirements.txt
```

---

## Módulo attack — execução

### Opção A — Demo com dados sintéticos

Gera um cenário realista com 10 funcionários fictícios da "Empresa X" (70% click rate, 40% capture rate, bot detection, dispositivo partilhado) e arranca a app:

```powershell
cd attack
python generate_demo_data.py
python app.py
```

Abre `http://localhost:5000/dashboard` para ver o painel. Corre o relatório forense:

```powershell
python forensics.py
```

### Opção B — Campanha real com emails

Requer ngrok e uma conta Gmail com App Password.

#### 1. Instalar e configurar o ngrok

1. Cria conta em https://ngrok.com (grátis)
2. Descarrega o `ngrok.exe` e coloca em `C:\ngrok\`
3. Copia o authtoken em https://dashboard.ngrok.com/get-started/your-authtoken
4. Configura o token (uma única vez):

```powershell
C:\ngrok\ngrok.exe config add-authtoken SEU_TOKEN_AQUI
```

#### 2. Criar App Password no Gmail

O Gmail bloqueia SMTP com a password normal. É necessária uma App Password:

1. Vai a https://myaccount.google.com/apppasswords
   (requer Verificação em dois passos ativa em https://myaccount.google.com/security)
2. Cria uma App Password com o nome `phishing-segred`
3. Google gera uma password de 16 caracteres — guarda-a

#### 3. Arrancar a app e o túnel

**Terminal 1** — servidor Flask:
```powershell
cd attack
python app.py
```

**Terminal 2** — túnel ngrok:
```powershell
C:\ngrok\ngrok.exe http 5000
```

Copia a URL pública gerada, ex: `https://abc123.ngrok-free.app`

> Nota: a URL muda a cada reinício do ngrok. Se precisares de reenviar emails, usa a nova URL.

#### 4. Editar os alvos

Edita `data/targets.json` com os emails reais a usar como alvos:

```json
[
  { "name": "Nome Pessoa", "email": "email@exemplo.com" }
]
```

#### 5. Enviar a campanha

```powershell
cd attack
$env:SMTP_PASSWORD = "app-password-sem-espacos"
python mailer.py --smtp smtp.gmail.com --port 587 --user teu@gmail.com --server https://abc123.ngrok-free.app --targets ../data/targets.json
```

O mailer regista a campanha em `data/logs/campaign.json` e imprime o estado de cada envio.

#### 6. Monitorizar

- Dashboard ao vivo: `http://localhost:5000/dashboard`
- Relatório forense após a campanha: `python forensics.py`

> **Importante:** antes de iniciar uma campanha real, apaga os logs de campanhas anteriores para não misturar dados:
> ```powershell
> Remove-Item data/logs/*.json
> ```

---

## Módulo detection — execução

```powershell
cd detection
python scanner.py "https://exemplo.com"
```

O scanner corre 6 módulos heurísticos, agrega o score (máximo entre módulos), imprime resultado colorido e guarda JSON em `reports/scan_*.json`.

**Vereditos:** ≤30 = SEGURO · 31–60 = SUSPEITO · >60 = PHISHING

### Comparação com VirusTotal (opcional)

```powershell
$env:VT_API_KEY = "chave-virustotal"
python scanner.py "https://exemplo.com"
```

Chave gratuita disponível em https://www.virustotal.com/ (perfil → API Key). Limite: 4 pedidos/min, 500/dia.

### Comparação com Google Safe Browsing (opcional)

```powershell
$env:SAFE_BROWSING_KEY = "chave-google"
python scanner.py "https://exemplo.com"
```

Chave gratuita via Google Cloud Console → APIs & Services → Safe Browsing API.

---

## Atualizar o repositório Git

```powershell
# Ver o que mudou
git status

# Adicionar ficheiros alterados (especificar ficheiros em vez de "git add .")
git add ficheiro1.py ficheiro2.html

# Criar commit
git commit -m "Descrição da alteração"

# Enviar para o GitHub
git push
```

**Notas:**
- `data/logs/` e `detection/reports/` são git-ignored — os logs nunca entram no repositório.
- Se o push falhar por divergência remota: `git pull` primeiro, resolve conflitos se existirem, depois `git push`.
- Para clonar noutro PC: `git clone https://github.com/DM1205/srs-phishing-sim.git`

---

## Aviso legal e ético

Este projeto destina-se **exclusivamente** a fins educativos em ambiente de laboratório controlado. Não conduzir campanhas em pessoas sem consentimento explícito. O uso indevido pode violar a Lei n.º 109/2009 (Cybercrime) e o RGPD.
