# SRS Phishing Simulation & Detection — Project Context

## Project Overview

University cybersecurity mini-project for the course **"Segurança de Redes e Sistemas"** (Network and Systems Security) at **IPVC/ESTG**.

- **Students:** Diogo Sá (31378) and Diogo Monteiro (32428)
- **Delivery date:** 18 June 2026
- **Full title:** *Simulação e Análise de Ataques de Phishing, do Ataque à Deteção*

---

## Project Goal

Build a complete phishing attack simulation and detection system — covering the full cycle from attack to detection.

---

## Environment

| Machine | IP | Role |
|---|---|---|
| Ubuntu Server | 192.168.64.6 | Runs the Flask phishing server. All server-side code runs here. |
| Kali Linux | 192.168.64.11 | Attacker machine. Runs the detection scanner, monitors traffic with Wireshark. |
| Ubuntu Desktop | 192.168.64.7 | Victim machine. Opens the browser and "falls" for the phishing page. |

- All 3 VMs are on the same network (UTM Shared Network on Apple Silicon Mac).
- **Development workflow:** code written locally on Mac via VS Code → pushed to GitHub → pulled on Ubuntu Server.
- **GitHub repo:** https://github.com/DM1205/srs-phishing-sim
- **Python venv on Ubuntu Server:** `~/srs-phishing-sim/venv`

---

## Folder Structure

```
srs-phishing-sim/
├── attack/
│   ├── server.py           # Flask server — DONE, working
│   ├── logger.py           # Credential capture + logging — DONE, working
│   └── templates/
│       └── login.html      # Fake Microsoft login page — DONE, working
├── detection/
│   ├── scanner.py          # Main scanner (integrates all modules) — TODO
│   ├── domain_analysis.py  # Domain analysis (typosquatting, age) — TODO
│   ├── ssl_analysis.py     # SSL certificate analysis — TODO
│   └── headers_analysis.py # HTTP headers analysis — TODO
├── data/
│   ├── logs/               # credentials.json saved here (gitignored)
│   └── reports/            # scanner reports saved here (gitignored)
├── docs/
│   └── relatorio.md        # technical report — TODO
├── CONTEXT.md              # this file
├── requirements.txt
└── .gitignore
```

---

## What Is Already Working

- Flask server serves a fake Microsoft login page at `http://192.168.64.6:5000`
- Victim (Ubuntu Desktop) opens the page in a browser
- Credentials submitted are captured and saved to `data/logs/credentials.json` with: `timestamp`, `ip`, `user_agent`, `page_id`, `username`, `password`
- Server redirects victim to real Microsoft login after capture
- Rich live dashboard in terminal shows captures in real time
- Git workflow is set up and working

---

## What Needs to Be Built Next

### Phase 2 — Detection scanner (Weeks 3–4)

Build the detection side in the `detection/` folder. The scanner analyses a given URL and determines if it is likely a phishing page. Three detection modules:

1. **`domain_analysis.py`** — checks for typosquatting (Levenshtein distance vs known brands), domain age via WHOIS, suspicious keywords in domain name.
2. **`ssl_analysis.py`** — checks if HTTPS is present, certificate issuer, certificate age, domain match.
3. **`headers_analysis.py`** — checks for missing security headers (`X-Frame-Options`, `Content-Security-Policy`, `HSTS`), suspicious redirects, server header info leakage.

`scanner.py` integrates all three modules and produces a final risk score + rich terminal report saved to `data/reports/`.

### Phase 3 — Presentation layer (Week 5)

- Add 2–3 slides worth of "how to protect yourself" content to the technical report (`docs/relatorio.md`)
- Final demo script: attacker sets up server → victim visits page → credentials captured in real time → scanner analyses the phishing URL → report generated

---

## Key Design Decisions

- **No web dashboard** — use `rich` library for terminal UI. Faster to build, more reliable, looks professional in a demo.
- **3 detection modules only** — domain, SSL, headers. Quality over quantity. VirusTotal/Google Safe Browsing API kept as optional bonus if time allows.
- Scope is realistic for 2 people in ~3 weeks without heavy AI assistance.
- The project covers both **offensive** (attack simulation) and **defensive** (detection) sides, which is what the professor expects.

---

## How to Run

```bash
cd ~/srs-phishing-sim
source venv/bin/activate
python3 attack/server.py
```

Then open `http://192.168.64.6:5000` on Ubuntu Desktop (victim machine).
