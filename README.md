# Simulação e Deteção de Phishing

Projeto universitário da disciplina **Segurança de Redes e Sistemas (SEGRED)**.

**Autores:** Diogo Sá (31378) · Diogo Monteiro (32428)

---

## Descrição

Sistema de simulação e deteção de phishing para fins educativos. O módulo **attack** replica uma página de login Microsoft 365, regista metadados (sem passwords) e apresenta uma página de consciencialização. O módulo **detection** está planeado para análise de URLs, SSL, cabeçalhos HTTP e estrutura HTML.

---

## Estrutura

```
srs-phishing-sim/
├── attack/
│   ├── app.py              # Servidor Flask
│   ├── logger.py           # Persistência em JSON
│   └── templates/
│       ├── login.html
│       └── warning.html
├── data/
│   ├── logs/               # captures.json (gerado em runtime)
│   └── reports/            # Relatórios de deteção (futuro)
├── ARCHITECTURE.md
├── requirements.txt
└── README.md
```

---

## Instalação

Requer Python 3.8+.

```bash
pip install -r requirements.txt
```

---

## Execução

```bash
cd attack
python app.py
```

Abrir **http://127.0.0.1:5000**. Após submissão do formulário, o utilizador é redirecionado para `/warning`. Os metadados ficam em `data/logs/captures.json`.

### Módulo detection

```bash
cd detection
python scanner.py https://exemplo.com/login
```

Relatórios JSON gerados em `detection/reports/`.

#### Comparação com VirusTotal (opcional)

O scanner compara o veredito heurístico com o VirusTotal, mas só se a variável de ambiente `VT_API_KEY` estiver definida. Sem chave, o scanner funciona normalmente e mostra "Indisponível: VT_API_KEY não configurada".

1. Criar conta gratuita em https://www.virustotal.com/ e copiar a API key (perfil → API Key).
2. Definir a variável de ambiente antes de correr o scanner:

```powershell
$env:VT_API_KEY = "a_tua_chave_aqui"
python scanner.py https://exemplo.com/login
```

A versão gratuita tem limite de 4 pedidos/minuto e 500/dia — suficiente para testes pontuais.

| Módulo     | Estado      | Função                                              |
|------------|-------------|-----------------------------------------------------|
| **attack** | Funcional   | Simulação, registo de metadados, página de aviso    |
| **detection** | Funcional (base) | Análise heurística de URLs (`scanner.py`) |

Detalhes técnicos em [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Atualizar o repositório Git

Na pasta `srs-phishing-sim` (raiz do repositório clonado):

```bash
# 1. Ver o que mudou
git status

# 2. Adicionar ficheiros (novos e alterados)
git add .

# 3. Criar commit com mensagem descritiva
git commit -m "Refatorar módulo attack: app.py, warning, documentação"

# 4. Enviar para o GitHub
git push origin main
```

**Notas:**

- Ficheiros em `data/logs/` e `data/reports/` (excepto `.gitkeep`) não entram no Git — estão no `.gitignore`.
- Se o `git push` falhar por alterações remotas, primeiro: `git pull origin main`, resolve conflitos se existirem, depois volta a fazer `git push`.
- Primeira vez neste PC: `git clone https://github.com/DM1205/srs-phishing-sim.git`

---

## Aviso legal e ético

Este projeto destina-se **exclusivamente** a fins educativos em ambiente isolado (VM ou laboratório). Não conduzir campanhas reais nem expor o servidor à Internet pública. O uso indevido pode violar a legislação aplicável (Lei n.º 109/2009, RGPD).
