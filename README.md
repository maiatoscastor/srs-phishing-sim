# Phishing Simulation & Detection

University project for the **Network and Systems Security** course.

**Authors:**
- Diogo Sá (31378)
- Diogo Monteiro (32428)

---

## Project Description

This project implements a controlled phishing simulation and detection system for educational purposes. The simulation component replicates common phishing attack techniques in an isolated environment, while the detection component analyses URLs, emails, and network traffic to identify phishing indicators using heuristic and DNS-based methods.

The goal is to understand how phishing attacks are structured and how defensive tools can detect and mitigate them.

---

## Folder Structure

```
phishing-SEGRED/
├── attack/                 # Phishing simulation scripts
│   └── templates/          # HTML email and page templates used in the simulation
├── detection/              # Detection and analysis scripts
├── data/
│   ├── logs/               # Runtime logs (git-ignored, kept via .gitkeep)
│   └── reports/            # Generated analysis reports (git-ignored, kept via .gitkeep)
├── docs/                   # Project documentation and report assets
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

---

## Installation

Ensure you have Python 3.8+ installed, then install all dependencies:

```bash
pip install -r requirements.txt
```

---

## How to Run

> To be filled in as modules are developed.

---

## Disclaimer

> **This project is strictly for educational purposes.**
> All simulations are performed in an isolated virtual machine environment with no connection to real users or external networks. No actual phishing attacks are conducted. The techniques demonstrated here are studied solely to understand attacker methodologies and improve defensive capabilities.
> Misuse of these tools outside of the designated isolated environment is strictly prohibited and may violate applicable laws.
