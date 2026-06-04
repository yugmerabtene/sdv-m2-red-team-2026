# Jour 1 — Environnement Web & Applications

> 02/06/2026 · 7 heures

## Objectifs

- Cartographie des attaques avec MITRE ATT&CK
- Injections avancées (SQL, NoSQL, SSTI)
- Vulnérabilités d'authentification et logique métier
- Exploitation, pivoting et scénario autonome

## Modules

| Heure | Module | Durée | Technique ATT&CK |
|-------|--------|-------|------------------|
| 09:30–10:30 | [M1 — MITRE ATT&CK & OSINT](m1-mitre-attack.md) | 1h00 | T1595, T1592, T1593 |
| 10:45–12:30 | [M2 — Injections avancées](m2-injections-avancees.md) | 1h45 | T1190, T1191 |
| 13:30–14:45 | [M3 — Authentification & Logique métier](m3-authentification-logique.md) | 1h15 | T1548, T1078 |
| 14:45–16:15 | [M4 — Exploitation & Pivoting](m4-exploitation-pivoting.md) | 1h30 | T1068, T1021 |
| 16:15–17:00 | [M5 — Scénario autonome](m5-scenario-autonome.md) | 0h45 | Synthèse |

## Prérequis (J1)

### Outils système de base

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git jq netcat-openbsd openssl
sudo apt install -y dnsutils whois nmap
sudo apt install -y python3 python3-pip python3-venv
```

### Outils de fuzzing et découverte Web

```bash
sudo apt install -y ffuf gobuster dirsearch
# Alternative via Go
# go install github.com/ffuf/ffuf/v2@latest

# gau (Get All URLs) — depuis Go
go install github.com/lc/gau/v2/cmd/gau@latest
```

### Outils d'injection

```bash
# SQLMap
sudo apt install -y sqlmap
# Alternative : git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# NoSQLMap
git clone https://github.com/codingo/NoSQLMap.git /opt/nosqlmap
cd /opt/nosqlmap && pip3 install -r requirements.txt

# tplmap (SSTI)
git clone https://github.com/epinna/tplmap.git /opt/tplmap
cd /opt/tplmap && pip3 install -r requirements.txt
```

### Outils JWT

```bash
# jwt_tool
git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool
cd /opt/jwt_tool && pip3 install -r requirements.txt

# PyJWT
pip3 install pyjwt requests
```

### Burp Suite

```bash
sudo apt install -y burpsuite
# Extensions Burp recommandées :
# - Turbo Intruder
# - Active Scan++
# - Autorize
# - Hackvertor
# - Wappalyzer (extension navigateur)
```

### Outils d'exploitation et pivoting

```bash
# Amass
sudo apt install -y amass
# Alternative : go install -v github.com/owasp-amass/amass/v4/...@master

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# WhatWeb
sudo apt install -y whatweb

# BeEF
git clone https://github.com/beefproject/beef.git /opt/beef
cd /opt/beef && ./install

# Weevely
git clone https://github.com/epinna/weevely3.git /opt/weevely
cd /opt/weevely && pip3 install -r requirements.txt

# Chisel
wget -O /tmp/chisel.gz https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip /tmp/chisel.gz && chmod +x /tmp/chisel && sudo mv /tmp/chisel /usr/local/bin/

# Metasploit Framework
sudo apt install -y metasploit-framework

# Proxy chains
sudo apt install -y proxychains4

# rlwrap, ncat, socat
sudo apt install -y rlwrap ncat socat

# net-tools (ifconfig, route, arp, netstat)
sudo apt install -y net-tools
```

### Shodan

```bash
pip3 install shodan
shodan init <VOTRE_CLE_API>
```

### ATT&CK Navigator (optionnel, pour M1)

```bash
git clone https://github.com/mitre-attack/attack-navigator.git /opt/attack-navigator
cd /opt/attack-navigor/nav && npm install && npm run build
# Ou via Docker :
# docker run -p 8080:80 mitre/attack-navigator
```

### Python — bibliothèques

```bash
pip3 install requests beautifulsoup4 colorama
```

### Navigateurs — extensions recommandées

- **FoxyProxy** — basculer rapidement de proxy
- **Wappalyzer** — identifier les technologies Web
- **HackBar** — faciliter les injections manuelles

## Ressources

- **Cible EcoVault** : `http://localhost:8080`
- **Réseau interne** : `10.0.0.0/24`
- **Wordlists** : `/usr/share/wordlists/` (dirb, seclists si installé)
