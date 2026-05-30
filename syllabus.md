# SDV M2 — Red Team Advanced 2026

## Formation Pentet Avancé

**Dates :** 1—4 Juin 2026 (28 heures)
**Organisme :** COMCYBER / ANSSI / OTAN
**Référentiel :** MITRE ATT&CK Enterprise Matrix

---

## Objectif du cours

Ce cours vise à faire passer un cap technique aux participants en matière de tests d'intrusion, en approfondissant les méthodes, techniques et outils utilisés dans des contextes professionnels avancés. Chaque module est structuré autour du référentiel MITRE ATT&CK, standard universel utilisé par l'armée française (COMCYBER), l'ANSSI et l'OTAN.

### Compétences visées

- Concevoir et conduire un test d'intrusion avancé dans différents environnements (Web, Réseau, Active Directory, Mobile)
- Utiliser et combiner des outils d'attaque avancés de manière efficiente
- Adapter les techniques d'exploitation aux contextes spécifiques rencontrés
- Élaborer un rapport de pentest structuré, professionnel et adapté à l'audience (technique et décisionnelle)
- Intégrer les principes d'éthique et de conformité légale dans la réalisation d'un pentest

### Format pédagogique

> Démo live → TP guidé pas à pas → Correction collective → Mise en situation autonome

Chaque faille exploitée est taggée `TXXXX` selon MITRE ATT&CK. En fin de formation (J4), chaque apprenant produit une heat map ATT&CK complète servant de base au rapport de pentest.

---

## Programme détaillé

### Jour 1 — Environnement Web (01/06)

| Heure | Module | Durée |
|-------|--------|-------|
| 09:30—11:00 | M1 — MITRE ATT&CK : Le cadre universel | 1h30 |
| 11:15—12:30 | M2 — Rappels HTTP & Injections avancées | 1h15 |
| 13:30—14:30 | M3 — Authentification & Logique métier | 1h00 |
| 14:45—16:15 | M4 — Exploitation combinée & Pivoting | 1h30 |
| 16:15—17:00 | M5 — Scénario pratique autonome | 0h45 |

**Thèmes :** MITRE ATT&CK, SQLi, NoSQLi, SSTI, Command Injection, XXE, JWT, 2FA, Race Conditions, XSS, CSRF, Webshell, Reverse Shell, Pivoting

### Jour 2 — Infrastructure & Active Directory (02/06)

| Heure | Module | Durée |
|-------|--------|-------|
| 09:30—11:00 | M6 — Reconnaissance & Scanning réseau avancé | 1h30 |
| 11:15—12:30 | M7 — Attaques Active Directory | 1h15 |
| 13:30—14:30 | M8 — Élévation de privilèges & Lateral Movement | 1h00 |
| 14:45—16:15 | M9 — Attaques avancées AD (Kerberos, ACL) | 1h30 |
| 16:15—17:00 | M10 — Scénario AD autonome | 0h45 |

**Thèmes :** Nmap, BloodHound, Responder, Kerberoasting, AS-REP Roasting, ACL Abuse, DCSync, Pass-the-Hash, Pass-the-Ticket

### Jour 3 — Mobile & Techniques transverses (03/06)

| Heure | Module | Durée |
|-------|--------|-------|
| 09:30—11:00 | M11 — Introduction au pentest mobile | 1h30 |
| 11:15—12:30 | M12 — Reverse engineering & Analyse dynamique | 1h15 |
| 13:30—14:30 | M13 — Évasion, Persistance & Obfuscation | 1h00 |
| 14:45—16:15 | M14 — Synthèse & CTF encadré | 1h30 |
| 16:15—17:00 | M15 — Débrief CTF & Corrections | 0h45 |

**Thèmes :** Android APK analysis, Objection, Frida, Burp Mobile, Obfuscation, Anti-VM, Persistence mechanisms

### Jour 4 — Synthèse & Restitution (04/06)

| Heure | Module | Durée |
|-------|--------|-------|
| 09:30—11:00 | M16 — Structuration du rapport de pentest | 1h30 |
| 11:15—12:30 | M17 — Atelier rédactionnel sur cas d'étude | 1h15 |
| 13:30—14:30 | M18 — Heat map ATT&CK & Analyse des gaps | 1h00 |
| 14:45—16:15 | M19 — Restitution orale simulée (client fictif) | 1h30 |
| 16:15—17:00 | M20 — Débrief collectif & Évaluation des acquis | 0h45 |

**Thèmes :** Structure de rapport exécutif/technique, Heat map ATT&CK, Recommandations NIS2, Soutenance orale

---

## Conformité NIS2

La formation intègre les exigences de la directive **NIS2 (UE 2022/2555)** transposée par l'ANSSI :

| Article | Exigence | Application dans la formation |
|---------|----------|-------------------------------|
| Art. 21 | Mesures de gestion des risques | Threat modeling via ATT&CK, gap analysis, tests d'intrusion réguliers |
| Art. 23 | Notification des incidents (24h) | Qualification des incidents via techniques ATT&CK, reporting structuré |

---

## Prérequis techniques

### Environnement de travail

- **OS :** Linux (Kali Linux recommandé), macOS ou Windows + WSL2
- **RAM :** 8 Go minimum (16 Go recommandé)
- **Docker :** ≥ 20.10
- **Navigateur :** Firefox + Burp Suite (Community ou Pro)

### Outils à installer avant la formation

```bash
# Essentiels
sudo apt install -y nmap curl wget netcat-openbsd openssh-client
sudo apt install -y python3 python3-pip git

# Pentest web
pip3 install requests bs4 sqlmap
# Burp Suite : télécharger depuis https://portswigger.net/burp

# Active Directory (J2)
sudo apt install -y crackmapexec bloodhound impacket-scripts
pip3 install bloodhound pywerview

# Mobile (J3)
pip3 install objection frida-tools
sudo apt install -y apktool jadx

# Utilitaires
sudo apt install -y jq proxychains4 rlwrap
```

### Lab Docker (utilisé tous les jours)

```bash
cd lab
chmod +x setup.sh
./setup.sh start
# → http://localhost:8080
```

---

## Références

| Ressource | URL |
|-----------|-----|
| MITRE ATT&CK | https://attack.mitre.org/ |
| ATT&CK Navigator | https://github.com/mitre-attack/attack-navigator |
| OWASP Testing Guide | https://owasp.org/www-project-web-security-testing-guide/ |
| HackTricks | https://book.hacktricks.xyz/ |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| PortSwigger Web Security Academy | https://portswigger.net/web-security |
| ANSSI | https://cyber.gouv.fr/ |
| COMCYBER | https://www.defense.gouv.fr/comcyber |
| Directive NIS2 | https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32022L2555 |
