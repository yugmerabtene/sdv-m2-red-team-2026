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

**Thèmes :** Nmap avancé (NSE, évasion), Masscan, Rustscan, énumération SMB/SNMP/DNS/LDAP, BloodHound, Responder, CrackMapExec, Impacket, Mimikatz, Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, DCSync, Kerberoasting, AS-REP Roasting, Golden/Silver/Diamond Ticket, ACL Abuse, ADCS (ESC1/ESC8), Skeleton Key, DCShadow, Trust Attacks, SIDHistory, Kerberos Delegation

### Détail des modules J2

#### M6 — Reconnaissance & Scanning réseau avancé (T1595, T1046)
- Nmap avancé : types de scan (TCP SYN, Connect, UDP, NULL, FIN, Xmas), timing, fragmentation, OS detection, NSE scripts, évasion IDS
- Masscan : scan ultra-rapide, comparaison Nmap
- Rustscan : scan moderne avec intégration Nmap
- Énumération de services : SMB (smbclient, enum4linux, CME), SNMP (snmpwalk, onesixtyone), DNS (dig, dnsrecon, dnsenum, zone transfer), LDAP (ldapsearch, ldapdomaindump), NFS
- OSINT réseau : Shodan, Censys, Certificate Transparency (crt.sh)
- Énumération Web : ffuf, Gobuster, wfuzz

#### M7 — Attaques Active Directory (T1087, T1557)
- Concepts AD : domaine, forêt, DC, Kerberos, LDAP, SMB, NTLM
- Énumération LDAP : ldapsearch, windapsearch, ldapdomaindump
- BloodHound : installation Neo4j, collecte SharpHound/BloodHound.py, requêtes Cypher (DCSync, GenericAll, WriteDacl), analyses de chemins
- Responder : empoisonnement LLMNR/NBT-NS/MDNS/WPAD, capture hashs NTLMv2
- CrackMapExec : modules SMB/LDAP/MSSQL/WinRM, énumération, exécution, SAM dump
- Impacket : psexec, wmiexec, smbexec, secretsdump, GetADUsers, GetNPUsers

#### M8 — Élévation & Lateral Movement (T1003, T1550, T1558)
- Credential Dumping : Mimikatz (sekurlsa, lsadump), LaZagne, ProcDump + offline
- Pass-the-Hash : crackmapexec -H, impacket-psexec -hashes, xfreerdp /pth
- Pass-the-Ticket : Mimikatz kerberos::ptt, Rubeus ptt, conversion kirbi/ccache
- Overpass-the-Hash : Rubeus asktgt, impacket getTGT
- Mouvement latéral : PsExec, WMI, WinRM (evil-winrm), Scheduled Tasks
- DCSync : secretsdump -just-dc, Mimikatz lsadump::dcsync
- Kerberoasting : impacket-GetUserSPNs, Rubeus kerberoast, hashcat cracking
- AS-REP Roasting : impacket-GetNPUsers, Rubeus asreproast

#### M9 — Attaques avancées AD (T1098, T1558, T1484)
- ACL Abuse : GenericAll/WriteOwner/WriteDACL/ForceChangePassword, PowerView, dacledit.py
- AdminSDHolder : backdoor persistante via SDProp
- Golden Ticket : forge TGT avec hash KRBTGT (Mimikatz, ticketer.py)
- Silver Ticket : forge TGS pour service spécifique
- Diamond Ticket : modification TGT existant (Rubeus)
- Skeleton Key : backdoor LSASS sur DC
- DCShadow : usurpation DC pour modification AD
- Trust Attacks : SIDHistory injection, inter-forest crossing
- ADCS Abuse : ESC1 (certificat template), ESC8 (NTLM relay to ADCS Web Enrollment)
- Kerberos Delegation : Unconstrained/Constrained/RBCD

#### M10 — Scénario AD autonome
- Contexte CorpShadow, boîte noire, 60 min
- 6 flags : BloodHound → Responder → secretsdump → PtH → Kerberoasting → DCSync+Golden Ticket
- Documentation ATT&CK complète

### Jour 3 — Mobile & Techniques transverses (03/06)

| Heure | Module | Durée |
|-------|--------|-------|
| 09:30—11:00 | M11 — Introduction au pentest mobile | 1h30 |
| 11:15—12:30 | M12 — Reverse engineering & Analyse dynamique | 1h15 |
| 13:30—14:30 | M13 — Évasion, Persistance & Obfuscation | 1h00 |
| 14:45—16:15 | M14 — Synthèse & CTF encadré | 1h30 |
| 16:15—17:00 | M15 — Débrief CTF & Corrections | 0h45 |

**Thèmes :** APK analysis, Jadx, Smali, Frida, Objection, Burp Mobile, SSL Pinning bypass, AMSI bypass, obfuscation PowerShell/payload, persistance WMI/Scheduled Tasks, rootkit detection, CTF mobile

#### M11 — Introduction au pentest mobile (T1426)
- Architecture APK, AndroidManifest, classes.dex, sandboxing
- Setup lab : Android Studio + AVD, adb, apktool, jadx, dex2jar
- Burp Suite proxy pour mobile, certificat CA, interception HTTPS
- Analyse statique : décompilation, strings, secrets hardcodés

#### M12 — Reverse engineering & Analyse dynamique (T1407, T1406)
- Smali : lecture et modification de bytecode Dalvik
- Recompilation APK modifiée (apktool b → signer → installer)
- Frida : hooking Java, bypass SSL Pinning, root detection, emulator detection
- Objection : analyse runtime automatisée
- Analyse stockage local : SharedPreferences, SQLite, fichiers internes

#### M13 — Évasion, Persistance & Obfuscation (T1562, T1027, TA0003)
- AV/Defender bypass : registre, GPO, exclusions dossiers
- AMSI bypass PowerShell, AppLocker bypass, sandbox detection
- Obfuscation payload : XOR, AES, shikata_ga_nai, ScareCrow, Donut
- Persistance : RunOnce, Scheduled Tasks, WMI Event Subscription, DLL/COM Hijacking
- Rootkits (aperçu), entropie et détection

#### M14 — Synthèse & CTF encadré
- Scénario : application mobile "PayVault" + backend API
- 5 flags : credentials hardcodés → SSL Pinning → IDOR → SQLi → APK patching
- 90 minutes d'autonomie avec indices disponibles

#### M15 — Débrief CTF & Corrections
- Solution détaillée des 5 flags avec commandes exactes
- Remédiation pour chaque vulnérabilité
- Tableau synthèse ATT&CK du CTF

### Jour 4 — Synthèse & Restitution (04/06)

| Heure | Module | Durée |
|-------|--------|-------|
| 09:30—11:00 | M16 — Structuration du rapport de pentest | 1h30 |
| 11:15—12:30 | M17 — Atelier rédactionnel sur cas d'étude | 1h15 |
| 13:30—14:30 | M18 — Heat map ATT&CK & Analyse des gaps | 1h00 |
| 14:45—16:15 | M19 — Restitution orale simulée (client fictif) | 1h30 |
| 16:15—17:00 | M20 — Débrief collectif & Évaluation des acquis | 0h45 |

**Thèmes :** Rapport exécutif/technique, CVSS, DREAD, heat map ATT&CK, gap analysis, restitution orale, NIS2, certifications

#### M16 — Structuration du rapport de pentest
- Normes PTES, OSSTMM, CREST
- Rapport exécutif (COMEX) vs rapport technique (IT)
- Fiche par vulnérabilité : CVSS, PoC, impact, remédiation, TXXXX
- Outils : SysReptor, Dradis, LaTeX, Pandoc

#### M17 — Atelier rédactionnel sur cas d'étude
- Cas SOGETEL fourni : outputs bruts (nmap, sqlmap, BloodHound, secretsdump)
- Rédiger rapport exécutif (1 page) + 3 fiches techniques + heat map
- Grille d'évaluation sur 50 points
- Correction détaillée

#### M18 — Heat map ATT&CK & Gap Analysis
- Construction de heat map : code couleur (rouge/orange/gris)
- Gap analysis : identification des angles morts
- Mapping NIS2 ↔ ATT&CK (art. 21, art. 23)
- Outils : ATT&CK Navigator, DeTT&CT, VECTR

#### M19 — Restitution orale simulée
- Techniques de communication COMEX
- Vulgarisation technique, storytelling (kill chain)
- Gestion des questions difficiles
- Mise en situation : présentation 10 min + feedback

#### M20 — Débrief collectif & Évaluation
- Quiz 20 questions (QCM) couvrant les 4 jours
- Checklist des compétences acquises
- Certifications recommandées : OSCP, CRTP, CRTE, OSEP
- Ressources pour continuer : HTB, TryHackMe, GOAD, Atomic Red Team

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
