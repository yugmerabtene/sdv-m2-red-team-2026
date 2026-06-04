# Module 6 — Reconnaissance & Scanning réseau avancé

> **Durée :** 1h30 (09:30—11:00)
> **Référentiel :** MITRE ATT&CK — T1595 (Active Scanning), T1049 (Network Share Discovery), T1046 (Network Service Discovery), T1590 (Gather Victim Network Information), T1592 (Gather Victim Host Information), T1087 (Account Discovery)
> **Conformité :** NIS2 — Art. 21 (Cartographie des actifs, gestion des risques)
> **Prérequis :** VM Kali Linux, réseau local /24, cibles Docker

---

## Table des matières

1. [Introduction au scanning réseau](#1-introduction-au-scanning-réseau)
2. [Nmap avancé](#2-nmap-avancé)
3. [Masscan — Scan ultra-rapide](#3-masscan--scan-ultra-rapide)
4. [Rustscan — Scan moderne](#4-rustscan--scan-moderne)
5. [Énumération de services](#5-énumération-de-services)
6. [OSINT réseau](#6-osint-réseau)
7. [Énumération Web avancée](#7-énumération-web-avancée)
8. [Script d'automatisation de reconnaissance](#8-script-dautomatisation-de-reconnaissance)
9. [TP Synthèse](#9-tp-synthèse)

---

## 1. Introduction au scanning réseau

### 1.1 Objectifs de la phase de reconnaissance

La phase de reconnaissance est la **première étape** de toute opération Red Team. Elle répond à trois objectifs fondamentaux :

| Objectif | Description | Techniques MITRE associées |
|----------|-------------|---------------------------|
| **Discovery** | Découverte d'hôtes actifs sur le périmètre cible | T1595 (Active Scanning) |
| **Fingerprinting** | Identification des OS, services, versions | T1592 (Gather Victim Host Info) |
| **Énumération** | Collecte d'informations détaillées sur les services | T1046, T1049, T1590, T1087 |

Ces trois phases sont **itératives** : chaque découverte alimente la suivante et affine le périmètre d'attaque.

```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE DE RECONNAISSANCE                    │
├──────────────┬──────────────────┬────────────────────────────┤
│  Discovery   │  Fingerprinting  │      Énumération           │
│  (hôtes)     │  (OS/services)   │      (détails)             │
├──────────────┼──────────────────┼────────────────────────────┤
│  Ping sweep  │  Banner grab     │  Partage SMB              │
│  Port scan   │  OS detection    │  Utilisateurs LDAP        │
│  DNS lookup  │  Version detection│  Enregistrements DNS      │
│              │  NSE scripts     │  OID SNMP                 │
└──────────────┴──────────────────┴────────────────────────────┘
                              │
                              ▼
                ┌─────────────────────────┐
                │  Carte réseau complète  │
                │  Vecteurs d'attaque     │
                │  Priorisation           │
                └─────────────────────────┘
```

### 1.2 NIS2 — Cartographie des actifs (Article 21)

La directive **NIS2 (UE 2022/2555)** impose aux entités essentielles et importantes de mettre en œuvre des mesures de gestion des risques. L'article 21 stipule explicitement :

> *"Les États membres veillent à ce que les entités essentielles et importantes prennent des mesures techniques, opérationnelles et organisationnelles appropriées et proportionnées pour gérer les risques pesant sur la sécurité des réseaux et des systèmes d'information."*

**Parmi ces mesures :**
- **Cartographie des actifs** (inventaire matériel et logiciel)
- **Tests d'intrusion réguliers** (au moins annuels)
- **Détection et réponse aux incidents**

**Lien avec la reconnaissance offensive :**
- La cartographie des actifs côté défense correspond au **scan réseau** côté attaque
- Connaître ses assets = savoir ce qu'il faut protéger
- L'attaquant cherche à établir cette même cartographie pour identifier les failles

**Dans le cadre du pentest :**
- Chaque asset découvert doit être documenté
- La heat map ATT&CK finale servira à démontrer les gaps de couverture
- Le rapport de pentest (J4) intégrera ces éléments pour prouver la conformité ou non à la NIS2

### 1.3 MITRE ATT&CK — T1595 (Active Scanning)

La technique **T1595** est la technique racine pour toute la phase de scanning. Elle se décline en sous-techniques :

| ID | Nom | Description |
|----|-----|-------------|
| T1595.001 | Scanning IP Blocks | Scan de plages IP pour trouver des hôtes actifs |
| T1595.002 | Vulnerability Scanning | Scan de vulnérabilités connues |
| T1595.003 | Wordlist Scanning | Brute-force de chemins/dossiers DNS |

**Indicateurs de compromission (IOA) côté défense :**
- Requêtes SYN massives vers plusieurs ports
- Patterns de scan Nmap identifiables (User-Agent, timing)
- Requêtes DNS pour zone transfer
- Connexions vers des ports inhabituels

**Évasion IDS/IPS :**
- Ralentissement du scan (T1, T0)
- Fragmentation des paquets
- Utilisation de decoy (adresses leurres)
- Scan via proxy/circuits anonymisés

---

## 2. Nmap avancé

### 2.1 Installation et configuration

Nmap est préinstallé sur Kali Linux. Pour les autres distributions :

```bash
# Installation sur Debian/Ubuntu/Kali
# sudo = exécution en super-utilisateur (root), nécessaire pour installer des paquets système
# apt update = rafraîchit la liste des paquets disponibles depuis les dépôts
sudo apt update
# apt install -y nmap = installe le paquet nmap, -y répond "oui" automatiquement
sudo apt install -y nmap

# Vérification de l'installation
# nmap --version = affiche la version installée pour confirmer que l'installation a réussi
nmap --version

# Sur macOS (via Homebrew)
# brew install = commande d'installation du gestionnaire de paquets Homebrew pour macOS
brew install nmap

# Compilation depuis les sources (version de développement)
# git clone = télécharge le dépôt Git officiel de Nmap pour obtenir la dernière version
git clone https://github.com/nmap/nmap.git
# cd = se déplacer dans le dossier cloné
cd nmap
# ./configure = script d'auto-détection qui vérifie les dépendances et prépare la compilation
./configure
# make = compile le code source en binaires exécutables
make
# sudo make install = copie les binaires compilés dans les répertoires système (/usr/local/bin, etc.)
sudo make install
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `sudo apt update` | Rafraîchit l'index local des paquets depuis les dépôts Debian |
| `sudo apt install -y nmap` | Installe le paquet `nmap` avec confirmation automatique (-y) |
| `nmap --version` | Affiche la version de Nmap installée (test de bon fonctionnement) |
| `brew install nmap` | Installe Nmap via Homebrew (gestionnaire de paquets macOS) |
| `git clone` | Télécharge le dépôt Git pour obtenir les sources à jour |
| `./configure` | Script qui analyse l'environnement et génère le Makefile de compilation |
| `make` | Compile le code source en binaires |
| `sudo make install` | Installe les binaires compilés dans les répertoires système |

**Vérification des scripts NSE disponibles :**

```bash
# Lister toutes les catégories de scripts
# ls -la = liste détaillée des fichiers (dont les scripts .nse)
# wc -l = compte le nombre de lignes, donc le nombre total de scripts installés
ls -la /usr/share/nmap/scripts/ | wc -l

# Compter les scripts par catégorie
# grep -r "categories" = recherche récursivement "categories" dans tous les fichiers .nse
# grep -oP '"([^"]+)"' = extrait uniquement les chaînes entre guillemets (les noms de catégories)
# sort | uniq -c = trie puis compte les occurrences uniques de chaque catégorie
# sort -rn = trie par ordre numérique décroissant (les plus nombreuses d'abord)
grep -r "categories" /usr/share/nmap/scripts/*.nse | grep -oP '"([^"]+)"' | sort | uniq -c | sort -rn

# Chercher un script par nom
# ls = liste les fichiers, grep -i smb = filtre pour ne garder que ceux contenant "smb" (insensible à la casse)
# Permet de trouver rapidement les scripts liés à un protocole (SMB ici)
ls /usr/share/nmap/scripts/ | grep -i smb

# Afficher les informations d'un script spécifique
# nmap --script-help = affiche la documentation, les arguments et l'usage d'un script NSE
nmap --script-help smb-enum-shares.nse
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `ls -la` | Liste détaillée des fichiers (permissions, taille, date) |
| `\| wc -l` | Compte le nombre total de scripts dans le dossier |
| `grep -r "categories" *.nse` | Cherche récursivement le mot "categories" dans tous les scripts NSE |
| `grep -oP '"([^"]+)"'` | Extrait le texte entre guillemets (les noms de catégories) |
| `sort \| uniq -c` | Trie puis compte combien de scripts appartiennent à chaque catégorie |
| `sort -rn` | Trie les catégories par nombre décroissant |
| `grep -i smb` | Filtre les fichiers contenant "smb" (insensible à la casse) |
| `nmap --script-help` | Affiche l'aide détaillée d'un script NSE : arguments, usage, description |

### 2.2 Types de scans

#### TCP SYN Scan (-sS) — Scan furtif (par défaut)

Le SYN scan envoie un paquet SYN, analyse la réponse, puis envoie un RST pour ne pas terminer la connexion.

```
Client → Serveur : SYN
Serveur → Client : SYN-ACK  (port ouvert)
Client → Serveur : RST     (fermeture sans handshake complet)
```

```bash
# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
# Cible : Sous-réseau du lab AD — toutes les IP ci-dessous sont à adapter
# Remplacer 192.168.1.x par 10.0.1.x (lab AD Docker) ou l'IP de votre lab

# SYN scan basique (root requis)
# -sS = TCP SYN scan, envoie un paquet SYN sans compléter le handshake (furtif)
# L'adresse IP 192.168.1.1 est la cible (passive en argument)
sudo nmap -sS 192.168.1.1

# SYN scan avec ports spécifiques
# -p 22,80,443,3306,3389 = liste des ports à scanner (SSH, HTTP, HTTPS, MySQL, RDP)
# On cible uniquement les ports d'intérêt pour gagner du temps
sudo nmap -sS -p 22,80,443,3306,3389 192.168.1.1

# SYN scan sur une plage de ports
# -p 1-10000 = plage personnalisée (du port 1 au port 10000)
# Plus large que les seuls ports courants, plus long mais plus exhaustif
sudo nmap -sS -p 1-10000 192.168.1.1

# SYN scan sur tous les ports (65 535 ports)
# -p- = raccourci pour la plage 1-65535 (tous les ports TCP possibles)
# Très long (plusieurs minutes), réservé aux cibles prioritaires
sudo nmap -sS -p- 192.168.1.1
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `sudo` | Requis car -sS utilise des raw sockets (privilèges root) |
| `-sS` | TCP SYN scan : envoie un SYN, analyse la réponse (SYN-ACK = ouvert, RST = fermé), puis envoie RST pour ne pas compléter le handshake |
| `-p 22,80,443,3306,3389` | Liste de ports spécifiques séparés par des virgules |
| `-p 1-10000` | Plage de ports avec notation début-fin |
| `-p-` | Raccourci pour tous les ports (1-65535) |
| `192.168.1.1` | Adresse IP de la cible à scanner |

**Avantages :** Rapide, moins detectable que Connect scan, ne complète pas le handshake TCP
**Inconvénients :** Nécessite les privilèges root

#### TCP Connect Scan (-sT) — Scan complet

Le Connect scan complète le handshake TCP à trois voies, puis envoie un RST pour fermer.

```bash
# Connect scan (ne nécessite PAS root)
# -sT = TCP Connect scan : complète le handshake TCP (SYN → SYN-ACK → ACK) puis envoie RST
# Plus lent et plus détectable que -sS car la connexion est complètement établie
# Avantage : ne nécessite pas les privilèges root
nmap -sT 192.168.1.1

# Connect scan sur ports communs
# -p = ports ciblés : FTP(21), SSH(22), Telnet(23), SMTP(25), HTTP(80), POP3(110), IMAP(143),
#       HTTPS(443), IMAPS(993), POP3S(995) — les services les plus courants
nmap -sT -p 21,22,23,25,80,110,143,443,993,995 192.168.1.1
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `-sT` | TCP Connect scan : complète le handshake TCP (connexion complète), ne nécessite pas root |
| `-p 21,22,23,...` | Sélection des ports les plus communs : FTP, SSH, Telnet, SMTP, HTTP, POP3, IMAP, etc. |
| `nmap` (sans sudo) | Fonctionne sans root car -sT utilise l'appel système connect() et non des raw sockets |

**Avantages :** Ne nécessite pas root, plus fiable dans certains environnements
**Inconvénients :** Plus lent, plus détectable (logs applicatifs complets)

#### UDP Scan (-sU)

Le scan UDP est plus lent car le protocole UDP n'a pas de mécanisme de connexion.

```bash
# Scan UDP des ports courants
# -sU = UDP scan : envoie des datagrammes UDP et attend une réponse
# Plus lent que TCP car UDP est sans connexion : il faut attendre le timeout pour confirmer un port fermé
sudo nmap -sU 192.168.1.1

# Scan UDP avec ports spécifiques
# Ports UDP courants : DNS(53), DHCP(67,68), NTP(123), SNMP(161,162), IKE(500), Syslog(514)
# Ces ports sont souvent négligés car plus lents à scanner, mais riches en informations
sudo nmap -sU -p 53,67,68,123,161,162,500,514 192.168.1.1

# Scan UDP rapide (top 100 ports)
# --top-ports 100 = ne scanner que les 100 ports UDP les plus fréquemment ouverts
# Compromis acceptable entre vitesse et couverture pour le scan UDP
sudo nmap -sU --top-ports 100 192.168.1.1
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `-sU` | UDP scan : envoie des datagrammes UDP — pas de réponse = ouvert/filtré, ICMP Unreachable = fermé, réponse UDP = ouvert |
| `-p 53,67,68,123,161,162,500,514` | Ports UDP typiques : DNS, DHCP, NTP, SNMP, IKE, Syslog |
| `--top-ports 100` | Limite le scan aux 100 ports UDP les plus statistiquement ouverts (gain de temps significatif) |
| `sudo` | Requis pour les raw sockets UDP |

**Comportement :**
- Pas de réponse → port ouvert ou filtré (aucun moyen de savoir)
- ICMP Port Unreachable → port fermé
- Réponse UDP → port ouvert

#### NULL, FIN, Xmas Scans — Scans furtifs

Ces scans envoient des paquets avec des flags TCP inhabituels pour contourner certaines règles de pare-feu.

```bash
# NULL scan : aucun flag TCP activé
# -sN = NULL scan : envoie un paquet TCP sans aucun flag (header vide)
# Un paquet sans flag est anormal (hors RFC), conçu pour contourner certains pare-feu
# Comportement RFC : port fermé → RST | port ouvert → pas de réponse
sudo nmap -sN 192.168.1.1

# FIN scan : seul le flag FIN est activé
# -sF = FIN scan : envoie un paquet avec uniquement le flag FIN (normalement utilisé pour fermer une connexion)
# Similaire au NULL scan dans son comportement face aux ports ouverts/fermés
sudo nmap -sF 192.168.1.1

# Xmas scan : les flags FIN, PSH et URG sont activés
# -sX = Xmas scan : active les flags FIN + PSH + URG, allumés comme un sapin de Noël ("Christmas tree")
# Les trois flags simultanés sont invalides, ce qui permet de tester la conformité RFC de la cible
sudo nmap -sX 192.168.1.1
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `-sN` | NULL scan : paquet TCP sans aucun flag activé — port fermé → RST, port ouvert → pas de réponse |
| `-sF` | FIN scan : seul le flag FIN activé — même comportement que NULL scan |
| `-sX` | Xmas scan : flags FIN + PSH + URG activés ("Christmas tree") — même comportement |
| **Limitation** | Ne fonctionne pas contre Windows : Windows envoie toujours un RST (paquet invalide), donc tous les ports apparaissent fermés |
| **Objectif** | Contourner les pare-feu qui ne filtrent que les paquets SYN standards |

**Comportement attendu (RFC 793) :**
- Port fermé → RST reçu (car le paquet est invalide)
- Port ouvert → pas de réponse (car le paquet est invalide, l'hôte ignore)

**Limitation :** Ne fonctionne pas contre Windows (toujours RST, donc tous les ports semblent fermés)

### 2.3 Options de timing (-T0 à -T5)

Nmap propose 6 profils de timing qui contrôlent la vitesse et l'agressivité du scan.

| Profil | Nom | Usage | Description |
|--------|-----|-------|-------------|
| -T0 | Paranoid | Évasion IDS | Très lent, un paquet à la fois, attente de 5 min entre les envois |
| -T1 | Sneaky | Évasion IDS | Lent, attente de 15 secondes entre les envois |
| -T2 | Polite | Usage général | Lent mais raisonnable, attente de 0.4s |
| -T3 | Normal | Par défaut | Équilibre vitesse/discrétion |
| -T4 | Aggressive | Réseau rapide | Suppose un bon réseau, accélère les timeouts |
| -T5 | Insane | Très rapide | Timeout très court, peut manquer des ports |

```bash
# Scan furtif contre un IDS
# -T0 = profil "Paranoid" : un paquet à la fois, attente de 5 min entre les envois
# Objectif : ne pas déclencher les alarmes IDS/IPS qui détectent les scans rapides
sudo nmap -sS -T0 192.168.1.1

# Scan équilibré (par défaut)
# -T3 = profil "Normal" : valeur par défaut, équilibre entre vitesse et discrétion
# 192.168.1.0/24 = notation CIDR pour scanner les 256 adresses du sous-réseau
sudo nmap -sS -T3 192.168.1.0/24

# Scan agressif sur réseau local
# -T4 = profil "Aggressive" : suppose un réseau rapide, timeouts réduits
# -p- = tous les ports (1-65535), combiné avec -T4 pour un scan complet rapide
sudo nmap -sS -T4 -p- 192.168.1.1

# Scan très agressif (peut perdre des résultats)
# -T5 = profil "Insane" : timeouts très courts (max-tries=1), peut manquer des ports
# Réservé aux réseaux très rapides, certains ports ouverts peuvent ne pas répondre à temps
sudo nmap -sS -T5 10.0.0.1
```

**Explication des options :**
| Option | Profil | Usage |
|--------|--------|-------|
| `-T0` | Paranoid | Évasion IDS — 1 paquet, 5 min d'attente entre envois |
| `-T3` | Normal | Valeur par défaut, équilibre vitesse/discrétion |
| `-T4` | Aggressive | Réseau rapide, timeouts réduits (max-tries=2) |
| `-T5` | Insane | Très rapide, timeouts très courts (max-tries=1), peut manquer des résultats |

**Détail des paramètres modifiés par -T :**

```bash
# Examiner les valeurs de timing par défaut
# --verbose = affiche les détails d'exécution (dont les paramètres de timing)
# 2>&1 = redirige la sortie d'erreur (stderr) vers la sortie standard (stdout)
# grep -i timing = filtre les lignes contenant "timing" (insensible à la casse)
nmap -T4 --verbose 192.168.1.1 2>&1 | grep -i timing

# Paramètres concrets :
# -T0 : min-rtt-timeout 100ms, max-rtt-timeout 300ms, initial-rtt-timeout 300ms
#        max-scan-delay 1000ms, max-tries 5
# -T4 : min-rtt-timeout 100ms, max-rtt-timeout 1250ms, initial-rtt-timeout 500ms
#        max-scan-delay 10ms, max-tries 2
# -T5 : min-rtt-timeout 50ms, max-rtt-timeout 300ms, initial-rtt-timeout 250ms
#        max-scan-delay 5ms, max-tries 1
```

**Explication des paramètres :**
| Paramètre | Signification | Effet |
|-----------|---------------|-------|
| `min-rtt-timeout` | Temps minimum d'attente d'une réponse | Évite les timeouts trop rapides |
| `max-rtt-timeout` | Temps maximum d'attente d'une réponse | Limite le temps perdu sur les hôtes silencieux |
| `initial-rtt-timeout` | Timeout initial avant adaptation | Nmap ajuste ce temps en fonction des réponses reçues |
| `max-scan-delay` | Délai max entre l'envoi de deux paquets | -T0 = 1000ms (très lent), -T5 = 5ms (très rapide) |
| `max-tries` | Nombre de retransmissions max en cas de perte | -T0 = 5 (fiable), -T5 = 1 (risque de faux négatifs) |

### 2.4 Fragmentation (-f)

La fragmentation divise les paquets en fragments plus petits pour contourner les pare-feu qui inspectent les paquets complets.

```bash
# Fragmentation par défaut (8 octets par fragment)
# -f = fragmente les paquets en morceaux de 8 octets (en-tête IP + données)
# Objectif : diviser le paquet TCP SYN pour qu'il traverse les pare-feu sans inspection complète
sudo nmap -sS -f 192.168.1.1

# Fragmentation avec taille personnalisée (16 octets)
# --mtu 16 = définit la taille maximale d'unité de transmission (Maximum Transmission Unit) à 16 octets
# Plus la valeur est petite, plus il y a de fragments, plus l'évasion est efficace
sudo nmap -sS --mtu 16 192.168.1.1

# Double fragmentation (encore plus petits fragments)
# -ff = double fragmentation : les fragments sont eux-mêmes fragmentés
# Rend le réassemblage encore plus difficile pour le pare-feu cible
sudo nmap -sS -ff 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-f` | Fragmente les paquets IP en fragments de 8 octets pour contourner l'inspection des pare-feu |
| `--mtu 16` | Définit la taille MTU (Maximum Transmission Unit) à 16 octets — plus de fragments plus petits |
| `-ff` | Double fragmentation : fragmente les fragments déjà fragmentés — rend le réassemblage difficile |
| **Principe** | Un paquet TCP SYN normal fait ~40-60 octets. En le fragmentant, on cache l'en-tête TCP au pare-feu qui doit réassembler pour inspecter la couche 4 |

**Mécanisme :**
- Un paquet TCP SYN normal fait 40-60 octets (en-tête IP 20 + TCP 20-40)
- Avec `-f`, il est divisé en fragments IP de 8 octets
- Le pare-feu doit réassembler le paquet pour inspecter la couche TCP
- Certains pare-feu ne réassemblent pas et laissent passer

### 2.5 OS Detection (-O) et Version Detection (-sV)

#### OS Detection (-O)

```bash
# Détection du système d'exploitation
# -O = active l'OS detection (TCP/IP stack fingerprinting)
# Envoie jusqu'à 16 sondes TCP/UDP/ICMP et compare les réponses à une base de ~3000 fingerprints
sudo nmap -O 192.168.1.1

# OS detection avec verbosité
# -v = mode verbose, affiche les étapes intermédiaires du fingerprinting
# Utile pour comprendre comment Nmap arrive à sa conclusion
sudo nmap -O -v 192.168.1.1

# OS detection agressive (plus de probes)
# --osscan-guess = force Nmap à faire une supposition même si le fingerprint est imparfait
# Affiche le degré de confiance et les OS possibles classés par probabilité
sudo nmap -O --osscan-guess 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-O` | Active l'OS detection via TCP/IP stack fingerprinting (ISN, TTL, window size, options TCP) |
| `-v` | Mode verbeux : affiche les probes envoyées et les réponses analysées |
| `--osscan-guess` | Force une estimation même avec un fingerprint partiel, affiche le degré de confiance |

**Comment ça marche (TCP/IP fingerprinting) :**
1. Nmap envoie jusqu'à 16 probes TCP/UDP/ICMP
2. Il analyse les réponses selon :
   - Initial Sequence Number (ISN) sampling
   - Options TCP supportées (window scale, timestamp, etc.)
   - Taille initiale de la fenêtre TCP
   - Valeur du TTL (Time To Live)
   - Comportement DF (Don't Fragment)
3. Il compare à une base de ~3000 fingerprints

```bash
# Afficher le degré de confiance avec --osscan-guess
# --osscan-guess = affiche les OS possibles avec leur pourcentage de confiance même si le match n'est pas parfait
sudo nmap -O --osscan-guess 192.168.1.1

# OS detection sur tout un sous-réseau
# 192.168.1.0/24 = scan des 256 adresses du réseau
# --exclude 192.168.1.1 = exclut une adresse spécifique (par exemple la passerelle ou la machine de l'attaquant)
sudo nmap -O 192.168.1.0/24 --exclude 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--osscan-guess` | Affiche les suppositions d'OS avec la confiance associée en pourcentage |
| `--exclude <ip>` | Exclut une adresse IP du scan (évite de scanner sa propre machine ou la passerelle) |
| `192.168.1.0/24` | Notation CIDR pour le sous-réseau : netmask 255.255.255.0, soit 256 adresses |

**Exemple de sortie :**

```
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 1 hop
```

#### Version Detection (-sV)

```bash
# Détection de versions des services
# -sV = version detection : interroge les services ouverts pour déterminer leur nom et version exacte
# N'envoie pas de sondes spécifiques (probes) selon le service détecté et analyse les bannières
nmap -sV 192.168.1.1

# Version detection avec intensité (0-9, défaut 7)
# --version-intensity 9 = niveau d'intensité maximum (0 = probes minimales, 9 = toutes les probes possibles)
# Plus l'intensité est élevée, plus la détection est fiable mais longue
nmap -sV --version-intensity 9 192.168.1.1

# Version detection sur tous les ports
# -p- = tous les ports (1-65535), combiné avec -sV pour identifier chaque service
# Attention : très long sur une cible avec beaucoup de ports ouverts
nmap -sV -p- 192.168.1.1

# Version detection avec banner grabbing
# --version-all = alias de --version-intensity 9, envoie toutes les sondes disponibles
nmap -sV --version-all 192.168.1.1

# Version detection légère (probes limitées)
# --version-light = alias de --version-intensity 2, probes limitées aux plus probables
# Plus rapide mais peut manquer des versions rares ou personnalisées
nmap -sV --version-light 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-sV` | Active la détection de versions : envoie des probes spécifiques et analyse les bannières |
| `--version-intensity N` | Niveau 0-9 : 0 = probes minimales, 7 = défaut, 9 = exhaustif |
| `--version-all` | Équivalent de `--version-intensity 9` (toutes les sondes) |
| `--version-light` | Équivalent de `--version-intensity 2` (sondes limitées, plus rapide) |
| `-p-` | Tous les ports TCP (1-65535) — combiné avec -sV pour tout identifier |

**Intensité de version detection :**

| Intensité | Description |
|-----------|-------------|
| 0 | Uniquement les sondes les plus probables |
| 2-3 | Équilibre (défaut dans --version-light) |
| 7 | Par défaut, bonne couverture |
| 9 | Exhaustif, long mais précis |

```bash
# Combinaison OS + version
# -sV = version detection, -O = OS detection
# Combine les deux techniques de fingerprinting en un seul scan
sudo nmap -sV -O 192.168.1.1

# Combinaison avec détection de script
# -sC = active les scripts NSE par défaut (équivalent de --script default)
# Combine donc : fingerprinting OS + versions + scripts d'énumération standard
sudo nmap -sV -O -sC 192.168.1.1

# Combinaison complète : SYN scan + OS + version + scripts par défaut + tracing
# -sS = SYN scan furtif, -sV = versions, -O = OS, -sC = scripts, --traceroute = trace la route réseau
# Commande "tout-en-un" la plus utilisée en phase de reconnaissance détaillée
sudo nmap -sS -sV -O -sC --traceroute 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-sV` | Version detection des services ouverts |
| `-O` | OS detection via TCP/IP stack fingerprinting |
| `-sC` | Active les scripts NSE par défaut (--script default) |
| `--traceroute` | Trace le chemin réseau jusqu'à la cible (hops, latence) |
| `-sS` | TCP SYN scan (furtif, raw sockets) — complète la combinaison |

### 2.6 NSE Scripts (Nmap Scripting Engine)

Les scripts NSE permettent d'automatiser des tâches de détection et d'exploitation.

#### Catégories de scripts

| Catégorie | Description | Exemple |
|-----------|-------------|---------|
| auth | Détection d'authentification | http-brute, ftp-anon |
| broadcast | Découverte par broadcast | broadcast-ping, dhcp-discover |
| brute | Brute-force d'authentification | http-brute, smb-brute |
| default | Scripts par défaut (-sC) | http-title, ssh-hostkey |
| discovery | Découverte de services | dns-zone-transfer, smb-enum-shares |
| dos | Test de déni de service | http-slowloris |
| exploit | Exploitation de vulnérabilités | smb-vuln-ms17-010 |
| external | Requêtes externes | whois-ip, http-geolocate |
| fuzzer | Fuzzing | http-fuzzer, dns-fuzz |
| intrusive | Scripts intrusifs | smb-brute, http-sql-injection |
| malware | Détection de malwares | http-malware-host |
| safe | Scripts non intrusifs | ssh-hostkey, http-title |
| version | Détection de versions | Version-specific probes |
| vuln | Détection de vulnérabilités | smb-vuln-*, http-vuln-* |

#### Utilisation des scripts

```bash
# Scripts par défaut (-sC)
# -sC = raccourci pour --script default, exécute les scripts standards (safe + non intrusifs)
# Inclut : http-title, ssh-hostkey, smb-os-discovery, etc.
nmap -sC 192.168.1.1

# Script d'une catégorie spécifique
# --script vuln = exécute tous les scripts de la catégorie "vuln" (détection de vulnérabilités)
# Teste des failles connues comme MS17-010 (EternalBlue), Shellshock, etc.
nmap --script vuln 192.168.1.1

# Scripts de détection SMB
# --script = liste de scripts séparés par des virgules
# smb-enum-shares = énumère les partages SMB, smb-os-discovery = découvre l'OS via SMB
# smb-security-mode = vérifie la politique de sécurité SMB (signature, niveau d'authentification)
nmap --script smb-enum-shares,smb-os-discovery,smb-security-mode 192.168.1.1

# Script avec arguments
# --script-args = passe des paramètres personnalisés au(x) script(s)
# http-brute.path=/admin = chemin à brute-forcer
# userdb=users.txt = fichier de dictionnaire d'utilisateurs
# passdb=pass.txt = fichier de dictionnaire de mots de passe
nmap --script http-brute --script-args "http-brute.path=/admin,userdb=users.txt,passdb=pass.txt" 192.168.1.1

# Scripts multiples + version detection
# --script "vuln and safe" = opérateur logique AND : exécute les scripts qui sont à la fois dans vuln AND safe
# Opérateurs supportés : and, or, not (ex: "vuln or safe", "default and not intrusive")
nmap -sV --script "vuln and safe" 192.168.1.1

# Scripts avec timeout
# --script-timeout 30s = limite le temps d'exécution de chaque script à 30 secondes
# Évite qu'un script bloquant (ex: fuzzer) ne fige le scan entier
nmap --script http-sql-injection --script-timeout 30s 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-sC` | Équivalent de `--script default`, exécute les scripts standards non intrusifs |
| `--script <cat>` | Exécute tous les scripts d'une catégorie (vuln, safe, discovery, etc.) |
| `--script <s1,s2>` | Exécute une liste de scripts spécifiques (séparés par des virgules) |
| `--script-args "<k=v,...>"` | Passe des arguments aux scripts (ex: chemin, dictionnaires) |
| `--script "A and B"` | Opérateur logique : scripts dans la catégorie A ET B |
| `--script-timeout Ns` | Timeout maximum par script (évite les blocages) |

#### Scripts essentiels par service

**Pour SMB (port 445, 139) :**

```bash
# Énumération complète SMB
# -p 445 = port SMB (Server Message Block), également 139 (NetBIOS) pourrait être ajouté
# --script = liste de scripts NSE pour énumérer les partages (shares), utilisateurs (users),
#            OS (os-discovery), politique sécurité (security-mode), statistiques serveur (server-stats)
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-server-stats,smb-system-info 192.168.1.1

# Détection de vulnérabilités SMB
# --script smb-vuln-* = wildcard : tous les scripts commençant par "smb-vuln-" (ex: smb-vuln-ms17-010)
# Teste les failles SMB connues : EternalBlue (MS17-010), SMBGhost (CVE-2020-0796), etc.
nmap -p 445 --script smb-vuln-* 192.168.1.1
```

**Explication des options :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `-p 445` | Port SMB (utilisé pour le partage de fichiers Windows) |
| `smb-enum-shares` | Énumère les partages SMB accessibles (dossiers partagés) |
| `smb-enum-users` | Énumère les utilisateurs via SMB (RID cycling) |
| `smb-os-discovery` | Découvre le système d'exploitation via SMB |
| `smb-security-mode` | Vérifie la signature SMB, le niveau d'authentification |
| `smb-server-stats` | Statistiques du serveur SMB (sessions, fichiers ouverts) |
| `smb-system-info` | Informations système détaillées via SMB |
| `smb-vuln-*` | Wildcard : tous les scripts de vulnérabilités SMB |

**Pour HTTP/HTTPS (port 80, 443) :**

```bash
# Découverte HTTP
# -p 80,443 = ports HTTP et HTTPS
# --script : http-enum = énumère les répertoires/fichiers courants, http-headers = affiche les en-têtes HTTP
#            http-title = titre de la page, http-server-header = bannière du serveur Web
#            http-methods = liste les méthodes HTTP supportées (GET, POST, PUT, DELETE, OPTIONS...)
nmap -p 80,443 --script http-enum,http-headers,http-title,http-server-header,http-methods 192.168.1.1

# Détection de vulnérabilités web
# --script http-vuln-* = wildcard : tous les scripts de catégorie vuln pour HTTP
# Teste : SQL injection, XSS, LFI, RFI, Shellshock, etc.
nmap -p 80 --script http-vuln-* 192.168.1.1

# Découverte de technologies
# http-technologies-detect = identifie les frameworks/CMS utilisés (WordPress, Joomla, PHP, ASP.NET...)
# Analyse les cookies, les en-têtes et le HTML pour détecter les technologies côté serveur
nmap -p 80 --script http-technologies-detect 192.168.1.1
```

**Explication des scripts :**
| Script | Rôle/Explication |
|--------|------------------|
| `http-enum` | Énumère les répertoires et fichiers courants (wordlist intégrée) |
| `http-headers` | Affiche les en-têtes HTTP de la réponse (Server, X-Powered-By, etc.) |
| `http-title` | Extrait le titre de la page HTML (balise \<title\>) |
| `http-server-header` | Affiche l'en-tête Server (Apache, Nginx, IIS, etc.) |
| `http-methods` | Liste les méthodes HTTP autorisées (détecte PUT/DELETE non sécurisés) |
| `http-vuln-*` | Tous les scripts de détection de vulnérabilités web |
| `http-technologies-detect` | Identifie les technologies et frameworks web |

**Pour DNS (port 53) :**

```bash
# Zone transfer et énumération DNS
# -p 53 = port DNS (UDP et TCP)
# --script : dns-zone-transfer = tente un transfert de zone (faille critique si réussi)
#            dns-brute = brute-force de sous-domaines (utilise une wordlist interne)
#            dns-cache-snoop = vérifie si le serveur DNS a mis en cache des enregistrements spécifiques
#            dns-nsec-enum = énumération de sous-domaines via DNSSEC NSEC (faille de confidentialité)
#            dns-nsid = récupère les informations du serveur DNS (ID du serveur, version)
nmap -p 53 --script dns-zone-transfer,dns-brute,dns-cache-snoop,dns-nsec-enum,dns-nsid 192.168.1.1
```

**Explication des scripts :**
| Script | Rôle/Explication |
|--------|------------------|
| `dns-zone-transfer` | Teste la faille de transfert de zone DNS (AXFR) — expose tous les enregistrements DNS |
| `dns-brute` | Brute-force de sous-domaines via une wordlist intégrée |
| `dns-cache-snoop` | Vérifie le cache DNS pour détecter les domaines visités récemment |
| `dns-nsec-enum` | Énumération de sous-domaines via les enregistrements NSEC (DNSSEC) |
| `dns-nsid` | Récupère l'ID et les informations du serveur DNS (version, options) |

**Pour MySQL/MariaDB (port 3306) :**

```bash
# Énumération MySQL
# -p 3306 = port MySQL/MariaDB
# --script : mysql-enum = énumération des utilisateurs et bases de données
#            mysql-info = informations du serveur (version, protocole, thread ID)
#            mysql-users = liste des utilisateurs MySQL (nécessite authentification)
#            mysql-variables = affiche les variables de configuration MySQL
#            mysql-empty-password = teste les comptes avec mot de passe vide
#            mysql-databases = liste les bases de données accessibles
nmap -p 3306 --script mysql-enum,mysql-info,mysql-users,mysql-variables,mysql-empty-password,mysql-databases 192.168.1.1
```

**Explication des scripts :**
| Script | Rôle/Explication |
|--------|------------------|
| `mysql-enum` | Énumération des utilisateurs et bases de données MySQL |
| `mysql-info` | Récupère les informations du serveur (version, protocole) |
| `mysql-users` | Liste les noms d'utilisateurs MySQL (nécessite des credentials) |
| `mysql-variables` | Affiche les variables de configuration et d'état du serveur |
| `mysql-empty-password` | Teste l'existence de comptes sans mot de passe |
| `mysql-databases` | Liste les bases de données accessibles |

**Pour SSH (port 22) :**

```bash
# Fingerprinting SSH
# -p 22 = port SSH
# --script : ssh-hostkey = récupère l'empreinte (fingerprint) de la clé d'hôte SSH (RSA, ECDSA, Ed25519)
#            ssh-auth-methods = liste les méthodes d'authentification SSH supportées (password, publickey, keyboard-interactive)
#            ssh2-enum-algos = énumère les algorithmes de chiffrement, MAC et échange de clés supportés
nmap -p 22 --script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos 192.168.1.1
```

**Explication des scripts :**
| Script | Rôle/Explication |
|--------|------------------|
| `ssh-hostkey` | Récupère l'empreinte des clés d'hôte SSH (utile pour identifier le serveur) |
| `ssh-auth-methods` | Liste les méthodes d'authentification disponibles (password, clé publique, etc.) |
| `ssh2-enum-algos` | Énumère les algorithmes SSH supportés (chiffrement, MAC, échange de clés) — permet d'identifier les algorithmes faibles |

### 2.7 Évasion IDS/IPS

#### Decoy (-D) — Adresses leurres

```bash
# Scan avec 4 adresses leurres
# -D = decoy (leurres) : l'adresse source des paquets SYN est spoofée avec plusieurs adresses
# ME = marqueur qui indique la vraie adresse de l'attaquant (obligatoire pour recevoir les réponses)
# Les autres adresses sont des leurres : l'IDS voit des SYN provenant de 4 sources différentes
sudo nmap -D 192.168.1.10,192.168.1.20,192.168.1.30,ME 192.168.1.1

# Scan avec adresses leurres aléatoires
# -D RND:5 = génère 5 adresses IP aléatoires comme leurres
# Utile quand on ne connaît pas les adresses du réseau cible
sudo nmap -D RND:5 192.168.1.1

# Decoy avec des adresses d'un sous-réseau spécifique
# -D 192.168.1.10-50 = utilise toute la plage 192.168.1.10 à 192.168.1.50 comme leurres
# L'administrateur voit des SYN venant de 41 adresses différentes (plus réaliste)
sudo nmap -D 192.168.1.10-50 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-D <addr1,addr2,ME>` | Adresses leurres : l'IDS voit des requêtes SYN de multiples sources |
| `ME` | Marqueur obligatoire indiquant la vraie adresse de l'attaquant |
| `RND:N` | Génère N adresses IP aléatoires comme leurres |
| `-D <plage>` | Utilise toutes les adresses d'une plage comme leurres |
| **Limite** | Ne fonctionne pas si la cible utilise une route asymétrique (réponses vers les leurres) |

**Fonctionnement :**
- Chaque requête SYN est envoyée depuis les adresses leurres (spoofing d'adresse source)
- La cible reçoit des SYN de plusieurs sources simultanément
- L'administrateur ne sait pas quelle adresse est la vraie
- Attention : l'adresse ME désigne la vraie adresse de l'attaquant

#### Spoof (Spoofing d'adresse MAC)

```bash
# Spoof d'adresse MAC
# --spoof-mac 00:11:22:33:44:55 = remplace l'adresse MAC source par celle-ci dans les trames Ethernet
# Utile pour contourner le filtrage MAC ou masquer l'identité de la machine sur le réseau local
sudo nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1

# Spoof MAC avec un OUI connu (Apple, Cisco, etc.)
# --spoof-mac Apple = génère une adresse MAC avec l'OUI (Organizationally Unique Identifier) d'Apple
# Cisco, Dell, Apple sont des mots-clés reconnus par Nmap qui attribuent les OUI correspondants
# Permet de faire croire que le scan provient d'un équipement de la marque spécifiée
sudo nmap --spoof-mac Apple 192.168.1.1
sudo nmap --spoof-mac Cisco 192.168.1.1
sudo nmap --spoof-mac Dell 192.168.1.1

# Spoof MAC aléatoire
# --spoof-mac 0 = génère une adresse MAC complètement aléatoire à chaque scan
# Ne laisse aucune trace de l'adresse MAC réelle de la machine attaquante
sudo nmap --spoof-mac 0 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--spoof-mac <adresse>` | Remplace l'adresse MAC source par une adresse personnalisée |
| `--spoof-mac <Marque>` | Utilise l'OUI d'un constructeur (Apple, Cisco, Dell, VMware, etc.) |
| `--spoof-mac 0` | Génère une adresse MAC aléatoire |

#### MTU Custom et Data Length

```bash
# Taille de fragment personnalisée
# --mtu 24 = définit la taille Maximum Transmission Unit à 24 octets
# Les paquets seront fragmentés en morceaux de 24 octets maximum
# L'en-tête IP fait 20 octets, donc il reste 4 octets de données par fragment
sudo nmap --mtu 24 192.168.1.1

# Longueur de données personnalisée (défaut 0)
# --data-length 50 = ajoute 50 octets de données aléatoires dans le payload du paquet
# Les paquets Nmap standards ont un payload vide (0 octet) — les rendre plus gros les fait ressembler
# à du trafic normal plutôt qu'à des probes de scan
sudo nmap --data-length 50 192.168.1.1

# Ajout de données aléatoires pour obscurcir le scan
# --data-length 200 = ajoute 200 octets de données aléatoires (paquets encore plus gros)
# Plus la charge utile est grande, plus le scan ressemble à du trafic applicatif légitime
sudo nmap --data-length 200 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--mtu <taille>` | Définit la taille MTU (Minimum Transmission Unit) — fragmente les paquets |
| `--data-length <N>` | Ajoute N octets de données aléatoires dans le payload TCP |
| **Objectif** | Les paquets Nmap standards (payload vide) sont facilement identifiables par les IDS ; l'ajout de données et la fragmentation les rendent moins distinctifs |

#### Source Port Manipulation

```bash
# Spécifier un port source spécifique
# --source-port 53 = définit le port source à 53 (DNS) pour les paquets envoyés
# -g 445 = synonyme de --source-port, définit le port source à 445 (SMB)
# Certains pare-feu autorisent le trafic venant de ports privilégiés (< 1024)
sudo nmap -sS --source-port 53 192.168.1.1
sudo nmap -sS -g 445 192.168.1.1  # -g est synonyme de --source-port

# Pour imager du trafic DNS
# --source-port 53 = fait croire que le trafic provient d'un serveur DNS (port 53)
# -p 80,443 = scan des ports HTTP et HTTPS uniquement
# Le pare-feu peut laisser passer car il pense que c'est une réponse DNS légitime
sudo nmap -sS --source-port 53 -p 80,443 192.168.1.1
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--source-port <port>` | Définit le port source des paquets envoyés (aussi `-g`) |
| `-g <port>` | Synonyme de `--source-port` (pour "good port") |
| **Principe** | Les pare-feu autorisent souvent le trafic DNS (port 53) ou SMB (port 445) en entrée ; forcer le port source à ces valeurs permet de contourner les règles de filtrage |
| **Limite** | Fonctionne uniquement si les règles de pare-feu sont basées sur le port source plutôt que l'état de connexion |

**Pourquoi ?** Certains pare-feu autorisent le trafic entrant depuis des ports privilégiés (< 1024). En utilisant le port 53 (DNS) ou 80 (HTTP), on peut contourner ces règles.

#### Scan via Proxy (Proxychains)

```bash
# Configuration de proxychains
# cat = affiche le contenu du fichier de configuration de proxychains
# /etc/proxychains4.conf = fichier de config où sont listés les proxys à utiliser
# Vérifier les lignes actives : socks4 127.0.0.1 9050 (proxy Tor) ou http 127.0.0.1 8080 (Burp Suite)
cat /etc/proxychains4.conf
# → Vérifier : socks4 127.0.0.1 9050 (Tor) ou http 127.0.0.1 8080 (Burp)

# Scan via Tor (anonymisation complète)
# proxychains4 = outil qui force n'importe quel programme à passer par un proxy chaîné
# nmap -sT = Connect scan (obligatoire avec proxy, -sS ne fonctionne pas car raw sockets bloqués)
# -Pn = skip host discovery (ne pas envoyer de ping au préalable, car le proxy ne le supporte pas)
sudo proxychains4 nmap -sT -Pn 192.168.1.1

# Scan via SOCKS5
# Même principe : passage par un proxy SOCKS5 configuré dans proxychains4.conf
# -p 80,443 = uniquement les ports web (plus rapide via proxy qui est lent)
sudo proxychains4 nmap -sT -Pn -p 80,443 10.0.0.1

# Scan via HTTP proxy (Burp Suite)
# Configurer /etc/proxychains4.conf :
# http 127.0.0.1 8080
# Burp Suite intercepte le trafic Nmap via son proxy HTTP
sudo proxychains4 nmap -sT -Pn 10.0.0.1
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `cat /etc/proxychains4.conf` | Affiche la configuration des proxys (Tor, SOCKS, HTTP) |
| `proxychains4 <commande>` | Force la commande à passer par les proxys configurés |
| `-sT` | Connect scan (obligatoire avec proxy, -sS ne fonctionne pas) |
| `-Pn` | Skip host discovery (évite d'envoyer des probes ICMP qui ne passent pas le proxy) |
| **Limite** | Les scans SYN (-sS) nécessitent des raw sockets au niveau noyau, impossibles via proxy ; utiliser -sT (connect scan) à la place |

**Limites :**
- Les scans SYN (-sS) ne fonctionnent pas via proxy (nécessitent un raw socket)
- Utiliser -sT (Connect scan) avec -Pn (skip host discovery)
- Beaucoup plus lent

### 2.8 Sortie et Parsing

#### Formats de sortie

```bash
# Tous les formats en une fois
# -oA scan_result = All formats : génère simultanément les fichiers .nmap (normal), .xml (XML) et .gnmap (grepable)
# Le préfixe "scan_result" est utilisé pour nommer les trois fichiers
sudo nmap -oA scan_result 192.168.1.1

# Format normal (lisible)
# -oN = Normal output : format texte standard, le plus lisible pour un humain
sudo nmap -oN scan_normal.txt 192.168.1.1

# Format XML (pour parsing)
# -oX = XML output : format structuré parsable par des scripts (Python, XSLT, etc.)
# Utilisé pour générer des rapports HTML ou importer dans des bases de données
sudo nmap -oX scan_xml.xml 192.168.1.1

# Format Grepable (pour grep/awk)
# -oG = Grepable output : format compact avec une ligne par hôte, idéal pour les pipelines shell (grep, awk, cut)
sudo nmap -oG scan_grepable.txt 192.168.1.1
```

**Explication des options :**
| Option | Format | Usage |
|--------|--------|-------|
| `-oA <prefixe>` | All (Normal + XML + Grepable) | Production de tous les formats simultanément |
| `-oN <fichier>` | Normal (.nmap) | Format texte lisible pour relecture humaine |
| `-oX <fichier>` | XML (.xml) | Format structuré pour parsing automatisé |
| `-oG <fichier>` | Grepable (.gnmap) | Format compact une ligne/hôte pour grep/awk/sed |

#### Parsing XML avec Python

```bash
# Sauvegarder le script d'analyse :
cat > parse-nmap-xml.py << 'PYEOF'
```

```python
#!/usr/bin/env python3
# Shebang : indique au système que ce script doit être exécuté avec Python 3
# Sur Kali : /usr/bin/python3 est le binaire Python 3
"""
parse-nmap-xml.py — Parse un fichier XML de Nmap pour en extraire un rapport structuré.
Usage : python3 parse-nmap-xml.py scan_xml.xml
"""
# sys = accès aux arguments de la ligne de commande (sys.argv)
import sys
# xml.etree.ElementTree = module standard Python pour parser et manipuler du XML
import xml.etree.ElementTree as ET

# Définition de la fonction principale : prend un chemin de fichier XML en entrée
def parse_nmap_xml(xml_file):
    # ET.parse() = charge et parse le fichier XML en un arbre d'éléments
    tree = ET.parse(xml_file)
    # getroot() = récupère la racine de l'arbre XML (élément <nmaprun>)
    root = tree.getroot()

    # En-tête du rapport formaté avec 60 signes "=" de séparation
    print(f"{'='*60}")
    print(f"Rapport Nmap parsé — {xml_file}")
    # root.get('start') = attribut "start" de l'élément racine (timestamp Unix du scan)
    print(f"Date : {root.get('start')}")
    print(f"{'='*60}\n")

    # Parcourt tous les éléments <host> (chaque hôte scanné)
    for host in root.findall('host'):
        # Trouve l'élément <status> dans <host>
        status = host.find('status')
        # Vérifie si l'hôte est actif (état "up"), sinon on passe au suivant
        if status.get('state') != 'up':
            continue

        # Trouve l'élément <address> (contient l'adresse IP)
        addr = host.find('address')
        # Récupère l'attribut "addr" (l'IP), ou "inconnue" si absent
        ip = addr.get('addr') if addr is not None else 'inconnue'
        print(f"[+] Hôte : {ip}")

        # Recherche d'informations sur l'OS
        os = host.find('os')
        if os is not None:
            # Parcourt tous les éléments <osmatch> (suppositions d'OS)
            for osmatch in os.findall('osmatch'):
                # Affiche le nom de l'OS détecté et la confiance en pourcentage (attr "accuracy")
                print(f"    OS : {osmatch.get('name')} "
                      f"(confiance: {osmatch.get('accuracy')}%)")

        # Recherche des ports et services
        ports = host.find('ports')
        if ports is not None:
            # Parcourt tous les éléments <port>
            for port in ports.findall('port'):
                # Attributs du port : portid (numéro), protocol (tcp/udp)
                port_id = port.get('portid')
                protocol = port.get('protocol')
                # État du port (open, filtered, closed)
                state = port.find('state').get('state')
                # Élément <service> (nom, produit, version)
                service = port.find('service')

                # N'affiche que les ports ouverts
                if state == 'open':
                    # Récupère le nom du service (http, ssh, etc.) ou "?" si absent
                    svc_name = service.get('name') if service is not None else '?'
                    # Récupère le produit (Apache, OpenSSH, etc.) ou "" si absent
                    svc_product = service.get('product') if service is not None else ''
                    # Récupère la version (2.4.41, 8.0p1, etc.) ou "" si absent
                    svc_version = service.get('version') if service is not None else ''
                    print(f"    Port : {port_id}/{protocol} — {svc_name} "
                          f"{svc_product} {svc_version}")
        print()  # Ligne vide entre chaque hôte

# Point d'entrée : ne s'exécute que si le script est appelé directement (pas importé)
if __name__ == '__main__':
    # Vérifie qu'on a exactement 1 argument (le nom du script est sys.argv[0])
    if len(sys.argv) != 2:
        print("Usage : python3 parse-nmap-xml.py <fichier.xml>")
        sys.exit(1)  # Quitte avec code d'erreur 1
    # Appelle la fonction principale avec le fichier XML passé en argument
    parse_nmap_xml(sys.argv[1])
```
PYEOF
chmod +x parse-nmap-xml.py
```

**Explication du code Python :**
| Élément | Rôle/Explication |
|---------|------------------|
| `import xml.etree.ElementTree as ET` | Module standard pour parser du XML (natif, pas de dépendance externe) |
| `ET.parse(xml_file)` | Charge et parse le fichier XML en mémoire |
| `root.findall('host')` | Cherche tous les éléments `<host>` dans l'arbre XML |
| `status.get('state')` | Récupère l'attribut "state" de `<status>` ("up" = hôte actif) |
| `osmatch.get('name')` | Nom de l'OS détecté |
| `osmatch.get('accuracy')` | Confiance en pourcentage (100 = certain) |
| `port.find('service').get('product')` | Produit/service détecté (ex: Apache httpd) |
| `port.find('service').get('version')` | Version du produit (ex: 2.4.41) |
| `sys.argv[1]` | Premier argument passé au script (le fichier XML) |

#### Nmap Bootstrap XSL — Rapport HTML

```bash
# Télécharger la feuille de style XSL
# wget = télécharge le fichier depuis l'URL (outil de téléchargement en ligne de commande)
# nmap-bootstrap.xsl = feuille de style XSL qui transforme le XML Nmap en HTML avec le thème Bootstrap
# Le projet nmap-bootstrap-xsl permet de générer des rapports visuellement professionnels
wget https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/main/nmap-bootstrap.xsl

# Convertir le XML en HTML avec la feuille de style
# xsltproc = processeur XSLT en ligne de commande (libxslt)
# -o scan_result.html = fichier de sortie HTML
# nmap-bootstrap.xsl = feuille de style à appliquer
# scan_xml.xml = fichier XML source (données Nmap)
xsltproc -o scan_result.html nmap-bootstrap.xsl scan_xml.xml

# Alternative : spécifier le XSL directement dans le XML
# Modifier la deuxième ligne de scan_xml.xml pour ajouter :
# <?xml-stylesheet href="nmap-bootstrap.xsl" type="text/xsl"?>
# Ainsi le XML s'affiche comme du HTML quand on l'ouvre dans un navigateur
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `wget <url>` | Télécharge la feuille de style XSL Bootstrap depuis GitHub |
| `xsltproc -o <output> <xsl> <xml>` | Transforme le XML en HTML via la feuille de style XSL |
| `-o <fichier>` | Spécifie le fichier de sortie (output) |
| `<?xml-stylesheet ...?>` | Instruction de traitement XML : associe une feuille de style au fichier XML |

### 2.9 Scan ARP (découverte locale)

```bash
# Scan ARP sur le réseau local (plus rapide que ICMP)
# -PR = ARP ping : utilise le protocole ARP (couche 2) au lieu d'ICMP (couche 3)
# -sn = skip port scan : uniquement la découverte d'hôtes, pas de scan de ports
# Avantage ARP : fonctionne sur le segment local sans routage, détection quasi instantanée
sudo nmap -PR -sn 192.168.1.0/24

# Scan ARP + liste des hôtes
# -sL = list scan : ne fait que lister les cibles sans envoyer de paquets
# Combiné avec -PR, cela liste les hôtes qui répondent à l'ARP (présents sur le réseau)
sudo nmap -PR -sL 192.168.1.0/24
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-PR` | ARP ping : envoie des requêtes ARP (couche 2) pour découvrir les hôtes sur le réseau local |
| `-sn` | Ping sweep only : découvre les hôtes sans scanner les ports |
| `-sL` | List scan : liste les cibles sans envoyer de paquets (utilise ARP ou DNS) |
| **Pourquoi ARP plus rapide ?** | ARP fonctionne en couche 2 (pas besoin de pile IP complète), pas de routage, réponse quasi instantanée |

**Pourquoi le scan ARP est plus rapide ?**
- N'utilise pas la couche IP (pas de routage)
- Fonctionne uniquement sur le segment local
- Détection quasi instantanée

### 2.10 TP Guidé — Scan complet d'un sous-réseau /24

#### Objectif
Scanner un sous-réseau complet (192.168.1.0/24) pour découvrir tous les hôtes actifs, leurs OS, services ouverts et vulnérabilités potentielles.

#### Étape 1 : Découverte d'hôtes actifs (Ping Sweep)

```bash
# Étape 1a : Ping sweep ICMP
# Découvre les hôtes qui répondent au ping
# echo = affiche un message dans la console pour indiquer l'étape en cours
echo "=== ÉTAPE 1 : PING SWEEP ==="
# -sn = ping sweep uniquement (skip port scan), découvre les hôtes actifs
# 192.168.1.0/24 = notation CIDR : les 256 adresses du réseau (192.168.1.0 à 192.168.1.255)
# -oA rapport/01-ping-sweep = sauvegarde les résultats dans rapport/01-ping-sweep.{nmap,xml,gnmap}
sudo nmap -sn 192.168.1.0/24 -oA rapport/01-ping-sweep

# Étape 1b : Ping sweep ARP (si on est sur le même segment)
# Plus rapide, utilise la couche 2 au lieu de la couche 3
# -PR = ARP ping : envoie des requêtes ARP (protocole de résolution d'adresse)
# Contrairement à ICMP, ARP ne peut pas être bloqué par un pare-feu local
sudo nmap -PR -sn 192.168.1.0/24 -oA rapport/01-arp-sweep

# Étape 1c : Ping sweep avec TCP SYN sur port 80 et 443
# Utile si ICMP est bloqué mais que le port 80 répond
# -PS80,443 = TCP SYN ping : envoie un SYN aux ports 80 (HTTP) et 443 (HTTPS)
# Si la cible répond avec un SYN-ACK ou RST, l'hôte est considéré actif
# Contourne les pare-feu qui bloquent ICMP mais pas le trafic web
sudo nmap -PS80,443 -sn 192.168.1.0/24 -oA rapport/01-tcp-ping
```

**Analyse des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-sn` | Skip port scan : découvre uniquement les hôtes actifs sans scanner les ports |
| `-PR` | ARP ping : découvre les hôtes via ARP (couche 2) — le plus rapide sur le réseau local |
| `-PS80,443` | TCP SYN ping : envoie un SYN aux ports spécifiés pour détecter les hôtes qui répondent |
| `-oA <prefixe>` | Sortie dans les 3 formats (Normal, XML, Grepable) avec le préfixe donné |
| `192.168.1.0/24` | Sous-réseau cible (256 adresses, masque 255.255.255.0) |

#### Étape 2 : Scan de ports sur chaque hôte

```bash
# Étape 2a : Scan des 1000 ports les plus courants (rapide)
# Sur tous les hôtes découverts à l'étape 1
echo "=== ÉTAPE 2a : SCAN DES PORTS (TOP 1000) ==="

# Récupérer la liste des hôtes actifs
# grep "Nmap scan report for" = filtre les lignes contenant les entêtes d'hôtes
# grep -oP '\d+\.\d+\.\d+\.\d+' = extrait uniquement les adresses IP (expressions rationnelle avec -oP = -o only-matching, -P Perl regex)
# > rapport/hotes_actifs.txt = redirige la sortie vers un fichier texte
grep "Nmap scan report for" rapport/01-ping-sweep.nmap | \
    grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' > rapport/hotes_actifs.txt

# Scanner chaque hôte
# while read ip = boucle qui lit chaque ligne du fichier (chaque adresse IP)
# do ... done < fichier = redirige le contenu du fichier vers l'entrée standard de la boucle
while read ip; do
    echo "Scan de $ip..."
    # -sS = SYN scan (furtif), -sV = version detection
    # -T4 = profil agressif (timeouts courts), --top-ports 1000 = 1000 ports les plus courants
    # --min-rate 1000 = minimum 1000 paquets/s (évite un démarrage trop lent)
    # -oA "rapport/02-ports-$ip" = sortie dans rapport/ avec l'IP comme nom de fichier
    sudo nmap -sS -sV -T4 --top-ports 1000 --min-rate 1000 \
        -oA "rapport/02-ports-$ip" "$ip"
done < rapport/hotes_actifs.txt
```

**Explications des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `grep "Nmap scan report for"` | Filtre les lignes contenant "Nmap scan report for" (début de bloc de chaque hôte) |
| `grep -oP '\d+\.\d+\.\d+\.\d+'` | -o = only-matching (affiche uniquement le match), -P = Perl regex, extrait les adresses IP |
| `while read ip; do ... done < fichier` | Boucle shell : lit le fichier ligne par ligne et exécute les commandes pour chaque IP |
| `--top-ports 1000` | Ne scanner que les 1000 ports les plus statistiquement ouverts |
| `--min-rate 1000` | Minimum 1000 paquets par seconde (accélère le début du scan) |
| `-sV` | Detection de versions sur les ports ouverts |

#### Étape 3 : Détection d'OS

```bash
# Étape 3 : OS Detection sur chaque hôte
echo "=== ÉTAPE 3 : OS DETECTION ==="
# Boucle identique : pour chaque IP dans le fichier des hôtes actifs
while read ip; do
    echo "Détection OS pour $ip..."
    # -O = active l'OS detection (TCP/IP stack fingerprinting)
    # --osscan-guess = force une estimation même avec fingerprint partiel
    # -oA "rapport/03-os-$ip" = sauvegarde les 3 formats avec nom basé sur l'IP
    sudo nmap -O --osscan-guess -oA "rapport/03-os-$ip" "$ip"
done < rapport/hotes_actifs.txt
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-O` | Active l'OS detection : envoie jusqu'à 16 probes, analyse les réponses (ISN, TTL, window size, options TCP) |
| `--osscan-guess` | Affiche les suppositions même si la confiance est faible (affiche le %) |
| `-oA <prefixe>` | Sauvegarde les résultats dans les 3 formats (normal, XML, grepable) |

#### Étape 4 : Scripts NSE (vulnérabilités)

```bash
# Étape 4a : Scripts de vulnérabilités sur chaque hôte
echo "=== ÉTAPE 4 : SCRIPTS NSE ==="
# Boucle pour chaque hôte actif
while read ip; do
    echo "Scan vulnérabilités pour $ip..."
    # Premier scan : scripts de vulnérabilités non intrusifs
    # --script "vuln and safe" = logique AND : scripts qui sont à la fois dans vuln ET dans safe
    # --script-timeout 60s = timeout de 60 secondes par script (évite les blocages)
    # -sS = SYN scan, -sV = version detection (nécessaire pour que les scripts fonctionnent)
    sudo nmap -sS -sV --script "vuln and safe" \
        --script-timeout 60s -oA "rapport/04-vuln-$ip" "$ip"
    # Deuxième scan : scripts de découverte et de version
    # --script "discovery,version" = catégories séparées par des virgules (union)
    # discovery = scripts qui découvrent des informations supplémentaires
    # version = scripts qui améliorent la détection de versions
    sudo nmap -sS -sV --script "discovery,version" \
        -oA "rapport/04-discovery-$ip" "$ip"
done < rapport/hotes_actifs.txt
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--script "vuln and safe"` | Exécute les scripts qui sont à la fois de catégorie "vuln" ET "safe" (évite les tests destructeurs) |
| `--script-timeout 60s` | Limite chaque script à 60 secondes d'exécution max |
| `--script "discovery,version"` | Exécute les scripts des catégories "discovery" et "version" (union) |
| `-sS -sV` | SYN scan + version detection (prérequis pour la plupart des scripts) |

#### Étape 5 : Scan spécifique par service

```bash
# Étape 5a : Scan SMB
echo "=== ÉTAPE 5a : SCAN SMB ==="
# Boucle sur chaque hôte actif
while read ip; do
    # -p 445 = port SMB (Server Message Block, partage Windows)
    # Scripts : smb-enum-shares (partages), smb-os-discovery (OS), smb-security-mode (politique de sécurité)
    sudo nmap -p 445 --script smb-enum-shares,smb-os-discovery,smb-security-mode \
        -oA "rapport/05-smb-$ip" "$ip"
done < rapport/hotes_actifs.txt

# Étape 5b : Scan HTTP
echo "=== ÉTAPE 5b : SCAN HTTP ==="
while read ip; do
    # -p 80,443 = ports HTTP et HTTPS
    # Scripts : http-enum (répertoires), http-headers (en-têtes), http-title (titre page), http-server-header (bannière)
    sudo nmap -p 80,443 --script http-enum,http-headers,http-title,http-server-header \
        -oA "rapport/05-http-$ip" "$ip"
done < rapport/hotes_actifs.txt

# Étape 5c : Scan MySQL
echo "=== ÉTAPE 5c : SCAN MYSQL ==="
while read ip; do
    # -p 3306 = port MySQL/MariaDB
    # Scripts : mysql-enum (énumération), mysql-info (version), mysql-empty-password (mots de passe vides)
    sudo nmap -p 3306 --script mysql-enum,mysql-info,mysql-empty-password \
        -oA "rapport/05-mysql-$ip" "$ip"
done < rapport/hotes_actifs.txt
```

**Explication des options :**
| Étape | Option | Rôle/Explication |
|-------|--------|------------------|
| 5a SMB | `-p 445` | Port SMB pour le partage de fichiers Windows |
| 5a SMB | `smb-enum-shares,smb-os-discovery,smb-security-mode` | Scripts NSE pour l'énumération des partages, la détection d'OS et la politique de sécurité |
| 5b HTTP | `-p 80,443` | Ports HTTP et HTTPS |
| 5b HTTP | `http-enum,http-headers,http-title,http-server-header` | Scripts d'énumération web : répertoires, en-têtes, titre, bannière serveur |
| 5c MySQL | `-p 3306` | Port MySQL/MariaDB |
| 5c MySQL | `mysql-enum,mysql-info,mysql-empty-password` | Scripts d'énumération MySQL : utilisateurs, version, mots de passe faibles |

#### Étape 6 : Génération du rapport consolidé

```bash
# Étape 6 : Génération du rapport final
echo "=== ÉTAPE 6 : RAPPORT ==="

# Convertir XML en HTML avec bootstrap-xsl
# wget -q = quiet mode (n'affiche pas les barres de progression), télécharge la feuille XSL
# -O rapport/nmap-bootstrap.xsl = fichier de destination (Output)
wget -q https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/main/nmap-bootstrap.xsl \
    -O rapport/nmap-bootstrap.xsl

# Copier les fichiers XML et les convertir
# for xml in rapport/02-ports-*.xml = boucle sur tous les fichiers XML de scan de ports
for xml in rapport/02-ports-*.xml; do
    # basename "$xml" .xml = extrait le nom du fichier sans le chemin ni l'extension .xml
    base=$(basename "$xml" .xml)
    # xsltproc -o "rapport/${base}.html" = convertit le XML en HTML via la feuille XSL
    xsltproc -o "rapport/${base}.html" rapport/nmap-bootstrap.xsl "$xml"
    echo "  ✓ Rapport HTML généré : rapport/${base}.html"
done

# Générer un résumé texte
echo "=== RÉSUMÉ ===" > rapport/resume.txt  # Crée/écrase le fichier resume.txt
echo "Date : $(date)" >> rapport/resume.txt  # Ajoute la date (>> = append)
echo "" >> rapport/resume.txt

# Boucle sur chaque hôte actif
# $(cat rapport/hotes_actifs.txt) = substitution de commande, lit le fichier
for ip in $(cat rapport/hotes_actifs.txt); do
    echo "--- Hôte : $ip ---" >> rapport/resume.txt
    # grep -A 100 "Nmap scan report for $ip" = affiche les 100 lignes après le match
    # grep -E "^[0-9]+/tcp|^[0-9]+/udp|OS details|Aggressive OS guesses" = filtre les lignes
    # utiles : ports TCP/UDP ouverts et détails OS
    grep -A 100 "Nmap scan report for $ip" "rapport/02-ports-$ip.nmap" | \
        grep -E "^[0-9]+/tcp|^[0-9]+/udp|OS details|Aggressive OS guesses" >> rapport/resume.txt
    echo "" >> rapport/resume.txt
done

echo "Rapport consolidé : rapport/resume.txt"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `wget -q <url> -O <fichier>` | Télécharge en mode silencieux (quiet) vers un fichier de sortie spécifique |
| `for xml in *.xml; do ... done` | Boucle shell sur tous les fichiers correspondant au motif |
| `basename "$xml" .xml` | Extrait le nom de fichier sans l'extension (ex: "02-ports-192.168.1.1") |
| `xsltproc -o <out> <xsl> <xml>` | Transforme le XML en HTML via la feuille de style XSL |
| `> fichier` | Redirection : crée/écrase le fichier |
| `>> fichier` | Redirection : ajoute à la fin du fichier (append) |
| `grep -A 100 "motif"` | Affiche les 100 lignes qui suivent le motif (After context) |
| `grep -E "regex"` | Expression régulière étendue (supporte \| pour l'alternative) |

#### Script complet de scan automatisé

```bash
#!/bin/bash
# Shebang : script shell Bash (interpréteur Bash)
# scan-complet-reseau.sh — Scan automatisé complet d'un sous-réseau
# Usage : sudo ./scan-complet-reseau.sh <sous-reseau>
# Exemple : sudo ./scan-complet-reseau.sh 192.168.1.0/24

# set -e = exit on error : arrête le script immédiatement si une commande échoue
set -e

# [ "$EUID" -ne 0 ] = vérifie que l'UID effectif n'est pas 0 (root)
# EUID = Effective User ID, 0 = root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Ce script doit être exécuté en root."
    exit 1  # Quitte avec code d'erreur 1
fi

# [ -z "$1" ] = vérifie si le premier argument ($1) est vide (-z = zero length)
if [ -z "$1" ]; then
    echo "Usage : $0 <sous-reseau>"  # $0 = nom du script
    echo "Exemple : $0 192.168.1.0/24"
    exit 1
fi

# Variables globales
SUBNET="$1"  # Premier argument : le sous-réseau à scanner (ex: 192.168.1.0/24)
# date +%Y%m%d_%H%M%S = génère un timestamp (ex: 20260115_143022) pour un nom de dossier unique
RAPPORT_DIR="rapport-nmap-$(date +%Y%m%d_%H%M%S)"
HOSTS_FILE="${RAPPORT_DIR}/hotes_actifs.txt"  # Fichier contenant la liste des IPs actives

# mkdir -p = crée le dossier de rapport, -p ne génère pas d'erreur si le dossier existe déjà
mkdir -p "$RAPPORT_DIR"

echo "=========================================="
echo " Scan complet du sous-réseau : $SUBNET"
echo " Rapport dans : $RAPPORT_DIR"
echo "=========================================="

echo ""
echo "[1/5] Découverte d'hôtes actifs..."
# -sn = ping sweep (pas de scan de ports), -T4 = profil agressif
# -oA = sortie dans les 3 formats avec préfixe "01-ping-sweep"
# tee -a = affiche la sortie ET l'ajoute au fichier scan.log (-a = append)
sudo nmap -sn -T4 "$SUBNET" -oA "${RAPPORT_DIR}/01-ping-sweep" | tee -a "${RAPPORT_DIR}/scan.log"

# Extrait les adresses IP des hôtes découverts
# grep "Nmap scan report for" = trouve les lignes d'en-tête d'hôte
# grep -oP '\d+\.\d+\.\d+\.\d+' = extrait l'IP (Perl regex, only-matching)
grep "Nmap scan report for" "${RAPPORT_DIR}/01-ping-sweep.nmap" | \
    grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' > "$HOSTS_FILE"

# wc -l = compte le nombre de lignes (donc le nombre d'IPs actives)
NB_HOSTS=$(wc -l < "$HOSTS_FILE")
echo "[+] $NB_HOSTS hôtes actifs découverts."

# Si aucun hôte trouvé, arrêt propre du script
if [ "$NB_HOSTS" -eq 0 ]; then
    echo "[!] Aucun hôte actif trouvé. Arrêt."
    exit 0
fi

echo ""
echo "[2/5] Scan rapide des 1000 ports courants..."
# Boucle : lit chaque IP du fichier hosts.txt et lance un scan Nmap
while read -r ip; do
    echo "  → Scan de $ip..."
    # -sS = SYN scan, -sV = version detection, -T4 = agressif
    # --top-ports 1000 = 1000 ports les plus fréquents
    # >> "${RAPPORT_DIR}/scan.log" 2>&1 = redirige stdout ET stderr vers le log
    sudo nmap -sS -sV -T4 --top-ports 1000 \
        -oA "${RAPPORT_DIR}/02-ports-top1000-$ip" \
        "$ip" >> "${RAPPORT_DIR}/scan.log" 2>&1
done < "$HOSTS_FILE"

# Si 5 hôtes ou moins, on fait un scan complet de tous les ports
if [ "$NB_HOSTS" -le 5 ]; then
    echo ""
    echo "[3/5] Scan complet des ports (peut être long)..."
    while read -r ip; do
        echo "  → Scan complet de $ip..."
        # -p- = tous les ports (1-65535), --min-rate 1000 = débit minimum de 1000 pps
        sudo nmap -sS -sV -T4 -p- --min-rate 1000 \
            -oA "${RAPPORT_DIR}/03-ports-tous-$ip" \
            "$ip" >> "${RAPPORT_DIR}/scan.log" 2>&1
    done < "$HOSTS_FILE"
else
    echo "[3/5] Skippé (trop d'hôtes)."  # Évite un scan trop long
fi

echo ""
echo "[4/5] Détection d'OS..."
# OS Detection sur chaque hôte
while read -r ip; do
    echo "  → OS detection pour $ip..."
    # -O = OS detection, --osscan-guess = forcer l'estimation même avec fingerprint partiel
    sudo nmap -O --osscan-guess \
        -oA "${RAPPORT_DIR}/04-os-$ip" \
        "$ip" >> "${RAPPORT_DIR}/scan.log" 2>&1
done < "$HOSTS_FILE"

echo ""
echo "[5/5] Scripts NSE..."
# Scripts NSE de vulnérabilités sur chaque hôte
while read -r ip; do
    echo "  → NSE pour $ip..."
    # -sV = version detection (nécessaire), --script "vuln and safe" = vulnérabilités non destructives
    # --script-timeout 60s = timeout par script
    sudo nmap -sV --script "vuln and safe" --script-timeout 60s \
        -oA "${RAPPORT_DIR}/05-nse-$ip" \
        "$ip" >> "${RAPPORT_DIR}/scan.log" 2>&1
done < "$HOSTS_FILE"

echo ""
echo "=========================================="
echo " Scan terminé !"
echo " Résultats : $RAPPORT_DIR/"
echo " Hôtes découverts : $NB_HOSTS"
echo "=========================================="
```

**Explication du script :**
| Élément | Rôle/Explication |
|---------|------------------|
| `#!/bin/bash` | Shebang : indique l'interpréteur Bash |
| `set -e` | Exit on error : arrête le script en cas d'erreur |
| `$EUID` | Effective User ID (0 = root) |
| `$1` | Premier argument passé au script (le sous-réseau) |
| `$(date +%Y%m%d_%H%M%S)` | Timestamp pour nommer le dossier de rapport de manière unique |
| `\| tee -a <fichier>` | Affiche la sortie ET l'ajoute au fichier |
| `2>&1` | Redirige stderr (2) vers stdout (1) pour tout capturer dans le log |
| `while read -r ip; do ... done < fichier` | Boucle de lecture ligne par ligne d'un fichier |
| `-le 5` | Less-or-equal : condition si le nombre d'hôtes est ≤ 5 |

#### Exécution du TP guidé complet

```bash
# Rendre le script exécutable
# chmod +x = ajoute le droit d'exécution (+x) au fichier
# Sans cela, le script ne peut pas être lancé avec ./
chmod +x scan-complet-reseau.sh

# Exécuter le scan complet
# sudo = nécessaire car Nmap en mode SYN (-sS) nécessite les privilèges root
# ./ = chemin relatif vers le script dans le répertoire courant
sudo ./scan-complet-reseau.sh 192.168.1.0/24
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `chmod +x scan-complet-reseau.sh` | Rend le fichier exécutable (ajoute le bit d'exécution) |
| `sudo ./scan-complet-reseau.sh 192.168.1.0/24` | Exécute le script en root avec le sous-réseau 192.168.1.0/24 comme cible |


## 3. Masscan — Scan ultra-rapide

### 3.1 Installation

```bash
# Installation sur Kali/Debian
# sudo apt update = rafraîchit la liste des paquets disponibles
sudo apt update
# sudo apt install -y masscan = installe masscan avec confirmation automatique
sudo apt install -y masscan

# Compilation depuis les sources
# git clone = télécharge le dépôt officiel de Masscan (C, par Robert David Graham)
git clone https://github.com/robertdavidgraham/masscan.git
cd masscan  # Se déplace dans le dossier cloné
# make -j$(nproc) = compile en parallèle avec tous les coeurs CPU disponibles (nproc = nombre de processeurs)
make -j$(nproc)
sudo make install  # Installe le binaire compilé dans /usr/local/bin/

# Vérification
masscan --version  # Affiche la version installée
masscan --echo | head -20  # --echo = affiche la configuration par défaut de Masscan
                             # | head -20 = affiche seulement les 20 premières lignes
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `sudo apt install -y masscan` | Installe le paquet masscan depuis les dépôts |
| `git clone <url>` | Télécharge les sources depuis GitHub |
| `make -j$(nproc)` | Compile en utilisant tous les coeurs CPU disponibles (-j = jobs parallèles) |
| `sudo make install` | Copie le binaire compilé dans le système |
| `masscan --version` | Vérifie la version installée |
| `masscan --echo` | Affiche la configuration par défaut de Masscan |
| `head -20` | Affiche les 20 premières lignes de la sortie |

### 3.2 Comparaison Masscan vs Nmap

| Critère | Masscan | Nmap |
|---------|---------|------|
| **Vitesse** | Jusqu'à 25 000 000 paquets/s | ~1000 paquets/s (T4) |
| **Précision** | Moins précise (pas de handshake complet) | Très précise |
| **OS detection** | Non | Oui (-O) |
| **Version detection** | Non | Oui (-sV) |
| **Scripting** | Non | Oui (NSE ~600 scripts) |
| **Usage typique** | Scan de masse rapide | Scan détaillé et ciblé |
| **Protocole** | TCP/UDP seulement | TCP/UDP/SCTP/ICMP/ARP |
| **Sorties** | XML, JSON, Grepable | XML, HTML, Grepable, Nmap |
| **Évasion** | Basique (fragmentation limitée) | Avancée (decoy, spoof, proxy) |

**Stratégie recommandée :**
1. **Masscan** → découverte rapide des ports ouverts sur une large plage
2. **Nmap** → approfondissement (OS, version, scripts) sur les ports découverts

### 3.3 Syntaxe Masscan

```bash
# Scan basique : un port sur une IP
# -p80 = port TCP 80 à scanner (HTTP)
sudo masscan 192.168.1.1 -p80

# Scan de plusieurs ports
# -p80,443,22 = liste de ports séparés par des virgules (HTTP, HTTPS, SSH)
sudo masscan 192.168.1.1 -p80,443,22

# Scan d'une plage de ports
# -p1-65535 = tous les ports TCP (notation début-fin)
sudo masscan 192.168.1.1 -p1-65535

# Scan d'un sous-réseau complet
# 192.168.1.0/24 = 256 adresses, -p80,443,22,21 = ports HTTP, HTTPS, SSH, FTP
sudo masscan 192.168.1.0/24 -p80,443,22,21

# Scan avec un rate spécifique (paquets par seconde)
# --rate=1000 = limite le débit à 1000 paquets par seconde (évite de saturer le réseau)
sudo masscan 192.168.1.0/24 -p80,443 --rate=1000

# Scan avec interface spécifique
# -e eth0 = force l'utilisation de l'interface réseau eth0 (utile avec plusieurs interfaces)
sudo masscan -e eth0 10.0.0.0/24 -p80,443

# Scan avec adresse source spécifique
# --src-ip 192.168.1.100 = utilise l'adresse IP source 192.168.1.100 (spoofing)
sudo masscan --src-ip 192.168.1.100 192.168.1.0/24 -p80

# Scan avec port source spécifique
# --src-port 53 = utilise le port source 53 (DNS) pour contourner les pare-feu
sudo masscan --src-port 53 192.168.1.0/24 -p80
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-p <port>` | Port à scanner (simple : -p80, liste : -p80,443, plage : -p1-65535) |
| `--rate=<N>` | Nombre de paquets par seconde (défaut : 100) |
| `-e <interface>` | Spécifie l'interface réseau à utiliser (eth0, wlan0, etc.) |
| `--src-ip <ip>` | Adresse IP source (spoofing) |
| `--src-port <port>` | Port source (pour contourner les règles de pare-feu) |

### 3.4 Options avancées

```bash
# Format de sortie
# -oJ = sortie JSON (format structuré pour parsing automatisé)
# -oX = sortie XML (compatible avec les outils Nmap)
# -oL = sortie liste (format texte simple, une ligne par résultat)
sudo masscan 192.168.1.0/24 -p80,443 \
    --rate=10000 \
    -oJ masscan_result.json \
    -oX masscan_result.xml \
    -oL masscan_result.txt

# Exclure des adresses IP
# --exclude = exclut une adresse spécifique du scan (passerelle, broadcast, etc.)
sudo masscan 192.168.1.0/24 -p80,443 \
    --exclude 192.168.1.1 \
    --exclude 192.168.1.254

# Scan avec timeout
# --wait 10 = attend 10 secondes après le dernier paquet pour recevoir les réponses
sudo masscan 192.168.1.0/24 -p80 --wait 10

# Scan avec ports aléatoires (contournement IDS)
# --shards 4 = divise le scan en 4 parties (shards), les ports sont scannés dans un ordre aléatoire
# Rend le scan moins détectable car il ne suit pas une séquence linéaire
sudo masscan 192.168.1.0/24 -p0-65535 --shards 4

# Scan de multiples plages
# Peut scanner plusieurs plages IP en une seule commande
# 192.168.1.0/24 ET 10.0.0.0/8 (réseau de classe A, 16 millions d'adresses)
sudo masscan 192.168.1.0/24 10.0.0.0/8 -p80,443,22
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-oJ <fichier>` | Sortie JSON (format structuré pour parsing automatisé) |
| `-oX <fichier>` | Sortie XML (compatible Nmap) |
| `-oL <fichier>` | Sortie liste (format texte simple : "open tcp port ip timestamp") |
| `--exclude <ip>` | Exclut une adresse IP du scan |
| `--wait <N>` | Temps d'attente en secondes après le dernier paquet (pour collecter les réponses) |
| `--shards <N>` | Divise le scan en N fragments aléatoires (contournement IDS) |
| `192.168.1.0/24 10.0.0.0/8` | Multiples plages IP en arguments (séparées par des espaces) |

### 3.5 Masscan → Nmap pipeline

```bash
# Étape 1 : Masscan pour trouver les ports ouverts
# --rate=10000 = 10 000 paquets/s, scan complet de tous les ports (1-65535) sur tout le /24
# -oL = sortie liste (format : "open tcp <port> <ip> <timestamp>")
sudo masscan 192.168.1.0/24 -p1-65535 \
    --rate=10000 \
    -oL masscan_ports.txt

# Étape 2 : Extraire les IP:port
# grep "open tcp" = filtre les lignes qui indiquent des ports ouverts
# awk '{print $4 ":" $3}' = extrait la 4e colonne (IP) et la 3e (port) et les concatène avec ":"
# Exemple : "open tcp 80 192.168.1.1 1234567890" → "192.168.1.1:80"
grep "open tcp" masscan_ports.txt | \
    awk '{print $4 ":" $3}' > targets.txt

# Étape 3 : Lancer Nmap sur chaque cible pour le détail
# while read target = lit chaque ligne du fichier targets.txt (format "ip:port")
while read target; do
    # cut -d: -f1 = extrait le premier champ (IP) en coupant sur ":"
    ip=$(echo $target | cut -d: -f1)
    # cut -d: -f2 = extrait le second champ (port)
    port=$(echo $target | cut -d: -f2)
    # Nmap approfondi : -sV (version), -O (OS), --script default,vuln (scripts)
    # -p "$port" = cible uniquement le port découvert par Masscan
    sudo nmap -sV -O -p "$port" --script default,vuln "$ip" -oA "nmap_detail_${ip}_${port}"
done < targets.txt
```

**Explication du pipeline :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `masscan -p1-65535 --rate=10000 -oL` | Scan rapide de masse de tous les ports |
| `grep "open tcp"` | Filtre uniquement les ports ouverts détectés |
| `awk '{print $4 ":" $3}'` | Réorganise les colonnes au format "ip:port" (4e colonne = IP, 3e = port, 2e = protocole) |
| `cut -d: -f1` | Extrait le premier champ (l'IP) d'une chaîne "ip:port" |
| `cut -d: -f2` | Extrait le second champ (le port) |
| `nmap -sV -O -p <port> --script default,vuln` | Scan détaillé Nmap sur le port spécifique identifié par Masscan |

### 3.6 TP Guidé — Scanner 10.0.0.0/24 en 10 secondes

#### Objectif
Scanner le sous-réseau 10.0.0.0/24 pour trouver tous les ports ouverts en moins de 10 secondes.

```bash
# Étape 1 : Déterminer la bande passante disponible
echo "=== Test de bande passante ==="
# Test de débit : envoie à 100 000 pps sur un seul port pour mesurer la capacité réseau
# 2>&1 = redirige stderr vers stdout pour tout capturer
# head -5 = affiche les 5 premières lignes (informations de performance)
# || true = ignore les erreurs (ne pas arrêter le script si le test échoue)
sudo masscan 10.0.0.1 -p80 --rate=100000 2>&1 | head -5 || true

# Étape 2 : Scan complet du /24 en 10 secondes
echo "=== Scan complet 10.0.0.0/24 ==="
mkdir -p rapport-masscan

# time = mesure le temps d'exécution de la commande
# --rate=2000000 = 2 millions de paquets par seconde (très agressif)
# --wait 0 = ne pas attendre les réponses après l'envoi du dernier paquet
# --retries 0 = aucune retransmission en cas de perte (scan purement proactif)
# -oL = sortie liste (format compact)
time sudo masscan 10.0.0.0/24 -p1-65535 \
    --rate=2000000 \
    --wait 0 \
    --retries 0 \
    -oL rapport-masscan/scan-10s.txt

# Si rate trop élevé pour le réseau, réduire
echo "=== Scan avec rate adapté ==="
# Version plus conservative : rate réduit, attente et retransmissions
# --wait 5 = attend 5 secondes les réponses après le dernier paquet
# --retries 1 = 1 retransmission en cas de perte
# -oJ = sortie JSON (format structuré)
time sudo masscan 10.0.0.0/24 -p1-65535 \
    --rate=500000 \
    --wait 5 \
    --retries 1 \
    -oJ rapport-masscan/scan-10s.json
```

**Analyse des paramètres :**
- `--rate=2000000` : 2 millions de paquets par seconde (très agressif)
- `--wait 0` : ne pas attendre les réponses (scan purement proactif)
- `--retries 0` : pas de réessai en cas de perte

```bash
# Étape 3 : Analyser les résultats
echo "=== Analyse des résultats ==="

# Compter le nombre de ports ouverts trouvés
# grep "open tcp" = filtre les résultats de ports ouverts
# wc -l = compte le nombre de lignes (donc le nombre de ports ouverts)
grep "open tcp" rapport-masscan/scan-10s.txt | wc -l

# Afficher les résultats structurés
# awk '{print $4 " → " $3 "/" $2 " (" $5 ")"}' = formate l'affichage
# $4 = IP, $3 = port, $2 = protocole, $5 = timestamp
# Exemple : "192.168.1.1 → 80/tcp (1234567890)"
# sort -t. -k1,1n -k2,2n -k3,3n -k4,4n = tri par IP (tri numérique sur chaque octet)
grep "open tcp" rapport-masscan/scan-10s.txt | \
    awk '{print $4 " → " $3 "/" $2 " (" $5 ")"}' | \
    sort -t. -k1,1n -k2,2n -k3,3n -k4,4n

# Étape 4 : Exporter pour Nmap (approfondissement)
# Extrait les cibles au format "ip:port" pour les passer à Nmap
# awk '{print $4 ":" $3}' = concatène IP et port avec ":"
grep "open tcp" rapport-masscan/scan-10s.txt | \
    awk '{print $4 ":" $3}' > rapport-masscan/targets_nmap.txt

echo "Cibles à approfondir avec Nmap :"
wc -l rapport-masscan/targets_nmap.txt
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `grep "open tcp"` | Filtre les lignes correspondant à des ports TCP ouverts |
| `wc -l` | Compte le nombre de lignes (nombre de ports ouverts) |
| `awk '{print $4 " → " $3 "/" $2}'` | Formate l'affichage : IP → port/protocole |
| `sort -t. -k1,1n -k4,4n` | Tri numérique sur les 4 octets de l'adresse IP (trie par ordre IP) |
| `>` | Redirige les IP:port vers un fichier pour l'étape suivante avec Nmap |

**Résultat attendu :** Scan de 256 adresses IP × 65535 ports = 16 777 216 probes en ~10 secondes (si le réseau et la carte réseau le supportent).

---

## 4. Rustscan — Scan moderne

### 4.1 Installation

```bash
# Installation via cargo
# Nécessite Rust : curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# cargo = gestionnaire de paquets Rust (équivalent de pip pour Python)
cargo install rustscan

# Installation via apt (Kali 2023+)
# Version pré-compilée disponible dans les dépôts Kali récents
sudo apt install -y rustscan

# Installation manuelle
# git clone = télécharge le dépôt officiel (RustScan, écrit en Rust)
git clone https://github.com/RustScan/RustScan.git
cd RustScan
# cargo build --release = compile en mode Release (optimisé pour la vitesse)
cargo build --release
# sudo cp = copie le binaire compilé dans /usr/local/bin/ (accessible dans le PATH)
sudo cp target/release/rustscan /usr/local/bin/

# Vérification
rustscan --version  # Affiche la version installée
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `cargo install rustscan` | Installe RustScan via le gestionnaire de paquets de Rust (compile depuis les sources) |
| `sudo apt install -y rustscan` | Installe la version pré-compilée depuis les dépôts Kali |
| `cargo build --release` | Compile en mode Release (optimisations activées) - le binaire est dans target/release/ |
| `cp target/release/rustscan /usr/local/bin/` | Copie le binaire dans un dossier du PATH système |

### 4.2 Utilisation basique

```bash
# Scan simple d'une IP
# -a = target address (ou --address), l'IP ou le réseau à scanner
rustscan -a 192.168.1.1

# Scan avec plage de ports
# --range 1-65535 = spécifie la plage de ports à scanner (défaut : 1-1000)
rustscan -a 192.168.1.1 --range 1-65535

# Scan de multiples cibles
# -a = liste d'IPs séparées par des virgules (pas d'espaces)
rustscan -a 192.168.1.1,192.168.1.2,192.168.1.3

# Scan d'un sous-réseau
# Notation CIDR supportée directement dans -a
# Rustscan parallélise le scan de toutes les adresses du sous-réseau
rustscan -a 192.168.1.0/24

# Scan avec timeout (ms)
# --timeout 500 = timeout de connexion de 500 millisecondes (défaut : plus élevé)
# Valeur plus basse = scan plus rapide mais peut manquer des hôtes lents
rustscan -a 192.168.1.1 --timeout 500
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-a <cible>` | Adresse cible (IP, domaine, CIDR, ou liste séparée par des virgules) |
| `--range <début-fin>` | Plage de ports à scanner (défaut : 1-1000) |
| `--timeout <ms>` | Timeout de connexion en millisecondes (plus bas = plus rapide) |

### 4.3 Intégration avec Nmap

Rustscan est optimisé pour la rapidité (scan parallélisé en Rust) mais délègue le fingerprinting à Nmap.

```bash
# Intégration Nmap automatique
# -- = séparateur : tout ce qui suit est passé directement à Nmap
# -A = Nmap Aggressive mode (équivaut à -O -sC --traceroute)
# -sV = version detection
rustscan -a 192.168.1.1 -- -A -sV

# Avec scripts NSE
# -sC = scripts NSE par défaut (équivalent de --script default)
rustscan -a 192.168.1.1 -- -sC

# Avec OS detection
# -O = OS detection via TCP/IP stack fingerprinting
rustscan -a 192.168.1.1 -- -O

# Sortie XML Nmap
# -oX = sortie XML Nmap (pour import ou rapport)
# Rustscan a déjà trouvé les ports ouverts, Nmap ne fait que les approfondir
rustscan -a 192.168.1.1 -- -oX scan_result.xml

# Scan complet avec Nmap automatisé
# -p 1-65535 = tous les ports (scannés par Rustscan)
# -- = séparateur Rustscan/Nmap
# -sV = versions, -O = OS, -sC = scripts, --script vuln = vulnérabilités
# -oX = sortie XML
rustscan -a 192.168.1.1 -p 1-65535 -- \
    -sV -O -sC --script vuln \
    -oX rustscan_detailed.xml
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--` | Séparateur : passe tous les arguments suivants à Nmap (pas à Rustscan) |
| `-A` | Mode agressif Nmap : -O + -sC + --traceroute |
| `-sC` | Scripts NSE par défaut |
| `-O` | OS detection |
| `-sV` | Version detection |
| `-oX <fichier>` | Sortie Nmap au format XML |

**Remarque :** Tout ce qui se trouve après `--` est passé directement à Nmap.

### 4.4 Options avancées Rustscan

```bash
# Voir les hôtes actifs sans les scanner en détail
# --greparable = affiche les résultats dans un format facile à parser (une ligne par hôte)
rustscan -a 192.168.1.0/24 --greparable

# Scan avec batch size (nombre de ports par lot)
# --batch 500 = nombre de ports scannés simultanément par lot (défaut : dépend du système)
# Valeur plus élevée = plus de parallélisme = scan plus rapide mais plus de trafic
rustscan -a 192.168.1.1 --batch 500

# Scan avec ports personnalisés
# -p = liste de ports spécifiques (équivalent de --range mais pour des valeurs discrètes)
rustscan -a 192.168.1.1 -p 22,80,443,3306,8080

# Scan avec timeouts réduits (plus rapide)
# -t 100 = timeout de 100 ms par connexion (très rapide, peut manquer des réponses lentes)
rustscan -a 192.168.1.1 -t 100

# Activer le mode verbose
# -v = verbose : affiche plus de détails pendant le scan (progression, etc.)
rustscan -a 192.168.1.1 -v

# Utiliser une liste de cibles depuis un fichier
# -a targets.txt = Rustscan détecte automatiquement si l'argument est un fichier ou une IP
# Le fichier doit contenir une cible par ligne (IP, domaine ou CIDR)
rustscan -a targets.txt
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--greparable` | Format de sortie facile à parser (une ligne par hôte) |
| `--batch <N>` | Nombre de ports scannés en parallèle par lot |
| `-p <ports>` | Liste de ports spécifiques (séparés par des virgules) |
| `-t <ms>` | Timeout de connexion en millisecondes |
| `-v` | Mode verbose (affiche la progression) |
| `-a <fichier>` | Lit les cibles depuis un fichier texte |

### 4.5 Comparaison Rustscan vs Masscan vs Nmap

```bash
# Benchmark : scan d'un /24 sur 1000 ports top
# time = mesure le temps d'exécution de chaque commande pour comparer les performances
# Masscan : rate élevé (500 000 pps) sur les 1000 ports les plus courants
time sudo masscan 192.168.1.0/24 --top-ports 1000 --rate=500000
# Rustscan : timeout réduit (200 ms), plage 1-1000
time rustscan -a 192.168.1.0/24 --range 1-1000 -t 200
# Nmap : profil agressif T4, top 1000 ports (point de comparaison)
time sudo nmap -sS -T4 --top-ports 1000 192.168.1.0/24
```

**Explication du benchmark :**
| Commande | Outil | Objectif |
|----------|-------|----------|
| `time sudo masscan ... --rate=500000` | Masscan | Mesure du temps pour scanner 256 IP × 1000 ports à 500 000 pps |
| `time rustscan ... -t 200` | Rustscan | Mesure avec timeout de 200 ms, parallélisation native Rust |
| `time sudo nmap -sS -T4` | Nmap | Référence : scan Nmap standard sur les mêmes cibles |

**Résultats typiques (sur réseau 1 Gbps) :**

| Outil | Temps | Précision | Détails |
|-------|-------|-----------|---------|
| Masscan | ~3s | Moyenne | Aucun (IP:port seulement) |
| Rustscan | ~15s | Bonne | Intégration Nmap possible |
| Nmap | ~5min | Excellente | OS, versions, scripts |

### 4.6 TP Guidé — Rustscan

#### Objectif
Utiliser Rustscan pour découvrir rapidement les services ouverts sur un sous-réseau, puis approfondir avec Nmap.

```bash
# Étape 1 : Découverte rapide avec Rustscan
# === EXÉCUTER SUR LA MACHINE ATTAQUANTE (Kali) ===
# Cible : Adapter 192.168.1.0/24 à votre sous-réseau (ex: 10.0.1.0/24 pour le lab AD Docker)
echo "=== ÉTAPE 1 : SCAN RUSTSCAN ==="
mkdir -p rapport-rustscan  # Crée le dossier de rapport

# Rustscan sur tout le /24, ports 1-1000
# -t 200 = timeout de 200 ms (rapide), -b 1000 = batch de 1000 ports en parallèle
# --greparable = format de sortie lisible pour parsing
# -o = fichier de sortie
rustscan -a 192.168.1.0/24 \
    --range 1-1000 \
    -t 200 \
    -b 1000 \
    --greparable \
    -o rapport-rustscan/scan-initial.txt

cat rapport-rustscan/scan-initial.txt  # Affiche le résultat

# Étape 2 : Approfondir chaque hôte avec Nmap
echo "=== ÉTAPE 2 : APPROFONDISSEMENT ==="

# grep -oP '\d+\.\d+\.\d+\.\d+' = extrait les adresses IP du fichier de résultat
# sort -u = trie et supprime les doublons
grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' rapport-rustscan/scan-initial.txt | \
    sort -u > rapport-rustscan/hosts.txt

# Pour chaque hôte découvert, lance un scan complet avec Nmap
while read ip; do
    echo "Approfondissement : $ip"
    # Rustscan trouve tous les ports (1-65535), -- = passe les arguments à Nmap
    # Nmap : -sV (versions), -O (OS), -sC (scripts), --script vuln (vulnérabilités)
    # -oA = sortie dans tous les formats
    rustscan -a "$ip" --range 1-65535 -t 300 -- \
        -sV -O -sC --script vuln \
        -oA "rapport-rustscan/detailed-$ip"
done < rapport-rustscan/hosts.txt

# Étape 3 : Générer un rapport consolidé
echo "=== ÉTAPE 3 : RAPPORT ==="
echo "Rapport Rustscan - $(date)" > rapport-rustscan/resume.txt

# Pour chaque hôte, extrait les ports associés depuis le scan initial
while read ip; do
    # grep "$ip" = trouve les lignes contenant cette IP
    # tr '\n' ' ' = remplace les retours à la ligne par des espaces (mise en forme)
    ports=$(grep "$ip" rapport-rustscan/scan-initial.txt | tr '\\n' ' ')
    echo "$ip : $ports" >> rapport-rustscan/resume.txt
done < rapport-rustscan/hosts.txt

echo "[✓] Scan Rustscan terminé. Voir rapport-rustscan/"
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `mkdir -p` | Crée le dossier parent si nécessaire |
| `-t 200` | Timeout Rustscan en millisecondes (200 = très rapide) |
| `-b 1000` | Batch size : 1000 ports scannés en parallèle |
| `--greparable` | Format de sortie facile à parser par ligne |
| `-o <fichier>` | Fichier de sortie pour les résultats |
| `grep -oP '\d+\.\d+\.\d+\.\d+'` | Extrait les adresses IP avec une expression régulière Perl |
| `sort -u` | Trie et supprime les doublons |
| `-- -sV -O -sC` | -- sépare Rustscan de Nmap ; -sV -O -sC sont passés à Nmap |

---

## 5. Énumération de services

### 5.1 SMB — Server Message Block (T1049)

Le protocole SMB est utilisé pour le partage de fichiers, d'imprimantes et de ports COM dans les réseaux Windows.

#### smbclient — Client SMB en ligne de commande

```bash
# Lister les partages SMB (sans authentification)
# smbclient -L = list les partages disponibles sur le serveur SMB
# //192.168.1.1 = adresse du serveur SMB (notation UNC : double slash)
# -N = no password (tente une connexion sans mot de passe)
smbclient -L //192.168.1.1 -N

# Lister les partages avec authentification anonyme
# -U "" = utilisateur vide (connexion anonyme)
# -N = no password
smbclient -L //192.168.1.1 -U "" -N

# Lister les partages avec un nom d'utilisateur
# -U "administrateur" = tente de se connecter avec ce nom d'utilisateur (mot de passe demandé interactivement)
smbclient -L //192.168.1.1 -U "administrateur"

# Connexion à un partage spécifique
# //192.168.1.1/partage = UNC vers le partage nommé "partage"
# -U "utilisateur" = authentification avec ce nom d'utilisateur
smbclient //192.168.1.1/partage -U "utilisateur"

# Connexion avec un fichier de credentials
# -A credentials.txt = fichier contenant nom d'utilisateur et mot de passe (format : username=... password=...)
smbclient //192.168.1.1/partage -A credentials.txt

# Mode sans mot de passe (session null)
# -U "%" = utilisateur "%" (mot de passe vide), -N = no password
# Tente une session null (souvent acceptée par défaut sur les anciens Windows)
smbclient //192.168.1.1/partage -U "%" -N

# Télécharger tous les fichiers d'un partage
# -c 'prompt OFF; recurse ON; mget *' = commandes smbclient exécutées en mode non-interactif
# prompt OFF = ne pas demander confirmation pour chaque fichier
# recurse ON = parcourir les sous-dossiers récursivement
# mget * = télécharger tous les fichiers (multi-get)
smbclient //192.168.1.1/partage -N -c 'prompt OFF; recurse ON; mget *'
```

**Explication des options smbclient :**
| Option | Rôle/Explication |
|--------|------------------|
| `-L <serveur>` | Liste les partages disponibles (équivalent de "net view" Windows) |
| `-N` | No password : tente la connexion sans fournir de mot de passe |
| `-U <utilisateur>` | Nom d'utilisateur pour l'authentification |
| `-A <fichier>` | Fichier de credentials (username=..., password=..., domain=...) |
| `-c '<commandes>'` | Exécute des commandes smbclient en mode non-interactif |
| `prompt OFF` | Désactive les confirmations interactives |
| `recurse ON` | Active le parcours récursif des dossiers |
| `mget *` | Télécharge tous les fichiers (multi-get) |

**Interaction après connexion :**

```bash
# Connexion interactive à un partage SMB
smbclient //192.168.1.1/partage -U "admin"
# Une fois connecté, l'invite smb: \> apparaît, les commandes suivantes sont disponibles :
# → smb: \> ls              # Lister les fichiers et dossiers du partage
# → smb: \> cd dossier      # Changer de répertoire courant
# → smb: \> get fichier.txt # Télécharger un fichier distant vers la machine locale
# → smb: \> put local.txt   # Uploader un fichier local vers le partage
# → smb: \> mkdir test      # Créer un nouveau dossier sur le partage (si droits d'écriture)
# → smb: \> rm fichier.txt  # Supprimer un fichier sur le partage
# → smb: \> exit            # Quitter smbclient
```

**Explication des commandes interactives smbclient :**
| Commande | Rôle/Explication |
|----------|------------------|
| `ls` | Liste les fichiers et dossiers du partage courant |
| `cd <dossier>` | Change le répertoire courant |
| `get <fichier>` | Télécharge (download) un fichier du partage vers la machine locale |
| `put <fichier>` | Envoie (upload) un fichier local vers le partage |
| `mkdir <dossier>` | Crée un nouveau dossier sur le partage |
| `rm <fichier>` | Supprime un fichier sur le partage |
| `exit` | Quitte smbclient |

#### enum4linux — Énumération complète SMB

```bash
# Installation
sudo apt install -y enum4linux  # enum4linux = script Perl d'énumération SMB

# Énumération complète (tout en un)
# -a = all : exécute toutes les énumérations (OS, utilisateurs, partages, groupes, politiques, etc.)
enum4linux -a 192.168.1.1

# Énumération de l'OS
# -o = OS detection : identifie le système d'exploitation via SMB
enum4linux -o 192.168.1.1

# Énumération des utilisateurs (via RID cycling)
# -U = users : énumère les utilisateurs via la technique du RID cycling
# RID cycling = interroge les RID de 500 à 5000 pour découvrir les comptes
enum4linux -U 192.168.1.1

# Énumération des partages
# -S = shares : liste les partages SMB disponibles (ressources partagées)
enum4linux -S 192.168.1.1

# Énumération des groupes
# -G = groups : liste les groupes locaux et du domaine
enum4linux -G 192.168.1.1

# Énumération des politiques de mot de passe
# -P = password policy : récupère la politique de mot de passe (complexité, verrouillage, durée)
enum4linux -P 192.168.1.1

# Version étendue (enum4linux-ng)
# Version réécrite en Python avec plus de fonctionnalités
sudo apt install -y enum4linux-ng
enum4linux-ng -A 192.168.1.1  # -A = all (tout énumérer)
enum4linux-ng -A -oY 192.168.1.1  # -oY = sortie YAML (format structuré)
enum4linux-ng -A -oJ 192.168.1.1  # -oJ = sortie JSON (format structuré)
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-a` | All : exécute toutes les énumérations disponibles |
| `-o` | OS detection via SMB (bannière, version) |
| `-U` | User enumeration via RID cycling (RID 500 = admin, 501 = invité, 1000+ = utilisateurs) |
| `-S` | Share enumeration : liste les partages SMB |
| `-G` | Group enumeration : groupes locaux et domaine |
| `-P` | Password policy : récupère les règles de mot de passe |
| `-A` | (enum4linux-ng) All : tout énumérer |
| `-oY` | (enum4linux-ng) Sortie YAML |
| `-oJ` | (enum4linux-ng) Sortie JSON |

**RID Cycling expliqué :**
- RID (Relative Identifier) : identifiant unique pour chaque utilisateur/groupe
- Le RID 500 = administrateur, 501 = invité, 1000+ = utilisateurs créés
- enum4linux interroge les RID de 500 à 5000 pour trouver tous les utilisateurs

#### CrackMapExec (CME) — Framework SMB avancé

```bash
# Installation
sudo apt install -y crackmapexec  # Framework d'énumération et d'exploitation (Python)

# Énumération des partages
# smb = protocole cible (CME supporte aussi ssh, winrm, mssql, ldap, etc.)
# --shares = liste les partages SMB accessibles
crackmapexec smb 192.168.1.1 --shares

# Énumération des utilisateurs
# --users = énumère les utilisateurs du domaine via SAMR
crackmapexec smb 192.168.1.1 --users

# Énumération des groupes
# --groups = liste les groupes locaux et du domaine
crackmapexec smb 192.168.1.1 --groups

# Énumération des sessions actives
# --sessions = liste les sessions SMB actives (connexions en cours)
crackmapexec smb 192.168.1.1 --sessions

# Énumération des disques
# --disks = liste les disques partagés (C$, D$, ADMIN$, etc.)
crackmapexec smb 192.168.1.1 --disks

# Test d'accès anonyme
# -u '' -p '' = utilisateur vide et mot de passe vide (null session)
crackmapexec smb 192.168.1.1 -u '' -p ''

# Test de mot de passe faible
# -u 'admin' -p 'admin' = teste les credentials par défaut les plus courants
crackmapexec smb 192.168.1.1 -u 'admin' -p 'admin'

# Vérification MS17-010 (EternalBlue)
# -M ms17-010 = module de vérification de la vulnérabilité EternalBlue
crackmapexec smb 192.168.1.1 -u 'user' -p 'pass' -M ms17-010

# Exécution de commande via SMB (si admin)
# -x 'whoami' = exécute une commande shell à distance via SMB (nécessite admin)
crackmapexec smb 192.168.1.1 -u 'admin' -p 'password' -x 'whoami'

# Dump des hashs SAM (si admin)
# --sam = extrait les hashs de mots de passe du registre SAM (Security Account Manager)
crackmapexec smb 192.168.1.1 -u 'admin' -p 'password' --sam

# Dump des hashs LSA Secrets
# --lsa = extrait les secrets LSA (mots de passe de services, clés, etc.)
crackmapexec smb 192.168.1.1 -u 'admin' -p 'password' --lsa

# Module Spider+ (chercher des fichiers spécifiques)
# -M spider_plus = module de recherche de fichiers dans les partages
# -o = options du module : READ_ONLY=false (lecture et écriture), OUTPUT_FOLDER (dossier de sortie)
crackmapexec smb 192.168.1.1 -u 'admin' -p 'pass' -M spider_plus \
    -o READ_ONLY=false OUTPUT_FOLDER=cme_spider

# Test sur plusieurs hôtes
# 192.168.1.0/24 = CIDR : CME teste tous les hôtes du sous-réseau
crackmapexec smb 192.168.1.0/24 -u 'admin' -p 'password' --shares

# Utiliser des hashs (Pass-the-Hash)
# -H 'LMHASH:NTHASH' = utilise les hashs directement au lieu du mot de passe en clair
# Attaque Pass-the-Hash : s'authentifie avec le hash NTLM sans connaître le mot de passe
crackmapexec smb 192.168.1.1 -u 'admin' -H 'LMHASH:NTHASH' --shares
```

**Explication des options CME :**
| Option | Rôle/Explication |
|--------|------------------|
| `smb <cible>` | Protocole SMB (CME gère aussi : ssh, winrm, mssql, ldap, ftp) |
| `--shares` | Énumère les partages SMB accessibles |
| `--users` | Énumère les utilisateurs du domaine |
| `--groups` | Énumère les groupes |
| `--sessions` | Liste les sessions actives |
| `--disks` | Liste les disques partagés (C$, ADMIN$, etc.) |
| `-u <user> -p <pass>` | Credentials pour l'authentification |
| `-M <module>` | Charge un module (ms17-010, spider_plus, etc.) |
| `-x <commande>` | Exécute une commande shell à distance |
| `--sam` | Dump les hashs SAM (nécessite admin) |
| `--lsa` | Dump les secrets LSA (nécessite admin) |
| `-H <hash>` | Pass-the-Hash : s'authentifie avec le hash NTLM |

#### smbmap — Cartographie des partages

```bash
# Installation
sudo apt install -y smbmap  # smbmap = outil de cartographie des partages SMB

# Énumération des partages (null session)
# -H = host cible, -u '' -p '' = session nulle (sans authentification)
smbmap -H 192.168.1.1 -u '' -p ''

# Énumération avec authentification
smbmap -H 192.168.1.1 -u 'admin' -p 'password'

# Énumération récursive des partages accessibles
# -R = recursive : parcourt les dossiers récursivement
smbmap -H 192.168.1.1 -u '' -p '' -R

# Recherche de fichiers spécifiques
# -F "*.txt" = filtre par motif (tous les fichiers .txt)
smbmap -H 192.168.1.1 -u '' -p '' -R -F "*.txt"

# Upload de fichier
# --upload 'local.txt' 'remote.txt' = upload du fichier local vers le chemin distant
smbmap -H 192.168.1.1 -u 'admin' -p 'password' --upload 'local.txt' 'remote.txt'

# Download de fichier
# --download 'C$/Users/admin/secret.txt' = télécharge un fichier depuis un partage administratif
# C$ = partage administratif du disque système C:
smbmap -H 192.168.1.1 -u 'admin' -p 'password' --download 'C$/Users/admin/secret.txt'
```

**Explication des options smbmap :**
| Option | Rôle/Explication |
|--------|------------------|
| `-H <host>` | Adresse du serveur SMB cible |
| `-u <user> -p <pass>` | Credentials d'authentification |
| `-R` | Mode récursif : parcourt les sous-dossiers |
| `-F <motif>` | Filtre les fichiers par motif (wildcard : *.txt, *.docx, etc.) |
| `--upload <src> <dst>` | Upload un fichier local vers le partage distant |
| `--download <path>` | Download un fichier depuis le partage distant |

### 5.2 SNMP — Simple Network Management Protocol (T1046)

SNMP est utilisé pour la gestion des équipements réseau. Il expose énormément d'informations si la communauté est faible.

#### Installation

```bash
# Outils SNMP
# snmp = client SNMP (snmpwalk, snmpget, snmpset), snmp-mibs-downloader = base MIB standard
sudo apt install -y snmp snmp-mibs-downloader
sudo download-mibs  # Télécharge et installe les MIBs (Management Information Bases) standard

# Configuration pour utiliser les MIBs
# echo "mibs +ALL" = ajoute la directive pour charger toutes les MIBs
# tee -a /etc/snmp/snmp.conf = écrit ET affiche, -a = ajoute à la fin du fichier
echo "mibs +ALL" | sudo tee -a /etc/snmp/snmp.conf

# onesixtyone (brute-force de communautés)
# Outil de scan SNMP rapide qui teste plusieurs community strings
sudo apt install -y onesixtyone

# snmp-check
# Outil de rapport SNMP automatisé (énumération complète en une commande)
sudo apt install -y snmpcheck
```

**Explication des outils :**
| Outil | Rôle/Explication |
|-------|------------------|
| `snmp` | Client SNMP de base (inclut snmpwalk, snmpget, snmpset, snmptrap) |
| `snmp-mibs-downloader` | Télécharge les MIBs standards (traduit les OIDs en noms lisibles) |
| `download-mibs` | Script de téléchargement des MIBs |
| `"mibs +ALL"` | Directive de configuration pour charger toutes les MIBs (évite les OIDs numériques illisibles) |
| `/etc/snmp/snmp.conf` | Fichier de configuration global SNMP |
| `onesixtyone` | Scan SNMP rapide : teste des community strings sur une plage IP |
| `snmpcheck` | Rapport automatisé d'énumération SNMP |

#### snmpwalk — Énumération SNMP

```bash
# Walk complet de l'arbre OID (public community)
# snmpwalk = parcourt récursivement l'arbre SNMP (OID par OID)
# -v2c = version SNMP v2c (la plus courante), -c public = community string "public" (défaut)
snmpwalk -v2c -c public 192.168.1.1

# Walk avec version 1
# -v1 = version SNMP v1 (plus ancienne, moins de fonctionnalités mais supportée partout)
snmpwalk -v1 -c public 192.168.1.1

# Walk d'une OID spécifique (système)
# 1.3.6.1.2.1.1 = OID "system" : nom d'hôte, description, version, uptime, localisation
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1

# Walk des interfaces réseau
# 1.3.6.1.2.1.2 = OID "interfaces" : liste des interfaces, adresses MAC, débits, statut
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.2

# Walk des processus en cours
# 1.3.6.1.2.1.25.4.2.1.2 = OID "hrSWRunName" : noms des processus en cours d'exécution
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.25.4.2.1.2

# Walk des utilisateurs
# 1.3.6.1.4.1.77.1.2.25 = OID propriétaire Microsoft : liste des utilisateurs Windows
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.4.1.77.1.2.25

# Walk des partages Windows
# 1.3.6.1.4.1.77.1.2.27 = OID propriétaire Microsoft : liste des partages SMB
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.4.1.77.1.2.27

# Walk des logiciels installés
# 1.3.6.1.2.1.25.6.3.1.2 = OID "hrSWInstalledName" : noms des logiciels installés
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.25.6.3.1.2

# Walk du stockage
# 1.3.6.1.2.1.25.2.3.1.3 = OID "hrStorageDescr" : description des points de montage/disques
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.25.2.3.1.3
```

**Explication des options :**
| Option | OID | Rôle/Explication |
|--------|-----|------------------|
| `-v2c` | | Version SNMP v2c (communauté en clair, sans chiffrement) |
| `-v1` | | Version SNMP v1 (plus ancienne, rétrocompatible) |
| `-c public` | | Community string "public" (lecture seule par défaut) |
| | 1.3.6.1.2.1.1 | system : nom d'hôte, OS, version, uptime, localisation |
| | 1.3.6.1.2.1.2 | interfaces : cartes réseau, MAC, débit |
| | 1.3.6.1.2.1.25.4.2.1.2 | hrSWRunName : processus en cours |
| | 1.3.6.1.4.1.77.1.2.25 | Utilisateurs Windows (OID Microsoft) |
| | 1.3.6.1.4.1.77.1.2.27 | Partages Windows (OID Microsoft) |
| | 1.3.6.1.2.1.25.6.3.1.2 | Logiciels installés |
| | 1.3.6.1.2.1.25.2.3.1.3 | Points de montage/disques |

**OIDs SNMP utiles :**

| OID | Description |
|-----|-------------|
| 1.3.6.1.2.1.1.1.0 | Description du système |
| 1.3.6.1.2.1.1.5.0 | Nom d'hôte |
| 1.3.6.1.2.1.1.6.0 | Localisation |
| 1.3.6.1.2.1.25.4.2.1.2 | Processus en cours |
| 1.3.6.1.2.1.25.6.3.1.2 | Logiciels installés |
| 1.3.6.1.2.1.2.2.1.2 | Interfaces réseau |
| 1.3.6.1.4.1.77.1.2.25 | Utilisateurs Windows |
| 1.3.6.1.4.1.77.1.2.27 | Partages Windows |
| 1.3.6.1.4.1.77.1.4.1 | Sessions SMB |
| 1.3.6.1.2.1.25.2.3.1.3 | Points de montage |

#### onesixtyone — Brute-force de communautés SNMP

```bash
# Scanner un réseau avec des communautés par défaut
# onesixtyone = scan SNMP rapide, teste la community "public" par défaut
onesixtyone 192.168.1.0/24

# Avec une liste de communautés personnalisée
# echo -e = interprète les séquences d'échappement (\n = retour à la ligne)
# Crée un fichier de community strings à tester (public, private, manager, secret, snmp, admin)
echo -e "public\nprivate\nmanager\nsecret\nsnmp\nadmin" > community.txt
# -c community.txt = utilise cette liste de communities au lieu de la valeur par défaut
onesixtyone -c community.txt 192.168.1.0/24

# Avec timeout et délai personnalisés
# -t 5000 = timeout de 5 secondes (5000 ms), -d 100 = délai de 100 ms entre les envois
onesixtyone -c community.txt -t 5000 -d 100 192.168.1.0/24

# Sortie vers fichier
# -o snmp_results.txt = écrit les résultats dans le fichier spécifié
onesixtyone -c community.txt -o snmp_results.txt 192.168.1.0/24
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-c <fichier>` | Fichier contenant les community strings à tester (une par ligne) |
| `-t <ms>` | Timeout en millisecondes (attente max de réponse) |
| `-d <ms>` | Délai en millisecondes entre l'envoi de chaque paquet |
| `-o <fichier>` | Fichier de sortie pour les résultats |

#### snmp-check — Rapport SNMP automatisé

```bash
# Scan complet d'une cible SNMP
# snmp-check = outil de rapport automatisé (utilise snmpwalk en interne)
# -c public = community string, -v2c = version SNMP
snmp-check 192.168.1.1 -c public -v2c

# Scan avec timeout
# -t 10 = timeout de 10 secondes (défaut plus long)
snmp-check 192.168.1.1 -c public -v2c -t 10

# Sortie vers fichier
# > rapport-snmp.txt = redirige toute la sortie vers un fichier
snmp-check 192.168.1.1 -c public -v2c > rapport-snmp.txt
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-c <community>` | Community string SNMP (public, private, etc.) |
| `-v2c` | Version SNMP v2c (chiffrement par communauté) |
| `-t <secondes>` | Timeout en secondes |
| `> fichier` | Redirection de la sortie standard vers un fichier |

### 5.3 DNS — Domain Name System (T1590)

#### dig — Domain Information Groper

```bash
# Résolution DNS simple
# dig = Domain Information Groper, outil DNS le plus complet
dig example.com

# Requête vers un serveur DNS spécifique
# @8.8.8.8 = interroge le serveur DNS Google (au lieu du DNS configuré sur la machine)
dig @8.8.8.8 example.com

# Type d'enregistrement spécifique
dig example.com A          # A = IPv4 address record (enregistrement IPv4)
dig example.com AAAA       # AAAA = IPv6 address record (enregistrement IPv6)
dig example.com MX         # MX = Mail Exchange (serveur de messagerie)
dig example.com NS         # NS = Name Servers (serveurs DNS autoritaires)
dig example.com CNAME      # CNAME = Canonical Name (alias de domaine)
dig example.com TXT        # TXT = Text records (SPF, DKIM, DMARC, vérifications)
dig example.com SOA        # SOA = Start of Authority (informations de zone)
dig example.com ANY        # ANY = tous les types d'enregistrements

# Résolution inverse (PTR)
# -x = reverse lookup : trouve le nom de domaine associé à une IP
dig -x 8.8.8.8

# Tente de transfert de zone
# AXFR = type de requête pour le transfert complet de zone DNS
# Réussir expose tous les enregistrements DNS du domaine (faille critique)
dig @ns1.example.com example.com AXFR

# Transfert de zone avec short output
# +short = affichage court (une ligne par résultat, sans détails)
dig @ns1.example.com example.com AXFR +short

# Affichage court
# +short = mode résumé : n'affiche que l'essentiel (l'adresse IP par exemple)
dig example.com +short

# Suivi de la délégation DNS
# +trace = suit la résolution DNS depuis la racine (.) jusqu'au serveur autoritaire
# Affiche chaque étape : root → TLD → serveur autoritaire
dig example.com +trace

# Résolution avec DNSSEC
# +dnssec = ajoute les enregistrements RRSIG pour vérifier l'authenticité DNSSEC
dig example.com +dnssec

# Batch lookup (depuis un fichier)
# -f domains.txt = lit les domaines depuis un fichier (un par ligne) et résout chacun
# +short = affichage court
dig -f domains.txt +short
```

**Explication des options dig :**
| Option | Rôle/Explication |
|--------|------------------|
| `@<serveur>` | Interroge un serveur DNS spécifique (par défaut : celui configuré dans /etc/resolv.conf) |
| `-x <ip>` | Résolution inverse PTR (Reverse DNS lookup) |
| `AXFR` | Type de requête pour le transfert de zone complet (Authoritative Transfer) |
| `+short` | Affichage court (une ligne par résultat) |
| `+trace` | Suit la résolution depuis la racine DNS |
| `+dnssec` | Inclut les enregistrements DNSSEC (RRSIG) |
| `-f <fichier>` | Lit les requêtes depuis un fichier (batch mode) |

#### nslookup — Simple DNS lookup

```bash
# Résolution de nom
nslookup example.com

# Résolution avec serveur spécifique
nslookup example.com 8.8.8.8

# Mode interactif
nslookup           # Lance le mode interactif
> server 8.8.8.8   # Change le serveur DNS utilisé
> set type=MX      # Définit le type d'enregistrement à interroger (Mail Exchange)
> example.com      # Interroge le domaine example.com
> set type=ANY     # Change pour tous les types d'enregistrements
> example.com      # Ré-interroge avec le nouveau type
> ls -d example.com  # Tentative de zone transfer (lister toute la zone DNS)
> exit             # Quitte nslookup

# Résolution inverse
nslookup 8.8.8.8

# Type MX
nslookup -type=MX example.com

# Type TXT
nslookup -type=TXT example.com
```

**Explication des options nslookup :**
| Option | Rôle/Explication |
|--------|------------------|
| `nslookup <domaine>` | Résout un nom de domaine en adresse IP |
| `nslookup <domaine> <serveur>` | Résout en utilisant un serveur DNS spécifique |
| `set type=<type>` | Change le type d'enregistrement (A, AAAA, MX, NS, TXT, ANY, etc.) |
| `server <ip>` | Change le serveur DNS interrogé |
| `ls -d <domaine>` | Tente un transfert de zone (lister tous les enregistrements) |
| `-type=<type>` | Spécifie le type d'enregistrement directement en ligne de commande |

#### dnsrecon — Énumération DNS avancée

```bash
# Installation
sudo apt install -y dnsrecon  # Outil d'énumération DNS avancé

# Énumération de base
# -d = domaine cible (target domain)
dnsrecon -d example.com

# Transfert de zone
# -t axfr = type de test : tente un transfert de zone (AXFR)
dnsrecon -d example.com -t axfr

# Brute-force de sous-domaines
# -D = fichier de dictionnaire (wordlist), -t brt = type brute force
dnsrecon -d example.com -D /usr/share/wordlists/amass/subdomains-top1mil.txt -t brt

# Énumération SRV (services)
# -t srv = recherche les enregistrements SRV (services : LDAP, Kerberos, SIP, etc.)
dnsrecon -d example.com -t srv

# Énumération avec résolution inverse
# -t rvl = reverse lookup, -r = plage IP à interroger en inverse
dnsrecon -d example.com -t rvl -r 192.168.1.0/24

# Détection de DNS wildcard
# -t wild = vérifie si le domaine utilise un wildcard DNS (*.example.com → même IP)
dnsrecon -d example.com -t wild

# Scan complet
# -t std = standard : NS, SOA, MX, SPF, etc.
dnsrecon -d example.com -t std
# -t brt avec dictionary, -c output.csv = sortie CSV
dnsrecon -d example.com -D subdomains.txt -t brt -c output.csv
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-d <domaine>` | Domaine cible de l'énumération |
| `-t <type>` | Type de test : axfr (zone transfer), brt (bruteforce), srv, rvl (reverse), wild, std |
| `-D <fichier>` | Fichier de dictionnaire pour le brute-force de sous-domaines |
| `-r <CIDR>` | Plage IP pour la résolution inverse |
| `-c <fichier>` | Sortie CSV (Comma-Separated Values) |

#### dnsenum — Énumération DNS exhaustive

```bash
# Installation
sudo apt install -y dnsenum  # Outil d'énumération DNS exhaustive

# Énumération complète (par défaut)
dnsenum example.com

# Avec brute force de sous-domaines
# --enum = énumération complète, -f = fichier de wordlist pour sous-domaines
dnsenum --enum example.com -f /usr/share/wordlists/dnsmap.txt

# Avec thread
# --threads 10 = parallélisation sur 10 threads (accélère le brute-force)
dnsenum --threads 10 example.com

# Avec sortie vers fichier
# -o dnsenum_output.xml = fichier de sortie au format XML
dnsenum example.com -o dnsenum_output.xml

# Énumération complète avec tout
# --dnsserver 8.8.8.8 = serveur DNS à interroger
# --threads 20 = 20 threads parallèles
# --timeout 10 = timeout de 10 secondes
# --pages 5 = nombre de pages à scraper sur Google
# --scrap 1 = active le scraping de sous-domaines via Google
# --file = wordlist pour brute-force
# --enum = mode énumération complète
dnsenum \
    --dnsserver 8.8.8.8 \
    --threads 20 \
    --timeout 10 \
    --pages 5 \
    --scrap 1 \
    --file /usr/share/wordlists/dnsmap.txt \
    --enum \
    example.com
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--enum` | Mode énumération complète (tous les tests) |
| `-f <fichier>` | Wordlist pour le brute-force de sous-domaines |
| `--threads <N>` | Nombre de threads parallèles |
| `--timeout <s>` | Timeout en secondes pour les requêtes DNS |
| `--pages <N>` | Nombre de pages Google à scraper pour trouver des sous-domaines |
| `--scrap <0/1>` | Active/désactive le scraping Google |
| `--dnsserver <ip>` | Serveur DNS utilisé pour les requêtes |
| `-o <fichier>` | Fichier de sortie XML |

#### Zone Transfer — La faille classique du DNS

```bash
# Test de zone transfer avec dig
# for ns in $(dig ... NS +short) = boucle sur tous les serveurs DNS autoritaires
for ns in $(dig example.com NS +short); do
    echo "=== Test NS: $ns ==="
    # dig @$ns example.com AXFR +short = tente un transfert de zone sur chaque serveur
    dig @$ns example.com AXFR +short
done

# Test de zone transfer avec dnsrecon
dnsrecon -d example.com -t axfr

# Test de zone transfer avec nmap
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 example.com

# Script bash complet de test de zone transfer
#!/bin/bash
DOMAIN="${1}"                           # Premier argument : domaine à tester
if [ -z "$DOMAIN" ]; then               # Vérifie si un domaine a été fourni
    echo "Usage: $0 <domain>"
    exit 1
fi

NAMESERVERS=$(dig "$DOMAIN" NS +short)  # Récupère les serveurs NS autoritaires

for ns in $NAMESERVERS; do              # Teste chaque serveur NS
    echo "[*] Test de $ns..."
    RESULT=$(dig @"$ns" "$DOMAIN" AXFR +short 2>&1)  # Tente le transfert AXFR
    if [ -n "$RESULT" ]; then           # Si le résultat n'est pas vide = réussi
        echo "[✓] Zone transfer réussi depuis $ns !"
        dig @"$ns" "$DOMAIN" AXFR +noall +answer  # Affiche les enregistrements
    else
        echo "[✗] Zone transfer refusé par $ns"
    fi
    echo ""
done
```

**Explication du script de zone transfer :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `dig <domaine> NS +short` | Récupère les serveurs de noms autoritaires pour le domaine |
| `dig @<ns> <domaine> AXFR +short` | Tente un transfert de zone (AXFR) sur le serveur NS spécifié |
| `+noall +answer` | Affiche uniquement les enregistrements de réponse (pas les métadonnées) |
| `-n "$RESULT"` | Vérifie si la variable n'est pas vide (zone transfer réussi) |
| **Faille** | Un transfert de zone réussi expose tous les enregistrements DNS (sous-domaines, IPs, MX, etc.) |

### 5.4 LDAP — Lightweight Directory Access Protocol (T1087)

L'annuaire LDAP (Active Directory) contient l'intégralité des utilisateurs, groupes, ordinateurs et politiques de sécurité.

#### ldapsearch — Client LDAP standard

```bash
# Installation des outils LDAP
sudo apt install -y ldap-utils  # Paquet contenant ldapsearch, ldapadd, ldapmodify, etc.

# Requête LDAP basique (sans auth)
# -x = authentification simple (pas SASL), -H = URI du serveur LDAP
# -b = base DN (Distinguished Name = point de départ de la recherche)
ldapsearch -x -H ldap://192.168.1.1 -b "dc=example,dc=com"

# Requête avec authentification simple
# -D = bind DN (identifiant de connexion LDAP)
# -w = mot de passe en clair (attention : visible dans les logs)
# -b = base DN pour la recherche
ldapsearch -x -H ldap://192.168.1.1 \
    -D "cn=admin,dc=example,dc=com" \
    -w "password" \
    -b "dc=example,dc=com"

# Énumération de tous les utilisateurs
# -s sub = scope "subtree" (recherche récursive dans tout l'arbre)
# "(objectClass=user)" = filtre : objets de type "user"
# sAMAccountName displayName mail = attributs à retourner (login, nom, email)
ldapsearch -x -H ldap://192.168.1.1 \
    -b "dc=example,dc=com" \
    -s sub \
    "(objectClass=user)" \
    sAMAccountName displayName mail

# Énumération de tous les groupes
# "(objectClass=group)" = filtre pour les groupes
# cn member = attributs : nom du groupe (cn) et membres (member)
ldapsearch -x -H ldap://192.168.1.1 \
    -b "dc=example,dc=com" \
    -s sub \
    "(objectClass=group)" \
    cn member

# Énumération des ordinateurs
# "(objectClass=computer)" = filtre pour les comptes ordinateurs
# cn operatingSystem dNSHostName = nom, OS, nom DNS
ldapsearch -x -H ldap://192.168.1.1 \
    -b "dc=example,dc=com" \
    -s sub \
    "(objectClass=computer)" \
    cn operatingSystem dNSHostName

# Énumération des administrateurs du domaine
# cn=Domain Admins,cn=Users,dc=example,dc=com = DN du groupe Domain Admins
# member = liste des membres du groupe
ldapsearch -x -H ldap://192.168.1.1 \
    -b "cn=Domain Admins,cn=Users,dc=example,dc=com" \
    -s sub \
    "(objectClass=group)" \
    member

# Recherche d'utilisateurs sans mot de passe requis
# userAccountControl avec bitmask 32 = flag "PASSWD_NOTREQD" (mot de passe non requis)
# 1.2.840.113556.1.4.803 = OID pour le matching de bits (AND)
ldapsearch -x -H ldap://192.168.1.1 \
    -b "dc=example,dc=com" \
    "(userAccountControl:1.2.840.113556.1.4.803:=32)" \
    sAMAccountName

# Recherche de mots de passe qui n'expirent jamais
# userAccountControl avec bitmask 65536 = flag "DONT_EXPIRE_PASSWORD"
ldapsearch -x -H ldap://192.168.1.1 \
    -b "dc=example,dc=com" \
    "(userAccountControl:1.2.840.113556.1.4.803:=65536)" \
    sAMAccountName
```

**Explication des options ldapsearch :**
| Option | Rôle/Explication |
|--------|------------------|
| `-x` | Authentification simple (SASL désactivé) |
| `-H ldap://<ip>` | URI du serveur LDAP |
| `-b <DN>` | Base DN : point de départ de la recherche dans l'annuaire |
| `-D <DN>` | Bind DN : identifiant de connexion |
| `-w <password>` | Mot de passe (en clair) |
| `-s sub` | Scope "subtree" : recherche récursive dans toute l'arborescence |
| `sAMAccountName` | Attribut : nom de compte Windows (login) |
| `userAccountControl` | Attribut : flags de contrôle du compte (masque de bits) |
| `1.2.840.113556.1.4.803:=<valeur>` | Règle de matching LDAP : AND bitwise (vérifie si un bit spécifique est activé) |

**Filtres LDAP utiles :**

```bash
# Tous les utilisateurs
(objectClass=user)

# Tous les groupes
(objectClass=group)

# Tous les ordinateurs
(objectClass=computer)

# Utilisateurs actifs
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Utilisateurs avec mot de passe qui n'expire pas
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))

# Groupes avec membres
(&(objectClass=group)(member=*))
```

**Flags UserAccountControl expliqués :**

| Valeur | Signification |
|--------|---------------|
| 2 | Compte désactivé |
| 32 | Mot de passe non requis |
| 512 | Compte standard activé |
| 65536 | Mot de passe n'expire jamais |
| 66048 | Compte standard + mot de passe permanent |
| 262144 | Compte de type service (SPN) |
| 4194816 | Compte administrateur avec privilèges |

#### windapsearch — Script Python pour l'énumération LDAP

```bash
# Installation
git clone https://github.com/ropnop/windapsearch.git  # Clone le dépôt
cd windapsearch
pip3 install -r requirements.txt  # Installe les dépendances Python

# Énumération des utilisateurs
# --dc-ip = IP du contrôleur de domaine, -u "" = utilisateur vide (session nulle)
# -U = users : énumère les utilisateurs du domaine
python3 windapsearch.py --dc-ip 192.168.1.1 -u "" -U

# Énumération des administrateurs
# -d = domaine, --admin-count = compte les membres du groupe Domain Admins
python3 windapsearch.py --dc-ip 192.168.1.1 -u "" -d example.com --admin-count

# Énumération des groupes
# -G = groups : liste tous les groupes du domaine
python3 windapsearch.py --dc-ip 192.168.1.1 -u "" -G

# Énumération des ordinateurs
# -C = computers : liste tous les ordinateurs du domaine
python3 windapsearch.py --dc-ip 192.168.1.1 -u "" -C

# Énumération des utilisateurs privilégiés
# --privileged-users = trouve les utilisateurs dans les groupes privilégiés (Domain Admins, Enterprise Admins, etc.)
python3 windapsearch.py --dc-ip 192.168.1.1 -u "" --privileged-users

# Utilisateurs avec SPN (pour Kerberoasting)
# --da = find users with Domain Admin privileges via SPN (Service Principal Name)
# Ces comptes sont candidats à l'attaque Kerberoasting
python3 windapsearch.py --dc-ip 192.168.1.1 -u "" --da

# Avec authentification
# -u 'admin' -p 'password' = connexion authentifiée (plus de résultats qu'en session nulle)
python3 windapsearch.py --dc-ip 192.168.1.1 -u 'admin' -p 'password' -U
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `--dc-ip <ip>` | Adresse IP du contrôleur de domaine (Domain Controller) |
| `-u <user>` | Nom d'utilisateur ("" = session nulle/anonyme) |
| `-p <pass>` | Mot de passe pour authentification |
| `-d <domaine>` | Nom du domaine (ex: example.com) |
| `-U` | Énumération des utilisateurs |
| `-G` | Énumération des groupes |
| `-C` | Énumération des ordinateurs |
| `--admin-count` | Compte les administrateurs du domaine |
| `--privileged-users` | Recherche les utilisateurs dans les groupes privilégiés |
| `--da` | Utilisateurs avec SPN (candidats Kerberoasting) |

#### ldapdomaindump — Dump de l'annuaire en fichiers lisibles

```bash
# Installation
pip3 install ldapdomaindump  # Outil de dump LDAP en HTML/JSON

# Dump complet de l'annuaire
# -u "EXAMPLE\\administrator" = nom d'utilisateur au format DOMAINE\\utilisateur
# -p "P@ssw0rd" = mot de passe
# -o ldap-dump/ = dossier de sortie
ldapdomaindump ldap://192.168.1.1 \
    -u "EXAMPLE\\\\administrator" \
    -p "P@ssw0rd" \
    -o ldap-dump/

# Contenu du dossier ldap-dump/
ls -la ldap-dump/  # Liste les fichiers générés par ldapdomaindump
# Fichiers générés :
# → domain_users.html      → Rappport HTML des utilisateurs (consultable dans un navigateur)
# → domain_users.json      → Export JSON des utilisateurs (pour parsing)
# → domain_groups.html     → Groupes du domaine (format HTML)
# → domain_computers.html  → Ordinateurs du domaine
# → domain_policy.html     → Politiques de sécurité (mot de passe, verrouillage, etc.)
# → domain_trusts.html     → Relations de confiance avec d'autres domaines
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-u "DOMAINE\\utilisateur"` | Identifiant au format DOMAINE\nom_utilisateur (NetBIOS) |
| `-p <password>` | Mot de passe en clair |
| `-o <dossier>` | Dossier de sortie pour les fichiers HTML/JSON |
| `domain_trusts.html` | Relations de confiance inter-domaines (critique pour le mouvement latéral) |

### 5.5 NFS — Network File System

NFS permet le partage de fichiers sur les systèmes UNIX/Linux.

```bash
# Installation des outils NFS
sudo apt install -y nfs-common  # Paquet client NFS (showmount, mount.nfs)

# Découverte des exports NFS
# showmount -e = liste les répertoires exportés (partagés) par le serveur NFS
showmount -e 192.168.1.1

# Montage d'un partage NFS
# mount -t nfs = monte un système de fichiers NFS
# 192.168.1.1:/partage = serveur:chemin exporté, /mnt/nfs = point de montage local
sudo mount -t nfs 192.168.1.1:/partage /mnt/nfs

# Montage avec version spécifique
# -o vers=3 = force la version NFS 3 (rétrocompatibilité, sécurisé)
sudo mount -t nfs -o vers=3 192.168.1.1:/partage /mnt/nfs

# Montage avec options de sécurité (noexec)
# -o noexec = empêche l'exécution de binaires sur le partage monté
# nosuid = ignore les bits SUID/SGID sur le partage (sécurité)
sudo mount -t nfs -o noexec,nosuid 192.168.1.1:/partage /mnt/nfs

# Lister les exports avec Nmap
# -p 2049 = port NFS
# --script nfs-ls = liste les fichiers, nfs-showmount = liste les exports, nfs-statfs = statistiques
nmap -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs 192.168.1.1

# Énumération complète NFS
# --script "nfs-*" = wildcard : tous les scripts NFS (ls, showmount, statfs)
nmap -p 2049 --script "nfs-*" 192.168.1.1
```

**Explication des options :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `showmount -e <ip>` | Liste les exports NFS disponibles (showmount = show remote mount daemon) |
| `mount -t nfs <src> <dst>` | Monte un partage NFS distant sur le système local |
| `-o vers=3` | Force la version NFS 3 |
| `-o noexec,nosuid` | Options de sécurité : pas d'exécution, pas de SUID |
| `-p 2049` | Port NFS par défaut (portmapper sur 111) |
| `--script nfs-*` | Tous les scripts NSE liés à NFS (ls, showmount, statfs) |

**Exploitation d'un mauvais root squash :**

```bash
# Vérifier si "root_squash" est désactivé
# cat /etc/exports = affiche la configuration des exports NFS
# no_root_squash = option dangereuse : l'utilisateur root distant conserve ses privilèges root
# Normalement root est "squashé" (rétrogradé) en utilisateur nobody
cat /etc/exports
# /export *(rw,no_root_squash)  → Exploitable (root distant = root local)

# Créer un fichier SUID sur le partage
# 1. Monter le partage NFS distant
sudo mount -t nfs 192.168.1.1:/export /mnt/nfs
# 2. Copier /bin/bash (shell) sur le partage
sudo cp /bin/bash /mnt/nfs/shell
# 3. Ajouter le bit SUID (setuid) sur le fichier copié
# u+s = le fichier s'exécute avec les droits du propriétaire (root) au lieu de l'utilisateur
sudo chmod u+s /mnt/nfs/shell
# Puis depuis la cible : exécuter /mnt/nfs/shell -p pour obtenir un shell root
# -p = préserve les privilèges (évite que bash les rétrograde)
```

**Explication de l'exploitation NFS :**
| Option | Rôle/Explication |
|--------|------------------|
| `no_root_squash` | Option NFS dangereuse : préserve les privilèges root distant (devrait être root_squash) |
| `chmod u+s <fichier>` | Ajoute le bit SUID : le fichier s'exécute avec les droits de son propriétaire |
| `/bin/bash -p` | Lance bash en mode privilégié (évite le drop de privilèges) |
| **Principe** | Sur le serveur NFS, si no_root_squash est actif, créer un binaire SUID root depuis la machine cliente → n'importe quel utilisateur sur le serveur peut l'exécuter pour devenir root |

### 5.6 TP Guidé — Énumération complète de services

#### Objectif
Effectuer une énumération complète de tous les services découverts sur un sous-réseau.

```bash
#!/bin/bash
# enum-services.sh — Énumération complète des services
# Usage : sudo ./enum-services.sh <sous-reseau>
# Exemple : sudo ./enum-services.sh 192.168.1.0/24

set -e  # Exit on error : arrête le script si une commande échoue

SUBNET="${1}"  # Premier argument : sous-réseau à scanner
# Nom de dossier unique avec timestamp
RAPPORT_DIR="rapport-enum-$(date +%Y%m%d_%H%M%S)"

if [ -z "$SUBNET" ]; then  # Vérifie qu'un sous-réseau a été fourni
    echo "Usage : $0 <sous-reseau>"
    exit 1
fi

mkdir -p "$RAPPORT_DIR"  # Crée le dossier de rapport
echo "[*] Rapport dans : $RAPPORT_DIR"

echo "[1/6] Découverte des hôtes actifs..."
# -sn = ping sweep, -T4 = profil agressif, -oG = sortie greppable (format compact)
sudo nmap -sn -T4 "$SUBNET" -oG "${RAPPORT_DIR}/01-hosts.gnmap"

# Extrait les adresses IP du fichier greppable (grep -oP = Perl regex, only-matching)
grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' "${RAPPORT_DIR}/01-hosts.gnmap" | \
    sort -u > "${RAPPORT_DIR}/hosts.txt"  # sort -u = trie et supprime les doublons

NB_HOSTS=$(wc -l < "${RAPPORT_DIR}/hosts.txt")  # Compte le nombre d'hôtes
echo "  → $NB_HOSTS hôtes découverts"

echo "[2/6] Scan des ports (top 1000)..."
# Boucle sur chaque hôte pour un scan SYN + version detection
while read -r ip; do
    sudo nmap -sS -sV -T4 --top-ports 1000 \
        -oN "${RAPPORT_DIR}/02-ports-${ip}.txt" \
        "$ip" > /dev/null 2>&1  # Redirige stdout et stderr vers /dev/null (silencieux)
done < "${RAPPORT_DIR}/hosts.txt"

echo "[3/6] Énumération SMB..."
# grep -l "445/open" = cherche les fichiers contenant "445/open" (port SMB ouvert)
# grep -oP '\d+\.\d+\.\d+\.\d+' = extrait l'IP depuis le nom du fichier
for ip in $(grep -l "445/open" "${RAPPORT_DIR}"/02-ports-*.txt 2>/dev/null | \
    grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+'); do
    echo "  → SMB : $ip"
    # Lance enum4linux, smbclient et crackmapexec en parallèle pour chaque hôte SMB
    enum4linux -a "$ip" > "${RAPPORT_DIR}/03-smb-${ip}.txt" 2>/dev/null
    smbclient -L "//${ip}" -N > "${RAPPORT_DIR}/03-smb-shares-${ip}.txt" 2>/dev/null
    crackmapexec smb "$ip" --shares > "${RAPPORT_DIR}/03-smb-cme-${ip}.txt" 2>/dev/null
done

echo "[4/6] Énumération SNMP..."
# Cherche les hôtes avec le port SNMP (161) ouvert
for ip in $(grep -l "161/open" "${RAPPORT_DIR}"/02-ports-*.txt 2>/dev/null | \
    grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+'); do
    echo "  → SNMP : $ip"
    # snmpwalk sur l'OID système pour les informations de base
    snmpwalk -v2c -c public "$ip" .1.3.6.1.2.1.1 \
        > "${RAPPORT_DIR}/04-snmp-system-${ip}.txt" 2>/dev/null
    # snmp-check pour un rapport complet
    snmp-check "$ip" -c public -v2c \
        > "${RAPPORT_DIR}/04-snmp-full-${ip}.txt" 2>/dev/null
done

echo "[5/6] Énumération DNS..."
# Cherche les hôtes avec le port DNS (53) ouvert
for ip in $(grep -l "53/open" "${RAPPORT_DIR}"/02-ports-*.txt 2>/dev/null | \
    grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+'); do
    echo "  → DNS : $ip"
    # Nmap avec scripts DNS : zone transfer et NSID (informations du serveur DNS)
    nmap -p 53 --script dns-zone-transfer,dns-nsid \
        "$ip" > "${RAPPORT_DIR}/05-dns-${ip}.txt" 2>/dev/null
done

echo "[6/6] Énumération LDAP..."
# Cherche les hôtes avec LDAP (389), LDAPS (636) ou Global Catalog (3268) ouvert
for ip in $(grep -l "389/open\\|636/open\\|3268/open" "${RAPPORT_DIR}"/02-ports-*.txt 2>/dev/null | \
    grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+'); do
    echo "  → LDAP : $ip"
    # Requête de base pour découvrir le naming context (racine de l'annuaire)
    ldapsearch -x -H "ldap://${ip}" -b "" -s base \
        "(objectClass=*)" namingContexts \
        > "${RAPPORT_DIR}/06-ldap-base-${ip}.txt" 2>/dev/null

    # Extrait le domaine depuis le naming context (première ligne après "namingContexts:")
    domain=$(grep "namingContexts:" "${RAPPORT_DIR}/06-ldap-base-${ip}.txt" | \
        awk '{print $2}' | grep -v CN | head -1)
    if [ -n "$domain" ]; then  # Si un domaine a été trouvé
        # Énumère les utilisateurs via le domaine découvert
        ldapsearch -x -H "ldap://${ip}" -b "$domain" \
            "(objectClass=user)" sAMAccountName \
            > "${RAPPORT_DIR}/06-ldap-users-${ip}.txt" 2>/dev/null
    fi
done

echo ""
echo "=========================================="
echo " Énumération terminée !"
echo " Résultats : ${RAPPORT_DIR}/"
echo "=========================================="
```

**Explication du script enum-services.sh :**
| Étape | Action | Outils | Logique |
|-------|--------|--------|---------|
| 1/6 | Découverte d'hôtes | nmap -sn | Ping sweep sur tout le sous-réseau |
| 2/6 | Scan de ports | nmap -sS -sV | SYN scan + version sur les top 1000 ports |
| 3/6 | Énumération SMB | enum4linux + smbclient + CME | Si port 445 ouvert → énumération complète SMB |
| 4/6 | Énumération SNMP | snmpwalk + snmp-check | Si port 161 ouvert → infos système et rapport SNMP |
| 5/6 | Énumération DNS | nmap scripts | Si port 53 ouvert → zone transfer et NSID |
| 6/6 | Énumération LDAP | ldapsearch | Si ports 389/636/3268 → découverte du domaine puis utilisateurs |

---

## 6. OSINT réseau

### 6.1 Shodan — Moteur de recherche d'équipements connectés

Shodan indexe les bannières de services de tous les équipements connectés à Internet.

#### Configuration

```bash
# Installation de l'outil CLI Shodan
# pip3 install shodan = installe le client Python en ligne de commande pour Shodan
pip3 install shodan

# Configuration de la clé API (obtenue sur https://account.shodan.io)
# shodan init = initialise l'outil avec votre clé API personnelle
# La clé est stockée dans ~/.shodan/api_key
shodan init "VOTRE_CLE_API"

# Vérification du compte
# shodan info = affiche les informations du compte (crédits restants, plan, etc.)
shodan info
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `pip3 install shodan` | Installe le client CLI Python pour l'API Shodan |
| `shodan init <clé>` | Configure la clé API Shodan (fichier de config : ~/.shodan/api_key) |
| `shodan info` | Affiche les infos du compte : plan, crédits de recherche restants |

#### Recherches Shodan

```bash
# Recherche basique
shodan search "SSH"  # Cherche tous les serveurs SSH exposés sur Internet

# Recherche par service et pays
shodan search "apache country:FR"  # Serveurs Apache en France (country:FR = filtre pays)

# Recherche par organisation
shodan search "org:Google"  # Tous les équipements appartenant à Google (filtre organisation)

# Recherche par port
shodan search "port:443"  # Tous les services sur le port 443 (HTTPS)

# Recherche par ville
shodan search "city:Paris"  # Équipements situés à Paris (filtre ville)

# Recherche de vulnérabilités
shodan search "vuln:CVE-2021-41773"  # Serveurs vulnérables à Apache Path Traversal (CVE-2021-41773)

# Recherche d'équipements spécifiques
shodan search "cisco ios"  # Équipements réseau Cisco
shodan search "mikrotik"   # Routeurs MikroTik
shodan search "Siemens"    # Équipements industriels Siemens (SCADA/ICS)

# Recherche de bases de données exposées
shodan search "MongoDB" --limit 10       # Bases MongoDB exposées (limite 10 résultats)
shodan search "product:MySQL" --limit 5  # Serveurs MySQL exposés (limite 5)
shodan search "product:Elasticsearch"    # Serveurs Elasticsearch exposés

# Recherche d'ICS/SCADA
shodan search "SCADA"   # Équipements SCADA (Supervisory Control And Data Acquisition)
shodan search "MODBUS"  # Protocole MODBUS (automatisation industrielle)
shodan search "S7"      # Automates Siemens S7 (PLC)
```

**Explication des filtres Shodan :**
| Filtre | Rôle/Explication |
|--------|------------------|
| `country:<code>` | Filtre par code pays à 2 lettres (FR, US, CN, etc.) |
| `org:<nom>` | Filtre par organisation propriétaire des IPs |
| `port:<num>` | Filtre par numéro de port |
| `city:<ville>` | Filtre par ville |
| `vuln:<CVE>` | Filtre par CVE (vulnérabilité connue) |
| `product:<nom>` | Filtre par produit/logiciel |
| `--limit <N>` | Limite le nombre de résultats affichés |

#### Filtres Shodan avancés

```bash
# Filtres puissants
shodan search "apache after:2024-01-01 country:FR"  # Apache en France, découverts après 2024
shodan search "port:3306 product:MySQL"              # Port 3306 ET produit = MySQL
shodan search "port:445 os:Windows"                  # Port SMB ouvert sur des machines Windows
shodan search "hostname:example.com"                 # Serveurs avec hostname correspondant
shodan search "ssl:example.com"                      # Certificats SSL avec le CN = example.com
shodan search "net:203.0.113.0/24"                   # Plage IP spécifique (CIDR)
shodan search "has_vuln:true port:80"                # Serveurs HTTP avec vulnérabilités connues
shodan search "asn:AS15169"                          # Filtre par ASN (Google : AS15169)
```

**Explication des filtres avancés :**
| Filtre | Rôle/Explication |
|--------|------------------|
| `after:<date>` | Résultats découverts après une date (YYYY-MM-DD) |
| `os:<nom>` | Filtre par système d'exploitation détecté |
| `hostname:<domaine>` | Filtre par nom d'hôte |
| `ssl:<domaine>` | Filtre par CN (Common Name) du certificat SSL |
| `net:<CIDR>` | Filtre par plage réseau (CIDR) |
| `has_vuln:true` | Filtre les hôtes avec des vulnérabilités connues |
| `asn:<numéro>` | Filtre par ASN (Autonomous System Number) |

#### Commandes avancées Shodan

```bash
# Informations d'un hôte spécifique
shodan host 8.8.8.8  # Affiche tous les ports, services, vulnérabilités connus pour cette IP

# Statistiques d'une recherche
# --facets "port,country,org" = affiche les statistiques par port, pays et organisation
shodan stats --facets "port,country,org" "apache"

# Téléchargement des résultats
# shodan download <fichier> <requête> = télécharge les résultats au format JSON compressé
shodan download resultats "apache country:FR"

# Visualiser les résultats téléchargés
# shodan parse = lit le fichier .json.gz et affiche les champs sélectionnés
# --fields = liste des champs à afficher (ip_str, port, org, hostnames)
shodan parse --fields ip_str,port,org,hostnames resultats.json.gz

# Scan d'une plage IP (nécessite un abonnement)
# shodan scan submit = soumet une plage IP au scanneur Shodan (payant)
shodan scan submit 203.0.113.0/24

# API Python (script inline)
python3 -c "
import shodan                                          # Importe la bibliothèque Shodan
api = shodan.Shodan('VOTRE_CLE_API')                  # Initialise l'API avec la clé
results = api.search('apache country:FR', limit=50)    # Recherche : 50 résultats max
for result in results['matches']:                      # Parcourt les résultats
    print(f\"{result['ip_str']}:{result['port']} — {result.get('http', {}).get('title', 'N/A')}\")
"
```

**Explication des commandes avancées :**
| Commande | Rôle/Explication |
|----------|------------------|
| `shodan host <ip>` | Affiche toutes les informations connues sur une IP (ports, services, vulnérabilités, géolocalisation) |
| `shodan stats --facets` | Statistiques agrégées d'une recherche (top ports, pays, organisations) |
| `shodan download <fichier> <requête>` | Télécharge les résultats bruts au format JSON.gz |
| `shodan parse --fields` | Parse le fichier téléchargé et affiche les champs sélectionnés |
| `shodan scan submit <CIDR>` | Soumet une plage IP au scanneur de Shodan (monitoring continu, abonnement requis) |
| `python3 -c "..."` | Exécute un script Python inline (entre guillemets) |

#### Recherche via l'API REST

```bash
# Recherche Shodan via curl
# curl -s = envoie une requête HTTP GET à l'API Shodan (silent mode, pas de barre de progression)
# jq = outil JSON en ligne de commande, filtre et reformate le JSON
# .matches[] = boucle sur chaque résultat, | {ip: .ip_str, ...} = construit un objet JSON personnalisé
curl -s "https://api.shodan.io/shodan/host/search?key=VOTRE_CLE&query=apache+country:FR" | \
    jq '.matches[] | {ip: .ip_str, port: .port, org: .org, hostnames: .hostnames}'

# Vulnérabilités d'un hôte
# Requête API REST pour obtenir les détails d'un hôte spécifique
# | jq '{ip: .ip_str, ports: .ports, vulns: .vulns}' = extrait IP, ports ouverts et CVE associées
curl -s "https://api.shodan.io/shodan/host/203.0.113.1?key=VOTRE_CLE" | \
    jq '{ip: .ip_str, ports: .ports, vulns: .vulns}'
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl -s <url>` | Requête HTTP GET, -s = silent (pas de progression), récupère le JSON brut |
| `jq '.matches[] \| {ip: .ip_str}'` | Parse le JSON : boucle sur .matches[] et construit un objet avec les champs sélectionnés |
| `?key=VOTRE_CLE&query=...` | Paramètres GET de l'API : clé API et requête de recherche |
| `/shodan/host/<ip>` | Endpoint REST : informations détaillées d'un hôte spécifique |
| `.vulns` | Liste des CVE (vulnérabilités) associées à l'hôte |

### 6.2 Censys — Alternative à Shodan

```bash
# Installation
pip3 install censys  # Client CLI Python pour l'API Censys

# Configuration
censys config  # Configure l'API ID et l'API Secret (interactif)

# Recherche d'hôtes
# --per-page 5 = nombre de résultats par page
censys search "services.service_name: HTTP" --per-page 5

# Recherche par service
censys search "services.service_name: SSH"  # Tous les serveurs SSH exposés

# Recherche par pays
censys search "location.country: France"  # Hôtes localisés en France

# Recherche par réseau
censys search "ip: 203.0.113.0/24"  # Hôtes dans la plage IP spécifiée

# Recherche de certificats TLS
censys search "services.tls.certificate.parsed.subject.common_name: example.com"

# Détails d'un hôte
censys view 8.8.8.8  # Affiche toutes les informations sur un hôte spécifique

# Via l'API directement
# curl -u "API_ID:API_SECRET" = authentification HTTP Basic Auth
# jq '.result.ports' = extrait uniquement la liste des ports ouverts
curl -s -u "API_ID:API_SECRET" \
    "https://search.censys.io/api/v2/hosts/8.8.8.8" | \
    jq '.result.ports'
```

**Explication des commandes :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `pip3 install censys` | Installe le client CLI Censys |
| `censys config` | Configuration interactive (API ID + API Secret) |
| `censys search "<filtre>"` | Recherche d'hôtes/Certificats avec des filtres |
| `services.service_name: <nom>` | Filtre par nom de service (HTTP, SSH, MySQL, etc.) |
| `location.country: <pays>` | Filtre par pays |
| `ip: <CIDR>` | Filtre par plage IP |
| `censys view <ip>` | Détails complets d'un hôte |
| `curl -u "id:secret"` | API REST directement via curl avec Basic Auth |

### 6.3 Certificate Transparency — crt.sh

crt.sh indexe les certificats TLS publiés dans les logs Certificate Transparency.

```bash
# Recherche via l'API (format JSON)
# crt.sh = Certificate Transparency log, indexe tous les certificats TLS émis
# ?q=example.com&output=json = requête avec sortie JSON
# | jq . = formate le JSON pour le rendre lisible
curl -s "https://crt.sh/?q=example.com&output=json" | jq .

# Avec jq pour un format propre
# %25.example.com = wildcard encodé (%25 = %) pour chercher *.example.com et sous-domaines
# jq -r '.[].name_value' = extrait le champ name_value (nom de domaine) en mode raw (-r)
# sort -u = trie et supprime les doublons
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
    jq -r '.[].name_value' | \
    sort -u

# Script bash de découverte de sous-domaines
#!/bin/bash
DOMAIN="${1}"  # Premier argument : domaine à analyser
echo "[*] Sous-domaines pour $DOMAIN via crt.sh..."
# Interroge l'API crt.sh avec wildcard, extrait les noms de domaines
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | \
    jq -r '.[].name_value' | \
    sed 's/\\*\\.//g' | \  # Supprime les wildcards (*.example.com → example.com)
    sort -u > "crt-subdomains-${DOMAIN}.txt"  # Sauvegarde dans un fichier
echo "[+] $(wc -l < "crt-subdomains-${DOMAIN}.txt") sous-domaines trouvés"

# Résolution des sous-domaines
# while read sub = lit chaque sous-domaine du fichier
# dig +short "$sub" A = résout l'enregistrement A (IPv4)
# grep -v "^$" = supprime les lignes vides (domaines non résolus)
# && echo "  → $sub" = si dig retourne une IP, affiche le sous-domaine
while read sub; do
    dig +short "$sub" A | grep -v "^$" && echo "  → $sub"
done < "crt-subdomains-${DOMAIN}.txt" > "resolved-${DOMAIN}.txt"
echo "[+] $(wc -l < "resolved-${DOMAIN}.txt") sous-domaines résolvables"
```

**Explication des commandes crt.sh :**
| Commande/Option | Rôle/Explication |
|----------------|------------------|
| `curl -s "https://crt.sh/?q=..."` | Interroge l'API publique de crt.sh (Certificate Transparency) |
| `%25.<domaine>` | Wildcard encodé (%25 = %) : cherche tous les certificats pour *.<domaine> |
| `jq -r '.[].name_value'` | Extrait le champ name_value (nom de domaine) de chaque entrée JSON en mode raw |
| `sed 's/\*\.//g'` | Supprime le préfixe "asterisk + point" des wildcards (ex: *.example.com → example.com) |
| `dig +short "$sub" A` | Résout l'enregistrement A (IPv4) d'un nom de domaine |
| **Principe** | Chaque certificat TLS est enregistré dans des logs Certificate Transparency. crt.sh indexe ces logs et permet de trouver tous les sous-domaines associés à un domaine |

### 6.4 TP Guidé — Trouver des assets exposés

#### Objectif
Utiliser Shodan, Censys et crt.sh pour cartographier les assets exposés d'un domaine cible.

```bash
#!/bin/bash
# osint-reseau.sh — OSINT réseau automatisé
# Usage : ./osint-reseau.sh <domaine>
# Exemple : ./osint-reseau.sh example.com

set -e  # Exit on error
DOMAIN="${1}"  # Premier argument : domaine cible
# Dossier de rapport avec timestamp
RAPPORT_DIR="rapport-osint-$(date +%Y%m%d_%H%M%S)"

if [ -z "$DOMAIN" ]; then
    echo "Usage : $0 <domaine>"
    exit 1
fi

mkdir -p "$RAPPORT_DIR"

echo "=========================================="
echo " OSINT réseau pour : $DOMAIN"
echo "=========================================="

# Phase 1 : Sous-domaines via crt.sh
echo "[1/4] Sous-domaines via Certificate Transparency..."
# Interroge l'API crt.sh avec wildcard, extrait les noms, supprime les *., trie unique
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\\*\\.//g' | \
    sort -u > "${RAPPORT_DIR}/01-subdomain-crtsh.txt" 2>/dev/null

NB_CRTSH=$(wc -l < "${RAPPORT_DIR}/01-subdomain-crtsh.txt" 2>/dev/null || echo 0)
echo "  → $NB_CRTSH sous-domaines trouvés via crt.sh"

# Résolution DNS : pour chaque sous-domaine, on résout l'enregistrement A
while read -r sub; do
    ip=$(dig +short "$sub" A 2>/dev/null | head -1)  # Résout l'IP
    if [ -n "$ip" ]; then  # Si l'IP n'est pas vide (résolution réussie)
        echo "$ip $sub" >> "${RAPPORT_DIR}/01-resolved.txt"  # Sauvegarde IP + domaine
    fi
done < "${RAPPORT_DIR}/01-subdomain-crtsh.txt"

NB_RESOLVED=$(wc -l < "${RAPPORT_DIR}/01-resolved.txt" 2>/dev/null || echo 0)
echo "  → $NB_RESOLVED sous-domaines résolvables"

# Phase 2 : Plages IP
echo "[2/4] Découverte des plages IP..."
# awk '{print $1}' = extrait la première colonne (les IPs) du fichier résolu
awk '{print $1}' "${RAPPORT_DIR}/01-resolved.txt" 2>/dev/null | \
    sort -u > "${RAPPORT_DIR}/02-ips.txt"
echo "  → $(wc -l < "${RAPPORT_DIR}/02-ips.txt" 2>/dev/null || echo 0) IPs uniques"

# Phase 3 : Shodan (si configuré)
echo "[3/4] Shodan recherche..."
# command -v shodan = vérifie si shodan est dans le PATH
# shodan info &>/dev/null = vérifie si la clé API est configurée (redirige stdout ET stderr vers /dev/null)
if command -v shodan &>/dev/null && shodan info &>/dev/null 2>&1; then
    for ip in $(head -10 "${RAPPORT_DIR}/02-ips.txt" 2>/dev/null); do
        shodan host "$ip" > "${RAPPORT_DIR}/03-shodan-${ip}.txt" 2>/dev/null &
    done
    wait  # Attend la fin de tous les processus Shodan en arrière-plan
    echo "  → Résultats Shodan enregistrés"
else
    echo "  → Shodan non configuré."
fi

# Phase 4 : Scan rapide
echo "[4/4] Scan rapide des IPs..."
if [ -f "${RAPPORT_DIR}/02-ips.txt" ]; then
    while read -r ip; do
        # Nmap : SYN scan, top 100 ports (rapide), profils T4
        sudo nmap -sS -T4 --top-ports 100 \
            -oA "${RAPPORT_DIR}/04-scan-${ip}" \
            "$ip" > /dev/null 2>&1
    done < "${RAPPORT_DIR}/02-ips.txt"
fi

echo ""
echo "=========================================="
echo " OSINT terminé !"
echo "=========================================="
```

**Explication du script osint-reseau.sh :**
| Phase | Action | Outils | Méthode |
|-------|--------|--------|---------|
| 1/4 | Sous-domaines | crt.sh + dig | Certificate Transparency logs + résolution DNS |
| 2/4 | Plages IP | awk + sort | Extraction et dédoublonnage des IPs résolues |
| 3/4 | Shodan | shodan host | Consultation de l'API Shodan pour chaque IP (background jobs avec &) |
| 4/4 | Scan rapide | nmap -sS | SYN scan des top 100 ports sur chaque IP découverte |

---

## 7. Énumération Web avancée (T1592)

### 7.1 ffuf — Fuzzing Web haute performance

ffuf (Fuzz Faster U Fool) est un outil de fuzzing écrit en Go, extrêmement rapide.

#### Installation

```bash
# Installation via apt
sudo apt install -y ffuf  # ffuf = Fuzz Faster U Fool, fuzzer web écrit en Go

# Via Go
# go install = télécharge et compile depuis le dépôt Go officiel
# @latest = dernière version disponible
go install github.com/ffuf/ffuf/v2@latest

# Vérification
ffuf -V  # Affiche la version de ffuf installée
```

**Explication :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo apt install -y ffuf` | Installe le paquet ffuf depuis les dépôts |
| `go install <module>@latest` | Compile et installe ffuf depuis les sources Go |
| `ffuf -V` | Affiche la version (vérification de l'installation) |

#### Directory Fuzzing

```bash
# Directory bruteforce basique
# FUZZ = mot-clé (placeholder) qui sera remplacé par chaque mot de la wordlist
# -w = wordlist (dictionnaire de chemins à tester)
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt

# Avec extension
# -e = liste d'extensions à ajouter à chaque mot de la wordlist
# Teste : /admin, /admin.php, /admin.asp, /admin.html, etc.
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -e .php,.asp,.aspx,.jsp,.html,.txt

# Avec code HTTP filtré (ignorer 404)
# -fc 404 = filtre les réponses avec code HTTP 404 (les ignore)
# N'affiche que les réponses intéressantes (200, 301, 403, 500, etc.)
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -fc 404

# Avec taille de réponse filtrée
# -fs 1234 = filtre (ignore) les réponses dont la taille est exactement 1234 octets
# Utile quand la page 404 personnalisée a une taille fixe
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -fs 1234

# Avec threadings (vitesse)
# -t 100 = 100 threads parallèles (accélère considérablement le fuzzing)
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -t 100

# Avec authentification
# -H = header HTTP personnalisé
# Authorization: Basic = authentification HTTP Basic (credentials en base64)
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -H "Authorization: Basic $(echo -n 'user:pass' | base64)"

# Avec cookie
# -b = cookie HTTP à envoyer avec chaque requête (session, session_id, etc.)
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -b "session=abc123"

# Avec header personnalisé
# -H = ajoute un en-tête HTTP personnalisé (ici : X-Forwarded-For pour contourner des restrictions IP)
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -H "X-Forwarded-For: 127.0.0.1"

# Sortie JSON
# -o results.json = fichier de sortie, -of json = format de sortie JSON (structuré)
ffuf -u http://example.com/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -o results.json -of json
```

**Explication des options ffuf :**
| Option | Rôle/Explication |
|--------|------------------|
| `-u <url>` | URL cible (FUZZ = point d'injection du dictionnaire) |
| `-w <fichier>` | Wordlist (dictionnaire) à utiliser pour le fuzzing |
| `-e <extensions>` | Extensions à ajouter aux mots (ex: .php,.html,.txt) |
| `-fc <code>` | Filter by HTTP status code (ignore les codes spécifiés) |
| `-fs <taille>` | Filter by response size (ignore les réponses de cette taille) |
| `-t <N>` | Nombre de threads (parallélisme) |
| `-H <header>` | Header HTTP personnalisé |
| `-b <cookie>` | Cookie HTTP personnalisé |
| `-o <fichier> -of json` | Sortie JSON (pour parsing automatisé) |

#### Virtual Host Discovery

```bash
# Découverte de vhost
# Virtual Host discovery : teste différents noms d'hôte (Host header) sur la même IP
# -H "Host: FUZZ.example.com" = modifie l'en-tête Host pour chaque mot de la wordlist
# -fc 200,404 = ignore les réponses 200 et 404 (ne garde que les différences intéressantes)
ffuf -w /usr/share/wordlists/amass/subdomains-top1mil.txt \
    -u http://192.168.1.1 \
    -H "Host: FUZZ.example.com" \
    -fc 200,404

# Vhost avec taille de réponse filtrée
# -fs 1234 = filtre les réponses dont la taille est 1234 (taille de la page par défaut)
ffuf -w /usr/share/wordlists/amass/subdomains-top1mil.txt \
    -u http://192.168.1.1 \
    -H "Host: FUZZ.example.com" \
    -fs 1234

# Vhost sur HTTPS
# -k = ignore les erreurs de certificat TLS (skip TLS verification)
# Utile pour les self-signed certificates ou les IPs sans nom de domaine valide
ffuf -w /usr/share/wordlists/amass/subdomains-top1mil.txt \
    -u https://192.168.1.1 \
    -H "Host: FUZZ.example.com" \
    -k
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-H "Host: FUZZ.example.com"` | Fuzzing du header Host (virtual host discovery) |
| `-fc 200,404` | Filtre les codes HTTP 200 et 404 |
| `-fs <taille>` | Filtre les réponses par taille (en octets) |
| `-k` | Skip TLS verification (ignore les certificats invalides) |
| **VHost vs DNS** | DNS = sous-domaines résolus via DNS ; VHost = sites web hébergés sur la même IP répondant à différents Host headers |

#### Parameter Fuzzing

```bash
# Fuzzing de paramètres GET
# FUZZ dans l'URL = chaque mot remplace FUZZ pour découvrir les noms de paramètres valides
ffuf -u http://example.com/page?FUZZ=test \
    -w /usr/share/wordlists/param-mini.txt

# Fuzzing de valeurs de paramètres
# id=FUZZ = fuzze la valeur d'un paramètre connu (ex: id=1, id=2, id=admin, etc.)
ffuf -u http://example.com/page?id=FUZZ \
    -w ids.txt

# Fuzzing de paramètres POST
# -X POST = méthode HTTP POST
# -d "FUZZ=test" = corps de la requête POST avec FUZZ comme placeholder
ffuf -u http://example.com/login \
    -w /usr/share/wordlists/param-mini.txt \
    -X POST \
    -d "FUZZ=test"

# Fuzzing avec données JSON
# -H "Content-Type: application/json" = header de type JSON
# -d '{"FUZZ":"test"}' = corps JSON avec FUZZ comme placeholder pour fuzzer les clés JSON
ffuf -u http://example.com/api \
    -w /usr/share/wordlists/param-mini.txt \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"FUZZ":"test"}'
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `-X <methode>` | Méthode HTTP (GET, POST, PUT, DELETE, etc.) |
| `-d <data>` | Corps de la requête (data) avec FUZZ comme placeholder |
| `-H "Content-Type: ..."` | Header Content-Type pour les requêtes JSON |
| **FUZZ** | Placeword principal remplacé par chaque mot de la wordlist |

#### Wordlists recommandées

```bash
# Wordlists disponibles sur Kali
ls /usr/share/wordlists/          # Liste tous les dictionnaires disponibles
ls /usr/share/wordlists/dirb/     # Wordlists pour directory bruteforce (dirb)
ls /usr/share/wordlists/dirbuster/ # Wordlists DirBuster (plus exhaustif)

# Wordlists SecLists
# SecLists = la collection de wordlists la plus complète (danielmiessler)
git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists

# Directory fuzzing :
/usr/share/wordlists/dirb/common.txt           # 4614 mots (rapide, pour premiers tests)

# Vhost :
/usr/share/wordlists/amass/subdomains-top1mil.txt  # 1 million de sous-domaines (exhaustif)

# Parameters :
/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt  # Noms de paramètres web
```

**Explication des wordlists :**
| Wordlist | Contenu | Usage |
|----------|---------|-------|
| `dirb/common.txt` | 4614 mots (répertoires et fichiers courants) | Directory bruteforce rapide |
| `amass/subdomains-top1mil.txt` | 1 million de sous-domaines | DNS bruteforce et VHost discovery |
| `burp-parameter-names.txt` | Noms de paramètres HTTP | Parameter fuzzing (GET/POST) |
| SecLists | Collection exhaustive (découverte, injections, passwords, etc.) | Référence complète |

### 7.2 Gobuster — Multi-mode fuzzing

#### Installation

```bash
# Installation
sudo apt install -y gobuster  # gobuster = multi-mode fuzzer écrit en Go

# Via Go
# go install = télécharge et compile depuis les sources officielles
go install github.com/OJ/gobuster/v3@latest
```

**Explication :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo apt install -y gobuster` | Installe le paquet depuis les dépôts |
| `go install <module>@latest` | Compile et installe la dernière version depuis les sources Go |

#### Mode dir (Directory)

```bash
# Directory bruteforce basique
# gobuster dir = mode directory bruteforce
# -u = URL cible, -w = wordlist
gobuster dir -u http://example.com \
    -w /usr/share/wordlists/dirb/common.txt

# Avec extensions
# -x php,html,txt,asp = extensions à ajouter aux mots (comme -e de ffuf)
# Teste chaque mot avec chaque extension : admin.php, admin.html, admin.txt, admin.asp
gobuster dir -u http://example.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -x php,html,txt,asp

# Avec status codes exclus
# -b 404,403 = exclude (blacklist) les codes HTTP 404 et 403 des résultats
gobuster dir -u http://example.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -x php,html \
    -b 404,403

# Avec threads
# -t 50 = 50 threads parallèles (accélère le bruteforce)
gobuster dir -u http://example.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -t 50

# Avec cookie
# -c "session=abc123" = cookie HTTP pour les requêtes authentifiées
gobuster dir -u http://example.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -c "session=abc123"

# Avec proxy
# -p http://127.0.0.1:8080 = proxy HTTP (Burp Suite, etc.) pour intercepter le trafic
gobuster dir -u http://example.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -p http://127.0.0.1:8080
```

**Explication des options gobuster dir :**
| Option | Rôle/Explication |
|--------|------------------|
| `dir` | Mode directory bruteforce |
| `-u <url>` | URL cible |
| `-w <fichier>` | Wordlist (dictionnaire) |
| `-x <extensions>` | Extensions à tester (séparées par des virgules) |
| `-b <codes>` | Blacklist : exclut certains codes HTTP des résultats |
| `-t <N>` | Nombre de threads (parallélisme) |
| `-c <cookie>` | Cookie HTTP personnalisé |
| `-p <proxy>` | Proxy HTTP pour interception (Burp, ZAP) |

#### Mode dns (Sous-domaines)

```bash
# DNS bruteforce basique
# gobuster dns = mode DNS bruteforce (sous-domaines)
# -d = domaine cible, -w = wordlist de sous-domaines
gobuster dns -d example.com \
    -w /usr/share/wordlists/amass/subdomains-top1mil.txt

# Avec serveur DNS spécifique
# -r 8.8.8.8 = utilise le serveur DNS Google au lieu du DNS configuré localement
gobuster dns -d example.com \
    -w /usr/share/wordlists/amass/subdomains-top1mil.txt \
    -r 8.8.8.8

# Avec wildcard detection
# --wildcard = active la détection des enregistrements DNS wildcard (*.example.com)
# Un wildcard DNS répond à TOUS les sous-domaines (même inexistants), ce qui fausse les résultats
# --wildcard identifie ce comportement et filtre les faux positifs
gobuster dns -d example.com \
    -w /usr/share/wordlists/amass/subdomains-top1mil.txt \
    --wildcard
```

**Explication des options gobuster dns :**
| Option | Rôle/Explication |
|--------|------------------|
| `dns` | Mode DNS bruteforce (sous-domaines) |
| `-d <domaine>` | Domaine cible |
| `-w <fichier>` | Wordlist de sous-domaines |
| `-r <serveur>` | Serveur DNS à utiliser (par défaut : /etc/resolv.conf) |
| `--wildcard` | Détection des wildcards DNS (évite les faux positifs) |

#### Mode vhost (Virtual Host)

```bash
# Vhost discovery
# gobuster vhost = mode Virtual Host discovery
# --append-domain = ajoute automatiquement le domaine aux mots de la wordlist
# (si la wordlist contient "mail" et le domaine est example.com → "mail.example.com")
gobuster vhost -u http://192.168.1.1 \
    -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain

# Vhost avec TLS
# -k = ignore les erreurs de certificat TLS (skip TLS verification)
gobuster vhost -u https://example.com \
    -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -k
```

**Explication des options gobuster vhost :**
| Option | Rôle/Explication |
|--------|------------------|
| `vhost` | Mode Virtual Host discovery |
| `-u <url>` | URL de base (IP ou domaine) |
| `-w <fichier>` | Wordlist de noms d'hôte |
| `--append-domain` | Ajoute le domaine aux mots de la wordlist (ex: "mail" + "example.com" = "mail.example.com") |
| `-k` | Skip TLS verification (certificats auto-signés) |

### 7.3 wfuzz — Fuzzing de paramètres

#### Installation

```bash
# Installation
sudo apt install -y wfuzz  # wfuzz = fuzzer web Python, spécialisé dans le fuzzing de paramètres

# Vérification
wfuzz --help  # Affiche l'aide complète avec toutes les options disponibles
```

**Explication :**
| Commande | Rôle/Explication |
|----------|------------------|
| `sudo apt install -y wfuzz` | Installe le paquet wfuzz (outil de fuzzing web écrit en Python) |
| `wfuzz --help` | Affiche le manuel d'utilisation complet |

#### Utilisation de wfuzz

```bash
# Directory bruteforce
# --hc 404 = hide code 404 (cache les réponses avec code HTTP 404)
wfuzz -w /usr/share/wordlists/dirb/common.txt \
    --hc 404 \
    http://example.com/FUZZ

# Fuzzing de paramètres GET
# FUZZ = placeholder dans l'URL (découverte de paramètres GET valides)
wfuzz -w /usr/share/wordlists/param-mini.txt \
    -u http://example.com/page?FUZZ=1

# Fuzzing de paramètres POST
# -d "FUZZ=1" = corps POST avec placeholder pour fuzzer les noms de paramètres POST
wfuzz -w /usr/share/wordlists/param-mini.txt \
    -d "FUZZ=1" \
    http://example.com/page

# Fuzzing de cookie
# -b "FUZZ=1" = fuzze le nom d'un cookie HTTP
wfuzz -w /usr/share/wordlists/param-mini.txt \
    -b "FUZZ=1" \
    http://example.com/page

# Fuzzing de header
# -H "X-Forwarded-For: FUZZ" = fuzze la valeur du header X-Forwarded-For (IP spoofing)
wfuzz -w /usr/share/wordlists/param-mini.txt \
    -H "X-Forwarded-For: FUZZ" \
    http://example.com/page

# Fuzzing avec payload multiple
# -w users.txt -w passwords.txt = deux dictionnaires différents
# FUZZ = premier dictionnaire (users), FUZ2Z = second dictionnaire (passwords)
wfuzz -w users.txt -w passwords.txt \
    -d "username=FUZZ&password=FUZ2Z" \
    http://example.com/login

# Filtrage par code HTTP
# --hc 404,403 = hide codes 404 et 403 (ne pas les afficher dans les résultats)
wfuzz -w /usr/share/wordlists/dirb/common.txt \
    --hc 404,403 \
    http://example.com/FUZZ

# Filtrage par taille
# --hw 120 = hide words (cache les réponses avec 120 mots)
wfuzz -w /usr/share/wordlists/dirb/common.txt \
    --hw 120 \
    http://example.com/FUZZ

# Itérateurs (range, hex)
# -z range,0-10 = payload generator : génère les nombres de 0 à 10
# Pas besoin de wordlist, le payload est généré automatiquement
wfuzz -z range,0-10 \
    -u http://example.com/page?id=FUZZ
```

**Explication des options wfuzz :**
| Option | Rôle/Explication |
|--------|------------------|
| `-w <fichier>` | Wordlist (un dictionnaire par -w, jusqu'à FUZ2Z, FUZ3Z, etc.) |
| `-u <url>` | URL cible (peut être après l'URL directement) |
| `-d <data>` | Corps de la requête POST |
| `-b <cookie>` | Cookie HTTP |
| `-H <header>` | Header HTTP personnalisé |
| `--hc <codes>` | Hide HTTP codes (cache ces codes de réponse) |
| `--hw <N>` | Hide words (cache les réponses avec N mots) |
| `-z <generateur>` | Payload generator intégré (range, list, hex, file, etc.) |
| `FUZZ` | Placeword primaire (premier dictionnaire) |
| `FUZ2Z` | Placeword secondaire (deuxième dictionnaire) |

### 7.4 TP Guidé — Découverte d'endpoints cachés

#### Objectif
Découvrir les endpoints cachés, sous-domaines et paramètres d'une application web cible.

```bash
#!/bin/bash
# decouverte-web.sh — Découverte d'endpoints web
# Usage : ./decouverte-web.sh <url>
# Exemple : ./decouverte-web.sh http://192.168.1.1

set -e  # Exit on error

URL="${1}"  # Premier argument : URL cible
RAPPORT_DIR="rapport-web-$(date +%Y%m%d_%H%M%S)"  # Dossier avec timestamp

if [ -z "$URL" ]; then
    echo "Usage : $0 <url>"
    exit 1
fi

mkdir -p "$RAPPORT_DIR"
echo "[*] Cible : $URL"

# Étape 1 : Directory bruteforce avec ffuf
echo "[1/4] Directory bruteforce (ffuf)..."
# ffuf : fuzzing de répertoires avec wordlist dirb/common.txt
# -e = extensions à tester (php, html, txt, asp, aspx, jsp, bak, old, inc, config, xml, json)
# -fc 404,403 = filtre les codes 404 et 403 (cache les réponses inintéressantes)
# -t 50 = 50 threads, -o = sortie JSON structurée
ffuf -u "${URL}/FUZZ" \
    -w /usr/share/wordlists/dirb/common.txt \
    -e .php,.html,.txt,.asp,.aspx,.jsp,.bak,.old,.inc,.config,.xml,.json \
    -fc 404,403 \
    -t 50 \
    -o "${RAPPORT_DIR}/01-ffuf-dir.json" \
    -of json \
    > /dev/null 2>&1  # Silencieux (pas de sortie console)

# Affiche les résultats du ffuf en filtrant les 404
# jq -r = raw output, select(.status != 404) = exclut les 404
cat "${RAPPORT_DIR}/01-ffuf-dir.json" 2>/dev/null | \
    jq -r '.results[] | select(.status != 404) | "  \(.status) \(.length) \(.url)"' 2>/dev/null

# Étape 2 : Découverte de sous-domaines (si domaine)
echo "[2/4] Sous-domaines..."
# awk -F/ '{print $3}' = extrait le domaine/hôte de l'URL (ex: http://example.com/page → example.com)
DOMAIN=$(echo "$URL" | awk -F/ '{print $3}')
if echo "$DOMAIN" | grep -qP '\\.'; then  # Vérifie si c'est un domaine (contient un point)
    gobuster dns -d "$DOMAIN" \
        -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
        -o "${RAPPORT_DIR}/02-gobuster-dns.txt" \
        > /dev/null 2>&1
fi

# Étape 3 : Virtual Host discovery
echo "[3/4] Virtual Host discovery..."
# gobuster vhost = découvre les sites web hébergés sur la même IP avec des Host headers différents
gobuster vhost -u "$URL" \
    -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain \
    -o "${RAPPORT_DIR}/03-gobuster-vhost.txt" \
    > /dev/null 2>&1

# Étape 4 : Parameter fuzzing
echo "[4/4] Parameter fuzzing (wfuzz)..."
# wfuzz : fuzzing de noms de paramètres GET
# -t 20 = 20 threads, --hc 404,403,500 = cache les codes d'erreur
# /page?FUZZ=test = fuzze le nom du paramètre GET
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    --hc 404,403,500 \
    -t 20 \
    "${URL}/page?FUZZ=test" \
    > "${RAPPORT_DIR}/04-wfuzz-params.txt" 2>/dev/null || true  # || true = ignore les erreurs wfuzz

echo ""
echo "=========================================="
echo " Découverte web terminée !"
echo " Rapport : ${RAPPORT_DIR}/"
echo "=========================================="
```

**Explication du script decouverte-web.sh :**
| Étape | Action | Outil | Méthode |
|-------|--------|-------|---------|
| 1/4 | Directory bruteforce | ffuf | Teste des chemins web avec wordlist et extensions multiples |
| 2/4 | Sous-domaines DNS | gobuster dns | Brute-force de sous-domaines via résolution DNS |
| 3/4 | Virtual Hosts | gobuster vhost | Découverte de vhosts via modification du Header Host |
| 4/4 | Paramètres GET | wfuzz | Fuzzing de noms de paramètres dans l'URL |

---

## 8. Script d'automatisation de reconnaissance

### 8.1 Script Python complet

Ce script Python automatisé orchestre l'ensemble de la phase de reconnaissance.

```python
#!/usr/bin/env python3
# Shebang Python 3 : le script sera exécuté avec l'interpréteur Python 3 du système
"""
recon-automation.py — Automatisation complète de la phase de reconnaissance.

Usage :
    python3 recon-automation.py <target> [options]

Options :
    -m, --mode <fast|full|stealth>   Mode de scan (defaut: fast)
    -o, --output <dir>               Dossier de sortie
    -p, --ports <range>              Plage de ports (defaut: top1000)
    --no-enum                        Desactiver l'enumeration de services
    --no-web                         Desactiver l'enumeration web
    --no-osint                       Desactiver l'OSINT
    --verbose                        Mode verbeux
"""

# Modules standards Python (pas de dépendances externes nécessaires)
import os       # Opérations système (chemins, dossiers)
import sys      # Arguments CLI (sys.argv) et sortie (sys.exit)
import json     # Sérialisation JSON pour les rapports structurés
import argparse # Parsing des arguments en ligne de commande
import subprocess # Exécution de commandes système (Nmap, ffuf, etc.)
import datetime  # Horodatage pour les logs et noms de dossiers
from pathlib import Path  # Manipulation de chemins (moderne, OO)


# Dictionnaire des chemins de wordlists utilisées par le script
WORDLISTS = {
    "dir": "/usr/share/wordlists/dirb/common.txt",              # Directory bruteforce
    "subdomains": "/usr/share/wordlists/amass/subdomains-top1mil.txt",  # Sous-domaines
    "params": "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",  # Paramètres
}

# Liste des scripts NSE à utiliser pour l'énumération de services
NSE_SCRIPTS = [
    "smb-enum-shares", "smb-os-discovery", "smb-security-mode",  # SMB
    "http-enum", "http-headers", "http-title", "http-server-header",  # HTTP
    "dns-zone-transfer", "dns-nsid",  # DNS
    "mysql-enum", "mysql-info", "mysql-empty-password",  # MySQL
    "ssh-hostkey", "ssh-auth-methods", "ssh2-enum-algos",  # SSH
    "ftp-anon", "tftp-enum",  # FTP/TFTP
]


def log(message, level="INFO"):
    """
    Fonction de logging avec timestamp.
    Affiche : [HH:MM:SS] [NIVEAU] message
    """
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")


def run_command(command, shell=False, timeout=300):
    """
    Exécute une commande système via subprocess.
    Retourne : (stdout, stderr, code_retour)
    - command : liste (si shell=False) ou chaîne (si shell=True)
    - shell : si True, exécute via le shell (pipe, redirections)
    - timeout : temps max d'exécution (secondes)
    """
    try:
        result = subprocess.run(
            command, shell=shell, capture_output=True,  # Capture stdout et stderr
            text=True, timeout=timeout,  # Mode texte et timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1  # Timeout : retourne -1
    except FileNotFoundError as e:
        return "", f"Command not found: {e}", -1  # Commande introuvable


def ensure_directory(path):
    """
    Crée un dossier s'il n'existe pas (parents inclus).
    """
    Path(path).mkdir(parents=True, exist_ok=True)


def save_json(data, filepath):
    """
    Sauvegarde un dictionnaire Python au format JSON avec indentation.
    """
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


class ReconAutomation:
    """
    Classe principale qui orchestre toutes les phases de reconnaissance.
    """

    def __init__(self, target, output_dir, mode="fast", ports="top1000",
                 enable_enum=True, enable_web=True, enable_osint=True,
                 verbose=False):
        # Initialisation des paramètres
        self.target = target              # Cible (IP, CIDR, domaine)
        self.output_dir = output_dir       # Dossier de sortie
        self.mode = mode                   # Mode : fast, full, stealth
        self.ports = ports                 # Ports : top1000 ou plage
        self.enable_enum = enable_enum     # Activer énumération services
        self.enable_web = enable_web       # Activer énumération web
        self.enable_osint = enable_osint   # Activer OSINT
        self.verbose = verbose             # Mode verbeux
        self.target_type = self._detect_target_type(target)  # Type auto-détecté
        self.hosts = []                    # Liste des hôtes découverts
        self.open_ports = {}               # Dict : {ip: [{port, service}]}
        self.results = {                   # Structure du rapport final
            "target": target,
            "start_time": datetime.datetime.now().isoformat(),
            "phases": {},
        }
        ensure_directory(output_dir)

    def _detect_target_type(self, target):
        """
        Détecte automatiquement si la cible est :
        - "cidr" : si contient "/" (ex: 192.168.1.0/24)
        - "ip" : si que des chiffres et points (ex: 192.168.1.1)
        - "domain" : si contient un point (ex: example.com)
        - "unknown" : sinon
        """
        if "/" in target:
            return "cidr"
        if target.replace(".", "").isdigit():
            return "ip"
        if "." in target:
            return "domain"
        return "unknown"

    def phase1_discovery(self):
        """
        Phase 1 : Découverte d'hôtes actifs.
        - CIDR/IP : Nmap ping sweep
        - Domaine : dig pour résoudre l'IP
        """
        log("Phase 1 : Decouverte d'hotes actifs...")
        phase_dir = f"{self.output_dir}/01-discovery"
        ensure_directory(phase_dir)

        if self.target_type in ("ip", "cidr"):
            # Ping sweep : découvre les hôtes actifs sur le réseau
            cmd = ["nmap", "-sn", "-T4", self.target, "-oA", f"{phase_dir}/ping-sweep"]
            run_command(cmd)

            # Extrait les IPs du rapport Nmap avec grep
            grep_cmd = (
                f"grep 'Nmap scan report for' {phase_dir}/ping-sweep.nmap "
                f"| grep -oP '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'"
            )
            hosts_out, _, _ = run_command(grep_cmd, shell=True)
            self.hosts = hosts_out.strip().split("\\n") if hosts_out.strip() else []

        elif self.target_type == "domain":
            # Résolution DNS pour trouver l'IP du domaine
            cmd = ["dig", "+short", self.target, "A"]
            stdout, _, _ = run_command(cmd)
            # Filtre les lignes non vides (IPs valides)
            ips = [ip for ip in stdout.strip().split("\\n") if ip]
            self.hosts = ips

        # Sauvegarde des hôtes découverts en JSON
        save_json({"hosts": self.hosts}, f"{phase_dir}/hosts.json")
        self.results["phases"]["discovery"] = {
            "hosts_found": len(self.hosts), "hosts": self.hosts,
        }
        log(f"  -> {len(self.hosts)} hotes decouverts")
        return self.hosts

    def phase2_port_scan(self):
        """
        Phase 2 : Scan de ports.
        Utilise Nmap avec SYN scan, version detection, OS detection.
        Timing adapté selon le mode (stealth, fast, full).
        """
        log("Phase 2 : Scan de ports...")
        phase_dir = f"{self.output_dir}/02-port-scan"
        ensure_directory(phase_dir)

        if not self.hosts:
            return {}

        # Mapping mode → paramètre timing Nmap
        timing_map = {"stealth": "-T1", "fast": "-T4", "full": "-T4"}
        timing = timing_map.get(self.mode, "-T4")
        # Gestion des ports : top1000 ou plage personnalisée
        ports_arg = "--top-ports 1000" if self.ports == "top1000" else f"-p {self.ports}"

        for host in self.hosts:
            log(f"  -> Scan de {host}...")
            # Commande Nmap : SYN scan + timing + ports + versions + OS
            cmd = f"nmap -sS {timing} {ports_arg} -sV -O --osscan-guess -oA {phase_dir}/scan-{host} {host}"
            run_command(cmd, shell=True, timeout=600)

            # Parse les résultats : cherche les lignes avec ports ouverts
            grep_cmd = f"grep -E '^[0-9]+/(tcp|udp)' {phase_dir}/scan-{host}.nmap | grep 'open'"
            ports_out, _, _ = run_command(grep_cmd, shell=True)

            # Extrait les informations : port, protocole et service
            ports = []
            for line in ports_out.strip().split("\\n"):
                if line:
                    parts = line.split()
                    port_proto = parts[0]  # Ex: "80/tcp"
                    service = parts[2] if len(parts) > 2 else "?"  # Ex: "http"
                    ports.append({"port": port_proto, "service": service})
            self.open_ports[host] = ports

        save_json(self.open_ports, f"{phase_dir}/ports.json")
        return self.open_ports

    def phase3_service_enum(self):
        """
        Phase 3 : Énumération des services.
        Pour chaque service détecté, lance l'outil approprié :
        - SMB → enum4linux
        - HTTP → Nmap NSE scripts
        - DNS → Nmap scripts DNS
        """
        if not self.enable_enum:
            return {}
        log("Phase 3 : Enumeration des services...")
        phase_dir = f"{self.output_dir}/03-service-enum"
        ensure_directory(phase_dir)

        for host, ports in self.open_ports.items():
            services = [p["service"] for p in ports]
            # Énumération SMB si microsoft-ds ou netbios-ssn détecté
            if "microsoft-ds" in services or "netbios-ssn" in services:
                stdout, _, _ = run_command(["enum4linux", "-a", host], timeout=120)
                with open(f"{phase_dir}/smb-{host}.txt", "w") as f:
                    f.write(stdout)
            # Énumération HTTP si http ou https détecté
            if any(s in services for s in ["http", "https"]):
                cmd = ["nmap", "-p", "80,443,8080,8443",
                       "--script", "http-enum,http-headers,http-title",
                       "-oA", f"{phase_dir}/http-{host}", host]
                run_command(cmd, timeout=180)
            # Énumération DNS si domaine détecté
            if "domain" in services:
                cmd = ["nmap", "-p", "53",
                       "--script", "dns-zone-transfer,dns-nsid",
                       "-oA", f"{phase_dir}/dns-{host}", host]
                run_command(cmd, timeout=60)
        return {}

    def phase4_web_enum(self):
        """
        Phase 4 : Énumération web (directory bruteforce).
        Utilise ffuf pour découvrir les chemins cachés sur chaque service HTTP/HTTPS.
        """
        if not self.enable_web:
            return {}
        log("Phase 4 : Enumeration web...")
        phase_dir = f"{self.output_dir}/04-web-enum"
        ensure_directory(phase_dir)

        for host, ports in self.open_ports.items():
            # Filtre les ports HTTP/HTTPS uniquement
            http_ports = [p["port"] for p in ports if p["service"] in ("http", "https")]
            for port_str in http_ports:
                port = port_str.split("/")[0]  # Extrait le numéro de port
                proto = "https" if port in ("443", "8443") else "http"
                url = f"{proto}://{host}:{port}"
                # ffuf : directory bruteforce avec wordlist et extensions
                cmd = (
                    f"ffuf -u {url}/FUZZ -w {WORDLISTS['dir']} "
                    f"-e .php,.html,.txt,.bak,.asp -fc 404,403 "
                    f"-t 50 -of json -o {phase_dir}/ffuf-{host}-{port}.json "
                    f"> /dev/null 2>&1"
                )
                run_command(cmd, shell=True, timeout=120)
        return {}

    def phase5_osint(self):
        """
        Phase 5 : OSINT réseau via Certificate Transparency (crt.sh).
        Ne s'exécute que si la cible est un nom de domaine.
        """
        if not self.enable_osint:
            return {}
        log("Phase 5 : OSINT reseau...")
        phase_dir = f"{self.output_dir}/05-osint"
        ensure_directory(phase_dir)

        if self.target_type == "domain":
            # Interroge crt.sh pour trouver les sous-domaines via les logs de certificats TLS
            cmd = (
                f"curl -s 'https://crt.sh/?q=%25.{self.target}&output=json' "
                f"| jq -r '.[].name_value' | sed 's/\\\\*\\\\.//g' "
                f"| sort -u > {phase_dir}/crt-subdomains.txt"
            )
            run_command(cmd, shell=True, timeout=30)
        return {}

    def generate_report(self):
        """
        Génère le rapport final au format JSON et TXT.
        - JSON : structuré, pour parsing automatisé
        - TXT : lisible, pour relecture humaine
        """
        log("Generation du rapport final...")
        self.results["end_time"] = datetime.datetime.now().isoformat()
        self.results["summary"] = {
            "total_hosts": len(self.hosts),
            "total_open_ports": sum(len(p) for p in self.open_ports.values()),
            "phases_completed": list(self.results["phases"].keys()),
        }
        # Sauvegarde JSON
        save_json(self.results, f"{self.output_dir}/rapport_final.json")

        # Sauvegarde TXT (format lisible)
        txt_path = f"{self.output_dir}/rapport_final.txt"
        with open(txt_path, "w") as f:
            f.write("RAPPORT DE RECONNAISSANCE\n")
            f.write(f"Cible : {self.target}\n")
            f.write(f"Date : {self.results['start_time']}\n\n")
            for host in self.hosts:
                f.write(f"\n[+] HOTE : {host}\n")
                ports = self.open_ports.get(host, [])
                for p in ports:
                    f.write(f"  - {p['port']} -> {p['service']}\n")
        log(f"  -> Rapport genere dans {self.output_dir}/")

    def run(self):
        """
        Orchestrateur principal : exécute toutes les phases dans l'ordre.
        """
        log(f"Demarrage de la reconnaissance pour : {self.target}")
        self.phase1_discovery()          # Découverte d'hôtes
        if self.hosts:                   # Si des hôtes ont été trouvés
            self.phase2_port_scan()      # Scan de ports
            self.phase3_service_enum()   # Énumération des services
            self.phase4_web_enum()       # Énumération web
        self.phase5_osint()              # OSINT réseau
        self.generate_report()           # Rapport final
        log("Reconnaissance terminee !")


def main():
    """
    Point d'entrée : parse les arguments CLI et lance l'automation.
    """
    parser = argparse.ArgumentParser(description="Recon Automation")
    parser.add_argument("target", help="Cible (CIDR, IP, domaine)")  # Argument obligatoire
    parser.add_argument("-m", "--mode", choices=["fast", "full", "stealth"],
                        default="fast")  # Mode de scan
    parser.add_argument("-o", "--output", default=None)  # Dossier de sortie personnalisé
    parser.add_argument("-p", "--ports", default="top1000")  # Plage de ports
    parser.add_argument("--no-enum", action="store_true")    # Désactiver énumération
    parser.add_argument("--no-web", action="store_true")     # Désactiver web enum
    parser.add_argument("--no-osint", action="store_true")   # Désactiver OSINT
    parser.add_argument("--verbose", "-v", action="store_true")  # Mode verbeux
    args = parser.parse_args()  # Parse les arguments

    # Nettoie le nom de la cible pour l'utiliser comme nom de dossier
    target_safe = args.target.replace("/", "_").replace(".", "-")
    # Génère un nom de dossier par défaut avec timestamp
    output_dir = args.output or f"recon-{target_safe}-{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Instancie la classe d'automation avec les paramètres
    recon = ReconAutomation(
        target=args.target, output_dir=output_dir, mode=args.mode,
        ports=args.ports, enable_enum=not args.no_enum,
        enable_web=not args.no_web, enable_osint=not args.no_osint,
        verbose=args.verbose,
    )
    try:
        recon.run()  # Lance l'automation
    except KeyboardInterrupt:
        # Capture Ctrl+C pour une sortie propre
        log("\nInterruption utilisateur.", "WARN")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### 8.2 Utilisation du script

```bash
# Rendre le script executable
# chmod +x = ajoute le droit d'exécution pour lancer ./recon-automation.py
chmod +x recon-automation.py

# Mode rapide sur un sous-reseau
# Utilise les paramètres par défaut : mode fast, top 1000 ports
python3 recon-automation.py 192.168.1.0/24

# Mode complet sur une IP unique
# -m full = mode complet, -p 1-65535 = tous les ports, -v = verbose
python3 recon-automation.py 10.0.0.1 -m full -p 1-65535 -v

# Mode furtif (evasion IDS)
# -m stealth = utilise -T1 (timing lent) pour éviter la détection
python3 recon-automation.py 192.168.1.0/24 -m stealth

# OSINT seulement
# --no-enum --no-web = désactive l'énumération de services et l'énumération web
# Seulement la découverte d'hôtes et l'OSINT (crt.sh)
python3 recon-automation.py example.com --no-enum --no-web

# Dossier de sortie personnalise
# -o /tmp/rapport-recon = dossier de sortie spécifique (au lieu du dossier auto-généré)
python3 recon-automation.py 10.0.0.0/24 -o /tmp/rapport-recon
```

**Explication des options :**
| Option | Rôle/Explication |
|--------|------------------|
| `chmod +x` | Rend le script exécutable |
| `-m fast\|full\|stealth` | Mode de scan (défaut : fast) |
| `-p <ports>` | Ports à scanner (top1000 ou plage comme 1-65535) |
| `-v` / `--verbose` | Mode verbeux (affiche plus de détails) |
| `--no-enum` | Désactive l'énumération de services (SMB, HTTP, DNS) |
| `--no-web` | Désactive l'énumération web (ffuf) |
| `--no-osint` | Désactive l'OSINT (crt.sh) |
| `-o <dossier>` | Dossier de sortie personnalisé (par défaut : auto-généré avec timestamp) |

---

## 9. TP Synthèse

### 9.1 Objectif

Reconnaissance complète d'un domaine cible (exemple : `megacorp.local`). Pipeline complet :

```
1. Scan ports (Masscan/Rustscan/Nmap)
2. Enumeration services (SMB, SNMP, DNS, LDAP, NFS)
3. Fingerprinting (OS, versions)
4. OSINT (Shodan, crt.sh)
5. Enumeration web (ffuf, gobuster)
6. Rapport structure
```

### 9.2 Pipeline complet de reconnaissance

```bash
#!/bin/bash
# tp-synthese.sh — TP Synthese : Reconnaissance complete
# Usage : sudo ./tp-synthese.sh <cible>
# Exemple : sudo ./tp-synthese.sh megacorp.local

set -e  # Exit on error : stoppe au premier échec
CIBLE="${1}"  # Premier argument : cible (IP, domaine ou CIDR)
BASE_DIR="tp-synthese-$(date +%Y%m%d_%H%M%S)"  # Dossier unique avec timestamp

if [ -z "$CIBLE" ]; then
    echo "Usage : $0 <cible>"
    exit 1
fi

mkdir -p "$BASE_DIR"
echo "============================================="
echo " TP SYNTHESE - RECONNAISSANCE COMPLETE"
echo " Cible : $CIBLE"
echo " Date : $(date)"
echo "============================================="

# Phase 1 : Resolution DNS et OSINT (si domaine)
echo ""
echo "===== [PHASE 1] OSINT & DNS ====="

# Vérifie si la cible est un nom de domaine (commence par une lettre)
if echo "$CIBLE" | grep -qP '^[a-zA-Z]'; then
    echo "[*] Domaine : $CIBLE"

    # Resolution DNS de l'IP principale
    IP=$(dig +short "$CIBLE" A | head -1)  # Résout l'enregistrement A
    echo "[1a] Resolution DNS : $CIBLE -> $IP"

    # Sous-domaines via Certificate Transparency (crt.sh)
    echo "[1b] Sous-domaines via crt.sh..."
    curl -s "https://crt.sh/?q=%25.${CIBLE}&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | \
        sed 's/\\*\\.//g' | sort -u > "${BASE_DIR}/subdomains.txt" 2>/dev/null
    echo "  -> $(wc -l < "${BASE_DIR}/subdomains.txt" 2>/dev/null || echo 0) sous-domaines"

    # Résolution DNS des sous-domaines découverts
    while read -r sub; do
        sub_ip=$(dig +short "$sub" A 2>/dev/null | head -1)
        [ -n "$sub_ip" ] && echo "$sub_ip $sub" >> "${BASE_DIR}/resolved.txt"
    done < "${BASE_DIR}/subdomains.txt"

    TARGET_IP="$IP"  # IP principale utilisée pour définir le sous-réseau
else
    TARGET_IP="$CIBLE"  # Si c'est directement une IP
fi

# Déduit le sous-réseau /24 de l'IP (remplace le dernier octet par .0)
CIDR_TARGET="${TARGET_IP%.*}.0/24"
echo "[1d] Sous-reseau cible : $CIDR_TARGET"

# Phase 2 : Decouverte d'hotes
echo ""
echo "===== [PHASE 2] DECOUVERTE D'HOTES ====="
# Ping sweep Nmap : découvre les hôtes actifs sur le sous-réseau
sudo nmap -sn -T4 "$CIDR_TARGET" -oA "${BASE_DIR}/ping-sweep"

# Extrait les IPs des hôtes découverts depuis le format greppable
grep "Nmap scan report for" "${BASE_DIR}/ping-sweep.nmap" | \
    grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' > "${BASE_DIR}/hosts.txt"

NB_HOSTS=$(wc -l < "${BASE_DIR}/hosts.txt")  # Compte le nombre d'hôtes
echo "[+] $NB_HOSTS hotes actifs"

# Phase 3 : Scan de ports
echo ""
echo "===== [PHASE 3] SCAN DE PORTS ====="

# Masscan : scan ultra-rapide si l'outil est installé
# -iL = input list (fichier d'hôtes), -p1-65535 = tous les ports
# --rate=100000 = 100k pps, --wait 2 = 2 secondes d'attente
if command -v masscan &>/dev/null; then
    echo "[3a] Masscan ultra-rapide..."
    sudo masscan -iL "${BASE_DIR}/hosts.txt" -p1-65535 \
        --rate=100000 --wait 2 \
        -oL "${BASE_DIR}/masscan-ports.txt" 2>/dev/null || true
fi

# Nmap approfondi : SYN scan + versions + OS + scripts sur chaque hôte
echo "[3b] Nmap approfondi..."
while read -r host; do
    sudo nmap -sS -sV -O -T4 --top-ports 1000 \
        --script default,vuln --script-timeout 60s \
        -oA "${BASE_DIR}/nmap-${host}" "$host" > /dev/null 2>&1
    echo "  -> $host scanne"
done < "${BASE_DIR}/hosts.txt"

# Phase 4 : Enumeration des services
echo ""
echo "===== [PHASE 4] ENUMERATION ====="

for host in $(cat "${BASE_DIR}/hosts.txt"); do
    # SMB : si port 445 détecté → enum4linux
    if grep -q "445/open" "${BASE_DIR}/nmap-${host}.nmap" 2>/dev/null; then
        echo "[SMB] $host..."
        enum4linux -a "$host" > "${BASE_DIR}/smb-${host}.txt" 2>/dev/null
    fi
    # HTTP : si port 80 ou 443 → gobuster directory bruteforce
    if grep -qE "(80|443)/open" "${BASE_DIR}/nmap-${host}.nmap" 2>/dev/null; then
        echo "[HTTP] $host..."
        gobuster dir -u "http://${host}" \
            -w /usr/share/wordlists/dirb/common.txt \
            -x php,html,txt,bak -b 404,403 \
            -o "${BASE_DIR}/gobuster-${host}.txt" > /dev/null 2>&1 || true
    fi
    # DNS : si port 53 → test de zone transfer
    if grep -q "53/open" "${BASE_DIR}/nmap-${host}.nmap" 2>/dev/null; then
        echo "[DNS] $host..."
        dig @"$host" example.com AXFR +short > "${BASE_DIR}/zone-transfer-${host}.txt" 2>/dev/null
    fi
    # SNMP : si port 161 → snmpwalk sur les infos système
    if grep -q "161/open" "${BASE_DIR}/nmap-${host}.nmap" 2>/dev/null; then
        echo "[SNMP] $host..."
        snmpwalk -v2c -c public "$host" .1.3.6.1.2.1.1 \
            > "${BASE_DIR}/snmp-${host}.txt" 2>/dev/null
    fi
    # LDAP : si port 389 ou 636 → ldapsearch sur le naming context
    if grep -qE "(389|636)/open" "${BASE_DIR}/nmap-${host}.nmap" 2>/dev/null; then
        echo "[LDAP] $host..."
        ldapsearch -x -H "ldap://${host}" -b "" -s base \
            "(objectClass=*)" namingContexts \
            > "${BASE_DIR}/ldap-${host}.txt" 2>/dev/null
    fi
done

# Phase 5 : Rapport final
echo ""
echo "===== [PHASE 5] RAPPORT FINAL ====="

# Génère un rapport Markdown avec les informations collectées
cat > "${BASE_DIR}/rapport-synthese.md" << 'RAPPORT_EOF'
# Rapport de Reconnaissance

**Cible :** $CIBLE
**Sous-reseau :** $CIDR_TARGET
**Hotes decouverts :** $NB_HOSTS

## Reseau

## Services decouverts

## Techniques MITRE ATT&CK identifiees

| Technique | ID | Detection |
|-----------|----|-----------|
| Active Scanning | T1595 | Requetes SYN massives |
| Network Service Discovery | T1046 | Scans de ports |
| Network Share Discovery | T1049 | Enumeration SMB |
| Gather Victim Network Info | T1590 | Requetes DNS |
| Gather Victim Host Info | T1592 | Fingerprinting |
| Account Discovery | T1087 | Enumeration LDAP |

## Recommandations NIS2

- Cartographier et inventorier tous les actifs
- Restreindre les acces aux services sensibles
- Desactiver les protocoles non necessaires
- Mettre a jour les versions identifiees
RAPPORT_EOF

echo "[✓] Rapport genere : ${BASE_DIR}/rapport-synthese.md"

# Resume final : affiche les ports ouverts pour chaque hôte
echo ""
echo "============================================="
echo " RESUME DE LA RECONNAISSANCE"
echo "============================================="
echo " Cible : $CIBLE"
echo " Hotes : $NB_HOSTS"
echo ""
for host in $(cat "${BASE_DIR}/hosts.txt" 2>/dev/null); do
    echo "--- $host ---"
    # grep des lignes de ports ouverts dans le rapport Nmap
    # Si le fichier existe et contient des ports ouverts, les affiche
    [ -f "${BASE_DIR}/nmap-${host}.nmap" ] && \
        grep -E "^[0-9]+/(tcp|udp).*open" "${BASE_DIR}/nmap-${host}.nmap" || \
        echo "  Aucun port ouvert"
done

echo ""
echo "============================================="
echo " TP Synthese termine !"
echo " Rapport complet : ${BASE_DIR}/"
echo "============================================="
```

**Explication du script tp-synthese.sh :**
| Phase | Action | Outils | Logique |
|-------|--------|--------|---------|
| 1 | OSINT & DNS | dig + crt.sh | Résolution DNS puis découverte de sous-domaines via Certificate Transparency |
| 2 | Découverte d'hôtes | nmap -sn | Ping sweep ICMP sur le sous-réseau /24 |
| 3a | Scan rapide | masscan | Si installé, scan de tous les ports (1-65535) à 100k pps |
| 3b | Scan détaillé | nmap -sS -sV -O | SYN scan + versions + OS + scripts NSE sur top 1000 ports |
| 4 | Énumération services | enum4linux, gobuster, dig, snmpwalk, ldapsearch | Énumération conditionnelle selon les ports ouverts détectés |
| 5 | Rapport | Markdown | Génération d'un rapport structuré avec les résultats consolidés |

### 9.3 Exécution du TP synthèse

```bash
# Rendre le script executable
# chmod +x = ajoute les droits d'exécution au fichier tp-synthese.sh
chmod +x tp-synthese.sh

# Executer sur un domaine
# Lance le pipeline complet : OSINT (crt.sh) → découverte d'hôtes → scan ports → enum services → rapport
# sudo = nécessaire pour les sockets raw (Nmap SYN scan, Masscan)
# megacorp.local = nom de domaine (le script détecte automatiquement que c'est un domaine, pas une IP)
sudo ./tp-synthese.sh megacorp.local

# Executer sur une IP
# 192.168.1.1 = IP unique (le script déduit le sous-réseau /24 : 192.168.1.0/24)
sudo ./tp-synthese.sh 192.168.1.1

# Executer sur un sous-reseau
# 192.168.1.0/24 = sous-réseau directement spécifié (pas de déduction CIDR)
sudo ./tp-synthese.sh 192.168.1.0/24
```

**Explication des commandes :**
| Commande | Rôle/Explication |
|----------|------------------|
| `chmod +x tp-synthese.sh` | Rend le script exécutable (permet de le lancer avec `./`) |
| `sudo ./tp-synthese.sh <cible>` | Lance le pipeline complet avec les privilèges root (nécessaires pour les sockets raw) |
| `megacorp.local` | Cible domaine : déclenche la phase OSINT (crt.sh) + résolution DNS avant le scan réseau |
| `192.168.1.1` | Cible IP unique : le script déduit automatiquement le sous-réseau /24 |
| `192.168.1.0/24` | Cible CIDR : le script utilise directement ce sous-réseau sans déduction |

### 9.4 Tableau ATT&CK à remplir

Chaque étudiant doit remplir ce tableau pendant le TP :

| Phase | Technique MITRE | ID | Détecté ? (O/N) | Outil utilisé | Évidence |
|-------|-----------------|----|-----------------|---------------|----------|
| Reconnaissance | Active Scanning | T1595.001 | | Nmap/Masscan/Rustscan | |
| Reconnaissance | Active Scanning | T1595.002 | | NSE vuln scripts | |
| Reconnaissance | Active Scanning | T1595.003 | | ffuf/gobuster/wfuzz | |
| Reconnaissance | Gather Victim Network Info | T1590 | | dig/dnsrecon | |
| Reconnaissance | Gather Victim Host Info | T1592.001 | | Nmap -O/-sV | |
| Reconnaissance | Gather Victim Host Info | T1592.004 | | Shodan/Censys/crt.sh | |
| Énumération | Network Service Discovery | T1046 | | Nmap/service enum | |
| Énumération | Network Share Discovery | T1049 | | enum4linux/CME | |
| Énumération | Account Discovery | T1087 | | ldapsearch/windapsearch | |

---

## Références

| Ressource | URL |
|-----------|-----|
| MITRE ATT&CK T1595 | https://attack.mitre.org/techniques/T1595/ |
| Nmap Documentation | https://nmap.org/docs.html |
| Nmap NSE | https://nmap.org/nsedoc/ |
| Masscan | https://github.com/robertdavidgraham/masscan |
| Rustscan | https://github.com/RustScan/RustScan |
| ffuf | https://github.com/ffuf/ffuf |
| Gobuster | https://github.com/OJ/gobuster |
| wfuzz | https://github.com/xmendez/wfuzz |
| Shodan | https://www.shodan.io/ |
| Censys | https://search.censys.io/ |
| crt.sh | https://crt.sh/ |
| CrackMapExec | https://github.com/byt3bl33d3r/CrackMapExec |
| SecLists | https://github.com/danielmiessler/SecLists |
| NIS2 Directive | https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32022L2555 |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng |
| windapsearch | https://github.com/ropnop/windapsearch |
| ldapdomaindump | https://github.com/dirkjanm/ldapdomaindump |
| nmap-bootstrap-xsl | https://github.com/honze-net/nmap-bootstrap-xsl |
