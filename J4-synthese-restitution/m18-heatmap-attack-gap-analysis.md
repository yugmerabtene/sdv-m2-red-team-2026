# Module 18 — Heat Map ATT&CK & Analyse des Gaps (1h00)

> **Niveau** : M2 Red Team · **Jour** : J4 — Synthèse & Restitution  
> **Prérequis** : Modules M1 à M17 · Connaissance du framework MITRE ATT&CK  
> **Objectif** : Maîtriser la construction de heat maps, l'analyse des gaps et le mapping NIS2 ↔ ATT&CK

---

## Table des matières

1. [Rappel : ATT&CK Navigator](#1-rappel--attck-navigator)
2. [Méthodologie de construction de heat map](#2-méthodologie-de-construction-de-heat-map)
3. [Gap Analysis — Méthodologie](#3-gap-analysis--méthodologie)
4. [Mapping NIS2 ↔ ATT&CK](#4-mapping-nis2--attck)
5. [TP Guidé — Construire sa heat map](#5-tp-guidé--construire-sa-heat-map)
6. [Outils complémentaires](#6-outils-complémentaires)
7. [Annexes](#7-annexes)

---

## 1. Rappel : ATT&CK Navigator

### 1.1 Présentation de l'outil

L'ATT&CK Navigator est l'outil de visualisation officiel du framework MITRE ATT&CK. Il permet de créer des matrices interactives représentant la couverture des techniques offensives et défensives d'une organisation.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     MITRE ATT&CK NAVIGATOR                          │
│                                                                     │
│   ┌─────────────────────────────────────────────────────────────┐  │
│   │                                                             │  │
│   │   [Initial Access] [Execution] [Persistence] [Priv Esc] ... │  │
│   │                                                             │  │
│   │   T1190  ████████  T1053  ░░░░░░░░  T1547  ████████         │  │
│   │   T1133  ░░░░░░░░  T1059  ████████  T1543  ████████         │  │
│   │   T1078  ████████  T1203  ░░░░░░░░  T1505  ░░░░░░░░         │  │
│   │   T1199  ░░░░░░░░  T1559  ████████  T1136  ██░░░░░░         │  │
│   │                                                             │  │
│   │   ████ = Exploitée  ░░░░ = Non testée  ██░░ = Partielle    │  │
│   └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Trois modes d'accès :**

| Mode | URL | Usage |
|------|-----|-------|
| **Web** | https://mitre-attack.github.io/attack-navigator/ | Usage ponctuel, pas de persistance |
| **Docker** | `docker pull mitreattack/attack-navigator` | Instance locale persistante |
| **Application** | Release GitHub | Hors-ligne, embarqué dans les rapports |

### 1.2 Installation locale

```bash
# === METHODE 1 : NPM (recommandé) ===
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
npm install
npm start
# Puis ouvrir http://localhost:4200

# === METHODE 2 : Via le JSON directement ===
# Importer le fichier JSON dans l'instance en ligne :
# https://mitre-attack.github.io/attack-navigator/
```

**Installation depuis les sources (recommandée pour la personnalisation) :**

```bash
# Clonage du dépôt
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator

# Installation des dépendances
npm install

# Compilation et lancement
npm run build
npm start
```

### 1.3 Création d'une heat map

**Workflow complet :**

```
Étape 1               Étape 2              Étape 3              Étape 4
┌──────────┐         ┌──────────┐         ┌──────────┐         ┌──────────┐
│ Nouvelle │────────▶│ Sélection│────────▶│  Ajout   │────────▶│  Export  │
│  couche  │         │   des    │         │  scores  │         │   JSON   │
│  (layer) │         │techniques│         │  et      │         │          │
└──────────┘         └──────────┘         │couleurs  │         └──────────┘
                                          └──────────┘
```

**Création pas à pas :**

1. Ouvrir ATT&CK Navigator
2. Cliquer sur **"Create New Layer"**
3. Sélectionner le domaine : **Enterprise ATT&CK v15.1** (ou version la plus récente)
4. Choisir la plateforme : `Windows`, `Linux`, `macOS`, `Cloud` ou `Network`
5. Nommer la couche : `Pentest_ClientX_2026-05`
6. Appliquer les scores manuellement ou via import JSON

### 1.4 Palette de couleurs recommandée

Le code couleur standardisé pour une heat map de pentest Red Team :

| Couleur | Code Hex | Signification | Critère |
|---------|----------|---------------|---------|
| 🔴 **Rouge** | `#e60d0d` | Exploitée avec succès | Accès obtenu, objectif atteint |
| 🟠 **Orange** | `#f98d0b` | Tentée / Succès partiel | Technique exécutée mais chemin non abouti |
| 🟡 **Jaune** | `#fee003` | Détectée par le SOC | L'action a généré une alerte / Incident Response |
| ⬜ **Gris** | `#c1c1c1` | Non testée | Hors scope, contrainte temporelle, non applicable |
| 🟢 **Vert** | `#03c03c` | Testée, non exploitée | EDR bloqué, configuration robuste |
| 🔵 **Bleu** | `#1e90ff` | Mitigation en place | Contre-mesure déployée et efficace |

```json
{
  "name": "Palette Pentest",
  "gradient": [
    {"color": "#e60d0d", "value": 100},
    {"color": "#f98d0b", "value": 75},
    {"color": "#fee003", "value": 50},
    {"color": "#03c03c", "value": 25},
    {"color": "#c1c1c1", "value": 0}
  ]
}
```

### 1.5 Annotations des techniques

L'ATT&CK Navigator permet d'ajouter trois types de métadonnées par technique :

| Champ | Description | Exemple |
|-------|-------------|---------|
| **comment** | Note libre, texte riche | `"Accès DA obtenu via certificat ESC1 — T1649, certipy-ad"` |
| **enabled** | Visibilité de la technique | `true` / `false` |
| **score** | Valeur numérique 0–100 | `75` (succès partiel) |
| **metadata** | Objet JSON libre | `{"outil": "crackmapexec", "chemin": "SRV01 → DC02"}` |

**Exemple d'annotation enrichie :**

```json
{
  "techniqueID": "T1649",
  "score": 100,
  "color": "#e60d0d",
  "comment": "ADCS ESC1 — Certipy-ad. Obtention certificat DA. Détection : Event ID 4886, 4887 sur CA.",
  "metadata": {
    "outil": "certipy-ad",
    "commande": "certipy-ad req -u user@domain -p pass -ca CA-SERVER -template ESC1",
    "chemin_attaque": "SRV01 → DC01 (CA)",
    "detection": "EventID 4886, 4887",
    "mitigation": "Modifier les flags du template (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)"
  }
}
```

### 1.6 Export et partage

**Formats d'export supportés :**

```bash
# Export JSON (couche ATT&CK Navigator)
# Depuis l'UI : Layer Control → Download Layer → JSON

# Export SVG (pour intégration dans un rapport)
# Depuis l'UI : SVG → Download SVG

# Export Excel (pour analyse tabulaire)
# Conversion manuelle : JSON → CSV via script Python
```

**Script Python de conversion JSON → CSV :**

```python
#!/usr/bin/env python3
"""
Convertit une couche ATT&CK Navigator (JSON) en tableau CSV.
Usage : python3 nav2csv.py layer.json > output.csv

Tags MITRE : N/A (outillage)
"""

import json
import csv
import sys

def convert_nav_to_csv(json_path):
    with open(json_path, 'r') as f:
        layer = json.load(f)

    techniques = layer.get('techniques', [])

    writer = csv.writer(sys.stdout)
    writer.writerow(['Technique ID', 'Tactique', 'Nom', 'Score', 'Commentaire', 'Détection'])

    for tech in techniques:
        tid = tech['techniqueID']
        tactic = tech.get('tactic', '')
        score = tech.get('score', 0)
        comment = tech.get('comment', '')
        detection = tech.get('metadata', {}).get('detection', '') if tech.get('metadata') else ''

        writer.writerow([tid, tactic, '', score, comment, detection])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 nav2csv.py layer.json", file=sys.stderr)
        sys.exit(1)
    convert_nav_to_csv(sys.argv[1])
```

---

## 2. Méthodologie de construction de heat map

### 2.1 Vue d'ensemble — Les 4 étapes

```
┌──────────────────────────────────────────────────────────────────────┐
│              MÉTHODOLOGIE DE CONSTRUCTION DE HEAT MAP                │
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌───────┐ │
│  │   Étape 1    │   │   Étape 2    │   │   Étape 3    │   │Étape 4│ │
│  │              │   │              │   │              │   │       │ │
│  │  Lister les  │──▶│  Marquer le  │──▶│  Appliquer   │──▶│ Gap   │ │
│  │ techniques   │   │  résultat    │   │  code couleur│   │Analysis│ │
│  │  testées     │   │  par tech.   │   │              │   │       │ │
│  └──────────────┘   └──────────────┘   └──────────────┘   └───────┘ │
│                                                                      │
│  Entrée : Rapport de pentest → Sortie : Heat map + Gap analysis      │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.2 Étape 1 — Lister toutes les techniques testées

**Sources des techniques :**

| Source | Contenu | Extraction |
|--------|---------|------------|
| Rapport de pentest | Kill chain déroulée | Relecture systématique |
| Logs C2 (Cobalt Strike, Mythic, Sliver) | Commandes exécutées | Export des logs |
| Notes personnelles | Observables, tentatives | Carnet de bord |
| Scripts et outils utilisés | Techniques sous-jacentes | Mapping outil → ATT&CK |

**Méthode d'extraction systématique :**

Pour chaque phase de la kill chain, lister :

```
Phase : Initial Access
├── Technique : T1190 — Exploit Public-Facing Application
│   Cible : https://portail.client.lan/login.jsp (CVE-2021-44228)
│   Résultat : Exploitée → RCE obtenue → shell SYSTEM (tomcat)
│   Outil  : curl + payload Log4Shell personnalisé
│
├── Technique : T1078 — Valid Accounts
│   Cible : OWA https://mail.client.lan (password spraying)
│   Résultat : 3 comptes valides, MFA bloquant
│   Outil  : SprayingToolkit, liste utilisateurs LinkedIn
│
Phase : Execution
├── Technique : T1059.001 — PowerShell
│   Cible : SRV01 (depuis accès initial)
│   Résultat : AMSI bypass, exécution beacon Cobalt Strike
│   Outil  : Cobalt Strike, script AMSI bypass custom
│
├── Technique : T1053.005 — Scheduled Task
│   Cible : SRV01 → persistance
│   Résultat : Tâche planifiée créée avec succès
│   Outil  : schtasks.exe
```

**Tableau récapitulatif à produire :**

| ID Tech. | Tactique | Technique | Résultat | Outil |
|----------|----------|-----------|----------|-------|
| T1190 | Initial Access | Exploit Public-Facing Application | Succès | Log4Shell exploit |
| T1078 | Initial Access | Valid Accounts | Partiel | SprayingToolkit |
| T1059.001 | Execution | PowerShell | Succès | Cobalt Strike |
| T1053.005 | Execution | Scheduled Task | Succès | schtasks.exe |
| T1562.001 | Defense Evasion | Disable or Modify Tools | Succès | AMSI bypass |
| T1003.001 | Credential Access | LSASS Memory | Bloqué | EDR (CrowdStrike) |
| T1649 | Credential Access | Steal or Forge Certificates | Succès | certipy-ad |
| T1482 | Discovery | Domain Trust Discovery | Succès | nltest.exe |
| T1021.002 | Lateral Movement | SMB/Windows Admin Shares | Succès | crackmapexec |
| T1005 | Collection | Data from Local System | Succès | Recherche manuelle |
| T1041 | Exfiltration | Exfiltration Over C2 Channel | Succès | Beacon SMB→HTTP |
| T1485 | Impact | Data Destruction | Non testée | Hors scope |

### 2.3 Étape 2 — Pour chaque technique, marquer le résultat

**Critères de classification :**

```
Arbre de décision pour le marquage d'une technique :

La technique a-t-elle été testée ?
├── OUI → A-t-elle abouti à l'objectif ?
│   ├── OUI → A-t-elle été détectée par le SOC ?
│   │   ├── OUI → JAUNE (détectée)
│   │   └── NON → ROUGE (exploitée avec succès)
│   │
│   └── NON → Pourquoi ?
│       ├── EDR/Mitigation bloquante → VERT (mitigation efficace)
│       ├── Tentative échouée → ORANGE (succès partiel)
│       └── Chemin non abouti → ORANGE
│
└── NON → Raison ?
    ├── Hors scope → GRIS (non testée)
    ├── Contrainte temporelle → GRIS (non testée)
    └── Non applicable (techno absente) → GRIS avec mention N/A
```

### 2.4 Étape 3 — Appliquer le code couleur

**Implémentation dans ATT&CK Navigator :**

```json
{
  "name": "Pentest ClientX - Mai 2026",
  "versions": {
    "attack": "15",
    "navigator": "5.1.0",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Heat map du pentest Red Team — ClientX, mai 2026. Rouge = exploitée, Orange = partielle, Jaune = détectée, Vert = mitigée, Gris = non testée.",
  "filters": {
    "platforms": ["Windows", "Linux", "Azure AD"]
  },
  "sorting": 3,
  "layout": {
    "layout": "side",
    "aggregateFunction": "average",
    "showID": true,
    "showName": true,
    "showAggregateScores": true,
    "countUnscored": true,
    "expandedSubtechniques": "expanded"
  },
  "hideDisabled": false,
  "techniques": [
    {
      "techniqueID": "T1190",
      "tactic": "initial-access",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Log4Shell sur portail externe — RCE obtenue, shell SYSTEM (tomcat). Voir rapport §3.2.1.",
      "enabled": true,
      "metadata": {
        "resultat": "Succès complet",
        "cible": "portail.client.lan",
        "outil": "exploit Log4Shell",
        "detection": "Aucune alerte SOC"
      }
    },
    {
      "techniqueID": "T1078",
      "tactic": "initial-access",
      "score": 75,
      "color": "#f98d0b",
      "comment": "Password spraying OWA — 3 comptes valides mais MFA bloque l'accès.",
      "enabled": true,
      "metadata": {
        "resultat": "Succès partiel",
        "cible": "mail.client.lan",
        "bloquant": "MFA (Azure AD Conditional Access)"
      }
    },
    {
      "techniqueID": "T1562.001",
      "tactic": "defense-evasion",
      "score": 100,
      "color": "#e60d0d",
      "comment": "AMSI bypass via patching en mémoire (PowerShell). EDR non déclenché.",
      "enabled": true,
      "metadata": {
        "resultat": "Succès complet",
        "outil": "Script PowerShell AMSI bypass",
        "edr": "Non détecté"
      }
    },
    {
      "techniqueID": "T1003.001",
      "tactic": "credential-access",
      "score": 25,
      "color": "#03c03c",
      "comment": "Tentative dump LSASS — Bloqué par CrowdStrike Falcon (suspicious process handle).",
      "enabled": true,
      "metadata": {
        "resultat": "Mitigation efficace",
        "bloquant": "CrowdStrike Falcon",
        "recommendation": "Maintenir la règle, tester T1003.002 (SAM dump)"
      }
    },
    {
      "techniqueID": "T1649",
      "tactic": "credential-access",
      "score": 100,
      "color": "#e60d0d",
      "comment": "ADCS ESC1 — Certipy-ad. Obtention certificat DA. Détection SIEM 2h après (EventID 4886).",
      "enabled": true,
      "metadata": {
        "resultat": "Succès complet",
        "detection": "Alertée avec 2h de retard (SIEM QRadar)",
        "recommendation": "Détection en temps réel à implémenter"
      }
    },
    {
      "techniqueID": "T1485",
      "tactic": "impact",
      "score": 0,
      "color": "#c1c1c1",
      "comment": "Phase impact non testée (hors scope, ROE §4.2).",
      "enabled": true,
      "metadata": {
        "resultat": "Non testée",
        "raison": "Hors scope — Règles d'engagement §4.2"
      }
    }
  ],
  "gradient": {
    "colors": [
      "#e60d0d",
      "#f98d0b",
      "#fee003",
      "#03c03c",
      "#c1c1c1"
    ],
    "minValue": 0,
    "maxValue": 100
  },
  "legendItems": [
    {"label": "Exploitée avec succès",  "color": "#e60d0d"},
    {"label": "Tentée / Partielle",    "color": "#f98d0b"},
    {"label": "Détectée par le SOC",   "color": "#fee003"},
    {"label": "Mitigation en place",   "color": "#03c03c"},
    {"label": "Non testée",            "color": "#c1c1c1"}
  ]
}
```

### 2.5 Étape 4 — Analyser les zones grises → Gap Analysis

Les zones grises (`score = 0`) représentent les angles morts de la mission. Leur analyse constitue le cœur de la **gap analysis** (voir section 3).

**Principe :**

```
Pour chaque technique GRISE (non testée), se poser 4 questions :

1. La technique est-elle applicable au contexte du client ?
   ├── NON → Justifier (techno absente, architecture différente)
   └── OUI → Passer à la question 2

2. Pourquoi n'a-t-elle pas été testée ?
   ├── Hors scope ROE → Mentionner dans le rapport
   ├── Contrainte de temps → Prioriser pour le prochain pentest
   ├── Compétence manquante → Identifier le besoin en formation
   └── Outil non disponible → Planifier l'acquisition/licensing

3. Quel est le risque si elle est exploitée par un attaquant réel ?
   → Probabilité × Impact = Risque résiduel

4. Quelle action recommander ?
   ├── Tester au prochain pentest
   ├── Ajouter une règle de détection SOC
   ├── Déployer une mitigation
   └── Accepter le risque (décision COMEX)
```

---

## 3. Gap Analysis — Méthodologie

### 3.1 Définition

La **Gap Analysis** (analyse des écarts) est le processus systématique d'identification des techniques ATT&CK non couvertes par le pentest et d'évaluation du risque résiduel associé.

```
┌──────────────────────────────────────────────────────────────────┐
│                    GAP ANALYSIS — PRINCIPE                       │
│                                                                  │
│   Couverture du pentest        Techniques ATT&CK totales         │
│   ┌────────────────────┐       ┌──────────────────────────────┐  │
│   │                    │       │                              │  │
│   │   ██████████████   │       │   ████████████████████████   │  │
│   │   ██████████████   │  ≠    │   ████████████████████████   │  │
│   │   ██████████████   │       │   ████████████████████████   │  │
│   │   Techniques       │       │   Toutes les techniques      │  │
│   │   testées (N)      │       │   ATT&CK (M, M >> N)         │  │
│   └────────────────────┘       └──────────────────────────────┘  │
│                                                                  │
│   GAP = Techniques totales — Techniques testées                  │
│   → Analyser le GAP pour identifier les RISQUES RÉSIDUELS        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Identifier les techniques non couvertes

**Méthode quantitative :**

1. Charger l'ensemble du référentiel ATT&CK (entreprise, v15.1)
2. Filtrer par plateforme pertinente (Windows, Linux, Cloud, etc.)
3. Soustraire les techniques testées
4. Obtenir la liste des techniques non couvertes

**Script d'analyse quantitative :**

```python
#!/usr/bin/env python3
"""
Gap Analysis quantitative — Compare les techniques testées vs référentiel ATT&CK.
Usage : python3 gap_analysis.py technique_tested.json enterprise-attack.json

Tags MITRE : N/A (outillage d'analyse)
"""

import json
import sys
from collections import defaultdict

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

def extract_techniques(attack_data):
    """Extrait toutes les techniques du fichier ATT&CK."""
    techniques = {}
    for obj in attack_data.get('objects', []):
        if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_is_subtechnique'):
            techniques[obj['id']] = {
                'name': obj.get('name', ''),
                'tactics': [p['phase_name'] for p in obj.get('kill_chain_phases', [])]
            }
    return techniques

def compute_gap(all_techniques, tested_ids):
    """Calcule l'écart entre référentiel complet et techniques testées."""
    gap = {}
    for tid, info in all_techniques.items():
        if tid not in tested_ids:
            gap[tid] = info
    return gap

def compute_risk_matrix(gap_techniques, threat_intel):
    """
    Évalue le risque résiduel : Probabilité × Impact.
    threat_intel : dict {tech_id: {'probability': 0-5, 'impact': 0-5}}
    """
    risk_matrix = defaultdict(list)
    for tid, info in gap_techniques.items():
        prob = threat_intel.get(tid, {}).get('probability', 3)  # 3 = moyen par défaut
        impact = threat_intel.get(tid, {}).get('impact', 3)
        score = prob * impact  # 1-25
        if score >= 15:
            risk_matrix['CRITIQUE'].append((tid, info['name'], score))
        elif score >= 8:
            risk_matrix['ÉLEVÉ'].append((tid, info['name'], score))
        elif score >= 3:
            risk_matrix['MODÉRÉ'].append((tid, info['name'], score))
        else:
            risk_matrix['FAIBLE'].append((tid, info['name'], score))
    return risk_matrix

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 gap_analysis.py techniques_tested.json enterprise-attack.json")
        sys.exit(1)

    tested = set(open(sys.argv[1]).read().splitlines())
    attack = load_json(sys.argv[2])
    all_techs = extract_techniques(attack)
    gap = compute_gap(all_techs, tested)

    # Affichage par tactique
    by_tactic = defaultdict(list)
    for tid, info in gap.items():
        for tactic in info['tactics']:
            by_tactic[tactic].append(f"  - {tid}: {info['name']}")

    print(f"\n=== GAP ANALYSIS : {len(gap)} techniques non couvertes sur {len(all_techs)} ===\n")
    for tactic in sorted(by_tactic):
        print(f"\n## {tactic.upper()} ({len(by_tactic[tactic])} non couvertes)")
        for line in sorted(by_tactic[tactic]):
            print(line)

    # Ajout des tactiques non couvertes du tout
    tested_tactics = set()
    for tid in tested:
        if tid in all_techs:
            tested_tactics.update(all_techs[tid]['tactics'])
    all_tactics = set()
    for info in all_techs.values():
        all_tactics.update(info['tactics'])

    untested_tactics = all_tactics - tested_tactics
    if untested_tactics:
        print(f"\n\n⚠️  TACTIQUES ENTIÈREMENT NON COUVERTES :")
        for t in sorted(untested_tactics):
            print(f"  - {t}")

if __name__ == '__main__':
    main()
```

### 3.3 Évaluer le risque résiduel

**Matrice Probabilité × Impact :**

```
┌─────────────────────────────────────────────────────────────┐
│                  MATRICE DE RISQUE RÉSIDUEL                 │
│                                                             │
│              IMPACT                                          │
│              1       2       3       4       5              │
│          ┌───────┬───────┬───────┬───────┬───────┐         │
│   P    5 │   M   │   E   │   E   │   C   │   C   │         │
│   R      │       │       │       │       │       │         │
│   O    4 │   M   │   E   │   E   │   E   │   C   │         │
│   B      │       │       │       │       │       │         │
│   A    3 │   F   │   M   │   E   │   E   │   E   │         │
│   B      │       │       │       │       │       │         │
│   I    2 │   F   │   F   │   M   │   E   │   E   │         │
│   L      │       │       │       │       │       │         │
│   I    1 │   F   │   F   │   F   │   M   │   M   │         │
│   T      └───────┴───────┴───────┴───────┴───────┘         │
│   É                                                         │
│          C = Critique   E = Élevé                           │
│          M = Modéré     F = Faible                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Formulaire d'évaluation par technique :**

```markdown
### TXXXX — Nom de la technique

| Critère | Valeur | Justification |
|---------|--------|---------------|
| **Applicabilité** | Oui / Non / Partielle | Contexte technique du client |
| **Probabilité d'exploitation** | 1 (rare) à 5 (quasi-certain) | Threat intelligence, campagnes récentes |
| **Impact métier** | 1 (négligeable) à 5 (critique) | Données exposées, services affectés |
| **Score de risque** | P × I = __ / 25 | Voir matrice |
| **Facilité de remédiation** | Facile / Moyen / Difficile | Coût, complexité, impact opérationnel |
| **Priorité** | P0 / P1 / P2 / P3 | P0 = immédiat, P3 = planifié |
```

### 3.4 Prioriser les actions

**Matrice de priorisation — Eisenhower du pentest :**

```
                    URGENCE DE CORRECTION
                    Faible              Élevée
          ┌─────────────────────┬─────────────────────┐
          │                     │                     │
   F      │       P3            │       P1            │
   A      │   Planifier         │   Faire immédiat    │
   I      │   (sprint +2)       │   (sprint courant)  │
   B      │                     │                     │
   L      │   Ex: Config non    │   Ex: RCE critique  │
   E      │   critique          │   sur DMZ           │
   (Impact│                     │                     │
    métier├─────────────────────┼─────────────────────┤
    élevé)│                     │                     │
          │       P2            │       P0            │
   F      │   Déléguer/         │   Escalader COMEX   │
   O      │   Automatiser       │   (incident)        │
   R      │                     │                     │
   T      │   Ex: Hardening     │   Ex: Compromission │
          │   OS long terme     │   DC en cours       │
          │                     │                     │
          └─────────────────────┴─────────────────────┘
```

### 3.5 Recommandations pour le prochain pentest

**Structure d'une recommandation :**

```markdown
## Recommandation #R-001 — Tester l'évasion EDR (T1562)

### Contexte
Lors du pentest de mai 2026, les techniques d'évasion EDR (T1562)
ont été peu testées (2 sous-techniques sur 10) car le bypass
initial d'AMSI a suffi. Cependant, l'absence de test exhaustif ne
garantit pas que l'EDR bloquera d'autres vecteurs.

### Risque résiduel
- Technique : T1562 (Impair Defenses) et ses 10 sous-techniques
- Probabilité : 4/5 (les attaquants ciblent activement les EDR)
- Impact : 5/5 (contournement EDR = full compromission possible)
- Score : 20/25 → **CRITIQUE**

### Plan d'action
| Action | Responsable | Délai | Indicateur |
|--------|-------------|-------|------------|
| Tester les 10 sous-techniques T1562 | Red Team | Prochain pentest (T3 2026) | 100% couvertes |
| Déployer règles EDR supplémentaires | Blue Team | T2 2026 | 0 faux positif |
| Simuler avec Atomic Red Team | Blue Team | Continu | Détection > 90% |

### Références
- MITRE ATT&CK T1562 : https://attack.mitre.org/techniques/T1562/
- Atomic Red Team : https://github.com/redcanaryco/atomic-red-team
```

---

## 4. Mapping NIS2 ↔ ATT&CK

### 4.1 Introduction à NIS2

La directive européenne **NIS2** (Network and Information Security Directive 2, 2022/2555) renforce les obligations de cybersécurité pour les entités essentielles et importantes. Le framework MITRE ATT&CK peut servir de **langage commun** entre les exigences réglementaires et la réalité technique des tests d'intrusion.

```
┌──────────────────────────────────────────────────────────────┐
│                     NIS2 ↔ ATT&CK — PRINCIPE                 │
│                                                              │
│   ┌───────────┐          ┌─────────────┐         ┌─────────┐ │
│   │ Exigences │          │  Techniques  │         │  Rapports│ │
│   │   NIS2    │ ◀──────▶ │   ATT&CK     │ ◀─────▶ │ Pentest │ │
│   │ (Art. 21, │          │  (TXXXX)     │         │  (Heat  │ │
│   │  23, 27)  │          │              │         │   Map)  │ │
│   └───────────┘          └─────────────┘         └─────────┘ │
│                                                              │
│   Les techniques ATT&CK documentent la conformité NIS2.      │
│   La heat map prouve que le pentest couvre les exigences.    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 4.2 Article 21 — Gestion des risques

L'**Article 21** de NIS2 impose aux entités de mettre en œuvre des mesures de gestion des risques en matière de cybersécurité, proportionnées aux risques identifiés.

**Exigences de l'Article 21 et techniques ATT&CK correspondantes :**

| § NIS2 | Exigence | Tactiques ATT&CK | Techniques clés | Justification |
|--------|----------|------------------|-----------------|---------------|
| 21.2(a) | Politique d'analyse des risques | *Toutes* | Mapping complet | L'analyse de risque doit couvrir toutes les tactiques ATT&CK |
| 21.2(b) | Gestion des incidents | `Impact` | T1485, T1486, T1489, T1490 | Capacité à détecter et répondre aux attaques destructrices |
| 21.2(c) | Continuité d'activité | `Impact` | T1499, T1531, T1491 | Résilience face aux attaques DoS et destructrices |
| 21.2(d) | Sécurité de la chaîne d'approvisionnement | `Initial Access` | T1195, T1199, T1478 | Compromission via tiers/fournisseurs |
| 21.2(e) | Sécurité des systèmes et du réseau | `Initial Access`, `Execution` | T1190, T1133, T1562, T1059 | Protection du périmètre et des endpoints |
| 21.2(f) | Politiques de contrôle d'accès | `Privilege Escalation`, `Defense Evasion` | T1078, T1068, T1548, T1134 | Gestion des identités et privilèges |
| 21.2(g) | Cryptographie et chiffrement | `Collection`, `Exfiltration` | T1022, T1030, T1041, T1573 | Protection des données au repos et en transit |
| 21.2(h) | Sécurité des ressources humaines | `Initial Access` | T1566, T1598, T1534 | Phishing, ingénierie sociale |

### 4.3 Article 23 — Obligations de signalement

L'**Article 23** impose la notification des incidents significatifs dans des délais stricts.

**Cycle de détection et notification :**

```
Incident           Alerte précoce      Notification        Rapport final
détecté            (24h)               incident (72h)      (1 mois)
  │                    │                    │                   │
  ▼                    ▼                    ▼                   ▼
┌──────┐            ┌──────┐            ┌──────┐            ┌──────┐
│TXXXX │───────────▶│SOC   │───────────▶│CSIRT │───────────▶│ANSSI │
│détecté│   EventID │alerté│   Ticket   │notifié│  Rapport  │ou    │
│       │   → SIEM  │      │   incident │       │  complet  │autorité│
└──────┘            └──────┘            └──────┘            └──────┘
```

**Correspondance techniques ATT&CK ↔ Capacités de détection NIS2 :**

| Exigence NIS2 Art.23 | Techniques ATT&CK pertinentes | Preuve de couverture |
|----------------------|-------------------------------|---------------------|
| Capacité de détection | Toutes techniques `Discovery` (T1016, T1018, T1046, T1069, T1082, T1087, T1135, T1482, T1518) | Logs IDS/EDR/SIEM |
| Capacité d'analyse | `Execution` (T1059), `Persistence` (T1547), `Lateral Movement` (T1021) | Timeline SOC |
| Capacité de réponse | `Defense Evasion` (T1562), `Credential Access` (T1003) | Playbook IR |
| Capacité de forensics | `Collection` (T1005, T1119), `Exfiltration` (T1041, T1048) | Images disque, logs |

### 4.4 Tableau de correspondance complet

**Mapping NIS2 Articles 21, 23, 27 ↔ Tactiques/Techniques ATT&CK :**

```markdown
| Article NIS2 | Paragraphe | Exigence | Tactique ATT&CK | ID Techniques représentatives |
|-------------|------------|----------|-----------------|-------------------------------|
| Art. 21.2(a) | Politique de sécurité | Toutes | Toutes tactiques | T1190, T1566, T1059, T1547, T1003, T1021, T1041 |
| Art. 21.2(b) | Gestion des incidents | Impact | T1485, T1486, T1489, T1490, T1531 |
| Art. 21.2(c) | Continuité d'activité et sauvegarde | Impact | T1485, T1486, T1490, T1499 |
| Art. 21.2(d) | Sécurité chaîne approvisionnement | Initial Access, Persistence | T1195, T1199, T1478, T1554 |
| Art. 21.2(e) | Sécurité acquisition/développement/maintenance | Initial Access, Execution, Persistence | T1190, T1133, T1059, T1543, T1505 |
| Art. 21.2(f) | Évaluation efficacité des mesures | Toutes | Gap analysis (heat map) |
| Art. 21.2(g) | Pratiques cyber de base et formation | Initial Access (Phishing) | T1566, T1598 |
| Art. 21.2(h) | Politiques cryptographie et chiffrement | Collection, C2, Exfiltration | T1040, T1573, T1030, T1568 |
| Art. 21.2(i) | Sécurité des ressources humaines | Initial Access | T1566, T1598, T1534 |
| Art. 21.2(j) | Authentification multifacteur | Credential Access, Defense Evasion | T1111, T1621, T1078 |
| Art. 23.1 | Notification incident significatif | Command & Control | T1071, T1090, T1105, T1573 |
| Art. 23.4 | Délai alerte précoce (24h) | Toutes | Détection temps réel SIEM/SOC |
| Art. 23.4 | Délai notification (72h) | Toutes | Capacité IR documentée |
| Art. 27 | Mise en conformité | Toutes | Audit complet + pentest annuel |
```

### 4.5 Justification NIS2 via la heat map

**Argumentaire type pour un rapport de pentest :**

> La présente heat map ATT&CK couvre **X** techniques sur les **Y** techniques applicables du référentiel MITRE Enterprise ATT&CK v15.1, soit un taux de couverture de **Z%**. Ces techniques documentent la conformité aux articles 21, 23 et 27 de la directive NIS2 (transposée en droit français).
>
> Les techniques non couvertes (gap de **W** techniques) font l'objet d'une analyse de risque résiduel détaillée en section §X du présent rapport. Les recommandations associées (R-001 à R-00N) constituent le plan d'action priorisé pour atteindre la conformité NIS2.
>
> En particulier :
> - Les techniques de la tactique `Credential Access` (T1003, T1649, T1552) documentent le contrôle d'accès (Art. 21.2.f) ;
> - Les techniques de la tactique `Impact` (T1485, T1486) documentent la gestion des incidents (Art. 21.2.b) et la continuité d'activité (Art. 21.2.c) ;
> - Les techniques de la tactique `Initial Access` (T1190, T1566) documentent la sécurité du réseau, la formation et l'approvisionnement (Art. 21.2.e, g, d).

---

## 5. TP Guidé — Construire sa heat map

> **Outil :** Utiliser l'instance ATT&CK Navigator locale (http://localhost:4200)  
> ou l'instance en ligne (https://mitre-attack.github.io/attack-navigator/).  
> Importer le fichier JSON généré ou créer une nouvelle couche manuellement.

### 5.1 Contexte

**Scénario :** Vous venez de terminer le pentest Red Team du module M17 contre la société fictive **CORPEX**. Vous disposez :

- Du rapport de pentest M17 complet
- Des logs Cobalt Strike exportés
- Des notes de chaque phase de la kill chain
- Des échanges avec le SOC simulé

**Votre mission :**

1. Extraire toutes les techniques ATT&CK utilisées
2. Construire la heat map dans ATT&CK Navigator
3. Rédiger la gap analysis
4. Présenter les recommandations NIS2

### 5.2 Étape 1 — Extraction des techniques depuis le rapport M17

**Extrait du rapport M17 (simulé) :**

```markdown
## Kill Chain Pentest CORPEX — Mai 2026

### Phase 1 : Reconnaissance
- OSINT LinkedIn → 47 employés identifiés → T1593
- Scan externe (shodan, subfinder, httpx) → T1592, T1595
- Analyse certificats TLS (crt.sh) → T1596

### Phase 2 : Initial Access
- CVE-2021-44228 (Log4Shell) sur portail externe → T1190, T1059
- Password spraying OWA (liste OSINT) → T1078, T1110.003
- 3 comptes valides mais MFA Azure AD → T1111 (mitigation en place)

### Phase 3 : Execution
- AMSI bypass PowerShell → T1562.001, T1059.001
- Déploiement beacon Cobalt Strike → T1105, T1071.001
- Scheduled Task pour persistance → T1053.005

### Phase 4 : Persistence
- Scheduled Task (SYSTEM) → T1053.005
- Clé registre Run → T1547.001

### Phase 5 : Privilege Escalation
- Kerberoasting (SPN) → T1558.003
- Token theft (incognito) → T1134.001
- ADCS ESC1 (Certipy) → T1649

### Phase 6 : Defense Evasion
- AMSI bypass → T1562.001
- ETW patch → T1562.006
- DLL sideloading → T1574.002

### Phase 7 : Credential Access
- LSASS dump (bloqué CrowdStrike) → T1003.001 (mitigation)
- SAM dump (reg save) → T1003.002
- NTDS.dit dump (ntdsutil) → T1003.003
- Certificat ADCS ESC1 → T1649

### Phase 8 : Discovery
- AD enumeration (BloodHound) → T1087, T1069, T1482
- Network scanning → T1046
- SMB share enumeration → T1135

### Phase 9 : Lateral Movement
- Pass-the-Hash → T1550.002
- WMI lateral → T1047
- PsExec → T1569.002

### Phase 10 : Collection
- Fichiers sensibles sur partages → T1005, T1039
- Email .pst → T1114.001

### Phase 11 : C2
- HTTPS Beacon → T1071.001
- SMB Beacon (pivot) → T1090.001

### Phase 12 : Exfiltration
- Exfiltration over C2 → T1041

### Phase 13 : Impact
- Non testée (hors scope ROE §4.2)
```

### 5.3 Étape 2 — Tableau récapitulatif des techniques

```markdown
| ID Tech. | Tactique | Technique | Score | Résultat |
|----------|----------|-----------|-------|----------|
| T1593 | Reconnaissance | Search Victim-Owned Websites (LinkedIn) | 100 | Succès |
| T1592 | Reconnaissance | Gather Victim Host Information | 100 | Succès |
| T1595 | Reconnaissance | Active Scanning | 100 | Succès |
| T1596 | Reconnaissance | Search Open Technical Databases (crt.sh) | 100 | Succès |
| T1190 | Initial Access | Exploit Public-Facing Application | 100 | Succès |
| T1078 | Initial Access | Valid Accounts | 75 | Partiel (MFA) |
| T1110.003 | Credential Access | Password Spraying (OWA) | 75 | Partiel |
| T1111 | Defense Evasion | Multi-Factor Authentication Interception | 25 | Bloqué |
| T1059.001 | Execution | PowerShell | 100 | Succès |
| T1105 | Command & Control | Ingress Tool Transfer | 100 | Succès |
| T1053.005 | Execution/Persistence | Scheduled Task | 100 | Succès |
| T1562.001 | Defense Evasion | Disable or Modify Tools (AMSI) | 100 | Succès |
| T1562.006 | Defense Evasion | Indicator Blocking (ETW) | 100 | Succès |
| T1574.002 | Defense Evasion | DLL Side-Loading | 100 | Succès |
| T1547.001 | Persistence | Registry Run Keys | 100 | Succès |
| T1558.003 | Credential Access | Kerberoasting | 100 | Succès |
| T1134.001 | Defense Evasion | Token Impersonation/Theft | 100 | Succès |
| T1649 | Credential Access | Steal or Forge Certificates (ADCS ESC1) | 100 | Succès |
| T1003.001 | Credential Access | LSASS Memory | 25 | Bloqué |
| T1003.002 | Credential Access | Security Account Manager (SAM) | 100 | Succès |
| T1003.003 | Credential Access | NTDS | 100 | Succès |
| T1087 | Discovery | Account Discovery | 100 | Succès |
| T1069 | Discovery | Permission Groups Discovery | 100 | Succès |
| T1482 | Discovery | Domain Trust Discovery | 100 | Succès |
| T1046 | Discovery | Network Service Discovery | 100 | Succès |
| T1135 | Discovery | Network Share Discovery | 100 | Succès |
| T1550.002 | Lateral Movement | Pass the Hash | 100 | Succès |
| T1047 | Lateral Movement | Windows Management Instrumentation | 100 | Succès |
| T1569.002 | Execution | Service Execution (PsExec) | 100 | Succès |
| T1005 | Collection | Data from Local System | 75 | Partiel |
| T1039 | Collection | Data from Network Shared Drive | 75 | Partiel |
| T1114.001 | Collection | Email Collection (Local .pst) | 75 | Partiel |
| T1071.001 | Command & Control | Web Protocols (HTTPS) | 100 | Succès |
| T1090.001 | Command & Control | Connection Proxy (SMB) | 100 | Succès |
| T1041 | Exfiltration | Exfiltration Over C2 Channel | 100 | Succès |
```

### 5.4 Étape 3 — Création de la heat map dans ATT&CK Navigator

**Procédure détaillée :**

```bash
# 1. Lancer ATT&CK Navigator
docker run -d -p 4200:4200 mitreattack/attack-navigator
firefox http://localhost:4200

# 2. Depuis l'interface web :
#    - "Create New Layer" → Enterprise ATT&CK v15
#    - Filtrer : Windows + Linux
#    - Nom : "Pentest_CORPEX_Mai2026"
#
# 3. Pour chaque technique du tableau :
#    - Rechercher par ID (ex: T1190)
#    - Clic droit → "Edit technique"
#    - Saisir le score (0-100)
#    - Saisir le commentaire
#    - Ajouter les métadonnées JSON
#
# 4. Sauvegarder → "Download Layer" → JSON
```

**Fichier JSON complet de la couche :**

```json
{
  "name": "Pentest CORPEX — Mai 2026",
  "versions": {
    "attack": "15",
    "navigator": "5.1.0",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Heat map du pentest Red Team CORPEX — Mai 2026. M17 SDV M2. Rouge = exploitée, Orange = partielle, Jaune = détectée SOC, Vert = mitigation, Gris = non testée.",
  "filters": {
    "platforms": ["Windows", "Linux", "Azure AD"]
  },
  "sorting": 3,
  "layout": {
    "layout": "side",
    "aggregateFunction": "average",
    "showID": true,
    "showName": true,
    "showAggregateScores": false,
    "countUnscored": true,
    "expandedSubtechniques": "expanded"
  },
  "hideDisabled": false,
  "techniques": [
    {
      "techniqueID": "T1593",
      "tactic": "reconnaissance",
      "score": 100,
      "color": "#e60d0d",
      "comment": "OSINT LinkedIn : 47 employés, format nom.prenom@corpex.fr. Source password spraying.",
      "metadata": {"outil": "LinkedIn + theHarvester", "cible": "Employés CORPEX"}
    },
    {
      "techniqueID": "T1592",
      "tactic": "reconnaissance",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Scan externe : Shodan, subfinder, httpx. Identification portail Tomcat vulnérable Log4Shell.",
      "metadata": {"outil": "shodan, subfinder, httpx, nuclei"}
    },
    {
      "techniqueID": "T1595",
      "tactic": "reconnaissance",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Scan actif des plages IP externes. Identification services exposés.",
      "metadata": {"outil": "nmap, masscan"}
    },
    {
      "techniqueID": "T1596",
      "tactic": "reconnaissance",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Recherche certificats TLS sur crt.sh. Sous-domaines identifiés.",
      "metadata": {"outil": "crt.sh, certspotter"}
    },
    {
      "techniqueID": "T1190",
      "tactic": "initial-access",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Log4Shell (CVE-2021-44228) sur portail externe. RCE → shell SYSTEM (tomcat). Cf rapport §3.2.1.",
      "metadata": {
        "outil": "curl + exploit Log4Shell personnalisé",
        "cible": "portail.corpex.fr:8443",
        "detection": "Aucune alerte SOC",
        "impact": "RCE non authentifiée → Accès initial au réseau interne"
      }
    },
    {
      "techniqueID": "T1078",
      "tactic": "initial-access",
      "score": 75,
      "color": "#f98d0b",
      "comment": "Password spraying OWA — 3 comptes valides. MFA Azure AD bloque l'accès.",
      "metadata": {
        "outil": "SprayingToolkit",
        "cible": "mail.corpex.fr",
        "bloquant": "Azure AD MFA",
        "recommandation": "MFA bien configuré, maintenir"
      }
    },
    {
      "techniqueID": "T1110.003",
      "tactic": "credential-access",
      "score": 75,
      "color": "#f98d0b",
      "comment": "Password spraying OWA. Mots de passe faibles sur 3 comptes.",
      "metadata": {"outil": "SprayingToolkit", "resultat": "3/47 comptes = 6.4%"}
    },
    {
      "techniqueID": "T1111",
      "tactic": "defense-evasion",
      "score": 25,
      "color": "#03c03c",
      "comment": "Tentative interception MFA — Échec (Azure AD Conditional Access bloque).",
      "metadata": {"bloquant": "Azure AD Conditional Access", "evaluation": "Mitigation robuste"}
    },
    {
      "techniqueID": "T1059.001",
      "tactic": "execution",
      "score": 100,
      "color": "#e60d0d",
      "comment": "PowerShell post-exploitation. AMSI bypass préalable. Déploiement beacon CS.",
      "metadata": {"outil": "Cobalt Strike", "bypass": "AMSI patch mémoire"}
    },
    {
      "techniqueID": "T1105",
      "tactic": "command-and-control",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Upload beacon Cobalt Strike via HTTP PUT après RCE Log4Shell.",
      "metadata": {"outil": "Cobalt Strike", "protocole": "HTTP PUT"}
    },
    {
      "techniqueID": "T1053.005",
      "tactic": "execution",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Scheduled Task SYSTEM pour persistance. Déclenchement beacon au reboot.",
      "metadata": {"outil": "schtasks.exe", "cible": "SRV01"}
    },
    {
      "techniqueID": "T1562.001",
      "tactic": "defense-evasion",
      "score": 100,
      "color": "#e60d0d",
      "comment": "AMSI bypass via patching en mémoire (PowerShell). EDR non déclenché.",
      "metadata": {"outil": "Script AMSI bypass", "edr": "CrowdStrike non déclenché"}
    },
    {
      "techniqueID": "T1562.006",
      "tactic": "defense-evasion",
      "score": 100,
      "color": "#e60d0d",
      "comment": "ETW patching PowerShell. Empêche la journalisation des commandes.",
      "metadata": {"outil": "Script ETW bypass", "impact": "Commandes PowerShell invisibles dans EventLog"}
    },
    {
      "techniqueID": "T1574.002",
      "tactic": "defense-evasion",
      "score": 100,
      "color": "#e60d0d",
      "comment": "DLL sideloading : placement DLL malveillante dans dossier d'application légitime.",
      "metadata": {"outil": "DLL custom", "cible": "Application signée Vulnérable"}
    },
    {
      "techniqueID": "T1547.001",
      "tactic": "persistence",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Clé registre Run (HKLM) pour exécution beacon au démarrage utilisateur.",
      "metadata": {"outil": "reg.exe", "cible": "HKLM\\...\\Run"}
    },
    {
      "techniqueID": "T1558.003",
      "tactic": "credential-access",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Kerberoasting : extraction tickets TGS, crack offline. 2 comptes service avec SPN crackés.",
      "metadata": {
        "outil": "Rubeus.exe",
        "resultat": "2 comptes service crackés (svc_sql, svc_backup)",
        "detection": "EventID 4769 (Kerberos TGS) - non surveillé par SOC"
      }
    },
    {
      "techniqueID": "T1134.001",
      "tactic": "defense-evasion",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Token theft : impersonation token svc_backup → accès partages sensibles.",
      "metadata": {"outil": "Cobalt Strike (steal_token)", "cible": "svc_backup → SRV02"}
    },
    {
      "techniqueID": "T1649",
      "tactic": "credential-access",
      "score": 100,
      "color": "#e60d0d",
      "comment": "ADCS ESC1 — Obtention certificat DA via Certipy. Détection SIEM retardée (2h).",
      "metadata": {
        "outil": "certipy-ad",
        "commande": "certipy-ad req -u svc_sql@corpex.local -p 'P@ssw0rd!' -ca CA-CORPEX -template ESC1",
        "detection": "EventID 4886, 4887 — Alerté par SIEM avec 2h de retard"
      }
    },
    {
      "techniqueID": "T1003.001",
      "tactic": "credential-access",
      "score": 25,
      "color": "#03c03c",
      "comment": "Tentative dump LSASS — Bloqué par CrowdStrike Falcon (suspicious process handle). Mitigation efficace.",
      "metadata": {
        "outil": "procdump.exe",
        "bloquant": "CrowdStrike Falcon",
        "recommandation": "Maintenir la règle EDR. Tester T1003.002 (SAM dump) comme alternative."
      }
    },
    {
      "techniqueID": "T1003.002",
      "tactic": "credential-access",
      "score": 100,
      "color": "#e60d0d",
      "comment": "SAM dump (reg save) — Succès. Extraction hash NTLM locaux. Alternative à LSASS dump.",
      "metadata": {
        "outil": "reg.exe save + secretsdump.py",
        "astuce": "Alternative car LSASS bloqué par EDR"
      }
    },
    {
      "techniqueID": "T1003.003",
      "tactic": "credential-access",
      "score": 100,
      "color": "#e60d0d",
      "comment": "NTDS.dit dump (ntdsutil snapshot). Extraction de tous les hash du domaine.",
      "metadata": {
        "outil": "ntdsutil.exe + secretsdump.py",
        "impact": "Compromission totale du domaine. Tous les hash NTLM du domaine extraits."
      }
    },
    {
      "techniqueID": "T1087",
      "tactic": "discovery",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Énumération AD : utilisateurs, groupes, sessions (BloodHound).",
      "metadata": {"outil": "SharpHound.exe + BloodHound", "cible": "corpex.local"}
    },
    {
      "techniqueID": "T1069",
      "tactic": "discovery",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Énumération groupes AD : Domain Admins, Enterprise Admins, groupes privilégiés.",
      "metadata": {"outil": "net group /domain, BloodHound", "resultat": "Chemin vers DA identifié via ADCS ESC1"}
    },
    {
      "techniqueID": "T1482",
      "tactic": "discovery",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Domain Trust Discovery — nltest /domain_trusts. Aucune trust identifiée.",
      "metadata": {"outil": "nltest.exe"}
    },
    {
      "techniqueID": "T1046",
      "tactic": "discovery",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Scan réseau interne : ports, services. Identification SRV02, DC01, SQL01.",
      "metadata": {"outil": "nmap (depuis beacon CS)", "cible": "172.16.0.0/24"}
    },
    {
      "techniqueID": "T1135",
      "tactic": "discovery",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Énumération partages SMB : \\\\SRV02\\Finance, \\\\DC01\\SYSVOL.",
      "metadata": {"outil": "crackmapexec smb --shares", "resultat": "Partage Finance accessible en lecture"}
    },
    {
      "techniqueID": "T1550.002",
      "tactic": "lateral-movement",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Pass-the-Hash : utilisation hash NTLM svc_sql → connexion SRV02.",
      "metadata": {"outil": "crackmapexec smb -H", "cible": "SRV02"}
    },
    {
      "techniqueID": "T1047",
      "tactic": "lateral-movement",
      "score": 100,
      "color": "#e60d0d",
      "comment": "WMI lateral movement : exécution distante beacon CS sur SRV02.",
      "metadata": {"outil": "wmic.exe / Cobalt Strike (wmi)", "cible": "SRV02"}
    },
    {
      "techniqueID": "T1569.002",
      "tactic": "execution",
      "score": 100,
      "color": "#e60d0d",
      "comment": "PsExec : exécution distante avec token SYSTEM. Contournement UAC.",
      "metadata": {"outil": "PsExec.exe", "cible": "SRV02"}
    },
    {
      "techniqueID": "T1005",
      "tactic": "collection",
      "score": 75,
      "color": "#f98d0b",
      "comment": "Collecte fichiers sensibles locaux (SRV02) : contrats, mots de passe en clair.",
      "metadata": {"outil": "Recherche manuelle + findstr", "resultat": "3 fichiers sensibles identifiés"}
    },
    {
      "techniqueID": "T1039",
      "tactic": "collection",
      "score": 75,
      "color": "#f98d0b",
      "comment": "Collecte depuis partage réseau Finance (SRV02). Extraction de documents confidentiels.",
      "metadata": {"outil": "Explorateur + beacon CS (download)", "volume": "~250 Mo"}
    },
    {
      "techniqueID": "T1114.001",
      "tactic": "collection",
      "score": 75,
      "color": "#f98d0b",
      "comment": "Collecte fichiers .pst locaux (SRV02). Extraction emails archivés.",
      "metadata": {"outil": "Recherche .pst + extraction beacon CS", "volume": "~1.2 Go"}
    },
    {
      "techniqueID": "T1071.001",
      "tactic": "command-and-control",
      "score": 100,
      "color": "#e60d0d",
      "comment": "C2 HTTPS (port 443). Trafic chiffré TLS, user-agent légitime. Non détecté par proxy.",
      "metadata": {"protocole": "HTTPS", "ja3": "Fingerprint Firefox ESR", "detection": "Proxy non configuré pour inspection TLS"}
    },
    {
      "techniqueID": "T1090.001",
      "tactic": "command-and-control",
      "score": 100,
      "color": "#e60d0d",
      "comment": "SMB Beacon comme proxy interne. Pivot depuis SRV01 vers SRV02 puis DC01.",
      "metadata": {"protocole": "SMB", "chemin": "SRV01 → SRV02 → DC01"}
    },
    {
      "techniqueID": "T1041",
      "tactic": "exfiltration",
      "score": 100,
      "color": "#e60d0d",
      "comment": "Exfiltration via canal C2 HTTPS. Données chiffrées dans flux TLS. DLP non déclenché.",
      "metadata": {"volume": "~1.5 Go", "protocole": "HTTPS POST", "dlp": "Aucune règle DLP pour flux C2 chiffré"}
    }
  ],
  "gradient": {
    "colors": ["#e60d0d", "#f98d0b", "#fee003", "#03c03c", "#c1c1c1"],
    "minValue": 0,
    "maxValue": 100
  },
  "legendItems": [
    {"label": "Exploitée avec succès", "color": "#e60d0d"},
    {"label": "Tentée / Partielle", "color": "#f98d0b"},
    {"label": "Détectée par le SOC", "color": "#fee003"},
    {"label": "Mitigation efficace", "color": "#03c03c"},
    {"label": "Non testée", "color": "#c1c1c1"}
  ]
}
```

### 5.5 Étape 4 — Rédaction de la gap analysis

**Modèle de rapport de gap analysis :**

```markdown
# GAP ANALYSIS — Pentest CORPEX Mai 2026

## 1. Résumé exécutif

Le pentest Red Team mené du 12 au 16 mai 2026 a couvert **36 techniques**
ATT&CK sur les ~200 techniques applicables (plateformes Windows/Linux/Azure AD)
du référentiel MITRE Enterprise ATT&CK v15.1, soit un taux de couverture
d'environ **18%**.

Ce taux est dans la norme pour un pentest Red Team de 5 jours. Cependant,
l'analyse des zones non couvertes révèle des risques résiduels significatifs
qui doivent être adressés.

## 2. Techniques non couvertes — Par tactique

### 2.1 Initial Access (5 techniques non couvertes)

| ID | Technique | Risque | Justification |
|----|-----------|--------|---------------|
| T1566.001 | Spearphishing Attachment | **CRITIQUE** | Non testé faute de temps. Principal vecteur d'attaque réel (80% des incidents). |
| T1189 | Drive-by Compromise | ÉLEVÉ | Non testé (navigateurs à jour). Risque résiduel si zero-day navigateur. |
| T1199 | Trusted Relationship | MODÉRÉ | Non testé (pas de partenaire identifié avec accès VPN). |
| T1200 | Hardware Additions | FAIBLE | Hors scope (test physique exclu). |
| T1091 | Replication Through Removable Media | FAIBLE | Hors scope (test physique exclu). |

### 2.2 Execution (8 techniques non couvertes)

| ID | Technique | Risque | Justification |
|----|-----------|--------|---------------|
| T1203 | Exploitation for Client Execution | CRITIQUE | Non testé. Risque zero-day Outlook/Teams. |
| T1569.001 | Launchctl (macOS) | FAIBLE | Non applicable (pas de macOS dans le scope). |
| T1053.002 | At (Linux) | MODÉRÉ | Présence serveurs Linux non testés exhaustivement. |

### 2.3 Persistence (12 techniques non couvertes)

| ID | Technique | Risque | Justification |
|----|-----------|--------|---------------|
| T1543.003 | Windows Service | CRITIQUE | Non testé. Vecteur commun APT. |
| T1546.008 | Accessibility Features (Sticky Keys) | CRITIQUE | Non testé. Persistance classique post-RDP. |
| T1136.001 | Local Account Creation | ÉLEVÉ | Non testé. Backdoor simple et fréquente. |

### 2.4 Privilege Escalation (9 techniques non couvertes)

| ID | Technique | Risque | Justification |
|----|-----------|--------|---------------|
| T1548.002 | Bypass User Account Control | CRITIQUE | UAC non testé (accès SYSTEM déjà obtenu). Mérite test exhaustif. |
| T1068 | Exploitation for Privilege Escalation | CRITIQUE | Non testé. Kernel exploits potentiels. |

### 2.5 Defense Evasion (15 techniques non couvertes)

| ID | Technique | Risque | Justification |
|----|-----------|--------|---------------|
| T1027 | Obfuscated Files or Information | ÉLEVÉ | Obfuscation non testée systématiquement. |
| T1055 | Process Injection | CRITIQUE | Injection non testée (EDR bloquant probable). |
| T1070 | Indicator Removal | ÉLEVÉ | Nettoyage de traces non testé. |
| T1218 | Signed Binary Proxy Execution | CRITIQUE | LOLBins non testés exhaustivement (mshta, regsvr32, etc.). |

[... tableau complet similaire pour toutes les tactiques ...]

## 3. Top 5 risques résiduels

| Rang | Technique | Score | Impact business |
|------|-----------|-------|-----------------|
| 1 | T1566.001 — Spearphishing Attachment | 25/25 CRITIQUE | Compromission initiale probable non testée |
| 2 | T1548.002 — Bypass UAC | 20/25 CRITIQUE | Chemin de privilege escalation non validé |
| 3 | T1055 — Process Injection | 20/25 CRITIQUE | Capacité EDR à détecter l'injection non évaluée |
| 4 | T1218 — Signed Binary Proxy Execution | 20/25 CRITIQUE | LOLBins non testés : angle mort de détection |
| 5 | T1566.002 — Spearphishing Link | 20/25 CRITIQUE | Phishing non testé : pas de mesure de sensibilisation |

## 4. Recommandations priorisées

### P0 — Immédiat (sprint courant)

- **R-001** : Déployer la détection des EventID ADCS (4886, 4887) en temps réel
- **R-002** : Activer l'inspection TLS sur le proxy (détection C2 HTTPS)
- **R-003** : Corriger le template ADCS ESC1 (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

### P1 — Prochain pentest (T3 2026)

- **R-004** : Test exhaustif des techniques d'accès initial (T1566, T1189, T1199)
- **R-005** : Test des techniques d'évasion EDR (T1055, T1027, T1070, T1218)
- **R-006** : Test des techniques de persistence (T1543.003, T1546.008, T1136)
- **R-007** : Test de bypass UAC (T1548.002) sur configurations standard

### P2 — Planifié (T4 2026)

- **R-008** : Test des tactiques Collection et Exfiltration avec scénarios DLP
- **R-009** : Test de la tactique Impact (T1485, T1486) avec sauvegarde et PRA
- **R-010** : Simulation complète APT29 couvrant toutes les tactiques

## 5. Conformité NIS2

La couverture actuelle (36 techniques) documente partiellement la conformité
aux articles 21, 23 et 27 de NIS2. Les gaps identifiés (notamment en Initial
Access, Privilege Escalation et Defense Evasion) représentent des angles morts
de conformité réglementaire.

Voir tableau de correspondance complet en Annexe A (§7.2).
```

### 5.6 Étape 5 — Présentation des recommandations NIS2

```markdown
# RECOMMANDATIONS NIS2 — CORPEX

## Synthèse exécutive

Conformément à la directive NIS2 et à sa transposition en droit français,
CORPEX, en tant qu'entité essentielle (secteur énergie), doit démontrer
sa conformité aux articles 21 (gestion des risques), 23 (notification des
incidents) et 27 (supervision et sanctions).

Le présent pentest Red Team constitue une mesure de contrôle au titre de
l'article 21.2(f) (évaluation de l'efficacité des mesures). Les gaps
identifiés doivent être comblés pour assurer une couverture conforme.

## Plan d'action NIS2

| Action | Article NIS2 | Technique ATT&CK | Priorité | Délai |
|--------|-------------|------------------|----------|-------|
| Test phishing (T1566) tous les trimestres | 21.2(g) Formation | T1566 | P1 | T3 2026 |
| Déployer EDR complet + règles custom | 21.2(e) Sécurité réseau | T1562, T1055, T1027 | P0 | T2 2026 |
| Implémenter MFA sur toutes les interfaces | 21.2(j) Authentification | T1111 | Réalisé ✓ | — |
| Durcir ADCS (templates ESC1-ESC13) | 21.2(f) Contrôle d'accès | T1649 | P0 | T2 2026 |
| Activer journalisation complète SIEM | 23.1 Détection incidents | Toutes | P0 | T2 2026 |
| Rédiger playbooks IR par tactique ATT&CK | 23.1-4 Réponse incident | Toutes tactiques | P1 | T3 2026 |
| Pentest annuel complet | 27 Supervision | Toutes | Récurrent | Annuel |
| Audit de conformité NIS2 | 27 Mise en conformité | N/A | P1 | T4 2026 |
```

---

## 6. Outils complémentaires

### 6.1 DeTT&CT — Detection Tactics, Techniques & Context

**DeTT&CT** (développé par Ruben Bouman / FalconForce) est un framework open-source qui mappe les capacités de détection d'une organisation sur le référentiel ATT&CK.

```
┌─────────────────────────────────────────────────────────────────┐
│                        DeTT&CT                                  │
│                                                                 │
│   ┌───────────┐       ┌───────────┐       ┌───────────┐        │
│   │Données    │──────▶│Couverture │──────▶│Gap        │        │
│   │de log     │       │de détection│      │détection  │        │
│   │(YAML)     │       │(heat map) │       │(rapport)  │        │
│   └───────────┘       └───────────┘       └───────────┘        │
│                                                                 │
│   Entrée : Fichiers YAML décrivant les capacités de log         │
│   Sortie : Heat map ATT&CK + Rapport de gap de détection        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Installation et utilisation :**

```bash
# Clonage
git clone https://github.com/rabobank-cdc/DeTTECT.git
cd DeTTECT

# Installation
pip install -r requirements.txt

# Création d'un fichier de données (techniques de détection)
python dettect.py d -e -ft enterprise-attack-15.1.json

# Génération de la heat map de détection
python dettect.py g -d data/soc_detection.yaml -t techniques.yaml

# Rapport de gap de détection
python dettect.py g -d data/soc_detection.yaml -t techniques.yaml -o rapport_detection.xlsx
```

**Fichier YAML de données de détection (exemple) :**

```yaml
# soc_detection.yaml — Capacités de détection SOC CORPEX
version: 1.0

detection_rules:
  - title: "Détection LSASS access"
    technique_id: "T1003.001"
    detection_score: 100
    description: "CrowdStrike Falcon bloque l'accès processus suspect à LSASS"
    data_sources:
      - "Process monitoring (EDR)"
      - "EventID 4663 (audit SACL LSASS)"
    applicable_to: ["Windows Server 2019", "Windows 10"]

  - title: "Détection Scheduled Task creation"
    technique_id: "T1053.005"
    detection_score: 75
    description: "Surveillance EventID 4698 (création tâche planifiée)"
    data_sources:
      - "EventID 4698 (Security log)"
      - "Sysmon EventID 1"
    applicable_to: ["Windows Server 2019", "Windows 10"]
    comment: "Délai de 15 min entre événement et alerte (batch SIEM)"

  - title: "Détection ADCS ESC1 certificate request"
    technique_id: "T1649"
    detection_score: 50
    description: "EventID 4886/4887 — Pas d'alerte temps réel"
    data_sources:
      - "EventID 4886 (CA Audit log)"
      - "EventID 4887 (CA Audit log)"
    applicable_to: ["Windows Server 2019 (CA)"]
    comment: "Logs ingérés dans SIEM mais pas de règle de corrélation active"

  - title: "Détection Pass-the-Hash (T1550.002)"
    technique_id: "T1550.002"
    detection_score: 0
    description: "Aucune détection configurée"
    data_sources: []
    applicable_to: []
    comment: "Angle mort critique — Pas de surveillance EventID 4624 Type 9"
```

### 6.2 VECTR — Threat Tracking & Purple Team

**VECTR** (développé par Security Risk Advisors) est une plateforme web de suivi des tests Red/Purple Team basée sur ATT&CK.

```
┌─────────────────────────────────────────────────────────────────┐
│                          VECTR                                  │
│                                                                 │
│   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌──────────┐ │
│   │Campagne  │──▶│Scénarios  │──▶│Résultats  │──▶│Dashboard │ │
│   │(Campaign)│   │(Test Case)│   │(Outcome)  │   │(Metrics) │ │
│   └───────────┘   └───────────┘   └───────────┘   └──────────┘ │
│                                                                 │
│   Chaque test case est mappé sur une technique ATT&CK.          │
│   Le résultat (detected/blocked/not detected) est enregistré.   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Installation simplifiée :**

```bash
# Docker
git clone https://github.com/SecurityRiskAdvisors/VECTR.git
cd VECTR
docker-compose up -d

# Interface web : https://localhost:8081
# Credentials par défaut : admin / admin (à changer immédiatement)
```

**Workflow VECTR :**

1. Créer une **campagne** (ex: "Pentest CORPEX Mai 2026")
2. Créer des **test cases** mappés sur ATT&CK
3. Exécuter les tests (manuellement ou via Atomic Red Team)
4. Saisir le **résultat** : `Prevented`, `Detected`, `Not Detected`, `Not Tested`
5. Générer le **rapport de couverture** et le **dashboard de progression**
6. Comparer les résultats au fil du temps (tendance d'amélioration)

### 6.3 Atomic Red Team

**Atomic Red Team** (Red Canary) est une bibliothèque de tests unitaires mappés sur les techniques ATT&CK. Chaque test est un script exécutable (PowerShell, bash, Python) qui simule une technique.

**Installation :**

```bash
# Clonage
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team

# Installation du module PowerShell d'exécution
Install-Module -Name invoke-atomicredteam -Scope CurrentUser

# Mise à jour des atomics
Invoke-AtomicRedTeam -UpdateAtomics
```

**Exécution d'un test unitaire :**

```powershell
# Lister tous les tests disponibles
Invoke-AtomicTest T1059.001 -ShowDetails

# Exécuter un test spécifique
Invoke-AtomicTest T1059.001 -TestNumbers 1, 2

# Exécuter avec prudence (certains tests sont destructeurs)
Invoke-AtomicTest T1003.001 -TestNumbers 1 -CheckPrereqs

# Générer un rapport de couverture
Invoke-AtomicTest T1003.001 -GenerateDocs
```

**Intégration avec le pentest :**

```
┌─────────────────────────────────────────────────────────────┐
│     UTILISATION D'ATOMIC RED TEAM PENDANT UN PENTEST        │
│                                                             │
│  1. AVANT le pentest :                                      │
│     → Blue Team exécute tous les atomics                    │
│     → Mesure la couverture de détection SOC initiale        │
│     → Documente le scoring dans DeTT&CT/VECTR               │
│                                                             │
│  2. PENDANT le pentest :                                    │
│     → Red Team utilise les atomics comme baseline           │
│     → Compare les atomics vs techniques réelles             │
│     → Identifie les faux négatifs (atomics détectés mais    │
│       techniques réelles non détectées)                     │
│                                                             │
│  3. APRÈS le pentest :                                      │
│     → Blue Team ré-exécute les atomics pour valider         │
│       les corrections                                       │
│     → Mesure l'amélioration de la couverture                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.4 Tableau comparatif des outils

| Outil | Focus | Format | Usage | Maturité |
|-------|-------|--------|-------|----------|
| **ATT&CK Navigator** | Visualisation | JSON | Heat map post-pentest | ★★★★★ |
| **DeTT&CT** | Détection | YAML | Gap de détection SOC | ★★★★☆ |
| **VECTR** | Tracking | Web UI | Suivi campagne Red/Purple | ★★★☆☆ |
| **Atomic Red Team** | Tests unitaires | PowerShell/bash | Simulation de techniques | ★★★★★ |
| **MITRE Caldera** | Automatisation | Plugin | Émulation d'adversaire automatisée | ★★★★☆ |
| **Prelude Operator** | Agent-based | Go | Déploiement et exécution techniques | ★★★☆☆ |

---

## 7. Annexes

### 7.1 Annexe A — Template JSON ATT&CK Navigator (vierge)

```json
{
  "name": "NOM_DU_PENTEST — DATE",
  "versions": {
    "attack": "15",
    "navigator": "5.1.0",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Heat map du pentest Red Team CLIENT — DATE. SDV M2.",
  "filters": {
    "platforms": ["Windows", "Linux", "Azure AD", "macOS"]
  },
  "sorting": 3,
  "layout": {
    "layout": "side",
    "aggregateFunction": "average",
    "showID": true,
    "showName": true,
    "showAggregateScores": false,
    "countUnscored": true,
    "expandedSubtechniques": "expanded"
  },
  "hideDisabled": false,
  "techniques": [],
  "gradient": {
    "colors": ["#e60d0d", "#f98d0b", "#fee003", "#03c03c", "#c1c1c1"],
    "minValue": 0,
    "maxValue": 100
  },
  "legendItems": [
    {"label": "Exploitée avec succès (ROUGE)", "color": "#e60d0d"},
    {"label": "Tentée / Partielle (ORANGE)", "color": "#f98d0b"},
    {"label": "Détectée par le SOC (JAUNE)", "color": "#fee003"},
    {"label": "Mitigation efficace (VERT)", "color": "#03c03c"},
    {"label": "Non testée (GRIS)", "color": "#c1c1c1"}
  ]
}
```

### 7.2 Annexe B — Modèle de tableau Gap Analysis

```markdown
# GAP ANALYSIS — [CLIENT] — [DATE DU PENTEST]

## Métriques globales

| Métrique | Valeur |
|----------|--------|
| Techniques totales (référentiel ATT&CK filtré) | [N] |
| Techniques testées | [M] |
| Taux de couverture | [M/N × 100]% |
| Techniques non couvertes (GAP) | [N-M] |
| Techniques critiques non couvertes | [X] |
| Techniques à haut risque non couvertes | [Y] |

## Gap Analysis par tactique

| Tactique | Testées | Non testées | Taux couverture | Niveau de risque |
|----------|---------|-------------|-----------------|-----------------|
| Reconnaissance | [ ] | [ ] | [ ]% | ⬜ |
| Resource Development | [ ] | [ ] | [ ]% | ⬜ |
| Initial Access | [ ] | [ ] | [ ]% | ⬛ |
| Execution | [ ] | [ ] | [ ]% | ⬛ |
| Persistence | [ ] | [ ] | [ ]% | ⬛ |
| Privilege Escalation | [ ] | [ ] | [ ]% | ⬛ |
| Defense Evasion | [ ] | [ ] | [ ]% | ⬛ |
| Credential Access | [ ] | [ ] | [ ]% | ⬛ |
| Discovery | [ ] | [ ] | [ ]% | ⬜ |
| Lateral Movement | [ ] | [ ] | [ ]% | ⬛ |
| Collection | [ ] | [ ] | [ ]% | ⬜ |
| Command & Control | [ ] | [ ] | [ ]% | ⬛ |
| Exfiltration | [ ] | [ ] | [ ]% | ⬛ |
| Impact | [ ] | [ ] | [ ]% | ⬜ |

Légende : ⬛ = Risque élevé  ⬜ = Risque modéré

## Top 10 Risques Résiduels

| # | Technique ID | Technique | Tactique | P | I | Score | Priorité |
|---|-------------|-----------|----------|---|---|-------|----------|
| 1 | TXXXX | Nom | Tactique | 5 | 5 | 25 | P0 |
| 2 | TXXXX | Nom | Tactique | 5 | 4 | 20 | P0 |
| 3 | TXXXX | Nom | Tactique | 4 | 5 | 20 | P1 |
| ... | ... | ... | ... | ... | ... | ... | ... |
| 10 | TXXXX | Nom | Tactique | 3 | 3 | 9 | P3 |

## Plan d'Action Recommandé

| ID | Action | Technique(s) | Responsable | Priorité | Délai | Statut |
|----|--------|-------------|-------------|----------|-------|--------|
| A-001 | [Action] | TXXXX | [Équipe] | P0 | [Date] | ☐ |
| A-002 | [Action] | TXXXX | [Équipe] | P1 | [Date] | ☐ |
| ... | ... | ... | ... | ... | ... | ... |

## Évolution attendue après actions

| Métrique | Actuel | Cible (après actions P0+P1) | Cible (après actions P2+P3) |
|----------|--------|------------------------------|------------------------------|
| Techniques couvertes | [M] | [M+Δ] | [N-ε] |
| Taux de couverture | [ % ] | [ % ] | > 80% |
| Risques CRITIQUES résiduels | [X] | 0 | 0 |
```

### 7.3 Annexe C — Checklist de vérification Heat Map

```markdown
# Checklist — Qualité de la Heat Map

## Complétude
- [ ] Toutes les techniques testées sont renseignées dans la couche
- [ ] Chaque technique possède un score numérique (0-100)
- [ ] Chaque technique possède un commentaire descriptif
- [ ] Chaque technique possède des métadonnées (outil, cible, résultat)
- [ ] Les techniques non testées sont marquées comme telles (score = 0, couleur gris)
- [ ] La légende est cohérente avec le code couleur utilisé

## Exactitude
- [ ] Les ID de techniques sont corrects et correspondent à la v15.x d'ATT&CK
- [ ] Les techniques sont rattachées à la bonne tactique
- [ ] Le score reflète fidèlement le résultat du pentest
- [ ] Les commentaires citent les sections du rapport correspondantes

## Pertinence
- [ ] La heat map couvre au moins 5 tactiques ATT&CK différentes
- [ ] Les techniques critiques sont mises en évidence
- [ ] Les techniques détectées par le SOC sont identifiées
- [ ] Les techniques bloquées par des mitigations sont documentées
- [ ] La heat map est exportable en SVG pour le rapport

## Storytelling
- [ ] La heat map raconte une histoire (kill chain visuelle)
- [ ] On peut suivre le chemin d'attaque de gauche à droite (Initial Access → Impact)
- [ ] Les zones grises sont commentées (justification de non-test)
- [ ] Les gaps critiques sont immédiatement visibles

## Conformité NIS2
- [ ] Les techniques couvrent les exigences des articles 21, 23, 27
- [ ] Le mapping ATT&CK ↔ NIS2 est documenté dans le rapport
- [ ] Les recommandations comblent les exigences NIS2 non couvertes
```

### 7.4 Annexe D — Glossaire

| Terme | Définition |
|-------|------------|
| **ATT&CK** | Adversarial Tactics, Techniques, and Common Knowledge — Framework MITRE documentant les comportements des attaquants |
| **Heat Map** | Carte de chaleur — Représentation visuelle du niveau de couverture/risque par technique ATT&CK |
| **Gap Analysis** | Analyse des écarts — Identification des techniques non testées et évaluation du risque résiduel |
| **NIS2** | Network and Information Security Directive 2 — Directive européenne 2022/2555 sur la cybersécurité |
| **DeTT&CT** | Detection Tactics, Techniques & Context — Framework de mapping de la couverture de détection SOC |
| **VECTR** | Plateforme de suivi des tests Red Team / Purple Team basée ATT&CK |
| **Atomic Red Team** | Bibliothèque de tests unitaires mappés sur ATT&CK par Red Canary |
| **COMEX** | Comité Exécutif — Direction générale de l'organisation |
| **RSSI** | Responsable de la Sécurité des Systèmes d'Information |
| **ROE** | Rules of Engagement — Règles définissant le périmètre et les limites du pentest |

### 7.5 Annexe E — Références

| Ressource | URL | Description |
|-----------|-----|-------------|
| MITRE ATT&CK | https://attack.mitre.org/ | Référentiel officiel |
| ATT&CK Navigator | https://mitre-attack.github.io/attack-navigator/ | Outil de visualisation |
| DeTT&CT | https://github.com/rabobank-cdc/DeTTECT | Framework de détection |
| VECTR | https://github.com/SecurityRiskAdvisors/VECTR | Tracking Red/Purple Team |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | Tests unitaires ATT&CK |
| NIS2 EU | https://eur-lex.europa.eu/eli/dir/2022/2555/oj | Directive NIS2 |
| ANSSI — NIS2 | https://www.ssi.gouv.fr/ | Transposition française NIS2 |
| ATT&CK pour NIS2 (ANSSI) | https://www.ssi.gouv.fr/ | Guide ANSSI de mapping |

---

> **Fin du Module 18 — Heat Map ATT&CK & Analyse des Gaps**
>
> *"Ce n'est pas ce que vous avez trouvé qui compte, c'est ce que vous n'avez pas cherché."*
>
> **Tags MITRE** : T1190, T1059, T1053, T1562, T1574, T1547, T1558, T1134, T1649, T1003, T1087, T1069, T1482, T1046, T1135, T1550, T1047, T1569, T1005, T1039, T1114, T1071, T1090, T1041
