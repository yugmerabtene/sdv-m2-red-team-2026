# Module 19 — Restitution Orale Simulée (1h30)

> **Niveau** : M2 Red Team · **Jour** : J4 — Synthèse & Restitution  
> **Prérequis** : Modules M17 (Rédaction rapport), M18 (Heat Map ATT&CK)  
> **Objectif** : Savoir restituer un pentest Red Team devant un COMEX en 30 minutes

---

## Table des matières

1. [Objectifs de la restitution orale](#1-objectifs-de-la-restitution-orale)
2. [Structure d'une restitution efficace](#2-structure-dune-restitution-efficace)
3. [Techniques de communication](#3-techniques-de-communication)
4. [Gestion des questions difficiles](#4-gestion-des-questions-difficiles)
5. [Mise en situation](#5-mise-en-situation)
6. [Grille d'évaluation de la restitution](#6-grille-dévaluation-de-la-restitution)
7. [Conseils pour le monde réel](#7-conseils-pour-le-monde-réel)

---

## 1. Objectifs de la restitution orale

### 1.1 Le pentest ne s'arrête pas au dernier shell

```
┌──────────────────────────────────────────────────────────────────┐
│                LE CYCLE DE VIE DU PENTEST                        │
│                                                                  │
│   Recon  →  Accès  →  PrivEsc  →  Latéral  →  Exfil  →  Rapport │
│                                                          │       │
│                                                    ┌──────▼────┐ │
│                                                    │ RESTITUTION│ │
│                                                    │   ORALE    │ │
│                                                    └──────┬────┘ │
│                                                          │       │
│                                              ┌───────────▼────┐  │
│                                              │ Actions        │  │
│                                              │ correctives    │  │
│                                              └────────────────┘  │
│                                                                  │
│   Sans restitution convaincante, le rapport finit dans un tiroir.│
│   La restitution est le MOMENT DE VÉRITÉ du pentest.             │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Les 4 objectifs de la restitution

```
┌──────────────────────────────────────────────────────────────────┐
│               LES 4 PILIERS DE LA RESTITUTION                    │
│                                                                  │
│  ┌──────────────────┐                                            │
│  │ 1. COMMUNIQUER   │  Faire comprendre au COMEX ce qui s'est   │
│  │    efficacement   │  passé, sans jargon technique excessif.   │
│  └──────────────────┘                                            │
│                                                                  │
│  ┌──────────────────┐                                            │
│  │ 2. TRADUIRE      │  Transformer chaque technique en risque    │
│  │    en business   │  business : impact financier, réputation,  │
│  │                  │  conformité, continuité d'activité.        │
│  └──────────────────┘                                            │
│                                                                  │
│  ┌──────────────────┐                                            │
│  │ 3. GÉRER les     │  Anticiper les objections, les remises     │
│  │    questions      │  en cause, les incompréhensions.          │
│  │    difficiles     │  Rester professionnel en toute circonstance│
│  └──────────────────┘                                            │
│                                                                  │
│  ┌──────────────────┐                                            │
│  │ 4. OBTENIR       │  Convaincre de débloquer le budget et les │
│  │    l'adhésion    │  ressources pour les actions correctives.  │
│  │                  │  Transformer la peur en plan d'action.     │
│  └──────────────────┘                                            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 1.3 La règle des 3C

| C | Signification | Application |
|---|---------------|-------------|
| **C**rédibilité | Démontrer la maîtrise technique | Appuyer chaque finding par une démo ou un schéma de kill chain |
| **C**ontextualisation | Adapter le discours à l'auditoire | COMEX = risques business ; RSSI = détails techniques ; DSI = planning correctif |
| **C**onviction | Faire adhérer à l'urgence d'agir | Chiffrer le risque, proposer une roadmap réaliste, montrer les quick wins |

---

## 2. Structure d'une restitution efficace

### 2.1 Le plan en 30 minutes

```
┌──────────────────────────────────────────────────────────────────┐
│          STRUCTURE TYPE D'UNE RESTITUTION EN 30 MINUTES          │
│                                                                  │
│  TIME     SECTION                 CONTENU                        │
│  ──────── ─────────────────────── ────────────────────────────── │
│  00:00    Introduction             Périmètre, objectifs,         │
│           (2 min)                  méthodologie, règles          │
│                                    d'engagement                  │
│                                                                  │
│  02:00    Executive Summary        Top 3 findings critiques,     │
│           (5 min)                  impact business, chiffrage     │
│                                                                  │
│  07:00    Findings détaillés       Pour chaque critique :        │
│           (10 min)                 kill chain, démo, schéma      │
│                                                                  │
│  17:00    Roadmap de remédiation   Quick wins, actions           │
│           (3 min)                  priorisées, estimation         │
│                                    planning/coût                 │
│                                                                  │
│  20:00    Conclusion &             Résumé, prochaines étapes,    │
│           Questions/Réponses       anticipation des questions    │
│           (10 min)                                               │
│  ──────── ─────────────────────── ────────────────────────────── │
│  30:00    FIN                                                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Introduction (2 min) — Slide 1

**Objectif** : Poser le cadre, rassurer, montrer le professionnalisme.

```
┌──────────────────────────────────────────────────────────────────┐
│                     SLIDE 1 — INTRODUCTION                       │
│                                                                  │
│   ┌────────────────────────────────────────────────────┐        │
│   │                                                    │        │
│   │   PENTEST RED TEAM — CORPEX                         │        │
│   │   12 au 16 mai 2026                                │        │
│   │                                                    │        │
│   │   Cabinet : [Votre cabinet]                        │        │
│   │   Intervenants : Prénom NOM (Lead), Prénom NOM    │        │
│   │                                                    │        │
│   │   Périmètre : SI interne CORPEX, DMZ, Azure AD    │        │
│   │   Objectif  : Obtention des privilèges Domain Admin│        │
│   │   Méthodo   : MITRE ATT&CK, kill chain en 12 phases│        │
│   │   ROE       : Pas d'impact, pas de DoS, pas de     │        │
│   │               données personnelles, arrêt sur       │        │
│   │               demande (go/no-go card)              │        │
│   │                                                    │        │
│   └────────────────────────────────────────────────────┘        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Script type (à adapter) :**

> *"Bonjour à tous. Merci de nous recevoir. Je suis [Prénom], pentester senior, accompagné de [Collègue]. Nous avons mené un pentest Red Team sur votre système d'information du 12 au 16 mai dernier. Le périmètre couvrait votre SI interne, la DMZ et Azure AD. L'objectif était l'obtention des privilèges Domain Admin — objectif que nous avons atteint. Nous allons vous présenter en 20 minutes notre kill chain, les risques associés, et nos recommandations. Nous garderons 10 minutes pour vos questions."*

### 2.3 Executive Summary (5 min) — Slides 2-4

**Objectif** : Donner la mesure du risque en termes business. C'est la partie que le COMEX retiendra.

```
┌──────────────────────────────────────────────────────────────────┐
│              SLIDE 2 — EXECUTIVE SUMMARY                         │
│                                                                  │
│   ┌────────────────────────────────────────────────────┐        │
│   │                                                    │        │
│   │   EN 5 JOURS, NOUS AVONS OBTENU                    │        │
│   │   LES PRIVILÈGES DOMAIN ADMIN                      │        │
│   │                                                    │        │
│   │   ┌──────────────────────────────────────┐        │        │
│   │   │                                      │        │        │
│   │   │  Portail Web ──▶ SRV01 ──▶ DC01     │        │        │
│   │   │  (Log4Shell)     (AMSI)   (ADCS)    │        │        │
│   │   │                                      │        │        │
│   │   │  1er jour        3e jour   5e jour   │        │        │
│   │   └──────────────────────────────────────┘        │        │
│   │                                                    │        │
│   │   Conséquences potentielles si attaquant réel :    │        │
│   │   • Vol de toutes les données du domaine           │        │
│   │   • Chiffrement total du SI (ransomware)           │        │
│   │   • Usurpation d'identité (certificats ADCS)       │        │
│   │                                                    │        │
│   └────────────────────────────────────────────────────┘        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Slide 3 — Les 3 findings critiques :**

```markdown
## Top 3 Findings Critiques

| # | Finding | Technique ATT&CK | Impact Business | Risque financier estimé |
|---|---------|------------------|-----------------|------------------------|
| 1 | **Log4Shell** — RCE non authentifiée sur portail externe | **[T1190]** | Accès initial non détecté au réseau interne. Aucune alerte SOC. | 500 k€ — 2 M€ (incident + remédiation + réputation) |
| 2 | **ADCS ESC1** — Obtention certificat Domain Admin | **[T1649]** | Compromission totale du domaine Active Directory. | 1 M€ — 5 M€ (reconstruction AD, impact métier) |
| 3 | **Absence de détection temps réel** — SIEM avec 2h de retard | **[T1562.001]**, **[T1003]** | Attaquant peut opérer librement pendant 2h avant alerte. | Variable (dépend de la vélocité de l'attaquant) |

## Chiffres clés

| Métrique | Valeur |
|----------|--------|
| Techniques ATT&CK exécutées avec succès | 31 |
| Techniques bloquées par l'EDR | 1 (T1003.001 — LSASS dump) |
| Techniques détectées par le SOC | 0 en temps réel, 1 en différé (2h) |
| Temps total pour atteindre Domain Admin | ~40 heures effectives |
| Délai avant détection SOC | 2h (post-compromission DC) |
```

**Slide 4 — Chiffrage du risque (modèle FAIR) :**

```
┌──────────────────────────────────────────────────────────────────┐
│            ESTIMATION DU RISQUE FINANCIER (FAIR)                 │
│                                                                  │
│   Scénario : Ransomware suite à compromission Domain Admin       │
│                                                                  │
│   ┌────────────────────────────────────────────────────┐        │
│   │                                                    │        │
│   │   Coûts directs :                                  │        │
│   │   ├── Investigation forensics  :   150 — 300 k€   │        │
│   │   ├── Remédiation technique    :   100 — 200 k€   │        │
│   │   ├── Notification (CNIL/RGPD) :    20 —  50 k€   │        │
│   │   ├── Rançon (si payée)        :   500 — 2000 k€  │        │
│   │   └── Reconstruction SI        :   200 — 500 k€   │        │
│   │                                                    │        │
│   │   Coûts indirects :                                │        │
│   │   ├── Perte d'exploitation     : 1 000 — 5 000 k€ │        │
│   │   ├── Atteinte à la réputation :   500 — 2 000 k€ │        │
│   │   └── Sanctions NIS2           :   100 — 1 000 k€ │        │
│   │                                                    │        │
│   │   TOTAL ESTIMÉ                 : 2 570 — 11 050 k€ │        │
│   │                                                    │        │
│   │   Coût de la remédiation proposée : 150 k€         │        │
│   │   ROI de la remédiation : 17x à 73x                │        │
│   │                                                    │        │
│   └────────────────────────────────────────────────────┘        │
│                                                                  │
│   « Investir 150 k€ aujourd'hui pour éviter un sinistre de       │
│     2,5 à 11 M€. Le ROI est indiscutable. »                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.4 Findings détaillés (10 min) — Slides 5-7

**Structure type par finding :**

```
┌──────────────────────────────────────────────────────────────────┐
│           STRUCTURE D'UN FINDING — LA MÉTHODE SCRIBE             │
│                                                                  │
│   S — Situation      : Contexte du finding                      │
│   C — Cause          : Racine technique de la vulnérabilité      │
│   R — Risque         : Impact business, probabilité              │
│   I — Illustration   : Démo, capture, schéma, kill chain        │
│   B — Budget/Action  : Recommandation, quick win, coût estimé   │
│   E — Évaluation     : Délai de mise en œuvre, difficulté       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Exemple — Finding #1 : Log4Shell (T1190) :**

```markdown
## Finding #1 — Log4Shell (CVE-2021-44228)

### Situation
Le portail applicatif externe `portail.corpex.fr` utilise Apache Tomcat
avec Log4j 2.14.1 (vulnérable à CVE-2021-44228).

### Cause
La bibliothèque Log4j est embarquée dans l'application métier sans mise
à jour. La configuration réseau permet au serveur Tomcat d'initier des
connexions sortantes (LDAP, DNS) vers Internet.

### Risque
- **Technique ATT&CK** : **[T1190]** — Exploit Public-Facing Application
- **CVSS** : 10.0 (Critique)
- **Impact** : Remote Code Execution (RCE) non authentifiée → shell SYSTEM
- **Business** : Contournement complet du périmètre de sécurité

### Illustration

┌──────────────────────────────────────────────────────────┐
│              KILL CHAIN — LOG4SHELL → DA                 │
│                                                          │
│  Internet                   DMZ                  LAN    │
│  ─────────                ────────            ─────────  │
│                                                          │
│  ┌──────┐   ${jndi:ldap:   ┌────────┐          ┌──────┐ │
│  │Attaquant│──────────────▶│Portail │  shell   │SRV01 │ │
│  │        │   //x.x.x.x/a  │Tomcat  │─────────▶│      │ │
│  └──┬─────┘                └────────┘  SYSTEM   └──┬───┘ │
│     │                                              │     │
│     │  Serveur LDAP                                │     │
│     │  malveillant                                 │     │
│     │  ┌───────────┐                               │     │
│     └──│JNDI: LDAP │                               │     │
│        │           │                               │     │
│        │ MarshalSec│                               │     │
│        │ + payload │                               │     │
│        └───────────┘                               │     │
│                                                    │     │
│  Étape 1 : Injection   Étape 2 : RCE    Étape 3 :  │     │
│  JNDI dans User-Agent  shell SYSTEM      Pivot LAN │     │
│                                                    │     │
└──────────────────────────────────────────────────────────┘

Démo : [Capture d'écran de la RCE avec reverse shell]

### Recommandation

| Action | Priorité | Difficulté | Coût estimé | Délai |
|--------|----------|------------|-------------|-------|
| Mettre à jour Log4j vers ≥ 2.17.1 | **P0** | Facile | 5 j/h | J+7 |
| Bloquer les connexions sortantes LDAP/DNS depuis DMZ | **P0** | Facile | 2 j/h | J+7 |
| Déployer WAF avec règle Log4Shell | **P1** | Moyen | 15 k€ | M+1 |
| Scanner toutes les applications Java du SI | **P1** | Moyen | 10 j/h | M+1 |

### Évaluation
L'exploitation de cette vulnérabilité est triviale (PoC public, pas
d'authentification requise). La correction est rapide et peu coûteuse.
Nous recommandons un déploiement d'urgence (J+7 maximum).
```

**Exemple — Finding #2 : ADCS ESC1 (T1649) :**

```markdown
## Finding #2 — ADCS ESC1 (Certificat Domain Admin)

### Situation
L'infrastructure ADCS (Active Directory Certificate Services) expose un
template de certificat vulnérable (ESC1). Ce template permet à tout
utilisateur du domaine de demander un certificat pour n'importe quel
utilisateur, y compris Domain Admin.

### Cause
Le template est configuré avec :
- `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé
- Pas de signature requise pour l'enrôlement
- `ENROLLEE_SUPPLIES_SUBJECT` permet de spécifier un UPN arbitraire

### Risque
- **Technique ATT&CK** : **[T1649]** — Steal or Forge Authentication Certificates
- **Impact** : Compromission totale du domaine. Un utilisateur standard
  peut obtenir un certificat Domain Admin.

### Illustration

```
┌─────────────────────────────────────────────────────────────┐
│              ADCS ESC1 — OBTENTION CERTIFICAT DA            │
│                                                             │
│   ┌──────────┐          ┌──────────┐         ┌──────────┐  │
│   │ svc_sql  │          │  CA      │         │   DC     │  │
│   │ (user    │─────────▶│  CORPEX  │         │          │  │
│   │ standard)│ 1. req   │          │         │          │  │
│   │          │  cert    │  ──────▶ │         │          │  │
│   │          │  UPN=DA  │ 2. issue │         │          │  │
│   │          │          │  cert    │         │          │  │
│   │          │◀─────────│          │         │          │  │
│   │          │  cert DA │          │         │          │  │
│   │          │          │          │         │          │  │
│   │          │────────────────────────────────▶│          │  │
│   │          │ 3. PKINIT (certificat DA)      │          │  │
│   │          │◀────────────────────────────────│          │  │
│   │          │ 4. TGT Domain Admin            │          │  │
│   │          │                                │          │  │
│   └──────────┘          └──────────┘         └──────────┘  │
│                                                             │
│   Commande :                                                │
│   certipy-ad req -u svc_sql@corpex.local \                 │
│     -p 'P@ssw0rd!' -ca CA-CORPEX \                        │
│     -template ESC1 -upn administrator@corpex.local         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Capture
[Capture certipy-ad montrant l'obtention du certificat + PKINIT réussi]

### Détection
EventID 4886 et 4887 sur le serveur CA. Ingérés par le SIEM QRadar mais
**aucune règle de corrélation active**. Alerte manuelle 2h après.

### Recommandation

| Action | Priorité | Difficulté | Délai |
|--------|----------|------------|-------|
| Modifier le template ESC1 — supprimer `ENROLLEE_SUPPLIES_SUBJECT` | **P0** | Facile | J+7 |
| Activer la signature requise pour enrôlement | **P0** | Facile | J+7 |
| Déployer la règle SIEM : EventID 4886 + 4887 + alerte temps réel | **P0** | Facile | J+7 |
| Auditer TOUS les templates ADCS (ESC1 → ESC13) | **P1** | Moyen | M+1 |
| Supprimer les serveurs CA non essentiels | **P2** | Moyen | M+2 |
```

### 2.5 Roadmap de remédiation (3 min) — Slide 8

```
┌──────────────────────────────────────────────────────────────────┐
│             ROADMAP DE REMÉDIATION — CORPEX                      │
│                                                                  │
│   URGENCE                                                         │
│   ┌──────────────────────────────────────────────────────┐      │
│   │                                                      │      │
│   │  P0 (J+7) — URGENT                                   │      │
│   │  ├── Mise à jour Log4j (T1190)                      │      │
│   │  ├── Correction template ADCS ESC1 (T1649)          │      │
│   │  ├── Déploiement alertes SIEM temps réel            │      │
│   │  └── Revue configuration proxy (T1071.001)         │      │
│   │                                                      │      │
│   │  P1 (M+1) — COURT TERME                              │      │
│   │  ├── Déployer WAF avec règles OWASP                  │      │
│   │  ├── Activer inspection TLS proxy                    │      │
│   │  ├── Durcir l'EDR (règles custom) (T1562, T1055)   │      │
│   │  ├── Auditer tous les templates ADCS (ESC2-ESC13)   │      │
│   │  └── Campagne de sensibilisation phishing (T1566)   │      │
│   │                                                      │      │
│   │  P2 (M+3) — MOYEN TERME                              │      │
│   │  ├── Pentest Red Team complet (re-test)              │      │
│   │  ├── Migration ADCS vers modèle sécurisé             │      │
│   │  ├── Déploiement DLP complet                        │      │
│   │  └── Mise en conformité NIS2 complète               │      │
│   │                                                      │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   BUDGET ESTIMÉ : 150 k€ (P0+P1) — ROI : 17x minimum              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.6 Conclusion & Questions (10 min) — Slide 9

```markdown
## Conclusion

### Ce que nous retenons

1. Le niveau de sécurité actuel de CORPEX est **insuffisant** face à
   un attaquant motivé. Nous avons atteint les privilèges Domain Admin
   en 5 jours, sans être détectés en temps réel.

2. Les corrections P0 sont **simples, rapides et peu coûteuses**.
   Elles doivent être déployées immédiatement.

3. La conformité **NIS2** impose ces mesures. Un incident non corrigé
   expose à des sanctions financières significatives.

### Prochaines étapes

- [ ] Validation du plan d'action par le COMEX (sous 7 jours)
- [ ] Déploiement des corrections P0 (J+7 à J+14)
- [ ] Point d'avancement intermédiaire (M+1)
- [ ] Re-test planifié (M+3)
- [ ] Audit de conformité NIS2 (M+4)

### Nous sommes à votre disposition

- Rapport complet (80 pages) déjà transmis
- Heat map ATT&CK interactive disponible
- Gap analysis détaillée fournie
- Support post-pentest : 3 mois de questions/réponses inclus
```

---

## 3. Techniques de communication

### 3.1 La vulgarisation — Parler business

**Principe fondamental : le COMEX ne comprend pas (et ne doit pas comprendre) le jargon technique.**

```
┌──────────────────────────────────────────────────────────────────┐
│                  ÉCHELLE DE VULGARISATION                        │
│                                                                  │
│   Niveau Technique (pentester → RSSI)                            │
│   ─────────────────────────────────────────────                  │
│   "SQLi time-based blind avec exfiltration out-of-band via       │
│    DNS, bypass du WAF par encodage hexadécimal double,           │
│    exploitation CVE-2021-43798 avec race condition."             │
│                                                                  │
│   Niveau Intermédiaire (RSSI → DSI)                              │
│   ─────────────────────────────────────────                      │
│   "Injection SQL permettant d'extraire la base de données        │
│    via le serveur DNS. Le pare-feu applicatif ne bloque          │
│    pas cette technique car l'encodage n'est pas détecté."        │
│                                                                  │
│   Niveau Business (pentester → COMEX)                             │
│   ───────────────────────────────────────                        │
│   "Nous avons pu accéder à l'intégralité des données clients     │
│    stockées dans la base de données, sans être détectés.         │
│    Le risque estimé : vol de données personnelles de 50 000      │
│    clients, exposition à une amende RGPD de 2 M€."               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Tableau de traduction Technique → Business :**

| Terme technique | Traduction business | Impact |
|-----------------|---------------------|--------|
| RCE (Remote Code Execution) | "Prise de contrôle du serveur à distance" | Arrêt de service, vol de données |
| Privilege Escalation | "Obtention de droits administrateur" | Accès à toutes les données |
| Lateral Movement | "Propagation dans le réseau" | Compromission de tous les serveurs |
| Persistence | "Porte dérobée permanente" | Accès continu même après redémarrage |
| Exfiltration | "Vol de données" | Perte de propriété intellectuelle, RGPD |
| Kerberoasting | "Cassage de mots de passe de services" | Accès à des comptes critiques |
| Pass-the-Hash | "Usurpation d'identité sans mot de passe" | Contournement de l'authentification |
| Dump LSASS | "Extraction des mots de passe en mémoire" | Vol de tous les identifiants |
| ADCS ESC1 | "Fabrication de faux certificats" | Usurpation d'identité totale |
| C2 Beacon | "Canal de communication caché" | Pilotage à distance non détecté |

### 3.2 Le Storytelling — Raconter l'histoire de l'attaque

```
┌──────────────────────────────────────────────────────────────────┐
│                     LA KILL CHAIN COMME HISTOIRE                  │
│                                                                  │
│   « Laissez-moi vous raconter comment, en 5 jours,               │
│     nous sommes passés d'un simple nom de domaine                 │
│     au contrôle total de votre entreprise. »                     │
│                                                                  │
│   ┌─────────────────────────────────────────────────────┐       │
│   │                                                     │       │
│   │   CHAPITRE 1 : La Reconnaissance (Jour 1)           │       │
│   │   Comme le ferait un attaquant, nous commençons     │       │
│   │   par chercher toutes les informations publiques    │       │
│   │   sur votre entreprise. LinkedIn, crt.sh, Shodan... │       │
│   │   En 2 heures, nous avons identifié 47 employés,    │       │
│   │   12 sous-domaines, et un portail exposé.           │       │
│   │                                                     │       │
│   │   CHAPITRE 2 : L'Intrusion (Jour 1-2)               │       │
│   │   Ce portail utilise une bibliothèque Java obsolète │       │
│   │   — Log4j. Une simple requête HTTP avec un paramètre│       │
│   │   spécial, et nous obtenons un accès complet au     │       │
│   │   serveur. Exactement comme les attaquants de       │       │
│   │   l'attaque Equifax en 2017.                        │       │
│   │                                                     │       │
│   │   CHAPITRE 3 : L'Exploration (Jour 2-3)             │       │
│   │   À l'intérieur du réseau, nous cartographions.     │       │
│   │   Qui sont les administrateurs ? Quels sont les     │       │
│   │   serveurs critiques ? Où sont les données ?        │       │
│   │   L'Active Directory devient notre carte au trésor. │       │
│   │                                                     │       │
│   │   CHAPITRE 4 : L'Ascension (Jour 3-5)               │       │
│   │   Nous trouvons un compte de service avec un mot    │       │
│   │   de passe faible. Puis, sur le serveur de           │       │
│   │   certificats, une configuration nous permet de     │       │
│   │   fabriquer un badge « Domain Admin ».              │       │
│   │   Comme un intrus qui imprimerait un badge visiteur │       │
│   │   pour accéder au bureau du PDG.                    │       │
│   │                                                     │       │
│   │   CHAPITRE 5 : Le Sacre (Jour 5)                    │       │
│   │   Nous sommes Domain Admin. Nous contrôlons tous    │       │
│   │   les comptes, tous les serveurs, toutes les        │       │
│   │   données. Et personne ne nous a vus.               │       │
│   │                                                     │       │
│   └─────────────────────────────────────────────────────┘       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Les visuels — Une image vaut mille mots

**Règles d'or des visuels :**

| Règle | Description | Exemple |
|-------|-------------|---------|
| **1 slide = 1 message** | Ne pas surcharger | Un seul finding par slide |
| **Pas de texte illisible** | Police ≥ 24pt | Titres en 36pt, corps en 28pt |
| **Schéma > Texte** | Préférer un diagramme à un paragraphe | Kill chain en boîtes |
| **Code couleur cohérent** | Rouge = critique, Orange = warning, Vert = OK | Heat map ATT&CK |
| **Démo > Capture > Schéma > Texte** | Hiérarchie de la preuve | Démo vidéo si possible, sinon capture, sinon schéma |
| **Annoter les captures** | Flèches, encadrés, légendes | Entourer le résultat critique en rouge |

**Types de visuels recommandés :**

```
┌──────────────────────────────────────────────────────────────────┐
│                   TYPES DE VISUELS PAR USAGE                     │
│                                                                  │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│   │   HEAT MAP      │  │   KILL CHAIN    │  │   ARCHITECTURE   │  │
│   │   ATT&CK        │  │   DIAGRAM      │  │   MAP           │  │
│   │                 │  │                 │  │                 │  │
│   │   Pour montrer  │  │   Pour raconter │  │   Pour situer   │  │
│   │   la couverture │  │   l'attaque     │  │   les cibles    │  │
│   │   et les gaps   │  │   étape/étape   │  │   dans le SI    │  │
│   └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                  │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│   │   CAPTURE       │  │   TABLEAU       │  │   GRAPHIQUE      │  │
│   │   ÉCRAN ANNOTÉE │  │   DE SYNTHÈSE   │  │   FINANCIER     │  │
│   │                 │  │                 │  │                 │  │
│   │   Pour apporter │  │   Pour comparer │  │   Pour chiffrer │  │
│   │   la preuve     │  │   et prioriser  │  │   le risque     │  │
│   └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.4 Chiffrage du risque — Donner une réalité financière

```
┌──────────────────────────────────────────────────────────────────┐
│                 MÉTHODE DE CHIFFRAGE RAPIDE                      │
│                                                                  │
│   Le chiffrage ne doit pas être précis — il doit être CRÉDIBLE.  │
│                                                                  │
│   Formule simplifiée :                                           │
│                                                                  │
│   Risque (€) = Impact direct + Impact indirect                   │
│                                                                  │
│   Impact direct =                                                │
│     Coût forensics (j/h × TJM IR)                               │
│     + Coût remédiation (j/h × TJM tech)                         │
│     + Coût notification (CNIL, avocats)                         │
│     + Rançon éventuelle (benchmark secteur)                     │
│                                                                  │
│   Impact indirect =                                              │
│     Perte d'exploitation (CA/jour × jours d'arrêt)              │
│     + Atteinte réputation (taux d'attrition client × CA/an)     │
│     + Sanctions réglementaires (RGPD : jusqu'à 4% CA mondial)   │
│     + Sanctions NIS2 (jusqu'à 10 M€ ou 2% CA mondial)           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Exemple de script de chiffrage :**

> *"Pour chiffrer le risque, nous utilisons la méthode FAIR. Prenons le scénario d'un ransomware. Si un attaquant exploite la même faille que nous :*
>
> *Coûts directs : investigation forensics (150 k€), remédiation d'urgence (100 k€), notification CNIL (50 k€), rançon probable (500 k€).*
>
> *Coûts indirects : 3 jours d'arrêt de production (votre CA est de 2 M€/jour, soit 6 M€), attrition client estimée à 5% la première année (soit 500 k€), et un risque de sanction NIS2 (jusqu'à 10 M€).*
>
> *Total : entre 2,5 M€ et 11 M€. Nos recommandations coûtent 150 k€. C'est un investissement avec un retour sur investissement de 17 à 73 fois."*

---

## 4. Gestion des questions difficiles

### 4.1 Typologie des questions difficiles

```
┌──────────────────────────────────────────────────────────────────┐
│                   LES 7 QUESTIONS QUI TUENT                       │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                                                         │    │
│  │  Q1  "Pourquoi n'avez-vous pas trouvé ça ?"             │    │
│  │  Q2  "Est-ce que ça veut dire qu'on est en danger ?"     │    │
│  │  Q3  "Combien ça coûte de tout corriger ?"              │    │
│  │  Q4  "C'est de votre faute si on se fait hacker ?"      │    │
│  │  Q5  "Vous êtes sûr que c'est critique ?"               │    │
│  │  Q6  "On ne peut pas juste... ne rien faire ?"          │    │
│  │  Q7  "Pourquoi vous vs un autre cabinet ?"              │    │
│  │                                                         │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 Réponses structurées

**Q1 — "Pourquoi n'avez-vous pas trouvé ça ?"**

```markdown
### Contexte
Le client mentionne une vulnérabilité qu'il connaissait mais qui
n'apparaît pas dans le rapport.

### Stratégie de réponse
1. **Reconnaître** : "Bonne question, c'est important."
2. **Cadrer** : Rappeler le scope et la méthodologie.
3. **Expliquer** : La raison spécifique (temps, scope, techno).
4. **Proposer** : "Nous pouvons ajouter ce point à un prochain test."

### Script
> "Excellente question. Notre mission avait un périmètre défini dans
> les règles d'engagement — 5 jours sur le SI interne et la DMZ.
> Cette vulnérabilité spécifique [nom] relève du [scope non couvert :
> applicatif mobile / physique / cloud externe].
>
> Si vous souhaitez que nous la testions, nous pouvons l'inclure dans
> un prochain pentest dédié. Nous pouvons aussi vous fournir des
> pistes de correction dès maintenant si vous le souhaitez.

### Pièges à éviter
- Ne pas se justifier excessivement
- Ne pas rejeter la faute sur le client
- Ne pas minimiser la question
```

**Q2 — "Est-ce que ça veut dire qu'on est en danger ?"**

```markdown
### Contexte
Le COMEX réalise soudainement la gravité des findings et panique.

### Stratégie de réponse
1. **Ne pas mentir** : dire la vérité avec tact.
2. **Contextualiser** : comparer au secteur, nuancer.
3. **Rassurer avec un plan** : montrer que c'est corrigible.

### Script
> "Permettez-moi d'être franc. Oui, les vulnérabilités que nous avons
> trouvées sont réelles et exploitables. Cependant, deux points sont
> rassurants :
>
> 1. **Vous n'êtes pas un cas isolé.** Dans notre expérience, 70% des
>    entreprises de votre taille présentent des vulnérabilités
>    similaires. Votre situation est malheureusement la norme.
>
> 2. **Vous avez un plan d'action.** Les corrections P0 sont simples
>    et rapides. En 2 semaines, vous éliminez 90% du risque critique.
>
> Le danger existe, mais vous avez maintenant la feuille de route
> pour le neutraliser. C'est l'objectif même du pentest."
```

**Q3 — "Combien ça coûte de tout corriger ?"**

```markdown
### Contexte
Le DSI/COMEX cherche à budgéter la remédiation.

### Stratégie de réponse
1. **Ne pas donner un chiffre unique** : proposer une fourchette.
2. **Distinguer quick wins et projets long terme**.
3. **Comparer au coût d'un incident**.

### Script
> "Nous avons priorisé les actions en trois niveaux :
>
> - **P0 (urgent)** : ~20 k€. Corrections rapides, sans investissement
>   lourd. ROI immédiat.
>
> - **P1 (court terme)** : ~80 k€. Projets de quelques semaines,
>   déploiement de solutions (WAF, proxy).
>
> - **P2 (moyen terme)** : ~50 k€. Audit, re-test, mise en conformité.
>
> Soit un total d'environ **150 k€** sur 6 mois. À titre de comparaison,
> le coût d'un incident ransomware est estimé entre 2,5 et 11 M€ pour
> votre organisation. L'investissement est de l'ordre de 1 à 6% du
> coût d'un sinistre."
```

**Q4 — "C'est de votre faute si on se fait hacker ?"**

```markdown
### Contexte
Question agressive d'un membre du COMEX qui cherche un responsable.
Peut arriver si un incident survient peu après le pentest.

### Stratégie de réponse
1. **Rester calme et professionnel**.
2. **Rappeler les ROE** : le pentest est une photographie.
3. **Replacer en posture de conseil** : nous sommes là pour aider.

### Script
> "Je comprends votre inquiétude. Laissez-moi clarifier notre rôle.
>
> Notre mission, définie dans les règles d'engagement, était de tester
> la sécurité de votre SI sur un périmètre défini, pendant 5 jours.
> Nous avons trouvé des vulnérabilités, nous les avons documentées,
> et nous vous fournissons des recommandations pour les corriger.
>
> Un pentest n'est pas une garantie de sécurité absolue. C'est un
> outil d'amélioration continue. La responsabilité de la sécurité
> opérationnelle incombe à l'organisation. Notre rôle est de vous
> éclairer sur les risques et les corrections — c'est ce que nous
> faisons aujourd'hui.
>
> Si un incident survient demain, nous sommes à vos côtés pour vous
> aider à investiguer et à répondre. Mais le pentest n'en est pas la
> cause — il révèle des faiblesses préexistantes."

### Points clés
- Ne jamais s'excuser pour avoir fait son travail.
- Le ton doit être calme et assertif, pas défensif.
- Rappeler le cadre contractuel (ROE, scope, durée).
```

**Q5 — "Vous êtes sûr que c'est critique ?"**

```markdown
### Stratégie de réponse
1. **Apporter la preuve** : démo, capture, log.
2. **Comparer à des incidents réels connus**.
3. **Utiliser un cadre standard** (CVSS, ATT&CK).

### Script
> "Oui, et je vais vous montrer pourquoi.
>
> [Afficher la démo de l'exploitation en direct ou en vidéo]
>
> Ce finding correspond à la technique **[T1190]** dans le framework
> MITRE ATT&CK, utilisé par l'ANSSI et toutes les agences de
> cybersécurité. Le score CVSS est de 10.0 — le maximum.
>
> Pour vous donner un parallèle concret : cette même vulnérabilité
> a été utilisée dans l'attaque contre [entreprise connue] en [année],
> qui a coûté [montant] et [conséquence]."
```

**Q6 — "On ne peut pas juste... ne rien faire ?"**

```markdown
### Stratégie de réponse
1. **Respecter la prérogative du client** — c'est son risque.
2. **Expliquer les conséquences de l'inaction**.
3. **Mentionner les obligations légales** (NIS2, RGPD).

### Script
> "Vous êtes décisionnaire, et c'est votre évaluation du risque qui
> prime. Notre rôle est de vous fournir l'information la plus complète
> pour éclairer cette décision.
>
> Si vous choisissez de ne pas corriger, voici ce à quoi vous vous
> exposez :
>
> 1. **Risque d'incident** : les vulnérabilités que nous avons
>    exploitées sont connues et activement ciblées par des groupes
>    cybercriminels (Log4Shell est dans le top 3 des vulnérabilités
>    les plus exploitées en 2024-2026).
>
> 2. **Obligations réglementaires** : en tant qu'entité essentielle
>    au sens de NIS2 (secteur énergie), vous avez l'obligation de
>    mettre en œuvre des mesures de sécurité proportionnées. Un
>    incident sur une vulnérabilité connue et documentée expose à
>    des sanctions.
>
> 3. **Responsabilité des dirigeants** : le COMEX peut être tenu
>    responsable en cas de manquement caractérisé.
>
> Nous vous recommandons a minima de corriger les P0. C'est rapide,
> peu coûteux, et cela réduit considérablement le risque."
```

**Q7 — "Pourquoi vous vs un autre cabinet ?"**

```markdown
### Stratégie de réponse
1. **Ne pas dénigrer la concurrence**.
2. **Mettre en avant sa méthodologie**.
3. **Prouver par les résultats**.

### Script
> "Je ne commenterai pas le travail d'autres cabinets. Ce que je peux
> vous dire, c'est notre approche :
>
> - Nous utilisons le framework **MITRE ATT&CK** comme référence, ce
>   qui permet de mesurer objectivement la couverture du test.
>
> - Nous fournissons une **heat map** et une **gap analysis** qui
>   vous donnent une vision claire de votre exposition.
>
> - Nous alignons nos recommandations avec vos obligations
>   réglementaires (**NIS2**, **RGPD**).
>
> - Et surtout, nos résultats parlent d'eux-mêmes : nous vous avons
>   montré en direct comment nous avons obtenu les privilèges
>   Domain Admin."
```

### 4.3 Anticipation — Préparer ses réponses avant la restitution

```
┌──────────────────────────────────────────────────────────────────┐
│              MATRICE D'ANTICIPATION DES QUESTIONS                 │
│                                                                  │
│   Pour chaque finding critique, anticiper :                      │
│                                                                  │
│   Finding : Log4Shell (T1190)                                     │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ Question probable          │ Réponse préparée         │      │
│   ├────────────────────────────┼──────────────────────────┤      │
│   │ "Pourquoi le WAF n'a pas   │ Le WAF est en mode       │      │
│   │ bloqué ?"                 │ monitoring, pas blocking  │      │
│   ├────────────────────────────┼──────────────────────────┤      │
│   │ "Est-ce que la mise à jour │ Le correctif existe depuis│      │
│   │ existe ?"                  │ décembre 2021 (Log4j     │      │
│   │                            │ 2.17.1). Testé et validé.│      │
│   ├────────────────────────────┼──────────────────────────┤      │
│   │ "Qui est responsable de    │ L'équipe Applicative      │      │
│   │ cette mise à jour ?"      │ (M. Dupont). Nous avons   │      │
│   │                            │ les procédures à fournir. │      │
│   ├────────────────────────────┼──────────────────────────┤      │
│   │ "Est-ce que ça impacte la  │ Non, la mise à jour est  │      │
│   │ production ?"              │ transparente. Fenêtre de │      │
│   │                            │ maintenance de 30 min.   │      │
│   └────────────────────────────┴──────────────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 5. Mise en situation

### 5.1 Organisation de l'exercice

**Format :** Chaque apprenant (ou binôme) prépare et délivre une restitution orale de 10 minutes.

```
┌──────────────────────────────────────────────────────────────────┐
│              DÉROULÉ DE LA MISE EN SITUATION                     │
│                                                                  │
│   Phase 1 — Préparation (15 min)                                 │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ • S'appuyer sur le rapport M17 (CORPEX)              │      │
│   │ • Préparer 5 slides maximum                          │      │
│   │ • Structurer selon le plan vu en section 2           │      │
│   │ • Anticiper 3 questions difficiles                   │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   Phase 2 — Présentation (10 min par apprenant/binôme)           │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ • 2 min : Introduction (périmètre, objectif)         │      │
│   │ • 3 min : Executive summary (top 3, impact business) │      │
│   │ • 3 min : Focus sur le finding le plus critique      │      │
│   │ • 2 min : Roadmap P0 et conclusion                   │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   Phase 3 — Questions du COMEX (5 min)                           │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ • Le formateur joue le rôle du RSSI/COMEX            │      │
│   │ • Pose 2-3 questions difficiles (cf. section 4)      │      │
│   │ • Peut aussi jouer le rôle de membre hostile         │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   Phase 4 — Feedback immédiat (3 min)                            │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ • Feedback du formateur (grille section 6)           │      │
│   │ • Feedback des pairs (1 point fort, 1 axe d'amélioration)│  │
│   │ • Auto-évaluation par l'apprenant                    │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Rôles et consignes

**Rôle du formateur (COMEX/RSSI) :**

| Profil | Attitude | Questions types |
|--------|----------|-----------------|
| **RSSI technique** | Intéressé, pose des questions de détails | "Quel EventID pour détecter ça ?", "Vous avez testé le bypass EDR ?" |
| **DSI** | Pragmatique, focus planning et coûts | "Combien de temps pour corriger ?", "Qui fait quoi ?" |
| **DRH** | Inquiet pour les collaborateurs | "Est-ce que le phishing a fonctionné ?", "Faut-il sanctionner ?" |
| **DG/PDG** | Focus business, réputation, conformité | "Quel est le risque financier ?", "Sommes-nous conformes NIS2 ?" |
| **Membre hostile** | Remet en cause, agressif | "C'est de votre faute si on est vulnérable", "Vous avez mal fait votre travail" |

**Consignes pour l'apprenant :**

1. **Rester debout** (posture professionnelle)
2. **Regarder l'auditoire** (pas l'écran)
3. **Parler fort et articuler**
4. **Ne pas lire ses slides**
5. **Gérer son temps** (10 min strict)
6. **Utiliser un pointeur laser** pour les schémas
7. **Avoir une bouteille d'eau** à disposition

### 5.3 Contenu de la restitution attendu

```markdown
## Restitution CORPEX — Template apprenant

### Slide 1 — Introduction (2 min)
- Qui : Cabinet [Nom], [Prénom NOM], [Collègue]
- Quoi : Pentest Red Team, 5 jours, 12-16 mai 2026
- Où : SI interne CORPEX, DMZ, Azure AD
- Comment : MITRE ATT&CK, kill chain 12 phases
- Règles : Pas d'impact, pas de DoS, pas de données personnelles

### Slide 2 — Executive Summary (3 min)
- OBJECTIF ATTEINT : Domain Admin en 5 jours
- Kill chain simplifiée (schéma 3 boîtes)
- Top 3 findings avec impact business
- Aucune détection temps réel par le SOC
- Chiffrage du risque : 2,5 – 11 M€

### Slide 3 — Finding #1 détaillé (3 min)
- Log4Shell (T1190) — Portail externe
- Schéma de la kill chain
- Démo ou capture d'écran
- Recommandation P0 (mise à jour Log4j + pare-feu sortant)
- Coût / délai de correction

### Slide 4 — Roadmap (1 min)
- Tableau P0 / P1 / P2
- Quick wins (7 jours)
- Budget total : 150 k€
- ROI : 17x à 73x
- Prochaines étapes

### Slide 5 — Conclusion (1 min)
- Résumé en une phrase
- Conformité NIS2
- Prochain pentest suggéré
- Disponibilité pour questions
- Remerciements

### Anticipation des questions (préparer en amont)
- Q1 : "Pourquoi pas de détection SOC ?" → SIEM configuré mais pas de règles
- Q2 : "Qui est responsable ?" → Processus, pas individu
- Q3 : "On commence par quoi ?" → P0 urgent, J+7 maximum
```

---

## 6. Grille d'évaluation de la restitution

### 6.1 Grille détaillée (/50)

```markdown
# GRILLE D'ÉVALUATION — RESTITUTION ORALE
## Module 19 — SDV M2 Red Team

### 1. CLARTÉ DU MESSAGE (/10)

| Critère | Excellent (2) | Bien (1) | Insuffisant (0) | Score |
|---------|---------------|----------|-----------------|-------|
| Structure | Plan clair, transitions fluides | Plan présent mais transitions hésitantes | Pas de structure perceptible | __/2 |
| Vulgarisation | Termes techniques absents ou expliqués | Quelques termes non expliqués | Jargon technique omniprésent | __/2 |
| Concision | Messages clés mémorisables | Quelques longueurs | Trop long, se perd dans les détails | __/2 |
| Élocution | Fort, articulé, rythme adapté | Correct mais perfectible | Inaudible, trop rapide, monotone | __/2 |
| Respect du temps | 9-11 min | 7-9 ou 11-13 min | < 7 ou > 13 min | __/2 |

### 2. PERTINENCE BUSINESS (/10)

| Critère | Excellent (2) | Bien (1) | Insuffisant (0) | Score |
|---------|---------------|----------|-----------------|-------|
| Impact business | Risques chiffrés en €, conséquences business claires | Mention business mais pas chiffrée | Aucune traduction business | __/2 |
| Conformité | NIS2/RGPD mentionnés avec articles précis | Mentionnés sans détail | Non mentionnés | __/2 |
| ROI de la remédiation | Coût correction vs coût incident comparé | Coût mentionné sans comparaison | Aucun chiffrage | __/2 |
| Priorisation | P0/P1/P2 avec critères clairs | Priorisation présente mais vague | Aucune priorisation | __/2 |
| Prochaines étapes | Plan d'action concret avec dates | Étapes mentionnées sans dates | Aucune prochaine étape | __/2 |

### 3. QUALITÉ DES VISUELS (/10)

| Critère | Excellent (2) | Bien (1) | Insuffisant (0) | Score |
|---------|---------------|----------|-----------------|-------|
| Schémas | Kill chain claire, boîtes, flèches, légendes | Schéma présent mais peu clair | Aucun schéma, que du texte | __/2 |
| Heat map ATT&CK | Heat map présente et commentée | Mentionnée mais non affichée | Absente | __/2 |
| Code couleur | Rouge/Orange/Vert cohérent et légendé | Code présent mais incohérent | Pas de code couleur | __/2 |
| Lisibilité | Police ≥ 24pt, pas de pavés de texte | Quelques slides trop chargées | Slides illisibles | __/2 |
| Preuves | Captures annotées, démo | Captures non annotées | Aucune preuve visuelle | __/2 |

### 4. GESTION DES QUESTIONS (/10)

| Critère | Excellent (2) | Bien (1) | Insuffisant (0) | Score |
|---------|---------------|----------|-----------------|-------|
| Écoute | Reformule la question | Répond sans reformuler | Ne comprend pas la question | __/2 |
| Pertinence | Répond directement et complètement | Réponse partielle | Évite la question, noie le poisson | __/2 |
| Honnêteté | "Je ne sais pas" assumé avec proposition | "Je ne sais pas" sans suivi | Bluff, réponse incorrecte | __/2 |
| Gestion conflit | Reste calme, assertif, non défensif | Un peu défensif | Agressif ou paniqué | __/2 |
| Proposition | Transforme la question en opportunité | Réponse sans proposition | Ne rebondit pas | __/2 |

### 5. POSTURE PROFESSIONNELLE (/10)

| Critère | Excellent (2) | Bien (1) | Insuffisant (0) | Score |
|---------|---------------|----------|-----------------|-------|
| Présence | Debout, regarde l'auditoire, pas l'écran | Quelques regards vers l'auditoire | Tourné vers l'écran, lit ses slides | __/2 |
| Gestion du stress | Serein, sourit, respire | Stressé mais contrôlé | Paniqué, bloque | __/2 |
| Apparence | Tenue professionnelle adaptée | Correct | Négligé | __/2 |
| Empathie | S'adapte aux réactions, vérifie la compréhension | Parle sans vérifier | Ignore l'auditoire | __/2 |
| Conclusion | Remercie, propose suivi, inspire confiance | Remercie | Fin abrupte | __/2 |

### TOTAL : ___/50

### Interprétation du score :

| Score | Niveau | Commentaire |
|-------|--------|-------------|
| 45-50 | Excellent | Prêt pour une restitution COMEX réelle |
| 35-44 | Bon | Quelques ajustements nécessaires |
| 25-34 | Intermédiaire | Entraînement supplémentaire requis |
| 15-24 | Débutant | Lacunes significatives à travailler |
| 0-14 | Insuffisant | Revoir les fondamentaux de la communication |
```

---

## 7. Conseils pour le monde réel

### 7.1 Adapter son discours au client

```
┌──────────────────────────────────────────────────────────────────┐
│             ADAPTATION DU DISCOURS PAR TYPE DE CLIENT             │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ PME / ETI                                            │      │
│   │ • COMEX réduit (DG + DSI, parfois même personne)     │      │
│   │ • Budget limité → focus sur quick wins à 0€         │      │
│   │ • Pas d'équipe SOC → insister sur les basiques       │      │
│   │ • Exemples concrets de PME piratées                  │      │
│   │ • Langage simple, pas de jargon                      │      │
│   │ • "Voilà ce que vous pouvez faire vous-même,         │      │
│   │   aujourd'hui, sans rien acheter"                    │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ Grand Groupe / CAC 40                                 │      │
│   │ • COMEX étoffé (DG, DSI, RSSI, DPO, Risk Manager...) │      │
│   │ • Attentes élevées en conformité (NIS2, RGPD, SOX)   │      │
│   │ • Budget conséquent → proposer plan d'amélioration    │      │
│   │ • Pression médiatique et actionnariale               │      │
│   │ • Concurrence entre RSSI et DSI possible             │      │
│   │ • Niveau technique intermédiaire acceptable          │      │
│   │ • "Voilà comment vous situez par rapport au secteur" │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ Secteur Public / Étatique / OIV                       │      │
│   │ • Forte culture de la hiérarchie et du formalisme     │      │
│   │ • Interlocuteurs : RSSI, DSI, parfois préfet/directeur│      │
│   │ • Langage administratif et juridique                  │      │
│   │ • Références obligatoires : ANSSI, LPM, NIS2, IGI1300 │      │
│   │ • Niveau de classification possible (DR, Confidentiel)│      │
│   │ • Remise du rapport : format, procédure, accusé       │      │
│   │ • "Voilà comment l'ANSSI évalue ce type de risque"    │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 7.2 Gérer les personnalités difficiles

```markdown
## Typologie des personnalités difficiles en restitution

### 1. Le Sceptique
- **Attitude** : "Ça n'arrive qu'aux autres", "Vous exagérez"
- **Stratégie** : Apporter des faits, des statistiques, des exemples
  concrets du même secteur
- **Phrase clé** : "En 2025, 4 entreprises de votre secteur ont subi
  exactement ce type d'attaque. Voici les chiffres."

### 2. Le Technicien Qui-Sait-Tout
- **Attitude** : "Pourquoi vous avez utilisé X au lieu de Y ?",
  "Moi j'aurais fait comme ça"
- **Stratégie** : Ne pas entrer dans le débat technique. Recentrer sur
  les résultats et l'impact business.
- **Phrase clé** : "Il existe effectivement plusieurs approches.
  Celle que nous avons choisie a fonctionné — comme vous le voyez,
  nous avons atteint l'objectif. L'important est la conclusion."

### 3. Le Silencieux
- **Attitude** : Ne dit rien, prend des notes, impassible
- **Stratégie** : Le solliciter directement (sans agressivité).
  "M. X, avez-vous des questions à ce stade ?"
- **Phrase clé** : "Je vois que vous prenez des notes. Y a-t-il un
  point que vous souhaiteriez que je clarifie ?"

### 4. L'Agressif
- **Attitude** : "C'est de votre faute", "Vous n'avez rien trouvé",
  "C'est quoi ce travail ?"
- **Stratégie** : Rester calme, ne pas se justifier excessivement,
  recentrer sur les faits et le plan d'action.
- **Phrase clé** : "Je comprends que ces résultats puissent être
  frustrants. Notre objectif aujourd'hui est de vous donner les
  clés pour corriger ces vulnérabilités."

### 5. Le Politicien
- **Attitude** : Cherche à détourner la conversation, à noyer le
  poisson, à diluer la responsabilité
- **Stratégie** : Ramener systématiquement aux faits et aux
  recommandations concrètes.
- **Phrase clé** : "Je prends note de ce contexte. Pour revenir à
  notre sujet : voici les actions concrètes que nous recommandons."

### 6. L'Urgentiste
- **Attitude** : "On fait quoi LÀ, MAINTENANT ?"
- **Stratégie** : Rassurer, donner les P0 immédiates, ne pas
  s'éparpiller
- **Phrase clé** : "Voici les 3 actions que vous pouvez lancer
  DÈS AUJOURD'HUI, sans attendre."
```

### 7.3 Post-pentest — Le suivi

```
┌──────────────────────────────────────────────────────────────────┐
│                  LE CYCLE POST-PENTEST                            │
│                                                                  │
│   Restitution                                                    │
│      │                                                           │
│      ▼                                                           │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌────────┐ │
│   │  Suivi   │────▶│  Re-test │────▶│  Rapport │────▶│ Clôture│ │
│   │  (3 mois)│     │  (M+3)   │     │  final   │     │        │ │
│   └──────────┘     └──────────┘     └──────────┘     └────────┘ │
│                                                                  │
│   Détail des étapes :                                            │
│                                                                  │
│   1. SUIVI (3 mois après restitution)                            │
│      • Répondre aux questions techniques du client               │
│      • Aider à la priorisation des corrections                   │
│      • Valider les plans d'action proposés par le client         │
│      • Documenter les échanges (traçabilité)                      │
│                                                                  │
│   2. RE-TEST (M+3 ou M+6)                                        │
│      • Vérifier la correction des vulnérabilités P0              │
│      • Tester les nouvelles vulnérabilités (gap analysis)        │
│      • Comparer les heat maps avant/après                       │
│      • Mesurer l'amélioration de la couverture                   │
│                                                                  │
│   3. RAPPORT DE RE-TEST                                          │
│      • Tableau comparatif (avant vs après)                       │
│      • Évolution de la heat map ATT&CK                           │
│      • Nouvelles recommandations                                 │
│      • Attestation de conformité NIS2 (si atteinte)              │
│                                                                  │
│   4. CLÔTURE                                                     │
│      • Réunion de clôture formelle                               │
│      • Remise du rapport final                                   │
│      • Proposition de contrat de pentest annuel                  │
│      • Demande de témoignage client (si positif)                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 7.4 Checklist pré-restitution

```markdown
# CHECKLIST — Préparation de la restitution

## J-7
- [ ] Rapport final relu et validé (pas de coquilles, pas d'erreurs techniques)
- [ ] Heat map ATT&CK exportée en SVG et intégrée au slide
- [ ] Gap analysis finalisée
- [ ] Slides préparés (5-7 slides max)
- [ ] Démo enregistrée en vidéo (backup si démo live échoue)

## J-3
- [ ] Répétition générale (seul ou avec un collègue)
- [ ] Vérification du matériel : PC, adaptateur HDMI/VGA, pointeur laser
- [ ] Version PDF des slides envoyée au client (si demandé)
- [ ] Anticipation des questions difficiles (matrice)

## J-1
- [ ] Dernière vérification du rapport (coquilles, screenshots, noms de domaine)
- [ ] Préparation de la tenue vestimentaire
- [ ] Repérage du lieu (adresse, parking, badge visiteur)
- [ ] Backup des slides sur clé USB (en plus du PC)

## Jour J — Avant la restitution
- [ ] Arrivée 30 min avant l'heure
- [ ] Test du vidéoprojecteur (résolution, câble, son si vidéo)
- [ ] Bouteille d'eau à portée de main
- [ ] Téléphone en silencieux
- [ ] Respiration, posture, sourire

## Jour J — Après la restitution
- [ ] Remise du rapport papier (si prévu)
- [ ] Envoi du rapport PDF + heat map JSON par email
- [ ] Proposition de date pour le point de suivi (M+1)
- [ ] Compte-rendu interne (retour d'expérience pour le cabinet)
- [ ] Mise à jour du CV/tracking des missions
```

### 7.5 Erreurs fatales à éviter

```
┌──────────────────────────────────────────────────────────────────┐
│                 LES 10 ERREURS FATALES EN RESTITUTION             │
│                                                                  │
│  1. LIRE ses slides mot à mot                                     │
│     → Le COMEX sait lire. Vos slides sont un support, pas un     │
│       prompteur.                                                 │
│                                                                  │
│  2. ÊTRE TROP TECHNIQUE                                          │
│     → "On a dumpé la LSASS via un handle DuplicateTokenEx puis   │
│       on a extrait les hash NTLM..." → incompréhensible.         │
│                                                                  │
│  3. MINIMISER les findings                                       │
│     → "C'est pas grave, y a pire ailleurs..." → vous êtes payé   │
│       pour trouver des problèmes, assumez-les.                   │
│                                                                  │
│  4. CATASTROPHER sans proposer de solution                       │
│     → "Vous êtes foutus, tout est à refaire" → le COMEX a besoin │
│       d'un plan, pas d'un constat d'échec.                       │
│                                                                  │
│  5. DONNER UN CHIFFRE PRÉCIS du coût de remédiation sans étude   │
│     → "Ça va coûter 1 247 532 €" → fourchette, pas précision     │
│       illusoire.                                                 │
│                                                                  │
│  6. CRITIQUER l'équipe interne                                   │
│     → "Franchement votre RSSI, il est nul..." → suicide          │
│       professionnel. Critiquez les processus, pas les personnes. │
│                                                                  │
│  7. ÊTRE AGRESSIF ou DÉFENSIF                                   │
│     → Rester calme, assertif, professionnel. Même si le client   │
│       est agressif.                                              │
│                                                                  │
│  8. DÉPASSER LE TEMPS imparti                                   │
│     → Le COMEX a un agenda chargé. 30 min = 30 min.              │
│                                                                  │
│  9. NE PAS AVOIR DE BACKUP                                      │
│     → Démo live qui échoue ? Pas de vidéo de backup ? Perte de   │
│       crédibilité immédiate.                                     │
│                                                                  │
│  10. OUBLIER DE CONCLURE                                        │
│     → Terminer par "Voilà, c'est tout..." → finir par un appel   │
│       à l'action, une prochaine étape, une ouverture.            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

> **Fin du Module 19 — Restitution Orale Simulée**
>
> *"La meilleure analyse technique ne vaut rien si elle n'est pas comprise par ceux qui prennent les décisions."*
>
> **Tags MITRE** : T1190, T1649, T1562.001, T1003, T1071.001, T1059, T1110, T1111, T1078

---

## Références

| Ressource | Description |
|-----------|-------------|
| MITRE ATT&CK | https://attack.mitre.org/ |
| Guide ANSSI — Restitution de pentest | https://www.ssi.gouv.fr/ |
| FAIR Institute (risque financier) | https://www.fairinstitute.org/ |
| NIS2 Directive | https://eur-lex.europa.eu/eli/dir/2022/2555/oj |
| RGPD — Sanctions | https://www.cnil.fr/ |
| Harvard Business Review — Presenting to Executives | https://hbr.org/ |
