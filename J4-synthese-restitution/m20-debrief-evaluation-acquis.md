# Module 20 — Débrief Collectif & Évaluation des Acquis (0h45)

> **Niveau** : M2 Red Team · **Jour** : J4 — Synthèse & Restitution  
> **Prérequis** : Modules M1 à M19  
> **Objectif** : Faire le bilan des 4 jours, évaluer les compétences acquises et tracer la suite du parcours

---

## Table des matières

1. [Débrief des 4 jours](#1-débrief-des-4-jours)
2. [Quiz d'évaluation des acquis](#2-quiz-dévaluation-des-acquis)
3. [Checklist des compétences acquises](#3-checklist-des-compétences-acquises)
4. [Poursuite de la montée en compétence](#4-poursuite-de-la-montée-en-compétence)
5. [Ressources pour continuer](#5-ressources-pour-continuer)
6. [Évaluation de la formation](#6-évaluation-de-la-formation)
7. [Mot de la fin](#7-mot-de-la-fin)

---

## 1. Débrief des 4 jours

### 1.1 Tour de table structuré

```
┌──────────────────────────────────────────────────────────────────┐
│                  DÉBRIEF COLLECTIF — MÉTHODE                      │
│                                                                  │
│   Format : Tour de table + Post-it + Discussion ouverte           │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │                                                      │      │
│   │   Chaque apprenant s'exprime 2-3 minutes sur :       │      │
│   │                                                      │      │
│   │   1. 🌟 TOP 1 — Ce qu'il a le plus apprécié          │      │
│   │   2. 💡 TOP 1 — Ce qu'il a appris de plus utile      │      │
│   │   3. 🔧 TOP 1 — Ce qu'il aurait voulu approfondir    │      │
│   │   4. ❓ 1 question restée sans réponse               │      │
│   │                                                      │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Ce qui a bien fonctionné — Synthèse collective

**Les points forts identifiés par les apprenants (exemples) :**

```markdown
| Domaine | Retour positif | Module |
|---------|---------------|--------|
| Progression pédagogique | Montée en puissance progressive sur 4 jours, du scan au rapport | M1 → M20 |
| Approche pratique | TP réalistes, labs live, scénarios concrets | M5, M8, M10, M17 |
| MITRE ATT&CK | Référentiel structurant pour tout le pentest | M2, M18 |
| AD / Post-exploitation | Découverte de l'écosystème d'attaque Active Directory | M6, M7, M8, M9 |
| Retour d'expérience | Anecdotes terrain, erreurs réelles, cas vécus | Tous |
| Reporting | Apprendre à rédiger un rapport professionnel | M17 |
| Restitution | Mise en situation orale, gestion du stress | M19 |
| Outils modernes | Certipy, BloodHound, Cobalt Strike/Mythic, Sliver | M6, M8, M10 |
```

### 1.3 Points d'amélioration — Synthèse collective

**Les axes d'amélioration remontés :**

```markdown
| Domaine | Retour négatif | Piste d'amélioration |
|---------|---------------|---------------------|
| Rythme | Trop dense, journées longues | Prévoir plus de pauses, étaler sur 5 jours |
| Prérequis | Hétérogénéité du groupe sur Linux/Windows | Envoyer une liste de prérequis + VM préinstallée |
| Temps TP | Manque de temps pour terminer tous les exercices | Réduire le scope ou augmenter la durée |
| Labs instables | Problèmes techniques (VM crash, réseau) | Checklist pré-vol VM, scripts de reset automatique |
| Mobile | Partie mobile mériterait plus de temps | Module dédié supplémentaire |
| Cloud | Azure AD survolé, mériterait approfondissement | Ajouter un module Cloud pentest (M21 ?) |
| SOC simulé | Pas assez d'interaction avec le SOC | Renforcer le scénario Blue vs Red |
```

### 1.4 Questions restantes — FAQ de clôture

**Questions fréquentes et réponses du formateur :**

```markdown
### Q1 — "Par où commencer dans le pentest après cette formation ?"

> Commencez par les certifications d'entrée : **eJPT** (gratuit,
> très pédagogique) puis **PNPT** (TCM Security, très pratique).
> Enchaînez avec **OSCP** (OffSec) pour la reconnaissance du marché.
> En parallèle, entraînez-vous sur **HackTheBox** et **TryHackMe**.

### Q2 — "Quel langage de programmation approfondir ?"

> **Python** pour l'automatisation et les exploits custom.
> **PowerShell** pour Windows et Active Directory (incontournable).
> **C#** pour le développement d'outils .NET (évasion EDR, C2).
> **C/C++** pour l'exploitation bas niveau (buffer overflow, kernel).
> Commencez par Python + PowerShell.

### Q3 — "Comment trouver une mission Red Team / pentest ?"

> 1. Construisez un portfolio : blog technique, GitHub, write-ups HTB.
> 2. Passez des certifications visibles : OSCP, eCPPT, CRTP.
> 3. Postulez dans des cabinets spécialisés (Synacktiv, Wavestone,
>    Oppida, Lexfo, etc.) ou dans des ESN avec pôle cybersécurité.
> 4. Réseautez : conférences (LeHack, SSTIC, BSides), Discord, Twitter.
> 5. Commencez par du pentest applicatif/web avant la Red Team.

### Q4 — "Red Team vs Pentest, quelle différence en pratique ?"

> Le pentest est un audit de vulnérabilités. La Red Team est une
> simulation d'attaque réaliste contre des cibles précises, avec
> un scénario et des objectifs définis. Le pentester trouve des
> failles. Le Red Teamer les exploite jusqu'au bout, en restant
> furtif, pour démontrer l'impact business réel.

### Q5 — "Comment rester à jour techniquement ?"

> Le domaine évolue très vite. Abonnez-vous à :
> - **Twitter/X** : @thegrugq, @harmj0y, @tiraniddo, @gentilkiwi
> - **Blogs** : Posts BySpecter, S3cur3Th1sSh1t, TrustedSec, SpecterOps
> - **Newsletters** : TL;DR Sec, Unsupervised Learning, Risky Biz
> - **Conférences** : SSTIC, LeHack, DEFCON (YouTube), BlackHat
```

### 1.5 Synthèse visuelle — Le mur des apprentissages

```
┌──────────────────────────────────────────────────────────────────┐
│              LE MUR DES APPRENTISSAGES — 4 JOURS                  │
│                                                                  │
│   J1 — FONDAMENTAUX                    J2 — AD & PRIVESC          │
│   ┌─────────────────────────┐         ┌─────────────────────────┐ │
│   │ • MITRE ATT&CK          │         │ • BloodHound            │ │
│   │ • Kill Chain            │         │ • Kerberoasting T1558   │ │
│   │ • Recon T1593-T1595     │         │ • AS-REP Roasting       │ │
│   │ • Scanning T1046        │         │ • ADCS T1649            │ │
│   │ • Web Pentest T1190     │         │ • Delegations           │ │
│   │ • SQLi, XSS, SSTI       │         │ • Lateral Movement T1021│ │
│   └─────────────────────────┘         └─────────────────────────┘ │
│                                                                  │
│   J3 — MOBILE & PERSISTENCE            J4 — REPORTING & RESTITUTION│
│   ┌─────────────────────────┐         ┌─────────────────────────┐ │
│   │ • Reverse APK           │         │ • Rapport pentest M17   │ │
│   │ • Interception TLS      │         │ • Heat map M18          │ │
│   │ • Frida hooking         │         │ • Gap analysis M18      │ │
│   │ • Patcher APK           │         │ • NIS2 ↔ ATT&CK M18     │ │
│   │ • Persistence AD T1547  │         │ • Restitution orale M19 │ │
│   │ • C2 & Exfil T1041      │         │ • Débrief M20           │ │
│   └─────────────────────────┘         └─────────────────────────┘ │
│                                                                  │
│   COMPÉTENCES TRANSVERSALES :                                    │
│   • Méthodologie  • Esprit critique  • Communication  • Éthique  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Quiz d'évaluation des acquis

### 2.1 Instructions

```
┌──────────────────────────────────────────────────────────────────┐
│              QUIZ D'ÉVALUATION — CONSIGNES                        │
│                                                                  │
│   • 20 questions à choix multiples (QCM)                         │
│   • Une seule réponse correcte par question                      │
│   • Durée : 15 minutes                                           │
│   • Barème : 1 point par bonne réponse, 0 sinon                  │
│   • Score sur 20                                                  │
│   • Correction collective après le quiz                          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Les 20 questions

---

**Question 1 — MITRE ATT&CK**

Quelle tactique MITRE ATT&CK correspond à l'obtention d'un accès initial non autorisé au système d'information ?

A. Execution  
B. Initial Access  
C. Persistence  
D. Privilege Escalation  

<details>
<summary>Réponse et explication</summary>

**B — Initial Access.** La tactique *Initial Access* (TA0001) regroupe les techniques utilisées par un attaquant pour obtenir un premier accès au système d'information cible : exploitation d'une application exposée (**[T1190]**), phishing (**[T1566]**), utilisation de comptes valides (**[T1078]**), etc.

</details>

---

**Question 2 — Reconnaissance**

Quel outil permet d'identifier des sous-domaines via les certificats TLS (Certificate Transparency) ?

A. Nmap  
B. BloodHound  
C. crt.sh  
D. Mimikatz  

<details>
<summary>Réponse et explication</summary>

**C — crt.sh.** crt.sh est un moteur de recherche de certificats TLS qui exploite les logs de Certificate Transparency (CT). Technique ATT&CK associée : **[T1596]** — Search Open Technical Databases.

</details>

---

**Question 3 — Kill Chain**

Dans la kill chain d'un pentest Red Team, à quelle phase correspond l'extraction des hash NTLM du contrôleur de domaine ?

A. Reconnaissance  
B. Lateral Movement  
C. Credential Access  
D. Exfiltration  

<details>
<summary>Réponse et explication</summary>

**C — Credential Access.** L'extraction des hash NTLM depuis le fichier NTDS.dit du contrôleur de domaine correspond à la technique **[T1003.003]** — NTDS, dans la tactique *Credential Access* (TA0006).

</details>

---

**Question 4 — Web Pentest**

Quelle vulnérabilité web permet d'exécuter des commandes système via une injection dans un template ?

A. SQL Injection (SQLi) — **[T1190]**  
B. Cross-Site Scripting (XSS)  
C. Server-Side Template Injection (SSTI) — **[T1190]**  
D. Local File Inclusion (LFI)  

<details>
<summary>Réponse et explication</summary>

**C — Server-Side Template Injection (SSTI).** Le SSTI se produit lorsqu'un attaquant injecte du code dans un moteur de template côté serveur (Jinja2, Twig, FreeMarker, etc.), menant potentiellement à une RCE. Exploitation via **[T1190]** — Exploit Public-Facing Application.

</details>

---

**Question 5 — Active Directory**

Quel outil est utilisé pour collecter et analyser les chemins d'attaque dans un environnement Active Directory ?

A. Nmap  
B. Metasploit  
C. BloodHound  
D. Burp Suite  

<details>
<summary>Réponse et explication</summary>

**C — BloodHound.** BloodHound (avec le collecteur SharpHound) utilise la théorie des graphes pour identifier les chemins de privilege escalation dans AD. Techniques associées : **[T1087]** (Account Discovery), **[T1069]** (Permission Groups Discovery).

</details>

---

**Question 6 — Kerberos**

Quelle attaque Kerberos consiste à demander des tickets TGS pour des comptes de service, puis à casser leur hash hors ligne ?

A. Pass-the-Hash — **[T1550.002]**  
B. Golden Ticket — **[T1558.001]**  
C. Kerberoasting — **[T1558.003]**  
D. AS-REP Roasting — **[T1558.004]**  

<details>
<summary>Réponse et explication</summary>

**C — Kerberoasting — [T1558.003].** Le Kerberoasting exploite le fait que tout utilisateur authentifié peut demander un TGS pour n'importe quel SPN. Le TGS est chiffré avec le hash du compte de service, qu'on peut casser hors ligne (hashcat mode 13100).

</details>

---

**Question 7 — ADCS**

Quel numéro d'ESC ADCS (certipy) correspond au template permettant à un utilisateur standard de spécifier un UPN arbitraire (comme celui d'un Domain Admin) ?

A. ESC1 — **[T1649]**  
B. ESC2  
C. ESC4  
D. ESC8  

<details>
<summary>Réponse et explication</summary>

**A — ESC1 — [T1649].** L'ESC1 survient quand un template de certificat a le flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé, sans signature requise pour l'enrôlement. Un utilisateur peut alors demander un certificat pour n'importe quel UPN, y compris `administrator@domain.local`.

</details>

---

**Question 8 — Lateral Movement**

Quelle technique permet de s'authentifier sur une machine distante en utilisant uniquement le hash NTLM, sans connaître le mot de passe en clair ?

A. Kerberoasting — **[T1558.003]**  
B. Pass-the-Hash — **[T1550.002]**  
C. Token Impersonation — **[T1134.001]**  
D. DLL Sideloading — **[T1574.002]**  

<details>
<summary>Réponse et explication</summary>

**B — Pass-the-Hash — [T1550.002].** Le Pass-the-Hash exploite le protocole NTLM qui ne vérifie pas que le demandeur connaît le mot de passe en clair — seule la possession du hash NTLM est requise. Outils : crackmapexec, impacket-psexec, mimikatz.

</details>

---

**Question 9 — Mobile Pentest**

Quel outil permet l'instrumentation dynamique d'une application Android (hooking de fonctions Java/Native, modification de valeurs en mémoire) ?

A. apktool  
B. jadx  
C. Frida  
D. MobSF  

<details>
<summary>Réponse et explication</summary>

**C — Frida.** Frida est un framework d'instrumentation dynamique. Il permet de hooker des fonctions, modifier le flux d'exécution, contourner le SSL Pinning ou le root detection sur Android et iOS.

</details>

---

**Question 10 — Persistence**

Quel mécanisme de persistence Windows consiste à modifier un exécutable système lancé au démarrage (comme `sethc.exe`, sticky keys) ?

A. Registry Run Keys — **[T1547.001]**  
B. Scheduled Task — **[T1053.005]**  
C. Accessibility Features — **[T1546.008]**  
D. Windows Service — **[T1543.003]**  

<details>
<summary>Réponse et explication</summary>

**C — Accessibility Features — [T1546.008].** Cette technique remplace un binaire d'accessibilité (sethc.exe, utilman.exe, osk.exe) par un shell (cmd.exe). Avant connexion, la pression répétée de Shift lance le shell avec les privilèges SYSTEM.

</details>

---

**Question 11 — Defense Evasion**

Quelle technique consiste à patcher la mémoire du processus PowerShell pour désactiver l'Antimalware Scan Interface (AMSI) ?

A. Process Injection — **[T1055]**  
B. Disable or Modify Tools — **[T1562.001]**  
C. Obfuscated Files — **[T1027]**  
D. Signed Binary Proxy Execution — **[T1218]**  

<details>
<summary>Réponse et explication</summary>

**B — Disable or Modify Tools — [T1562.001].** AMSI est une interface Windows qui permet à l'antivirus de scanner le contenu des scripts avant exécution. Le patching mémoire d'AMSI (`AmsiScanBuffer`) désactive cette protection sans toucher au processus antivirus.

</details>

---

**Question 12 — C2**

Quel protocole de C2 (Command & Control) est généralement le plus discret pour sortir d'un réseau d'entreprise, car le trafic est chiffré et ressemble à du trafic web légitime ?

A. DNS — **[T1071.004]**  
B. ICMP — **[T1095]**  
C. HTTPS (TLS) — **[T1071.001]**  
D. SMB — **[T1090.001]**  

<details>
<summary>Réponse et explication</summary>

**C — HTTPS (TLS) — [T1071.001].** Le trafic HTTPS est omniprésent dans les réseaux d'entreprise (navigation web, API REST, mises à jour). Un C2 HTTPS bien configuré (JA3 réaliste, certificat valide, user-agent légitime) est difficile à distinguer du trafic normal sans inspection TLS.

</details>

---

**Question 13 — NIS2**

Quel article de la directive NIS2 impose aux entités essentielles de mettre en œuvre des mesures de gestion des risques en matière de cybersécurité ?

A. Article 10  
B. Article 21  
C. Article 30  
D. Article 45  

<details>
<summary>Réponse et explication</summary>

**B — Article 21.** L'article 21 de NIS2 (2022/2555) détaille les mesures de gestion des risques que les entités essentielles et importantes doivent mettre en place : politique d'analyse des risques, gestion des incidents, continuité d'activité, sécurité de la chaîne d'approvisionnement, etc.

</details>

---

**Question 14 — Heat Map ATT&CK**

Dans une heat map ATT&CK de pentest Red Team, quelle couleur est conventionnellement utilisée pour marquer une technique qui a été exploitée avec succès (accès obtenu, objectif atteint) ?

A. Jaune `#fee003`  
B. Gris `#c1c1c1`  
C. Vert `#03c03c`  
D. Rouge `#e60d0d`  

<details>
<summary>Réponse et explication</summary>

**D — Rouge `#e60d0d`.** La convention standard : Rouge = exploitée avec succès, Orange = tentée/partielle, Jaune = détectée par le SOC, Vert = mitigation efficace, Gris = non testée.

</details>

---

**Question 15 — Gap Analysis**

Qu'est-ce que la Gap Analysis dans le contexte d'un pentest Red Team ?

A. L'analyse des vulnérabilités zero-day découvertes  
B. L'identification des techniques ATT&CK non couvertes et l'évaluation du risque résiduel  
C. Le calcul du temps nécessaire pour corriger les vulnérabilités  
D. La comparaison des performances entre plusieurs pentesters  

<details>
<summary>Réponse et explication</summary>

**B — L'identification des techniques ATT&CK non couvertes et l'évaluation du risque résiduel.** La Gap Analysis compare les techniques testées pendant le pentest à l'ensemble du référentiel ATT&CK pour identifier les angles morts et évaluer le risque résiduel associé.

</details>

---

**Question 16 — DeTT&CT**

À quoi sert l'outil DeTT&CT ?

A. Scanner les vulnérabilités web automatiquement  
B. Mapper les capacités de détection SOC sur le référentiel ATT&CK  
C. Automatiser les tests de phishing  
D. Générer des certificats ADCS malveillants  

<details>
<summary>Réponse et explication</summary>

**B — Mapper les capacités de détection SOC sur le référentiel ATT&CK.** DeTT&CT (Detection Tactics, Techniques & Context) est un framework qui permet aux équipes Blue Team de documenter leurs capacités de détection et d'identifier leurs angles morts par rapport au référentiel ATT&CK.

</details>

---

**Question 17 — Restitution orale**

Lors d'une restitution de pentest devant un COMEX, quel pourcentage du temps doit être consacré aux détails techniques (commandes, scripts, protocoles) ?

A. 80% — Le COMEX doit tout comprendre  
B. 50% — Moitié technique, moitié business  
C. 10% — Le minimum pour prouver la crédibilité  
D. 0% — Aucun détail technique, que du business  

<details>
<summary>Réponse et explication</summary>

**C — 10% — Le minimum pour prouver la crédibilité.** Le COMEX attend une traduction business des risques. Les détails techniques (outils, commandes) doivent être réduits au strict nécessaire pour démontrer la crédibilité des findings, et réservés aux échanges ultérieurs avec le RSSI/DSI.

</details>

---

**Question 18 — Testing**

Parmi ces certifications, laquelle est spécifiquement reconnue comme la référence pour le pentest offensif (Red Team / exploitation) ?

A. CISSP  
B. OSCP  
C. ISO 27001 Lead Auditor  
D. ITIL  

<details>
<summary>Réponse et explication</summary>

**B — OSCP.** L'Offensive Security Certified Professional (OSCP) est la certification de référence pour le pentest offensif. Elle valide la capacité à exploiter des vulnérabilités en conditions réelles (24h d'examen pratique). Le CISSP est défensif/gouvernance, l'ISO 27001 est audit, ITIL est gestion des services.

</details>

---

**Question 19 — Éthique**

Quel document définit le périmètre autorisé, les techniques interdites et les règles d'arrêt d'urgence lors d'un pentest ?

A. Le rapport de pentest  
B. Les Rules of Engagement (ROE)  
C. La heat map ATT&CK  
D. Le CV du pentester  

<details>
<summary>Réponse et explication</summary>

**B — Les Rules of Engagement (ROE).** Les ROE sont le contrat qui définit le cadre légal et opérationnel du pentest : périmètre autorisé (IP, domaines), techniques interdites (DoS, impact), horaires, contacts d'urgence, procédure d'arrêt (go/no-go).

</details>

---

**Question 20 — Atomic Red Team**

Quel est l'intérêt principal d'Atomic Red Team dans un contexte Purple Team ?

A. Scanner automatiquement les vulnérabilités réseau  
B. Fournir des tests unitaires exécutables pour chaque technique ATT&CK, permettant de valider les capacités de détection  
C. Remplacer le pentester humain par des tests automatisés  
D. Générer des rapports de conformité NIS2 automatiquement  

<details>
<summary>Réponse et explication</summary>

**B — Fournir des tests unitaires exécutables pour chaque technique ATT&CK.** Atomic Red Team (Red Canary) propose des scripts PowerShell/bash exécutables correspondant à chaque technique ATT&CK. La Blue Team les exécute pour vérifier que ses outils de détection (EDR, SIEM) génèrent bien des alertes.

</details>

---

### 2.3 Correction et interprétation du score

```markdown
# CORRECTION — Quiz d'évaluation Module 20

| Question | Réponse | Technique ATT&CK associée |
|----------|---------|---------------------------|
| Q1 | B — Initial Access | TA0001 |
| Q2 | C — crt.sh | T1596 |
| Q3 | C — Credential Access | T1003.003 |
| Q4 | C — SSTI | T1190 |
| Q5 | C — BloodHound | T1087, T1069 |
| Q6 | C — Kerberoasting | T1558.003 |
| Q7 | A — ESC1 | T1649 |
| Q8 | B — Pass-the-Hash | T1550.002 |
| Q9 | C — Frida | N/A (outillage mobile) |
| Q10 | C — Accessibility Features | T1546.008 |
| Q11 | B — Disable or Modify Tools | T1562.001 |
| Q12 | C — HTTPS (TLS) | T1071.001 |
| Q13 | B — Article 21 | NIS2 |
| Q14 | D — Rouge | Heat map |
| Q15 | B — Gap Analysis | M18 |
| Q16 | B — DeTT&CT | Détection |
| Q17 | C — 10% | Restitution M19 |
| Q18 | B — OSCP | Certification |
| Q19 | B — ROE | Éthique |
| Q20 | B — Atomic Red Team | Purple Team |

## Interprétation du score

| Score | Niveau | Recommandation |
|-------|--------|----------------|
| 18-20 | **Excellent** | Maîtrise complète des concepts. Prêt pour la certification OSCP/CRTP. |
| 15-17 | **Très bon** | Solides acquis. Revoir les points faibles identifiés. |
| 10-14 | **Bon** | Base correcte. Approfondir les modules où le score est le plus faible. |
| 5-9 | **Intermédiaire** | Revoir les fondamentaux (J1-J2). Entraînement supplémentaire recommandé. |
| 0-4 | **Débutant** | Reprendre la formation depuis le début. Ne pas se décourager. |
```

### 2.4 Grille d'auto-évaluation complémentaire

```markdown
# AUTO-ÉVALUATION — Compétences par domaine

Pour chaque compétence, s'auto-évaluer de 1 (débutant) à 5 (expert) :

### MÉTHODOLOGIE
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| Comprendre le framework MITRE ATT&CK (tactiques, techniques) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Construire une kill chain Red Team | ☐ | ☐ | ☐ | ☐ | ☐ |
| Lire et appliquer des Rules of Engagement (ROE) | ☐ | ☐ | ☐ | ☐ | ☐ |

### RECONNAISSANCE
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| OSINT (LinkedIn, crt.sh, Shodan, theHarvester) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Scan réseau et services (nmap, masscan) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Scan de vulnérabilités web (nuclei, Burp Suite) | ☐ | ☐ | ☐ | ☐ | ☐ |

### WEB PENTEST (T1190)
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| SQL Injection (SQLi) et extraction de données | ☐ | ☐ | ☐ | ☐ | ☐ |
| Cross-Site Scripting (XSS) | ☐ | ☐ | ☐ | ☐ | ☐ |
| SSTI et RCE | ☐ | ☐ | ☐ | ☐ | ☐ |
| Contournement de WAF | ☐ | ☐ | ☐ | ☐ | ☐ |

### ACTIVE DIRECTORY ET POST-EXPLOITATION
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| Énumération AD (BloodHound, ADExplorer) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Kerberoasting (T1558.003) | ☐ | ☐ | ☐ | ☐ | ☐ |
| AS-REP Roasting (T1558.004) | ☐ | ☐ | ☐ | ☐ | ☐ |
| ADCS ESC1-ESC13 (T1649) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Delegations et ACL abuse | ☐ | ☐ | ☐ | ☐ | ☐ |

### LATERAL MOVEMENT
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| Pass-the-Hash (T1550.002) | ☐ | ☐ | ☐ | ☐ | ☐ |
| WMI Lateral Movement (T1047) | ☐ | ☐ | ☐ | ☐ | ☐ |
| PsExec / SMBExec (T1569.002) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Pivoting (proxychains, chisel, ligolo) | ☐ | ☐ | ☐ | ☐ | ☐ |

### DEFENSE EVASION
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| AMSI bypass (T1562.001) | ☐ | ☐ | ☐ | ☐ | ☐ |
| ETW patching (T1562.006) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Process Injection (T1055) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Obfuscation (T1027) | ☐ | ☐ | ☐ | ☐ | ☐ |

### MOBILE PENTEST
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| Reverse engineering APK (jadx, apktool) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Interception TLS (Burp, mitmproxy) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Hooking dynamique (Frida) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Repackaging et signature d'APK | ☐ | ☐ | ☐ | ☐ | ☐ |

### C2 & EXFILTRATION
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| Déploiement et gestion C2 (Cobalt Strike / Mythic / Sliver) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Exfiltration furtive (T1041) | ☐ | ☐ | ☐ | ☐ | ☐ |
| Protocoles C2 alternatifs (DNS, SMB, ICMP) | ☐ | ☐ | ☐ | ☐ | ☐ |

### REPORTING
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| Rédiger un rapport de pentest complet | ☐ | ☐ | ☐ | ☐ | ☐ |
| Construire une heat map ATT&CK Navigator | ☐ | ☐ | ☐ | ☐ | ☐ |
| Réaliser une gap analysis | ☐ | ☐ | ☐ | ☐ | ☐ |
| Présenter une restitution orale devant COMEX | ☐ | ☐ | ☐ | ☐ | ☐ |

### CONFORMITÉ
| Compétence | 1 | 2 | 3 | 4 | 5 |
|-----------|---|---|---|---|---|
| Comprendre NIS2 et son lien avec ATT&CK | ☐ | ☐ | ☐ | ☐ | ☐ |
| Argumenter ROI de la remédiation | ☐ | ☐ | ☐ | ☐ | ☐ |
| Conseiller sur la conformité réglementaire | ☐ | ☐ | ☐ | ☐ | ☐ |

### TOTAL : ___ / 90 (18 compétences × 5 max)
```

---

## 3. Checklist des compétences acquises

### 3.1 Web Pentest — Injecter, Contourner, Pivoter

```
┌──────────────────────────────────────────────────────────────────┐
│              COMPÉTENCES WEB — CE QUE VOUS SAVEZ FAIRE           │
│                                                                  │
│   ✅ Identifier une surface d'attaque web (sous-domaines,        │
│      technologies, versions)                                     │
│   ✅ Tester les injections SQL (error-based, UNION, blind,       │
│      time-based, out-of-band) — T1190                            │
│   ✅ Exploiter les XSS (reflected, stored, DOM)                  │
│   ✅ Détecter et exploiter un SSTI (Jinja2, Twig, FreeMarker)    │
│   ✅ Identifier et exploiter un LFI/RFI                          │
│   ✅ Contourner un WAF basique (encodage, commentaires,          │
│      fragmentation)                                              │
│   ✅ Pivoter depuis une application web vers le réseau interne   │
│   ✅ Utiliser Burp Suite Pro pour l'automatisation des tests     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Active Directory — Énumérer, Élever, Persister

```
┌──────────────────────────────────────────────────────────────────┐
│           COMPÉTENCES AD — CE QUE VOUS SAVEZ FAIRE               │
│                                                                  │
│   ✅ Énumérer l'Active Directory (utilisateurs, groupes,         │
│      ordinateurs, ACLs, SPNs) — T1087, T1069                     │
│   ✅ Utiliser BloodHound pour cartographier les chemins          │
│      d'attaque (SharpHound + Neo4j)                              │
│   ✅ Exploiter le Kerberoasting (T1558.003) et cracker           │
│      les tickets avec hashcat                                    │
│   ✅ Exploiter AS-REP Roasting (T1558.004)                       │
│   ✅ Attaquer ADCS (ESC1, ESC2, ESC3, ESC4, ESC6, ESC8)         │
│      pour obtenir des certificats privilégiés — T1649           │
│   ✅ Abuser des délégations Kerberos (Unconstrained,             │
│      Constrained, RBCD)                                          │
│   ✅ Réaliser du lateral movement : Pass-the-Hash (T1550.002),   │
│      WMI (T1047), PsExec (T1569.002), WinRM                      │
│   ✅ Dumper les hash : LSASS (T1003.001), SAM (T1003.002),       │
│      NTDS.dit (T1003.003)                                        │
│   ✅ Contourner AMSI (T1562.001) et ETW (T1562.006)              │
│   ✅ Mettre en place de la persistence : Scheduled Task          │
│      (T1053.005), Registry Run (T1547.001), WMI                  │
│   ✅ Pivoter avec C2 : SMB Beacon (T1090.001), proxies, tunnels  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Mobile — Analyser, Intercepter, Patcher

```
┌──────────────────────────────────────────────────────────────────┐
│             COMPÉTENCES MOBILE — CE QUE VOUS SAVEZ FAIRE         │
│                                                                  │
│   ✅ Décompiler et analyser une APK (jadx, apktool)              │
│   ✅ Identifier des secrets hardcodés (clés API, tokens,         │
│      certificats, URLs internes)                                 │
│   ✅ Intercepter le trafic HTTPS (Burp Suite + proxy WiFi)       │
│   ✅ Contourner le SSL Pinning avec Frida                        │
│   ✅ Contourner la détection de root/émulateur avec Frida        │
│   ✅ Hooker des fonctions Java et Native (Frida scripts)         │
│   ✅ Patcher une APK (modification smali, repackaging,           │
│      signature, alignement)                                      │
│   ✅ Analyser les stockages locaux (SharedPreferences, SQLite,   │
│      Realm, fichiers internes)                                   │
│   ✅ Exploiter les WebViews vulnérables (JavaScript interfaces)  │
│   ✅ Comprendre l'architecture de sécurité Android (SEAndroid,    │
│      permissions, sandboxing)                                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.4 Reporting — Rédiger, Présenter, Convaincre

```
┌──────────────────────────────────────────────────────────────────┐
│           COMPÉTENCES REPORTING — CE QUE VOUS SAVEZ FAIRE        │
│                                                                  │
│   ✅ Rédiger un rapport de pentest Red Team complet              │
│      (Executive Summary + Findings + Recommandations)            │
│   ✅ Mapper chaque finding sur une technique MITRE ATT&CK        │
│   ✅ Construire et annoter une heat map ATT&CK Navigator         │
│   ✅ Réaliser une Gap Analysis (techniques non couvertes,        │
│      risque résiduel, priorisation)                              │
│   ✅ Mapper les exigences NIS2 sur les techniques ATT&CK         │
│   ✅ Chiffrer le risque business (méthode FAIR)                  │
│   ✅ Prioriser les recommandations (P0/P1/P2, matrice de risque) │
│   ✅ Présenter une restitution orale de 30 minutes devant COMEX  │
│   ✅ Vulgariser les concepts techniques pour un public business  │
│   ✅ Gérer les questions difficiles et les objections            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Poursuite de la montée en compétence

### 4.1 Certifications — Le parcours recommandé

```
┌──────────────────────────────────────────────────────────────────┐
│              PARCOURS DE CERTIFICATION RED TEAM                  │
│                                                                  │
│   NIVEAU 1 — FONDAMENTAUX                                        │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ eJPT (INE Security)      │ Gratuit, très pédagogique │      │
│   │ PJPT (TCM Security)      │ Pratique, AD, rapport     │      │
│   │ PNPT (TCM Security)      │ Réaliste, externe+interne │      │
│   └──────────────────────────────────────────────────────┘      │
│                              ▼                                    │
│   NIVEAU 2 — PENTEST PROFESSIONNEL                               │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ eCPPTv3 (INE Security)    │ Très complet, AD, pivot   │      │
│   │ OSCP (OffSec)             │ LA référence, reconnue    │      │
│   │ CRTP (Altered Security)   │ Spécialisé AD, Kerberos   │      │
│   └──────────────────────────────────────────────────────┘      │
│                              ▼                                    │
│   NIVEAU 3 — RED TEAM AVANCÉ                                     │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ CRTE (Altered Security)   │ AD avancé, cross-forest   │      │
│   │ OSEP (OffSec)             │ Evasion EDR, C2, furtif   │      │
│   │ eCPTX (INE Security)      │ Le plus complet Red Team  │      │
│   │ OSED (OffSec)             │ Exploit development       │      │
│   │ CRTO II (Zero-Point)      │ Cobalt Strike avancé      │      │
│   └──────────────────────────────────────────────────────┘      │
│                              ▼                                    │
│   NIVEAU 4 — EXPERT / RECHERCHE                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │ OSEE (OffSec)             │ Exploit dev avancé        │      │
│   │ SLAE/SLRE (PentesterAcad.)│ Shellcode x86/x64         │      │
│   │ Publications, CVEs,       │ Recherche en vulnérabilité│      │
│   │ conférences               │ SSTIC, BlackHat, DEFCON   │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Tableau comparatif des certifications :**

| Certification | Focus | Difficulté | Durée examen | Prix indicatif | Prérequis |
|---------------|-------|------------|-------------|----------------|-----------|
| **eJPT** | Pentest junior | ★★☆☆☆ | 2 jours | Gratuit (INE) | Aucun |
| **PNPT** | Pentest réaliste | ★★★☆☆ | 5 jours | ~400 € | OS, réseau |
| **OSCP** | Exploitation | ★★★★☆ | 24h | ~1 600 € | Linux, scripting |
| **eCPPTv3** | Pentest complet | ★★★★☆ | 7 jours | ~400 € | Intermédiaire |
| **CRTP** | AD Attack | ★★★★☆ | 24h | ~250 € | AD basics |
| **OSEP** | Evasion EDR | ★★★★★ | 48h | ~1 600 € | OSCP idéalement |
| **CRTE** | AD Expert | ★★★★★ | 24h | ~250 € | CRTP |
| **eCPTX** | Red Team complet | ★★★★★ | 7 jours | ~800 € | eCPPTv3 ou OSCP |

### 4.2 Plateformes d'entraînement

```
┌──────────────────────────────────────────────────────────────────┐
│                PLATEFORMES D'ENTRAÎNEMENT                        │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │                                                      │      │
│   │  GRATUITES / FREEMIUM                                │      │
│   │                                                      │      │
│   │  TryHackMe        │ Parcours guidés, rooms thématiques│      │
│   │  (tryhackme.com)  │ Idéal débutant → intermédiaire   │      │
│   │                                                      │      │
│   │  HackTheBox       │ Machines + Challenges + Pro Labs │      │
│   │  (hackthebox.com) │ Intermédiaire → Expert           │      │
│   │                                                      │      │
│   │  PentesterLab     │ Exercices web, progression       │      │
│   │  (pentesterlab.com)│ Focus web, code review          │      │
│   │                                                      │      │
│   │  VulnHub          │ VM vulnérables téléchargeables   │      │
│   │  (vulnhub.com)    │ Variété, gratuit                 │      │
│   │                                                      │      │
│   │  Root-Me          │ Challenges multi-domaines        │      │
│   │  (root-me.org)    │ Francophone, tous niveaux        │      │
│   │                                                      │      │
│   │  PwnTillDawn      │ Scénarios réalistes, gratuit     │      │
│   │  (wizer-ctf.com)  │ Active Directory inclus          │      │
│   │                                                      │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │                                                      │      │
│   │  PAYANTES (INVESTISSEMENT RECOMMANDÉ)                │      │
│   │                                                      │      │
│   │  HTB Pro Labs      │ Labs AD complets, multi-machines │      │
│   │  (Dante, RastaLabs)│ Simulation entreprise réelle    │      │
│   │                    │ ~20 €/mois                      │      │
│   │                                                      │      │
│   │  OffSec Proving    │ Machines style OSCP, progression │      │
│   │  Grounds           │ ~20 €/mois                      │      │
│   │                                                      │      │
│   │  PentesterAcademy  │ Formation + labs, focus AD      │      │
│   │  (AttackDefense)   │ ~40 €/mois                      │      │
│   │                                                      │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 4.3 Labs complémentaires à déployer

```bash
# ─── GOAD (Game Of Active Directory) ─────────────────────────────
# Environnement AD complet avec multiples vulnérabilités
# https://github.com/Orange-Cyberdefense/GOAD
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
vagrant up  # Déploie DC, SRV, utilisateurs, ACLs, ADCS

# ─── DetectionLab ─────────────────────────────────────────────────
# Lab Blue Team avec Splunk, Windows, AD
# https://github.com/clong/DetectionLab
git clone https://github.com/clong/DetectionLab.git
cd DetectionLab
vagrant up  # Déploie DC, Windows 10, Splunk, etc.

# ─── BadBlood ─────────────────────────────────────────────────────
# Peuple un AD avec des relations complexes et vulnérabilités
# https://github.com/davidprowe/BadBlood
Invoke-BadBlood  # Exécuter sur un DC Windows

# ─── Atomic Red Team (déjà présenté en M18) ──────────────────────
# Tests unitaires ATT&CK pour valider la détection
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Invoke-AtomicRedTeam -UpdateAtomics

# ─── Caldera ──────────────────────────────────────────────────────
# Framework d'émulation d'adversaire automatisé (MITRE)
git clone https://github.com/mitre/caldera.git
cd caldera
pip install -r requirements.txt
python3 caldera.py
# Interface web : http://localhost:8888
# Credentials : admin / admin → CHANGE IMMEDIATELY
```

### 4.4 Veille technique — Rester à jour

```markdown
## Comptes Twitter/X à suivre

| Compte | Spécialité | Pourquoi |
|--------|-----------|----------|
| @thegrugq | OpSec, contre-espionnage | Culture générale cybersécurité |
| @harmj0y | Active Directory, BloodHound | Référence AD et Kerberos |
| @tiraniddo | Windows internals, exploits | Deep dive Windows |
| @gentilkiwi | Mimikatz, Kerberos, Windows | Auteur de Mimikatz |
| @0xdf_ | Write-ups HTB, walkthrough | Apprentissage par l'exemple |
| @domchell | Mobile, Android security | Référence mobile pentest |
| @MalwareTechBlog | Malware, reverse, botnets | Analyse de malware |
| @cnotin | ADCS, PKI, Active Directory | Expert ADCS français |
| @_dirkjan | AD, Azure AD, ROADtools | Outillage AD écosystème |
| @HackAndDo | Red Team, C2, opérations | Contenu francophone |

## Blogs et sites

| Blog | URL | Spécialité |
|------|-----|------------|
| SpecterOps | https://posts.specterops.io/ | AD, Kerberos, BloodHound, attaques |
| S3cur3Th1sSh1t | https://s3cur3th1ssh1t.github.io/ | Red Team, C#, tooling |
| TrustedSec | https://trustedsec.com/blog | OSCP, Red Team, tool dev |
| MDSec | https://www.mdsec.co.uk/blog/ | C2, evasion, mobile |
| CyberArk | https://www.cyberark.com/resources/threat-research-blog | AD, Kerberos, EDR evasion |
| harmj0y | http://blog.harmj0y.net/ | Active Directory, PowerView |
| PentestLab | https://pentestlab.blog/ | Persistence, lateral, tooling |

## Conférences (présentiel + YouTube)

| Conférence | Lieu | Période | Contenu |
|------------|------|---------|---------|
| **LeHack** (ex-HZV) | Paris | Juin/juillet | Généraliste hacking |
| **SSTIC** | Rennes | Juin | Technique, recherche |
| **BSides** | Paris, Lyon, etc. | Variable | Communautaire |
| **DEFCON** | Las Vegas | Août | THE conférence mondiale |
| **BlackHat** | Las Vegas | Août | Recherche, industry |
| **Hack.lu** | Luxembourg | Octobre | Européen, technique |
| **Insomni'hack** | Genève | Mars | CTF, conférences |
| **Botconf** | Europe | Variable | Malware, botnets |

## Newsletters

| Newsletter | Description |
|------------|-------------|
| **TL;DR Sec** | Veille cybersécurité hebdomadaire, concise et actionnable |
| **Unsupervised Learning** | Veille tech + IA + cybersécurité par Daniel Miessler |
| **Risky Biz** | Podcast + newsletter, actualité cyber mondiale |
| **SANS NewsBites** | Résumé bimensuel des actualités cyber |
| **This Week in 4n6** | Veille forensics et DFIR |

## Discord / Slack communautaires

| Communauté | Description |
|------------|-------------|
| **HackTheBox** | Discord officiel, entraide, write-ups |
| **TryHackMe** | Discord officiel, très actif débutants |
| **The Many Hats Club** | Communauté hacking généraliste |
| **BloodHound Gang** | Slack spécialisé BloodHound et AD |
| **InfoSec Community Fr** | Discord francophone, petites annonces, entraide |
| **OffSec** | Discord officiel OffSec (OSCP, OSEP, etc.) |
```

---

## 5. Ressources pour continuer

### 5.1 Livres recommandés

```
┌──────────────────────────────────────────────────────────────────┐
│                    BIBLIOTHÈQUE DU RED TEAMER                     │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  NIVEAU DÉBUTANT / INTERMÉDIAIRE                     │      │
│   │                                                      │      │
│   │  "The Web Application Hacker's Handbook"             │      │
│   │  D. Stuttard, M. Pinto — La bible du web pentest     │      │
│   │                                                      │      │
│   │  "Penetration Testing: A Hands-On Introduction       │      │
│   │   to Hacking" — Georgia Weidman                      │      │
│   │  Introduction complète au pentest                    │      │
│   │                                                      │      │
│   │  "Metasploit: The Penetration Tester's Guide"        │      │
│   │  D. Kennedy et al. — Utilisation avancée de MSF      │      │
│   │                                                      │      │
│   │  "Violent Python" — TJ O'Connor                      │      │
│   │  Python appliqué à la sécurité offensive             │      │
│   │                                                      │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  NIVEAU AVANCÉ / EXPERT                               │      │
│   │                                                      │      │
│   │  "Windows Internals" (Part 1 & 2)                    │      │
│   │  M. Russinovich et al. — Le fonctionnement profond   │      │
│   │  de Windows. Incontournable pour l'évasion EDR.      │      │
│   │                                                      │      │
│   │  "The Art of Memory Forensics"                       │      │
│   │  M. Hale Ligh et al. — Analyse mémoire, Volatility   │      │
│   │  Utile pour comprendre ce que la Blue Team voit.     │      │
│   │                                                      │      │
│   │  "Practical Malware Analysis"                        │      │
│   │  M. Sikorski, A. Honig — Reverse engineering malware │      │
│   │                                                      │      │
│   │  "Attacking Network Protocols" — James Forshaw       │      │
│   │  Analyse et exploitation de protocoles réseau        │      │
│   │                                                      │      │
│   │  "The Hacker Playbook 3" — Peter Kim                 │      │
│   │  Scénarios d'attaque réalistes, Red Team             │      │
│   │                                                      │      │
│   │  "Operator Handbook: Red Team" — Joshua Picolet      │      │
│   │  Manuel de référence compact pour opérations         │      │
│   │                                                      │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  CULTURE CYBER / GÉOPOLITIQUE                         │      │
│   │                                                      │      │
│   │  "Sandworm" — Andy Greenberg                         │      │
│   │  Histoire de l'unité de cyber-espionnage russe       │      │
│   │                                                      │      │
│   │  "This Is How They Tell Me the World Ends"           │      │
│   │  Nicole Perlroth — Marché des zero-days              │      │
│   │                                                      │      │
│   │  "Countdown to Zero Day" — Kim Zetter                │      │
│   │  Histoire de Stuxnet, la première cyber-arme         │      │
│   │                                                      │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Chaînes YouTube

| Chaîne | URL | Contenu |
|--------|-----|---------|
| **IppSec** | youtube.com/c/ippsec | Walkthroughs HackTheBox, méthodologie exceptionnelle |
| **John Hammond** | youtube.com/c/JohnHammond010 | CTF, malware analysis, tutos |
| **The Cyber Mentor** | youtube.com/c/TheCyberMentor | Cours complets pentest, AD, certifications |
| **NahamSec** | youtube.com/c/Nahamsec | Bug bounty, reconnaissance web |
| **STÖK** | youtube.com/c/STOKfredrik | Bug bounty, mindset hacking |
| **LiveOverflow** | youtube.com/c/LiveOverflow | Reverse, binaire, exploitation, recherche |
| **Hackersploit** | youtube.com/c/Hackersploit | Pentest, Red Team, Blue Team |
| **13Cubed** | youtube.com/c/13cubed | Forensics, DFIR, mémoire |
| **MalwareTech** | youtube.com/@MalwareTechBlog | Reverse engineering, malware |
| **Altered Security** | youtube.com/@AlteredSecurity | AD attacks, CRTP, CRTE |
| **Processus** | youtube.com/@Processus | Chaîne francophone, Red Team, AD, tooling |
| **x0r** | youtube.com/@x0rfr | Chaîne francophone, hacking, CTF |

---

## 6. Évaluation de la formation

### 6.1 Questionnaire de satisfaction

```markdown
# QUESTIONNAIRE DE SATISFACTION — Formation SDV M2 Red Team

Merci de prendre 5 minutes pour évaluer cette formation.
Vos réponses sont anonymes et nous aident à nous améliorer.

### 1. SATISFACTION GLOBALE
Sur une échelle de 1 (très insatisfait) à 5 (très satisfait) :

| Question | 1 | 2 | 3 | 4 | 5 |
|----------|---|---|---|---|---|
| Satisfaction globale de la formation | ☐ | ☐ | ☐ | ☐ | ☐ |
| Adéquation avec vos attentes initiales | ☐ | ☐ | ☐ | ☐ | ☐ |
| Recommanderiez-vous cette formation ? | ☐ | ☐ | ☐ | ☐ | ☐ |

### 2. CONTENU PÉDAGOGIQUE

| Question | 1 | 2 | 3 | 4 | 5 |
|----------|---|---|---|---|---|
| Pertinence du programme | ☐ | ☐ | ☐ | ☐ | ☐ |
| Équilibre théorie / pratique | ☐ | ☐ | ☐ | ☐ | ☐ |
| Qualité des supports de cours | ☐ | ☐ | ☐ | ☐ | ☐ |
| Qualité des TP et exercices | ☐ | ☐ | ☐ | ☐ | ☐ |
| Progression pédagogique sur 4 jours | ☐ | ☐ | ☐ | ☐ | ☐ |

### 3. FORMATEUR

| Question | 1 | 2 | 3 | 4 | 5 |
|----------|---|---|---|---|---|
| Maîtrise technique du sujet | ☐ | ☐ | ☐ | ☐ | ☐ |
| Clarté des explications | ☐ | ☐ | ☐ | ☐ | ☐ |
| Disponibilité pour les questions | ☐ | ☐ | ☐ | ☐ | ☐ |
| Capacité à vulgariser | ☐ | ☐ | ☐ | ☐ | ☐ |
| Gestion du temps et du rythme | ☐ | ☐ | ☐ | ☐ | ☐ |

### 4. LOGISTIQUE

| Question | 1 | 2 | 3 | 4 | 5 |
|----------|---|---|---|---|---|
| Qualité de la salle et du matériel | ☐ | ☐ | ☐ | ☐ | ☐ |
| Qualité de l'environnement de lab | ☐ | ☐ | ☐ | ☐ | ☐ |
| Restauration et pauses | ☐ | ☐ | ☐ | ☐ | ☐ |
| Communication pré-formation | ☐ | ☐ | ☐ | ☐ | ☐ |

### 5. MODULES — LESQUELS APPROFONDIR ?

Quels modules mériteraient plus de temps ? (classer par priorité)

☐ M1-M3 — Fondamentaux et MITRE ATT&CK
☐ M4-M5 — Reconnaissance et Web Pentest
☐ M6-M9 — Active Directory et Post-Exploitation
☐ M10-M11 — C2 et Exfiltration
☐ M12-M14 — Defense Evasion
☐ M15-M16 — Mobile Pentest
☐ M17 — Rédaction de rapport
☐ M18 — Heat Map et Gap Analysis
☐ M19 — Restitution orale
☐ Autre (préciser) : _______________

### 6. COMMENTAIRE LIBRE

Qu'avez-vous le plus apprécié ?
_______________________________________________________________
_______________________________________________________________

Qu'est-ce qui pourrait être amélioré ?
_______________________________________________________________
_______________________________________________________________

Quel module ou sujet souhaiteriez-vous voir ajouté ?
_______________________________________________________________
_______________________________________________________________

Autre commentaire :
_______________________________________________________________
_______________________________________________________________
```

### 6.2 Synthèse pour le formateur

```markdown
# SYNTHÈSE D'ÉVALUATION — Template formateur

## Statistiques
- Nombre de répondants : ___ / ___ apprenants
- Note moyenne satisfaction : ___ / 5
- Taux de recommandation : ___ %

## Points forts (citations)
1. "..." — Apprenant
2. "..." — Apprenant
3. "..." — Apprenant

## Axes d'amélioration (citations)
1. "..." — Apprenant
2. "..." — Apprenant
3. "..." — Apprenant

## Modules à approfondir (top 3)
1. ___ (___ votes)
2. ___ (___ votes)
3. ___ (___ votes)

## Actions pour la prochaine session
- [ ] Action 1
- [ ] Action 2
- [ ] Action 3
```

---

## 7. Mot de la fin

### 7.1 Éthique et responsabilité

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│               AVEC DE GRANDS POUVOIRS VIENNENT                   │
│                  DE GRANDES RESPONSABILITÉS                       │
│                                                                  │
│   ┌────────────────────────────────────────────────────┐        │
│   │                                                    │        │
│   │   Les compétences que vous avez acquises pendant   │        │
│   │   ces 4 jours sont puissantes. Vous savez :        │        │
│   │                                                    │        │
│   │   • Pénétrer des systèmes d'information            │        │
│   │   • Élever vos privilèges jusqu'à Domain Admin     │        │
│   │   • Voler des mots de passe et des données         │        │
│   │   • Contourner les défenses modernes (EDR, AV)     │        │
│   │   • Rester furtif et non détecté                   │        │
│   │                                                    │        │
│   │   Ces compétences doivent être utilisées :          │        │
│   │                                                    │        │
│   │   ✅ Dans un cadre LÉGAL et CONTRACTUEL             │        │
│   │   ✅ Avec l'AUTORISATION ÉCRITE du client           │        │
│   │   ✅ Dans le RESPECT des ROE (Rules of Engagement)  │        │
│   │   ✅ Pour PROTÉGER, pas pour nuire                  │        │
│   │   ✅ Avec INTÉGRITÉ et PROFESSIONNALISME            │        │
│   │                                                    │        │
│   │   L'utilisation non autorisée de ces techniques    │        │
│   │   est un DÉLIT PÉNAL, passible de :                │        │
│   │                                                    │        │
│   │   • 5 ans d'emprisonnement (Art. 323-1 CP)         │        │
│   │   • 150 000 € d'amende (Art. 323-1 CP)             │        │
│   │   • Circonstances aggravantes si bande organisée   │        │
│   │     ou contre OIV (Art. 323-2 à 323-7 CP)          │        │
│   │                                                    │        │
│   └────────────────────────────────────────────────────┘        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 7.2 Le cadre légal en France

```markdown
## Rappel du cadre juridique applicable

### Code Pénal — Atteintes aux STAD (Systèmes de Traitement Automatisé de Données)

| Article | Infraction | Peine |
|---------|-----------|-------|
| 323-1 CP | Accès frauduleux à un STAD | 2 ans, 60 000 € |
| 323-2 CP | Entrave au fonctionnement d'un STAD | 5 ans, 150 000 € |
| 323-3 CP | Atteinte à l'intégrité des données | 5 ans, 150 000 € |
| 323-3-1 CP | Importation/détention d'outils de piratage sans motif légitime | 2 ans, 30 000 € |

### LPM (Loi de Programmation Militaire 2013-1168)

- Les **OIV** (Opérateurs d'Importance Vitale) ont des obligations
  renforcées de cybersécurité.
- L'ANSSI peut auditer et sanctionner les OIV.
- Obligation de déclarer les incidents significatifs.

### NIS2 (Directive 2022/2555, transposée en droit français)

- Renforce les obligations des **entités essentielles** (énergie,
  transport, santé, etc.) et **entités importantes**.
- Sanctions administratives pouvant atteindre **10 M€ ou 2% du
  chiffre d'affaires** mondial annuel.
- Responsabilité personnelle des dirigeants possible.

### RGPD (Règlement Général sur la Protection des Données)

- Sanctions jusqu'à **4% du chiffre d'affaires** annuel mondial
  ou **20 M€** (le plus élevé des deux).
- Obligation de notification des violations de données sous 72h.
- Applicable à toute organisation traitant des données de citoyens
  européens.

### Rôle du pentester dans ce cadre

- Le pentester doit avoir une **autorisation écrite** détaillant
  le périmètre (IP, domaines, horaires, techniques autorisées).
- Les **ROE** (Rules of Engagement) engagent contractuellement
  les deux parties.
- En cas de dommage involontaire, l'assurance responsabilité civile
  professionnelle du cabinet couvre le préjudice.
- **Ne jamais tester sans autorisation**, même « pour voir ».
- **Ne jamais outrepasser le périmètre autorisé**, même si c'est
  techniquement possible.
```

### 7.3 Message de clôture

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│                       FÉLICITATIONS                              │
│                                                                  │
│   Vous avez terminé la formation SDV M2 Red Team.                │
│                                                                  │
│   En 4 jours, vous avez parcouru le cycle complet d'une          │
│   opération Red Team :                                           │
│                                                                  │
│   Reconnaissance → Accès Initial → Élévation → Latéralisation   │
│   → Persistance → Exfiltration → Rapport → Restitution          │
│                                                                  │
│   Vous avez manipulé les outils et les techniques utilisés       │
│   par les Red Teamers professionnels.                            │
│                                                                  │
│   Vous savez maintenant :                                        │
│   • Penser comme un attaquant pour mieux défendre                │
│   • Mesurer la sécurité avec le cadre MITRE ATT&CK               │
│   • Communiquer les risques aux décideurs                        │
│   • Agir dans le respect de l'éthique et de la loi              │
│                                                                  │
│   ┌────────────────────────────────────────────────────┐        │
│   │                                                    │        │
│   │   La cybersécurité est un marathon, pas un sprint.  │        │
│   │                                                    │        │
│   │   Continuez à apprendre, à pratiquer, à partager.  │        │
│   │                                                    │        │
│   │   Le chemin est long, mais chaque pas compte.      │        │
│   │                                                    │        │
│   │   Bienvenue dans la communauté Red Team.           │        │
│   │                                                    │        │
│   │   Bonne chance, et bon hack (éthique) !            │        │
│   │                                                    │        │
│   └────────────────────────────────────────────────────┘        │
│                                                                  │
│   ── Le formateur                                                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 7.4 Contacts et suivi

```markdown
## Restons en contact

- **Email formateur** : formateur@exemple.fr
- **Discord de la promo** : [lien d'invitation]
- **LinkedIn** : [profil du formateur]
- **GitHub du cours** : [repo avec les supports]

## Dates à retenir

- **Certification cible** : OSCP / CRTP — À planifier sous 6 mois
- **Prochaine session avancée** : SDV M3 Red Team (automne 2026)
- **Webinaire alumni** : Trimestriel (invitation par email)

## Rappel — Ressources principales

| Ressource | URL |
|-----------|-----|
| MITRE ATT&CK | https://attack.mitre.org/ |
| ATT&CK Navigator | https://mitre-attack.github.io/attack-navigator/ |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team |
| HackTheBox | https://www.hackthebox.com/ |
| TryHackMe | https://tryhackme.com/ |
| DeTT&CT | https://github.com/rabobank-cdc/DeTTECT |
| VECTR | https://github.com/SecurityRiskAdvisors/VECTR |
```

---

> **Fin du Module 20 — Débrief Collectif & Évaluation des Acquis**
>
> *"La formation est terminée, l'apprentissage continue."*
>
> **Tags MITRE** : TA0001 → TA0011 (toutes les tactiques couvertes durant les 4 jours), T1190, T1566, T1078, T1059, T1053, T1558.003, T1558.004, T1649, T1550.002, T1047, T1569.002, T1003.001, T1003.002, T1003.003, T1562.001, T1562.006, T1574.002, T1547.001, T1546.008, T1543.003, T1027, T1055, T1041, T1071.001, T1090.001, T1087, T1069, T1482, T1046, T1135, T1005, T1039, T1114, T1593, T1592, T1595, T1596, T1110.003, T1111

---

## Annexes

### Annexe A — Glossaire des sigles

| Sigle | Signification |
|-------|---------------|
| **AD** | Active Directory |
| **ADCS** | Active Directory Certificate Services |
| **AMSI** | Antimalware Scan Interface |
| **ANSSI** | Agence Nationale de la Sécurité des Systèmes d'Information |
| **ATT&CK** | Adversarial Tactics, Techniques, and Common Knowledge |
| **C2** | Command & Control |
| **COMEX** | Comité Exécutif |
| **CRTP** | Certified Red Team Professional |
| **CRTE** | Certified Red Team Expert |
| **DA** | Domain Admin |
| **DLP** | Data Loss Prevention |
| **EDR** | Endpoint Detection and Response |
| **eJPT** | eLearnSecurity Junior Penetration Tester |
| **ESC** | Escalation (ADCS) |
| **ETW** | Event Tracing for Windows |
| **LPM** | Loi de Programmation Militaire |
| **MFA** | Multi-Factor Authentication |
| **NIS2** | Network and Information Security Directive 2 |
| **NTDS** | NT Directory Services |
| **OIV** | Opérateur d'Importance Vitale |
| **OSCP** | Offensive Security Certified Professional |
| **OSEP** | Offensive Security Experienced Penetration Tester |
| **PNPT** | Practical Network Penetration Tester |
| **RBCD** | Resource-Based Constrained Delegation |
| **RCE** | Remote Code Execution |
| **RGPD** | Règlement Général sur la Protection des Données |
| **ROE** | Rules of Engagement |
| **RSSI** | Responsable de la Sécurité des Systèmes d'Information |
| **SIEM** | Security Information and Event Management |
| **SPN** | Service Principal Name |
| **STAD** | Système de Traitement Automatisé de Données |
| **TGS** | Ticket Granting Service |
| **TGT** | Ticket Granting Ticket |
| **WAF** | Web Application Firewall |
```

### Annexe B — Template de certificat de participation

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║                    CERTIFICAT DE PARTICIPATION                   ║
║                                                                  ║
║               Formation SDV M2 — Red Team Pentest                ║
║                                                                  ║
║   Décerné à : [NOM Prénom]                                       ║
║                                                                  ║
║   Pour avoir suivi avec succès la formation intensive            ║
║   Red Team Pentest d'une durée de 28 heures (4 jours)            ║
║   couvrant les modules M1 à M20.                                 ║
║                                                                  ║
║   Compétences validées :                                         ║
║   • Reconnaissance et OSINT                                     ║
║   • Web Pentest (SQLi, XSS, SSTI, LFI)                          ║
║   • Active Directory Enumeration & Attacks                      ║
║   • Lateral Movement & Privilege Escalation                      ║
║   • ADCS Exploitation (ESC1-ESC13)                              ║
║   • Defense Evasion (AMSI, ETW)                                 ║
║   • C2 & Exfiltration                                            ║
║   • Mobile Pentest (Android)                                     ║
║   • Rédaction de rapport & Gap Analysis                         ║
║   • Restitution orale devant COMEX                              ║
║   • Conformité NIS2 et cadre légal                               ║
║                                                                  ║
║   Date : [JJ/MM/AAAA]                                            ║
║   Lieu : [Ville]                                                 ║
║                                                                  ║
║   Score au quiz d'évaluation : [XX]/20                           ║
║                                                                  ║
║   _________________________    ________________________________  ║
║   Formateur                     Directeur pédagogique            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```
