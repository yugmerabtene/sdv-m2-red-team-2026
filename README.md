# SDV M2 — Red Team Advanced 2026

Formation pentest avancé — 4 jours (1—4 Juin 2026) — **40 078 lignes de contenu**

## État : ✅ Testé et validé

| Composant | Statut |
|-----------|--------|
| J1 Lab Docker (EcoVault) | ✅ 19/19 vulnérabilités testées |
| J2 Lab Docker (Samba AD) | ✅ Build OK |
| Python / SQL / Markdown | ✅ Syntaxe validée |
| Références externes | ✅ 181 URLs vérifiées |

## Structure

```
├── syllabus.md                     ← Programme complet de la formation
├── J1-environnement-web/           ← Jour 1 : Web (détaillé)
│   ├── m1-mitre-attack.md          ←   M1 : MITRE ATT&CK
│   ├── m2-injections-avancees.md   ←   M2 : Injections (SQLi, NoSQLi, SSTI, etc.)
│   ├── m3-authentification-logique.md ← M3 : Auth & Logique métier
│   ├── m4-exploitation-pivoting.md ←   M4 : Exploitation & Pivoting
│   └── m5-scenario-autonome.md     ←   M5 : Scénario autonome
├── J2-infrastructure-ad/           ← Jour 2 : AD (détaillé)
│   ├── m6-reconnaissance-reseau.md
│   ├── m7-active-directory.md
│   ├── m8-elevation-mouvement-lateral.md
│   ├── m9-attaques-avancees-ad.md
│   └── m10-scenario-ad-autonome.md
├── J3-mobile-transverse/           ← Jour 3 : Mobile (détaillé)
│   ├── m11-intro-pentest-mobile.md
│   ├── m12-reverse-engineering-dynamique.md
│   ├── m13-evasion-persistance-obfuscation.md
│   ├── m14-synthese-ctf-encadre.md
│   └── m15-debrief-ctf-corrections.md
├── J4-synthese-restitution/        ← Jour 4 : Rapport (détaillé)
│   ├── m16-structuration-rapport-pentest.md
│   ├── m17-atelier-redactionnel.md
│   ├── m18-heatmap-attack-gap-analysis.md
│   ├── m19-restitution-orale-simulee.md
│   └── m20-debrief-evaluation-acquis.md
├── lab/                            ← Lab Docker vulnérable
│   ├── docker-compose.yml
│   ├── webapp/app.py               ← Application Flask vulnérable
│   ├── internal/server.py          ← Serveur interne (pivoting)
│   ├── mysql/init.sql              ← Base de données
│   └── setup.sh                    ← Script de démarrage
└── archive/                        ← Ancienne version HTML
```

## Référentiel

Toute la formation est structurée autour de **MITRE ATT&CK** et conforme à la directive **NIS2 (UE 2022/2555)**.

## Démarrage rapide

```bash
cd lab
./setup.sh start
# → http://localhost:8080
```
