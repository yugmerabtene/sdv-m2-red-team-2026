# SDV M2 — Red Team Advanced 2026

Formation pentest avancé — 4 jours (1—4 Juin 2026)

## Structure

```
├── syllabus.md                     ← Programme complet de la formation
├── J1-environnement-web/           ← Jour 1 : Web (détaillé)
│   ├── m1-mitre-attack.md          ←   M1 : MITRE ATT&CK
│   ├── m2-injections-avancees.md   ←   M2 : Injections (SQLi, NoSQLi, SSTI, etc.)
│   ├── m3-authentification-logique.md ← M3 : Auth & Logique métier
│   ├── m4-exploitation-pivoting.md ←   M4 : Exploitation & Pivoting
│   └── m5-scenario-autonome.md     ←   M5 : Scénario autonome
├── J2-infrastructure-ad/           ← Jour 2 : AD (à venir)
├── J3-mobile-transverse/           ← Jour 3 : Mobile (à venir)
├── J4-synthese-restitution/        ← Jour 4 : Rapport (à venir)
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
