# Jour 3 — Mobile & Techniques transverses

> 03/06/2026 · 7 heures

## Objectifs

- Introduction aux tests sur applications mobiles
- Reverse engineering et analyse dynamique
- Techniques transverses : evasion, persistance, obfuscation
- Synthese de cas complexes — Capture The Flag encadre

## Modules

| Heure | Module | Duree | Technique ATT&CK |
|-------|--------|-------|------------------|
| 09:30—11:00 | [M11 — Introduction au pentest mobile](m11-intro-pentest-mobile.md) | 1h30 | T1426, T1407 |
| 11:15—12:30 | [M12 — Reverse engineering & Analyse dynamique](m12-reverse-engineering-dynamique.md) | 1h15 | T1407, T1406, T1040 |
| 13:30—14:30 | [M13 — Evasion, Persistance & Obfuscation](m13-evasion-persistance-obfuscation.md) | 1h00 | T1562, T1027, TA0003 |
| 14:45—16:15 | [M14 — Synthese & CTF encadre](m14-synthese-ctf-encadre.md) | 1h30 | Synthese |
| 16:15—17:00 | [M15 — Debrief CTF & Corrections](m15-debrief-ctf-corrections.md) | 0h45 | Correction |

## Prerequis

```bash
# Outils mobile
sudo apt install -y adb apktool jadx dex2jar default-jdk
pip3 install frida-tools objection

# Android Studio + AVD (emulateur)
# Telecharger depuis https://developer.android.com/studio

# Burp Suite (deja installe J1)
```

## Lab

- Emulateur Android (AVD) avec une APK vulnerable fournie
- Serveur backend Docker pour l'API mobile
