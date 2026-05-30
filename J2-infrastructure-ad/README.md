# Jour 2 — Infrastructure & Active Directory

> 02/06/2026 · 7 heures

## Objectifs

- Techniques d'attaque réseau avancées
- Reconnaissance, élévation de privilèges et mouvements latéraux dans un domaine AD
- Attaques ciblées sur AD (Kerberoasting, AS-REP roasting, ACL abuse)
- Pratique et résolution de scénarios techniques

## Modules

| Heure | Module | Durée | Technique ATT&CK |
|-------|--------|-------|------------------|
| 09:30—11:00 | [M6 — Reconnaissance & Scanning réseau avancé](m6-reconnaissance-reseau.md) | 1h30 | T1595, T1046, T1590 |
| 11:15—12:30 | [M7 — Attaques Active Directory](m7-active-directory.md) | 1h15 | T1087, T1557, T1049 |
| 13:30—14:30 | [M8 — Élévation de privilèges & Lateral Movement](m8-elevation-mouvement-lateral.md) | 1h00 | T1003, T1550, T1558 |
| 14:45—16:15 | [M9 — Attaques avancées AD](m9-attaques-avancees-ad.md) | 1h30 | T1098, T1558, T1484 |
| 16:15—17:00 | [M10 — Scénario AD autonome](m10-scenario-ad-autonome.md) | 0h45 | Synthèse |

## Prérequis (J2)

### Outils à installer

```bash
# Reconnaissance réseau
sudo apt install -y nmap masscan rustscan
sudo apt install -y snmp snmp-mibs-downloader onesixtyone
sudo apt install -y dnsutils dnsrecon dnsenum
pip3 install shodan censys

# Active Directory
sudo apt install -y crackmapexec bloodhound
pip3 install impacket bloodhound pywerview

# Lateral Movement
sudo apt install -y freerdp2-x11 evil-winrm
pip3 install pypykatz

# Réseau
sudo apt install -y responder enum4linux smbclient smbmap
pip3 install ldap3 ldapdomaindump
```

### Ressources

- **Lab AD local** : à définir (Docker ou VM)
- **Mots de passe communs** : `SecLists/Passwords/Common-Credentials`
