# Lab AD — Samba Active Directory pour J2

> Infrastructure Active Directory vulnérable pour les modules M6—M10

## Prérequis

- **Docker** ≥ 20.10
- **RAM** : 2 Go libre minimum
- **Ports** : 53, 88, 135-139, 389, 445, 636, 3268-3269 (vérifier qu'ils sont libres)

## Mise en place

```bash
cd lab-ad
chmod +x setup.sh
./setup.sh start
```

Premier lancement : ~2 minutes (build + provisionnement).  
Lancements suivants : ~30 secondes.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              redteam.lab (10.0.1.0/24)           │
├───────────────────┬─────────────────────────────┤
│   DC01             │   WS01                       │
│   10.0.1.10        │   10.0.1.100                 │
│   Samba AD DC      │   Linux Workstation           │
│   DNS, LDAP, SMB   │   (LLMNR traffic simulation) │
└───────────────────┴─────────────────────────────┘
```

## Comptes

| Compte | Mot de passe | Rôle | Technique cible |
|--------|-------------|------|-----------------|
| `Administrator` | `Admin123!` | Domain Admin | DCSync, Golden Ticket |
| `jdoe` | `P@ssw0rd!2025` | IT, Support | Reconnaissance, BloodHound |
| `asmith` | `Passw0rd!2025` | IT | Enumération |
| `badmin` | `Summer2025!` | Domain Admins | ACL abuse |
| `nopreauth_user` | `NoPreAuth1!` | Standard | AS-REP Roasting |
| `svc_sql` | `SQL_Svc!2025` | MSSQL Service | Kerberoasting |
| `svc_http` | `WebSvc!2025` | HTTP Service | Kerberoasting |
| `svc_backup` | `Backup123` | Backup Service | Kerberoasting |
| `svc_ldap` | `LdapPass1!` | LDAP Service | Enumération |

## Vulnérabilités configurées

| Vulnérabilité | Technique | Module |
|--------------|-----------|--------|
| LLMNR/NBT-NS actif | T1557.001 | M7 |
| SPNs avec mots de passe faibles | T1558.003 | M8 |
| Compte sans pré-authentification Kerberos | T1558.004 | M8 |
| Comptes dans Domain Admins accessibles | T1078 | M9 |
| ACL abusables (via Samba AD) | T1098 | M9 |
| NTLM activé (PtH possible) | T1550.002 | M8 |
| DCSync possible avec droits | T1003.006 | M8 |

## Vérification rapide

```bash
# DNS fonctionnel ?
nslookup dc01.redteam.lab 10.0.1.10

# LDAP ?
ldapsearch -x -H ldap://10.0.1.10 -b "dc=redteam,dc=lab" -D "jdoe@redteam.lab" -w "P@ssw0rd!2025" "(objectClass=user)" | head -20

# Kerberos (obtenir un TGT)
echo "P@ssw0rd!2025" | kinit jdoe@REDTEAM.LAB
klist
```

## Résolution des problèmes

| Problème | Solution |
|----------|----------|
| Ports déjà utilisés | `sudo lsof -i :53` puis désactiver systemd-resolved |
| Build échoue | `docker system prune -f && ./setup.sh reset` |
| DC ne démarre pas | Vérifier les logs : `docker logs lab-dc01` |
| Samba ne répond pas | Attendre 60s (provisionnement en cours) |

## Commandes utiles

| Commande | Action |
|----------|--------|
| `./setup.sh start` | Démarrage |
| `./setup.sh stop` | Arrêt |
| `./setup.sh reset` | Réinitialisation complète |
| `./setup.sh test` | Tester la connexion |
| `./setup.sh status` | État |
| `./setup.sh shell-dc` | Shell interactif sur le DC |
| `./setup.sh shell-ws` | Shell interactif sur la workstation |
