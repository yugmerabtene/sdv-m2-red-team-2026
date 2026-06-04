#!/bin/bash
# Entrypoint — Samba AD Domain Controller
set -e

DOMAIN="${DOMAIN:-redteam.lab}"
DOMAIN_IP="${DOMAIN_IP:-10.0.1.10}"
ADMIN_PASS="${ADMIN_PASSWORD:-Admin123!}"
ROOT_PASS="${ROOT_PASSWORD:-RootPassword123!}"
REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
WORKGROUP=$(echo "$DOMAIN" | cut -d. -f1 | tr '[:lower:]' '[:upper:]')

echo "============================================================"
echo "  Samba AD DC — $REALM"
echo "  IP: $DOMAIN_IP  |  DC: dc01.$DOMAIN"
echo "============================================================"

# Check if domain is already provisioned
if [ -f /var/lib/samba/private/sam.ldb ]; then
    echo "[*] Domaine deja provisionne, demarrage rapide..."
    samba -F --no-process-group
    exit 0
fi

echo "[*] Provisionnement du domaine $REALM..."

# Configure /etc/hosts
cat > /etc/hosts << EOF
127.0.0.1   localhost
$DOMAIN_IP  dc01.$DOMAIN dc01
EOF

# Configure Kerberos
cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d

[realms]
    $REALM = {
        kdc = dc01.$DOMAIN
        admin_server = dc01.$DOMAIN
    }

[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
EOF

# Configure Samba
cat > /etc/samba/smb.conf << EOF
[global]
    server role = active directory domain controller
    workgroup = $WORKGROUP
    realm = $REALM
    netbios name = DC01
    dns forwarder = 8.8.8.8
    server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate, dns
    ldap server require strong auth = no
    ntlm auth = yes
    lanman auth = yes
    server signing = disabled
    smb encrypt = disabled
    log level = 1

[netlogon]
    path = /var/lib/samba/sysvol/$DOMAIN/scripts
    read only = No

[sysvol]
    path = /var/lib/samba/sysvol
    read only = No

[data]
    path = /srv/samba/data
    read only = No
    guest ok = Yes

[IT]
    path = /srv/samba/it
    read only = No
    valid users = @IT
EOF

mkdir -p /srv/samba/data /srv/samba/it

# Provision domain
samba-tool domain provision \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$WORKGROUP" \
    --adminpass="$ADMIN_PASS" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --host-name=dc01 \
    --option="interfaces=lo eth0" || {
    echo "[!] Erreur de provisionnement. Tentative avec samba-tool domain provision manuel..."
    samba-tool domain provision \
        --realm="$REALM" \
        --domain="$WORKGROUP" \
        --adminpass="$ADMIN_PASS" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --host-name=dc01
}

echo "[+] Domaine provisionne"

# Copy config
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

# Disable password complexity for lab
samba-tool domain passwordsettings set --complexity=off --min-pwd-length=4 2>/dev/null || true

echo "[*] Creation des utilisateurs et groupes..."

# Create Organizational Units
samba-tool ou create "OU=Utilisateurs" 2>/dev/null || true
samba-tool ou create "OU=Groupes" 2>/dev/null || true
samba-tool ou create "OU=Administrateurs" 2>/dev/null || true
samba-tool ou create "OU=ServiceAccounts" 2>/dev/null || true

# Create groups
samba-tool group add IT 2>/dev/null || true
samba-tool group add Support 2>/dev/null || true
samba-tool group add Dev 2>/dev/null || true
samba-tool group add "Domain Admins" 2>/dev/null || true

# Create regular users
echo "[*] Creation des utilisateurs standards..."
for user_info in \
    "jdoe:Jean:Doe:P@ssw0rd!2025:IT,Support" \
    "asmith:Alice:Smith:Passw0rd!2025:IT" \
    "badmin:Bob:Admin:Summer2025!:Dev"; do
    IFS=':' read -r uid first last pass groups <<< "$user_info"
    if ! samba-tool user show "$uid" &>/dev/null; then
        samba-tool user create "$uid" "$pass" \
            --given-name="$first" \
            --surname="$last" \
            --mail-address="$uid@$DOMAIN" \
            --description="Compte standard — $first $last"
        for grp in $(echo "$groups" | tr ',' ' '); do
            samba-tool group addmembers "$grp" "$uid" 2>/dev/null || true
        done
        echo "  [+] Utilisateur cree : $uid"
    fi
done

# Create service accounts (for Kerberoasting)
echo "[*] Creation des comptes de service (SPN)..."

# svc_sql — Service SQL avec mot de passe faible (Kerberoasting)
if ! samba-tool user show "svc_sql" &>/dev/null; then
    samba-tool user create svc_sql "SQL_Svc!2025" \
        --given-name="MSSQL" --surname="Service" \
        --description="Compte de service MSSQL — faillible au Kerberoasting"
    samba-tool spn add "MSSQLSvc/dc01.$DOMAIN:1433" svc_sql
    samba-tool spn add "MSSQLSvc/dc01.$DOMAIN:1433/$DOMAIN" svc_sql
    echo "  [+] SPN cree pour svc_sql"
fi

# svc_http — Service HTTP avec delegation non-contrainte
if ! samba-tool user show "svc_http" &>/dev/null; then
    samba-tool user create svc_http "WebSvc!2025" \
        --given-name="HTTP" --surname="Service" \
        --description="Compte de service HTTP — delegation non-contrainte"
    samba-tool spn add "HTTP/dc01.$DOMAIN" svc_http
    echo "  [+] SPN cree pour svc_http"
fi

# svc_backup — Service backup (mot de passe tres faible)
if ! samba-tool user show "svc_backup" &>/dev/null; then
    samba-tool user create svc_backup "Backup123" \
        --given-name="Backup" --surname="Service" \
        --description="Compte de service Backup — mot de passe tres faible"
    samba-tool spn add "HOST/fs01.$DOMAIN" svc_backup
    echo "  [+] SPN cree pour svc_backup"
fi

# svc_ldap — Service LDAP
if ! samba-tool user show "svc_ldap" &>/dev/null; then
    samba-tool user create svc_ldap "LdapPass1!" \
        --given-name="LDAP" --surname="Service" \
        --description="Compte de service LDAP"
    samba-tool spn add "LDAP/dc01.$DOMAIN" svc_ldap
fi

# Create accounts WITHOUT Kerberos pre-authentication (AS-REP roasting targets)
echo "[*] Creation des comptes sans pre-authentification Kerberos (AS-REP Roasting)..."
if ! samba-tool user show "nopreauth_user" &>/dev/null; then
    samba-tool user create nopreauth_user "NoPreAuth1!" \
        --given-name="NoPreAuth" --surname="User" \
        --description="Compte SANS pre-authentification Kerberos (AS-REP)"
    # Set UF_DONT_REQUIRE_PREAUTH (4194304) + UF_NORMAL_ACCOUNT (512)
    DN=$(ldbsearch -H /var/lib/samba/private/sam.ldb "sAMAccountName=nopreauth_user" dn 2>/dev/null | grep "^dn:" | head -1 | cut -d' ' -f2)
    if [ -n "$DN" ]; then
        echo "dn: $DN
changetype: modify
replace: userAccountControl
userAccountControl: 4194816" | ldbmodify -H /var/lib/samba/private/sam.ldb
        echo "[+] Pre-authentification Kerberos desactivee pour nopreauth_user"
    fi
fi

# Add user to Domain Admins for some attack paths
samba-tool group addmembers "Domain Admins" "badmin" 2>/dev/null || true

# Create flag files in SMB shares
echo "[*] Creation des flags..."
mkdir -p /srv/samba/data/Flags /srv/samba/it/Admin

echo 'flag{enumeration_ldap_2026}' > /srv/samba/data/Flags/flag1.txt
echo 'flag{bloodhound_path_to_da}' > /srv/samba/data/Flags/flag2.txt
echo 'flag{kerberoasting_svc_sql}' > /srv/samba/data/Flags/flag3.txt
echo 'flag{asrep_roasting_nopreauth}' > /srv/samba/data/Flags/flag4.txt
echo 'flag{pass_the_hash_admin}' > /srv/samba/it/Admin/flag5.txt
echo 'flag{dcsync_golden_ticket}' > /srv/samba/it/Admin/flag6.txt

# Store a fake NTDS hash hint
echo "KRBTGT hash location: /var/lib/samba/private/sam.ldb" > /srv/samba/it/Admin/hint.txt

# Partages SMB pret — les flags sont lisibles via SMB anonyme

echo ""
echo "============================================================"
echo "  [+] LAB AD PRET"
echo "  Domaine    : $REALM"
echo "  DC         : dc01.$DOMAIN ($DOMAIN_IP)"
echo "  Admin      : Administrator / $ADMIN_PASS"
echo "  Utilisateurs: jdoe, asmith, badmin, nopreauth_user"
echo "  Services   : svc_sql, svc_http, svc_backup, svc_ldap"
echo "  Flags      : /srv/samba/data/Flags/"
echo "============================================================"
echo ""

# Start Samba in foreground
exec samba -F --no-process-group
