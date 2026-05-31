#!/bin/bash
# Workstation entrypoint — Simulation d'activite client
set -e

DOMAIN="${DOMAIN:-redteam.lab}"
DC_IP="${DC_IP:-10.0.1.10}"
REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')

echo "[*] Configuration de la workstation..."

# Configure Kerberos
cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h

[realms]
    $REALM = {
        kdc = dc01.$DOMAIN
        admin_server = dc01.$DOMAIN
    }

[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
EOF

# Configure hosts
echo "$DC_IP  dc01.$DOMAIN dc01" >> /etc/hosts

echo "[*] Workstation prete"
echo "    DC: dc01.$DOMAIN ($DC_IP)"

# Keep container running and simulate LLMNR activity occasionally
while true; do
    # Periodically try to resolve random hostnames (to generate LLMNR traffic)
    sleep 30
    for host in "fileserver" "printserver" "intranet" "sharepoint" "erp" "mail"; do
        host "$host" "$DC_IP" 2>/dev/null || true
    done
    echo "[.] Heartbeat — $(date)"
    sleep 60
done
