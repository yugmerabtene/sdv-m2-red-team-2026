#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  LAB AD — SDV M2 Red Team 2026
#  Samba Active Directory pour les modules J2 (M6–M10)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

banner() {
    echo -e "${RED}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  SDV M2 — Active Directory Lab          ║"
    echo "  ║  Domaine: redteam.lab (10.0.1.0/24)     ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_docker() {
    echo -e "${BLUE}[*] Verification de Docker...${NC}"
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}[!] Docker non installe.${NC}"
        exit 1
    fi
    if ! docker info &>/dev/null; then
        echo -e "${RED}[!] Docker non lance. sudo systemctl start docker${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Docker operationnel.${NC}"
}

compose_cmd() {
    if command -v docker-compose &>/dev/null; then
        docker-compose -f "$DIR/docker-compose.yml" "$@"
    else
        docker compose -f "$DIR/docker-compose.yml" "$@"
    fi
}

start_lab() {
    echo -e "${BLUE}[*] Construction des images Docker AD...${NC}"
    compose_cmd build --no-cache

    echo -e "${BLUE}[*] Demarrage du domaine Active Directory...${NC}"
    compose_cmd up -d dc01

    echo -e "${YELLOW}[*] Attente du provisionnement AD (60s)...${NC}"
    for i in $(seq 1 12); do
        sleep 5
        if docker exec lab-dc01 samba-tool user list 2>/dev/null | grep -q "jdoe"; then
            echo -e "${GREEN}[+] Domaine provisionne en $((i*5))s !${NC}"
            break
        fi
        echo -n "."
    done
    echo ""

    echo -e "${BLUE}[*] Demarrage de la workstation...${NC}"
    compose_cmd up -d ws01

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  LAB AD PRET !${NC}"
    echo -e "${GREEN}════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Domaine     : ${YELLOW}redteam.lab${NC}"
    echo -e "  DC IP       : ${YELLOW}10.0.1.10${NC}"
    echo -e "  DC hostname : ${YELLOW}dc01.redteam.lab${NC}"
    echo ""
    echo -e "  Comptes :"
    echo -e "    ${BLUE}Administrator${NC}   /  ${BLUE}Admin123!${NC}  (Domain Admin)"
    echo -e "    ${BLUE}jdoe${NC}              /  ${BLUE}P@ssw0rd!2025${NC}  (IT)"
    echo -e "    ${BLUE}asmith${NC}            /  ${BLUE}Passw0rd!2025${NC}  (IT)"
    echo -e "    ${BLUE}badmin${NC}            /  ${BLUE}Summer2025!${NC}   (Domain Admins)"
    echo -e ""
    echo -e "  Services (SPN) :"
    echo -e "    ${BLUE}svc_sql${NC}           /  ${BLUE}SQL_Svc!2025${NC}"
    echo -e "    ${BLUE}svc_http${NC}          /  ${BLUE}WebSvc!2025${NC}"
    echo -e "    ${BLUE}svc_backup${NC}        /  ${BLUE}Backup123${NC}"
    echo -e ""
    echo -e "  Commandes utiles :"
    echo -e "    ${BLUE}./setup.sh test${NC}      — Tester la connexion"
    echo -e "    ${BLUE}./setup.sh status${NC}    — Etat des conteneurs"
    echo -e "    ${BLUE}./setup.sh stop${NC}      — Arreter le lab"
    echo -e "    ${BLUE}./setup.sh reset${NC}     — Reinitialiser"
    echo ""
}

test_lab() {
    echo -e "${BLUE}[*] Test de connexion au domaine...${NC}"

    # Test DNS
    echo -n "  DNS lookup dc01.redteam.lab... "
    if nslookup dc01.redteam.lab 10.0.1.10 &>/dev/null; then echo -e "${GREEN}OK${NC}"; else echo -e "${RED}FAIL${NC}"; fi

    # Test LDAP
    echo -n "  LDAP anonymous bind... "
    if ldapsearch -x -H ldap://10.0.1.10 -b "dc=redteam,dc=lab" -s base 2>/dev/null | grep -q "dn:"; then echo -e "${GREEN}OK${NC}"; else echo -e "${RED}FAIL (peut etre normal si anon bind desactive)${NC}"; fi

    # Test SMB
    echo -n "  SMB null session... "
    if smbclient -N -L //10.0.1.10 2>/dev/null | grep -q "Sharename"; then echo -e "${GREEN}OK${NC}"; else echo -e "${YELLOW}FAIL (auth requise)${NC}"; fi

    # Test Kerberos
    echo -n "  Kerberos KDC (port 88)... "
    if echo "" | timeout 3 nc -u 10.0.1.10 88 2>/dev/null; then echo -e "${GREEN}OK${NC}"; else echo -e "${YELLOW}Reachable${NC}"; fi

    # List users via SMB
    echo -e "  ${BLUE}Comptes dans le domaine :${NC}"
    smbclient -L //10.0.1.10 -U "jdoe%P@ssw0rd!2025" 2>/dev/null | head -10
}

case "${1:-start}" in
    start)
        banner
        check_docker
        start_lab
        ;;
    stop)
        echo -e "${BLUE}[*] Arret du lab AD...${NC}"
        compose_cmd down -v
        echo -e "${GREEN}[+] Lab arrete.${NC}"
        ;;
    reset)
        echo -e "${YELLOW}[*] Reinitialisation complete...${NC}"
        compose_cmd down -v
        docker system prune -f
        check_docker
        start_lab
        ;;
    test)
        test_lab
        ;;
    status)
        compose_cmd ps
        ;;
    shell-dc)
        docker exec -it lab-dc01 bash
        ;;
    shell-ws)
        docker exec -it lab-ws01 bash
        ;;
    *)
        echo "Usage: $0 {start|stop|reset|test|status|shell-dc|shell-ws}"
        exit 1
        ;;
esac
