#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  LAB SDV M2 — Red Team 2026
#  Script de mise en place automatique
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

banner() {
    echo -e "${RED}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  SDV M2 — Red Team Advanced Lab         ║"
    echo "  ║  EcoVault Pentest Environment            ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_docker() {
    echo -e "${BLUE}[*] Vérification de Docker...${NC}"
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}[!] Docker n'est pas installé.${NC}"
        echo "    Installation : https://docs.docker.com/engine/install/"
        exit 1
    fi
    if ! docker info &>/dev/null; then
        echo -e "${RED}[!] Docker n'est pas lancé ou vous n'avez pas les droits.${NC}"
        echo "    Essayez : sudo systemctl start docker"
        exit 1
    fi
    echo -e "${GREEN}[+] Docker est opérationnel.${NC}"

    if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null; then
        echo -e "${RED}[!] docker-compose n'est pas installé.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] docker-compose est disponible.${NC}"
}

check_ports() {
    echo -e "${BLUE}[*] Vérification des ports...${NC}"
    local ports=(8080)
    for p in "${ports[@]}"; do
        if ss -tln | grep -q ":$p "; then
            echo -e "${YELLOW}[!] Le port $p est déjà utilisé. Arrêtez le service qui l'occupe.${NC}"
            echo "    ss -tlnp | grep :$p"
            exit 1
        fi
    done
    echo -e "${GREEN}[+] Tous les ports sont libres.${NC}"
}

compose_cmd() {
    if command -v docker-compose &>/dev/null; then
        docker-compose "$@"
    else
        docker compose "$@"
    fi
}

build_lab() {
    echo -e "${BLUE}[*] Construction des images Docker...${NC}"
    compose_cmd build --no-cache
    echo -e "${GREEN}[+] Images construites.${NC}"
}

start_lab() {
    echo -e "${BLUE}[*] Démarrage des conteneurs...${NC}"
    compose_cmd up -d
    echo ""
    echo -e "${YELLOW}[*] Attente de l'initialisation de MySQL (15s)...${NC}"
    sleep 15
}

verify_lab() {
    echo -e "${BLUE}[*] Vérification des services...${NC}"
    local status
    status=$(compose_cmd ps --format json 2>/dev/null | grep -c '"State":"running"' || true)
    echo -e "${GREEN}[+] $status/4 conteneurs en cours d'exécution.${NC}"

    echo -e "${BLUE}[*] Test de l'application web...${NC}"
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ | grep -q 200; then
        echo -e "${GREEN}[+] Application web accessible : http://localhost:8080${NC}"
    else
        echo -e "${YELLOW}[!] L'application web ne répond pas encore, patientez...${NC}"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  LAB PRÊT !${NC}"
    echo -e "${GREEN}════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Application web : ${YELLOW}http://localhost:8080${NC}"
    echo ""
    echo -e "  Comptes fournis :"
    echo -e "    ${BLUE}user@ecovault.com${NC}  /  ${BLUE}User2026!${NC}"
    echo -e "    (trouvez les autres comptes par exploitation)"
    echo ""
    echo -e "  Commandes utiles :"
    echo -e "    ${BLUE}./setup.sh status${NC}   — Voir l'état des conteneurs"
    echo -e "    ${BLUE}./setup.sh logs${NC}     — Voir les logs"
    echo -e "    ${BLUE}./setup.sh stop${NC}     — Arrêter le lab"
    echo -e "    ${BLUE}./setup.sh reset${NC}    — Réinitialiser le lab"
    echo ""
    echo -e "  Objectifs (Jour 1) :"
    echo -e "    ${RED}Flag 1${NC} — IDOR : lire le profil d'un autre utilisateur"
    echo -e "    ${RED}Flag 2${NC} — SQLi : extraire la table users"
    echo -e "    ${RED}Flag 3${NC} — Auth bypass : devenir administrateur"
    echo -e "    ${RED}Flag 4${NC} — SSTI → RCE : obtenir un shell"
    echo -e "    ${RED}Flag 5${NC} — Pivoting : accéder au serveur interne (10.0.0.10)"
    echo ""
}

case "${1:-start}" in
    start)
        banner
        check_docker
        check_ports
        build_lab
        start_lab
        verify_lab
        print_summary
        ;;
    stop)
        echo -e "${BLUE}[*] Arrêt du lab...${NC}"
        compose_cmd down
        echo -e "${GREEN}[+] Lab arrêté.${NC}"
        ;;
    reset)
        echo -e "${YELLOW}[*] Réinitialisation complète...${NC}"
        compose_cmd down -v
        check_docker
        check_ports
        build_lab
        start_lab
        verify_lab
        print_summary
        ;;  
    status)
        compose_cmd ps
        echo ""
        echo -e "Test webapp : $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/ 2>/dev/null || echo 'DOWN')"
        ;;
    logs)
        compose_cmd logs -f --tail=100
        ;;
    *)
        echo "Usage: $0 {start|stop|reset|status|logs}"
        exit 1
        ;;
esac
