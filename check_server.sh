#!/usr/bin/env bash
set -u

APP_DIR="${BLITS_INSTALL_DIR:-/opt/blitz-amnezia-panel}"
if [ ! -d "$APP_DIR" ] && [ -d "/root/Blits-Amnezia.WG" ]; then
    APP_DIR="/root/Blits-Amnezia.WG"
fi

ENV_FILE="$APP_DIR/data/panel.env"
QUICK=false
if [ "${1:-}" = "--quick" ]; then
    QUICK=true
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass_count=0
warn_count=0
fail_count=0

ok() {
    pass_count=$((pass_count + 1))
    echo -e "${GREEN}OK${NC}   $1"
}

warn() {
    warn_count=$((warn_count + 1))
    echo -e "${YELLOW}WARN${NC} $1"
}

fail() {
    fail_count=$((fail_count + 1))
    echo -e "${RED}FAIL${NC} $1"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

get_env() {
    local key="$1"
    grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true
}

compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif has_cmd docker-compose; then
        echo "docker-compose"
    else
        echo ""
    fi
}

panel_local_url() {
    local port web_path
    port="$(get_env PANEL_PORT)"
    web_path="$(get_env PANEL_WEB_PATH)"
    port="${port:-80}"
    web_path="${web_path:-/}"
    web_path="/${web_path#/}"
    web_path="${web_path%/}"
    if [ -z "$web_path" ]; then
        web_path=""
    fi
    printf 'http://127.0.0.1:%s%s/login\n' "$port" "$web_path"
}

echo -e "${BLUE}=== Blitz AmneziaWG Panel self-check ===${NC}"
echo "Time: $(date)"
echo "Install dir: $APP_DIR"
echo ""

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    ok "script is running as root"
else
    fail "run this check as root"
fi

if [ -d "$APP_DIR" ]; then
    ok "project directory exists"
else
    fail "project directory not found: $APP_DIR"
fi

if [ -f "$ENV_FILE" ]; then
    ok "panel env file exists"
else
    fail "panel env file not found: $ENV_FILE"
fi

if has_cmd docker; then
    ok "docker command is available"
    if systemctl is-active --quiet docker 2>/dev/null || docker info >/dev/null 2>&1; then
        ok "docker daemon is running"
    else
        fail "docker daemon is not running"
    fi
else
    fail "docker command is not installed"
fi

DOCKER_COMPOSE_CMD="$(compose_cmd)"
if [ -n "$DOCKER_COMPOSE_CMD" ]; then
    ok "docker compose is available"
else
    fail "docker compose is not installed"
fi

if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'amnezia-panel'; then
    ok "amnezia-panel container is running"
else
    fail "amnezia-panel container is not running"
fi

if has_cmd awg; then
    ok "AmneziaWG command awg is installed"
else
    fail "AmneziaWG command awg is not installed"
fi

if systemctl is-active --quiet awg-quick@awg0 2>/dev/null; then
    ok "Amnezia 2.0 interface awg0 is active"
else
    fail "Amnezia 2.0 service awg-quick@awg0 is not active"
fi

if systemctl is-active --quiet awg-quick@awg_legacy 2>/dev/null; then
    ok "Amnezia 1 / Legacy interface awg_legacy is active"
else
    warn "Legacy service awg-quick@awg_legacy is not active"
fi

if has_cmd ip && ip link show awg0 >/dev/null 2>&1; then
    ok "network interface awg0 exists"
else
    fail "network interface awg0 not found"
fi

if has_cmd ip && ip link show awg_legacy >/dev/null 2>&1; then
    ok "network interface awg_legacy exists"
else
    warn "network interface awg_legacy not found"
fi

if docker exec amnezia-panel python3 -m py_compile \
    /app/app/main.py \
    /app/app/routes.py \
    /app/app/vpn_manager.py \
    /app/app/database.py >/dev/null 2>&1; then
    ok "panel Python modules compile"
else
    fail "panel Python modules do not compile"
fi

if docker exec -i amnezia-panel python3 - <<'PY' >/dev/null 2>&1
import sqlite3
conn = sqlite3.connect('/app/data/panel.db')
for table in ('users', 'clients', 'settings'):
    row = conn.execute("select name from sqlite_master where type='table' and name=?", (table,)).fetchone()
    assert row, table
conn.close()
PY
then
    ok "database schema is ready"
else
    fail "database schema is not ready"
fi

LOCAL_URL="$(panel_local_url)"
if has_cmd curl; then
    if curl -fsSL --max-time 8 "$LOCAL_URL" >/dev/null 2>&1; then
        ok "panel answers locally at $LOCAL_URL"
    else
        fail "panel does not answer locally at $LOCAL_URL"
    fi
else
    warn "curl is not installed, skipped HTTP check"
fi

if [ "$QUICK" = false ]; then
    echo ""
    echo -e "${BLUE}--- Containers ---${NC}"
    if [ -n "$DOCKER_COMPOSE_CMD" ] && [ -f "$APP_DIR/docker-compose.yml" ]; then
        (cd "$APP_DIR" && $DOCKER_COMPOSE_CMD ps) || true
    else
        docker ps -a --filter "name=amnezia-panel" --filter "name=nginx-proxy" || true
    fi

    echo ""
    echo -e "${BLUE}--- VPN state ---${NC}"
    awg show 2>/dev/null || warn "cannot read awg show"

    echo ""
    echo -e "${BLUE}--- Recent panel logs ---${NC}"
    docker logs --tail 60 amnezia-panel 2>&1 || true
fi

recent_errors="$(docker logs --since 2m amnezia-panel 2>&1 | grep -Ei 'traceback|exception|error|failed' || true)"
if [ -n "$recent_errors" ]; then
    warn "recent panel logs contain errors; run: docker logs --tail 120 amnezia-panel"
else
    ok "no recent panel errors found"
fi

echo ""
echo -e "${BLUE}Summary:${NC} ${GREEN}${pass_count} OK${NC}, ${YELLOW}${warn_count} WARN${NC}, ${RED}${fail_count} FAIL${NC}"

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
