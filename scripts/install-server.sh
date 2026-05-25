#!/usr/bin/env bash
# Free Turn Proxy Server — установщик. Интерактивный TUI + non-interactive (-y).
# Подробности: bash install-server.sh --help

set -Eeuo pipefail
trap 'rc=$?; printf "\n\033[0;31m[x]\033[0m строка %s (код %s): %s\n" "${LINENO}" "${rc}" "${BASH_COMMAND}" >&2; exit "${rc}"' ERR

REPO="samosvalishe/free-turn-proxy"
IMAGE="ghcr.io/${REPO}"
APP_DIR="/opt/free-turn-proxy"
CONF_FILE="${APP_DIR}/install.conf"
SERVICE="free-turn-proxy.service"
UNIT_FILE="/etc/systemd/system/${SERVICE}"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
CONTAINER="free-turn-proxy"
WT_BACK="Free Turn Proxy • установщик сервера"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[x]${NC} $1" >&2; exit 1; }

# Конфиг (перекрывается load_config / мастером / CLI)
INSTALL_METHOD="1"   # 1=docker 2=systemd
VERSION="latest"
PROXY_MODE="udp"
BACKEND_PORT=""
LISTEN_PORT="56000"
OBF_PROFILE="rtpopus"
OBF_KEY=""
CLIENTS_FILE_CONF=""

GOARCH=""
WG_PORT=""
HAS_WHIPTAIL=0
NONINTERACTIVE=0
OPEN_FIREWALL=""     # ""=спросить 1=да 0=нет
PURGE=0
ACTION=""
OVERRIDES=()

valid_port()  { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_hex64() { [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]]; }

# ---------------------------------------------------------------------------
# UI: whiptail | plain (/dev/tty — работает через `curl | bash`)
# ---------------------------------------------------------------------------
wt() { whiptail --backtitle "$WT_BACK" "$@"; }
ui_abort() { info "Отменено."; exit 0; }

ui_msg() {  # TITLE TEXT
    if [ "$HAS_WHIPTAIL" = 1 ]; then wt --title "$1" --msgbox "$2" 12 72; else echo; warn "$1: $2"; fi
}

ui_input() {  # VAR PROMPT DEFAULT
    local __v="$1" __p="$2" __d="${3:-}" __a
    if [ "$HAS_WHIPTAIL" = 1 ]; then
        __a=$(wt --title "Free Turn Proxy" --inputbox "$__p" 10 72 "$__d" 3>&1 1>&2 2>&3) || ui_abort
    else
        if [ -n "$__d" ]; then read -r -p "$__p [$__d]: " __a </dev/tty
        else read -r -p "$__p: " __a </dev/tty; fi
        __a="${__a:-$__d}"
    fi
    printf -v "$__v" '%s' "$__a"
}

ui_yesno() {  # PROMPT DEFAULT(Y|N) -> 0/1
    local __p="$1" __def="${2:-Y}" __a
    if [ "$HAS_WHIPTAIL" = 1 ]; then
        if [ "$__def" = "Y" ]; then wt --title "Free Turn Proxy" --yesno "$__p" 10 72
        else wt --title "Free Turn Proxy" --defaultno --yesno "$__p" 10 72; fi
        return $?
    fi
    local hint; [ "$__def" = "Y" ] && hint="Y/n" || hint="y/N"
    read -r -p "$__p [$hint]: " __a </dev/tty
    [[ "${__a:-$__def}" =~ ^[Yy]$ ]]
}

ui_menu() {  # VAR PROMPT DEFAULT_TAG tag desc [tag desc...]
    local __v="$1" __p="$2" __def="$3"; shift 3
    local tags=() descs=()
    while [ $# -gt 0 ]; do tags+=("$1"); descs+=("$2"); shift 2; done
    if [ "$HAS_WHIPTAIL" = 1 ]; then
        local args=() i sel
        for i in "${!tags[@]}"; do args+=("${tags[$i]}" "${descs[$i]}"); done
        sel=$(wt --title "Free Turn Proxy" --default-item "$__def" \
            --menu "$__p" 17 74 "${#tags[@]}" "${args[@]}" 3>&1 1>&2 2>&3) || ui_abort
        printf -v "$__v" '%s' "$sel"
    else
        local i sel
        echo; info "$__p"
        for i in "${!tags[@]}"; do
            [ "${tags[$i]}" = "$__def" ] && echo -e "  ${GREEN}${tags[$i]}${NC}) ${descs[$i]}" \
                                         || echo    "  ${tags[$i]}) ${descs[$i]}"
        done
        while :; do
            read -r -p "Выбор [${__def}]: " sel </dev/tty
            sel="${sel:-$__def}"
            for i in "${!tags[@]}"; do
                [ "$sel" = "${tags[$i]}" ] && { printf -v "$__v" '%s' "$sel"; return; }
            done
            warn "Неверный выбор: $sel"
        done
    fi
}

ask_port() {  # VAR PROMPT DEFAULT
    local __v="$1" __p="$2" __d="$3"
    while :; do
        ui_input "$__v" "$__p" "$__d"
        valid_port "${!__v}" && break
        ui_msg "Ошибка" "Порт — число 1–65535. Получено: '${!__v}'"
    done
}

# Прелоадер: gauge (whiptail) | спиннер (tty) | строка (pipe/NI). Возвращает код задачи.
with_progress() {  # TITLE CMD ARGS...
    local title="$1"; shift
    local log; log="$(mktemp)"
    local rc=0
    if [ "$HAS_WHIPTAIL" = 1 ]; then
        ( trap - ERR; "$@" >"$log" 2>&1 ) & local pid=$!
        {
            local p=0
            while kill -0 "$pid" 2>/dev/null; do
                echo "$p"; p=$((p+2)); if [ "$p" -gt 95 ]; then p=95; fi; sleep 0.25
            done
            echo 100
        } | wt --gauge "$title" 8 72 0
        wait "$pid" && rc=0 || rc=$?
        [ "$rc" -ne 0 ] && wt --title "Ошибка" --scrolltext --msgbox "$(tail -n 40 "$log")" 20 76
    elif [ -t 1 ]; then
        ( trap - ERR; "$@" >"$log" 2>&1 ) & local pid=$! ch='|/-\' i=0
        while kill -0 "$pid" 2>/dev/null; do
            i=$(((i+1)%4)); printf "\r${CYAN}[*]${NC} %s %s" "$title" "${ch:$i:1}"; sleep 0.2
        done
        wait "$pid" && rc=0 || rc=$?
        if [ "$rc" -eq 0 ]; then printf "\r${GREEN}[+]${NC} %s\033[K\n" "$title"
        else printf "\r${RED}[x]${NC} %s\033[K\n" "$title"; tail -n 40 "$log" >&2; fi
    else
        info "$title..."
        "$@" >"$log" 2>&1 && rc=0 || rc=$?
        [ "$rc" -ne 0 ] && tail -n 40 "$log" >&2
    fi
    rm -f "$log"
    return "$rc"
}

ui_info_start() { [ "$HAS_WHIPTAIL" = 1 ] && wt --title "Подождите" --infobox "$1" 7 60 || info "$1"; }

# ---------------------------------------------------------------------------
# Система
# ---------------------------------------------------------------------------
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  GOARCH="amd64" ;;
        aarch64|arm64) GOARCH="arm64" ;;
        *) error "Неподдерживаемая архитектура: $(uname -m)" ;;
    esac
}

pkg_install() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y -qq >/dev/null 2>&1 || true
        apt-get install -y -qq "$@" >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q "$@" >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then yum install -y -q "$@" >/dev/null 2>&1 || true
    fi
}

ensure_base_deps() {
    local missing=() b
    for b in curl jq openssl; do command -v "$b" >/dev/null 2>&1 || missing+=("$b"); done
    if [ "${#missing[@]}" -ne 0 ]; then
        with_progress "Установка зависимостей: ${missing[*]}" pkg_install "${missing[@]}"
        missing=()
        for b in curl jq openssl; do command -v "$b" >/dev/null 2>&1 || missing+=("$b"); done
        [ "${#missing[@]}" -ne 0 ] && error "Не удалось установить: ${missing[*]}. Поставьте вручную."
    fi
}

ensure_tui() {
    command -v whiptail >/dev/null 2>&1 && { HAS_WHIPTAIL=1; return; }
    if command -v apt-get >/dev/null 2>&1; then pkg_install whiptail; else pkg_install newt; fi
    command -v whiptail >/dev/null 2>&1 && HAS_WHIPTAIL=1 || { HAS_WHIPTAIL=0; warn "whiptail недоступен — текстовый режим."; }
}

detect_wg_port() {
    WG_PORT=""
    command -v wg >/dev/null 2>&1 || return 0
    if wg show all listen-port >/dev/null 2>&1; then
        WG_PORT="$(wg show all listen-port 2>/dev/null | head -n1 | awk '{print $2}' || true)"
    fi
    if [ -z "$WG_PORT" ] && ls /etc/wireguard/*.conf >/dev/null 2>&1; then
        WG_PORT="$(grep -i ListenPort /etc/wireguard/*.conf 2>/dev/null | head -n1 | awk -F= '{print $2}' | tr -d ' ' || true)"
    fi
}

# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------
gh_latest_version()  { curl -s --max-time 10 "https://api.github.com/repos/${REPO}/releases/latest" | jq -r '.tag_name // empty'; }
gh_recent_versions() { curl -s --max-time 10 "https://api.github.com/repos/${REPO}/releases?per_page=6" | jq -r '.[].tag_name'; }

resolve_asset_url() {  # VERSION ASSET
    local api
    [ "$1" = "latest" ] && api="https://api.github.com/repos/${REPO}/releases/latest" \
                        || api="https://api.github.com/repos/${REPO}/releases/tags/$1"
    curl -s --max-time 15 "$api" | jq -r --arg n "$2" '.assets[] | select(.name==$n) | .browser_download_url'
}

image_tag() { [ "$VERSION" = "latest" ] && echo "latest" || echo "$VERSION"; }

choose_version() {
    ui_info_start "Получение списка версий с GitHub..."
    local latest others t def="${VERSION:-latest}"
    latest="$(gh_latest_version || true)"
    others="$([ -n "$latest" ] && gh_recent_versions 2>/dev/null | grep -vx "$latest" | head -4 || true)"

    if [ "$HAS_WHIPTAIL" = 1 ] && [ -n "$latest" ]; then
        local args=("latest" "последний стабильный (= $latest)") sel
        while IFS= read -r t; do [ -n "$t" ] && args+=("$t" "релиз $t"); done <<< "$others"
        args+=("custom" "ввести тег вручную")
        sel=$(wt --title "Версия" --default-item "$def" --menu "Выберите версию" 17 72 8 "${args[@]}" 3>&1 1>&2 2>&3) || ui_abort
        [ "$sel" = "custom" ] && ui_input VERSION "Тег (latest или vX.Y.Z)" "$def" || VERSION="$sel"
    else
        echo
        if [ -n "$latest" ]; then
            echo -e "  ${GREEN}latest${NC} (= $latest)"
            [ -n "$others" ] && while IFS= read -r t; do echo "  $t"; done <<< "$others"
        else
            warn "Список релизов недоступен — введите тег вручную."
        fi
        echo
        ui_input VERSION "Версия (latest или vX.Y.Z)" "$def"
    fi
}

# ---------------------------------------------------------------------------
# Конфиг установки
# ---------------------------------------------------------------------------
is_installed() { [ -f "$CONF_FILE" ] || [ -f "$COMPOSE_FILE" ] || [ -f "$UNIT_FILE" ]; }
load_config()  { [ -f "$CONF_FILE" ] && . "$CONF_FILE" || true; }

save_config() {
    mkdir -p "$APP_DIR"
    cat > "$CONF_FILE" <<EOF
INSTALL_METHOD="$INSTALL_METHOD"
VERSION="$VERSION"
PROXY_MODE="$PROXY_MODE"
BACKEND_PORT="$BACKEND_PORT"
LISTEN_PORT="$LISTEN_PORT"
OBF_PROFILE="$OBF_PROFILE"
OBF_KEY="$OBF_KEY"
CLIENTS_FILE_CONF="$CLIENTS_FILE_CONF"
EOF
    chmod 600 "$CONF_FILE"
}

apply_overrides() {  # CLI бьёт install.conf
    local kv k v
    for kv in "${OVERRIDES[@]+"${OVERRIDES[@]}"}"; do k="${kv%%=*}"; v="${kv#*=}"; printf -v "$k" '%s' "$v"; done
}

connect_addr() { echo "127.0.0.1:${BACKEND_PORT}"; }
method_label() { [ "$INSTALL_METHOD" = "1" ] && echo "docker" || echo "systemd"; }

validate_config() {
    case "$INSTALL_METHOD" in 1|2) ;; *) error "method: docker|systemd (1|2), а не '$INSTALL_METHOD'" ;; esac
    case "$PROXY_MODE"    in udp|tcp) ;; *) error "mode: udp|tcp, а не '$PROXY_MODE'" ;; esac
    valid_port "$LISTEN_PORT" || error "listen-port невалиден: '$LISTEN_PORT'"
    [ -z "$BACKEND_PORT" ] && { [ "$PROXY_MODE" = "udp" ] && BACKEND_PORT="51820" || BACKEND_PORT="443"; }
    valid_port "$BACKEND_PORT" || error "backend-port невалиден: '$BACKEND_PORT'"
    case "$OBF_PROFILE" in
        rtpopus)
            [ -z "$OBF_KEY" ] && { OBF_KEY="$(openssl rand -hex 32)"; info "Сгенерирован ключ: $OBF_KEY"; }
            valid_hex64 "$OBF_KEY" || error "obf-key — ровно 64 hex-символа" ;;
        none) OBF_KEY="" ;;
        *) error "obf: rtpopus|none, а не '$OBF_PROFILE'" ;;
    esac
}

# ---------------------------------------------------------------------------
# Мастер
# ---------------------------------------------------------------------------
wizard() {
    local m def_method; [ "$INSTALL_METHOD" = "2" ] && def_method="systemd" || def_method="docker"
    ui_menu m "Метод установки сервера:" "$def_method" \
        docker  "Docker Compose (рекомендуется)" \
        systemd "Systemd (бинарь напрямую)"
    [ "$m" = "docker" ] && INSTALL_METHOD="1" || INSTALL_METHOD="2"

    ui_menu PROXY_MODE "Режим туннеля:" "${PROXY_MODE:-udp}" \
        udp "UDP-relay — WireGuard / AmneziaWG" \
        tcp "TCP-forward — Xray / sing-box"

    detect_wg_port
    local def_backend="$BACKEND_PORT"
    if [ -z "$def_backend" ]; then
        if [ -n "$WG_PORT" ]; then def_backend="$WG_PORT"; info "Найден WireGuard на порту $WG_PORT."
        elif [ "$PROXY_MODE" = "udp" ]; then def_backend="51820"; else def_backend="443"; fi
    fi
    ask_port BACKEND_PORT "Порт вашего VPN / бэкенда" "$def_backend"
    ask_port LISTEN_PORT  "Внешний порт (приём Free Turn Proxy)" "${LISTEN_PORT:-56000}"

    local obf_def="Y"; [ "$OBF_PROFILE" = "none" ] && obf_def="N"
    if ui_yesno "Включить маскировку rtpopus? (рекомендуется)" "$obf_def"; then
        OBF_PROFILE="rtpopus"
        if [ -n "$OBF_KEY" ]; then
            ui_yesno "Сгенерировать НОВЫЙ ключ? (нет — оставить текущий)" "N" && { OBF_KEY="$(openssl rand -hex 32)"; }
        elif ui_yesno "Сгенерировать случайный ключ?" "Y"; then
            OBF_KEY="$(openssl rand -hex 32)"
        else
            while :; do
                ui_input OBF_KEY "64-hex ключ обфускации" ""
                valid_hex64 "$OBF_KEY" && break
                ui_msg "Ошибка" "Ключ — ровно 64 hex-символа."
            done
        fi
    else
        OBF_PROFILE="none"; OBF_KEY=""
    fi

    local auth_def="N"; [ -n "$CLIENTS_FILE_CONF" ] && auth_def="Y"
    ui_yesno "Включить авторизацию по Client ID?" "$auth_def" \
        && CLIENTS_FILE_CONF="${APP_DIR}/clients.json" || CLIENTS_FILE_CONF=""

    choose_version

    ui_yesno "Открыть порт ${LISTEN_PORT}/udp в UFW/iptables?" "Y" && OPEN_FIREWALL=1 || OPEN_FIREWALL=0
}

firewall_open() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${LISTEN_PORT}/udp" >/dev/null 2>&1 || warn "ufw allow не удался."
        success "Порт ${LISTEN_PORT}/udp открыт (UFW)."
    elif command -v iptables >/dev/null 2>&1; then
        if ! iptables -C INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || warn "iptables -I не удался."
            command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
        fi
        success "Порт ${LISTEN_PORT}/udp открыт (iptables)."
    else
        warn "Брандмауэр не найден — откройте ${LISTEN_PORT}/udp вручную."
    fi
}

# ---------------------------------------------------------------------------
# Применение
# ---------------------------------------------------------------------------
init_clients_file() {
    [ -n "$CLIENTS_FILE_CONF" ] && [ ! -f "$CLIENTS_FILE_CONF" ] && echo "[]" > "$CLIENTS_FILE_CONF" || true
}

ensure_docker() {
    command -v docker >/dev/null 2>&1 && return 0
    if [ "$NONINTERACTIVE" != 1 ] && ! ui_yesno "Docker не найден. Установить?" "Y"; then
        error "Для метода docker нужен Docker."
    fi
    with_progress "Установка Docker" sh -c 'curl -fsSL https://get.docker.com | sh' \
        || error "Установка Docker не удалась."
    command -v docker >/dev/null 2>&1 || error "Docker не появился в PATH."
}

healthcheck_docker() {
    sleep 2
    [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo false)" = "true" ] && { success "Контейнер работает."; return; }
    warn "Контейнер не запущен. Логи:"
    docker logs --tail 40 "$CONTAINER" 2>&1 || true
    error "$CONTAINER не поднялся."
}

apply_docker() {
    ensure_docker
    {
        echo "services:"
        echo "  free-turn-proxy:"
        echo "    image: ${IMAGE}:$(image_tag)"
        echo "    container_name: ${CONTAINER}"
        echo "    network_mode: \"host\""
        echo "    restart: unless-stopped"
        echo "    environment:"
        echo "      - CONNECT_ADDR=$(connect_addr)"
        echo "      - LISTEN_ADDR=0.0.0.0:${LISTEN_PORT}"
        echo "      - MODE=${PROXY_MODE}"
        echo "      - OBF_PROFILE=${OBF_PROFILE}"
        echo "      - OBF_KEY=${OBF_KEY}"
        if [ -n "$CLIENTS_FILE_CONF" ]; then
            echo "      - CLIENTS_FILE=${CLIENTS_FILE_CONF}"
            echo "    volumes:"
            echo "      - ${CLIENTS_FILE_CONF}:${CLIENTS_FILE_CONF}"
        fi
    } > "$COMPOSE_FILE"

    cd "$APP_DIR"
    with_progress "Загрузка образа ${IMAGE}:$(image_tag)" docker compose pull || error "docker compose pull не удался."
    with_progress "Запуск контейнера" docker compose up -d || error "docker compose up не удался."
    healthcheck_docker
}

download_binary() {
    local url
    url="$(resolve_asset_url "$VERSION" "server-linux-${GOARCH}" || true)"
    [ -z "$url" ] && error "Не найден server-linux-${GOARCH} в релизе ${VERSION}."
    with_progress "Скачивание server-linux-${GOARCH} (${VERSION})" \
        curl -fL -o "${APP_DIR}/server.new" "$url" || error "Не удалось скачать $url"
    chmod +x "${APP_DIR}/server.new"
    mv -f "${APP_DIR}/server.new" "${APP_DIR}/server"
}

healthcheck_systemd() {
    sleep 1
    systemctl is-active --quiet "$SERVICE" && { success "Служба активна."; return; }
    warn "Служба не активна. Логи:"
    journalctl -u "$SERVICE" --no-pager -n 40 2>&1 || true
    error "$SERVICE не запустилась."
}

apply_systemd() {
    download_binary
    local args="-listen 0.0.0.0:${LISTEN_PORT} -connect $(connect_addr) -mode ${PROXY_MODE}"
    [ "$OBF_PROFILE" != "none" ] && args="$args -obf-profile ${OBF_PROFILE} -obf-key ${OBF_KEY}"
    [ -n "$CLIENTS_FILE_CONF" ] && args="$args -clients-file ${CLIENTS_FILE_CONF}"
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Free TURN Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=${APP_DIR}/server ${args}
Restart=always
RestartSec=5
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    systemctl restart "$SERVICE" || error "systemctl restart не удался."
    healthcheck_systemd
}

apply() {
    mkdir -p "$APP_DIR"
    init_clients_file
    if [ "$INSTALL_METHOD" = "1" ]; then apply_docker; else apply_systemd; fi
    [ "$OPEN_FIREWALL" = "1" ] && firewall_open
    save_config
}

print_summary() {
    local ext_ip; ext_ip="$(curl -s --max-time 5 ifconfig.me || echo "IP_СЕРВЕРА")"
    local body="Сервер (peer): ${ext_ip}:${LISTEN_PORT}\nРежим: ${PROXY_MODE}\nВерсия: ${VERSION}\nМетод: $(method_label)"
    [ "$OBF_PROFILE" != "none" ] && body="${body}\nОбфускация: ${OBF_PROFILE}\nКлюч: ${OBF_KEY}"
    if [ -n "$CLIENTS_FILE_CONF" ]; then
        if [ "$INSTALL_METHOD" = "1" ]; then
            body="${body}\n\nClient ID auth ВКЛ. Добавить клиента:\n  docker exec -it ${CONTAINER} /app/server clients add <id>"
        else
            body="${body}\n\nClient ID auth ВКЛ. Добавить клиента:\n  ${APP_DIR}/server -clients-file ${CLIENTS_FILE_CONF} clients add <id>"
        fi
    fi
    if [ "$HAS_WHIPTAIL" = 1 ]; then
        wt --title "Готово ✓" --msgbox "$(echo -e "$body")" 18 74
    else
        echo ""; success "Готово!"
        echo "--------------------------------------------------------"
        echo -e "$body"
        echo "--------------------------------------------------------"
    fi
    echo -e "Документация: https://github.com/${REPO}"
}

# ---------------------------------------------------------------------------
# Сценарии
# ---------------------------------------------------------------------------
flow_install()     { wizard; validate_config; apply; print_summary; }
flow_reconfigure() { wizard; validate_config; apply; print_summary; }

flow_update() {
    [ -f "$CONF_FILE" ] || { warn "Конфиг не найден — переконфигурация."; flow_reconfigure; return; }
    choose_version
    [ -z "$OPEN_FIREWALL" ] && OPEN_FIREWALL=0
    validate_config; apply; print_summary
}

do_uninstall() {  # REMOVE_DIR(0|1)
    if [ "$INSTALL_METHOD" = "1" ]; then
        [ -f "$COMPOSE_FILE" ] && ( cd "$APP_DIR" && docker compose down ) || warn "docker compose down — пропуск/ошибка."
    else
        systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
        rm -f "$UNIT_FILE"; systemctl daemon-reload || true
    fi
    success "Служба остановлена и удалена."
    [ "$1" = "1" ] && { rm -rf "$APP_DIR"; success "Каталог $APP_DIR удалён."; } || info "Каталог сохранён: $APP_DIR"
}

flow_uninstall() {
    ui_yesno "Удалить Free Turn Proxy Server?" "N" || { info "Отменено."; return; }
    local rm_dir=0
    ui_yesno "Удалить каталог ${APP_DIR} (ключи, clients.json, конфиг)?" "N" && rm_dir=1
    do_uninstall "$rm_dir"
}

menu_existing() {
    local choice
    ui_menu choice "Установка найдена (метод: $(method_label), версия: ${VERSION:-?}). Действие:" "update" \
        update      "Обновить версию (конфиг сохранён)" \
        reconfigure "Переконфигурировать" \
        uninstall   "Удалить" \
        exit        "Выход"
    case "$choice" in
        update) flow_update ;; reconfigure) flow_reconfigure ;;
        uninstall) flow_uninstall ;; exit) info "Выход."; exit 0 ;;
    esac
}

run_noninteractive() {
    is_installed && load_config || true
    apply_overrides
    if [ "${ACTION:-install}" = "uninstall" ]; then do_uninstall "$PURGE"; return; fi
    validate_config
    [ -z "$OPEN_FIREWALL" ] && OPEN_FIREWALL=1
    info "Применяю конфигурацию (метод: $(method_label))..."
    apply; print_summary
}

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Free Turn Proxy Server — установщик.

  sudo bash install-server.sh                 интерактивно (whiptail/текст)
  sudo bash install-server.sh -y [опции]      non-interactive

Опции:
  -y, --yes, --non-interactive   без вопросов
  --method docker|systemd        метод (default docker)
  --mode   udp|tcp               режим (default udp)
  --backend-port N               порт бэкенда (default udp→51820 / tcp→443)
  --listen-port N                внешний порт (default 56000)
  --obf rtpopus|none             обфускация (default rtpopus)
  --obf-key HEX64                ключ (нет → сгенерируется)
  --clients-auth / --no-clients-auth   авторизация Client ID (default off)
  --version latest|vX.Y.Z        версия (default latest)
  --firewall / --no-firewall     открывать порт (NI default: да)
  --update | --reconfigure       обновить / переустановить
  --uninstall [--purge]          удалить (--purge — снести каталог)
  -h, --help

Примеры:
  sudo bash install-server.sh -y --method docker --mode udp --backend-port 51820
  sudo bash install-server.sh -y --update --version v1.2.3
  sudo bash install-server.sh -y --uninstall --purge
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -y|--yes|--non-interactive) NONINTERACTIVE=1 ;;
            --method)
                case "${2:-}" in docker|1) OVERRIDES+=("INSTALL_METHOD=1");; systemd|2) OVERRIDES+=("INSTALL_METHOD=2");; *) error "--method: docker|systemd";; esac; shift ;;
            --mode)            OVERRIDES+=("PROXY_MODE=${2:-}"); shift ;;
            --backend-port)    OVERRIDES+=("BACKEND_PORT=${2:-}"); shift ;;
            --listen-port)     OVERRIDES+=("LISTEN_PORT=${2:-}"); shift ;;
            --obf)             OVERRIDES+=("OBF_PROFILE=${2:-}"); shift ;;
            --obf-key)         OVERRIDES+=("OBF_KEY=${2:-}"); shift ;;
            --clients-auth)    OVERRIDES+=("CLIENTS_FILE_CONF=${APP_DIR}/clients.json") ;;
            --no-clients-auth) OVERRIDES+=("CLIENTS_FILE_CONF=") ;;
            --version)         OVERRIDES+=("VERSION=${2:-}"); shift ;;
            --firewall)        OPEN_FIREWALL=1 ;;
            --no-firewall)     OPEN_FIREWALL=0 ;;
            --update)          ACTION="update"; NONINTERACTIVE=1 ;;
            --reconfigure)     ACTION="reconfigure"; NONINTERACTIVE=1 ;;
            --uninstall)       ACTION="uninstall"; NONINTERACTIVE=1 ;;
            --purge)           PURGE=1 ;;
            -h|--help)         usage; exit 0 ;;
            *) error "Неизвестный аргумент: $1 (см. --help)" ;;
        esac
        shift
    done
}

banner() {
    [ "$HAS_WHIPTAIL" = 1 ] && return 0
    echo -e "${CYAN}"
    cat << "EOF"
    ______               _____                 ____
   / ____/_______  ___  /_  __/_  ___________ / __ \_________  _  ____  __
  / /_  / ___/ _ \/ _ \  / / / / / / ___/ __ \/ /_/ / ___/ __ \| |/_/ / / /
 / __/ / /  /  __/  __/ / / / /_/ / /  / / / / ____/ /  / /_/ />  </ /_/ /
/_/   /_/   \___/\___/ /_/  \__,_/_/  /_/ /_/_/   /_/   \____/_/|_|\__, /
                                                                  /____/
EOF
    echo -e "${NC}"
}

main() {
    parse_args "$@"
    [ "$(id -u)" -ne 0 ] && error "Запустите от root (sudo)."
    ensure_base_deps
    detect_arch
    if [ "$NONINTERACTIVE" = 1 ]; then run_noninteractive; return; fi
    ensure_tui
    banner
    if is_installed; then load_config; menu_existing; else flow_install; fi
}

main "$@"
