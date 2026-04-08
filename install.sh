#!/usr/bin/env bash
set -euo pipefail

APP_NAME="AIVPN"
CONFIG_DIR="config"
ENV_FILE=".env"
COMPOSE_FILE="docker-compose.yml"
VPN_SUBNET="10.0.0.0/24"
VPN_PORT="443"
ADMIN_PORT="27449"

cd "$(dirname "${BASH_SOURCE[0]}")"

log() {
  printf '\n==> %s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

confirm() {
  local prompt="$1"
  local answer
  read -r -p "$prompt [y/N]: " answer
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

ask_value() {
  local prompt="$1"
  local default_value="${2:-}"
  local value
  if [ -n "$default_value" ]; then
    read -r -p "$prompt [$default_value]: " value
    printf '%s' "${value:-$default_value}"
  else
    read -r -p "$prompt: " value
    printf '%s' "$value"
  fi
}

compose() {
  docker compose "$@"
}

is_installed() {
  [ -f "$CONFIG_DIR/server.key" ] || [ -f "$CONFIG_DIR/clients.json" ] || compose ps -q aivpn-server >/dev/null 2>&1
}

print_installation_evidence() {
  printf 'Install directory: %s\n' "$(pwd)"
  if [ -f "$CONFIG_DIR/server.key" ]; then
    printf '  found: %s/server.key\n' "$CONFIG_DIR"
  fi
  if [ -f "$CONFIG_DIR/clients.json" ]; then
    printf '  found: %s/clients.json\n' "$CONFIG_DIR"
  fi
  if compose ps -q aivpn-server >/dev/null 2>&1; then
    printf '  found: Docker Compose service aivpn-server\n'
  fi
}

ensure_base_requirements() {
  need_cmd docker
  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is required."
  need_cmd openssl
  need_cmd git
  need_cmd ip
  need_cmd iptables
}

write_env_value() {
  local key="$1"
  local value="$2"
  touch "$ENV_FILE"
  if grep -q "^${key}=" "$ENV_FILE"; then
    local tmp
    tmp="$(mktemp)"
    sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" > "$tmp"
    mv "$tmp" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

remove_env_value() {
  local key="$1"
  [ -f "$ENV_FILE" ] || return 0
  local tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "$ENV_FILE" > "$tmp" || true
  mv "$tmp" "$ENV_FILE"
}

detect_public_ip() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true
  fi
}

read_env_value() {
  local key="$1"
  [ -f "$ENV_FILE" ] || return 0
  grep -E "^${key}=" "$ENV_FILE" | tail -n 1 | cut -d= -f2-
}

endpoint_host() {
  local endpoint="$1"
  if printf '%s' "$endpoint" | grep -q '^\[.*\]:'; then
    printf '%s' "$endpoint" | sed 's/^\[\(.*\)\]:.*$/\1/'
  else
    printf '%s' "$endpoint" | cut -d: -f1
  fi
}

server_host_for_urls() {
  local endpoint host
  endpoint="$(read_env_value AIVPN_SERVER_IP)"
  [ -n "$endpoint" ] || die "AIVPN_SERVER_IP is missing in ${ENV_FILE}. Install AIVPN or fix the configuration."
  host="$(endpoint_host "$endpoint")"
  [ -n "$host" ] || die "AIVPN_SERVER_IP is invalid in ${ENV_FILE}: ${endpoint}"
  printf '%s' "$host"
}

detect_tailscale_ip() {
  if command -v tailscale >/dev/null 2>&1; then
    tailscale ip -4 2>/dev/null | head -n 1 || true
  fi
}

default_route_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}'
}

can_sudo_noninteractive() {
  [ "$(id -u)" -eq 0 ] || sudo -n true >/dev/null 2>&1
}

run_privileged_or_print() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@" || true
  elif can_sudo_noninteractive; then
    sudo "$@" || true
  else
    printf '  skipped; run manually: sudo'
    printf ' %q' "$@"
    printf '\n'
  fi
}

require_root_or_sudo() {
  if [ "$(id -u)" -eq 0 ] || can_sudo_noninteractive; then
    return 0
  fi
  die "Root privileges are required. Run this script as root or enable sudo for this shell."
}

run_privileged() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

configure_host_networking() {
  log "Configuring host networking"
  require_root_or_sudo

  local iface
  iface="$(default_route_iface || true)"
  [ -n "$iface" ] || die "Cannot detect outbound interface for NAT."

  printf 'Outbound interface: %s\n' "$iface"
  run_privileged sysctl -w net.ipv4.ip_forward=1 >/dev/null

  if [ "$(id -u)" -eq 0 ]; then
    mkdir -p /etc/sysctl.d
    printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-aivpn.conf
  else
    printf 'net.ipv4.ip_forward=1\n' | sudo tee /etc/sysctl.d/99-aivpn.conf >/dev/null
  fi

  if run_privileged iptables -t nat -C POSTROUTING -s "$VPN_SUBNET" -o "$iface" -j MASQUERADE 2>/dev/null; then
    printf 'NAT rule already exists.\n'
  else
    run_privileged iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$iface" -j MASQUERADE
    printf 'NAT rule added for %s via %s.\n' "$VPN_SUBNET" "$iface"
  fi

  if command -v ufw >/dev/null 2>&1; then
    local ufw_status
    ufw_status="$(run_privileged ufw status 2>/dev/null | head -n 1 || true)"
    if printf '%s' "$ufw_status" | grep -qi 'active'; then
      run_privileged ufw allow "${VPN_PORT}/udp"
      printf 'UFW rule added for %s/udp.\n' "$VPN_PORT"
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && run_privileged firewall-cmd --state >/dev/null 2>&1; then
    run_privileged firewall-cmd --add-port="${VPN_PORT}/udp" --permanent
    run_privileged firewall-cmd --reload
    printf 'firewalld rule added for %s/udp.\n' "$VPN_PORT"
  fi
}

prepare_settings_from_scratch() {
  log "Preparing fresh settings"
  rm -rf "$CONFIG_DIR"
  mkdir -p "$CONFIG_DIR"
  openssl rand 32 > "$CONFIG_DIR/server.key"
  chmod 600 "$CONFIG_DIR/server.key"

  local public_ip default_endpoint endpoint
  public_ip="$(detect_public_ip)"
  if [ -n "$public_ip" ]; then
    default_endpoint="${public_ip}:${VPN_PORT}"
  else
    default_endpoint="YOUR_PUBLIC_IP:${VPN_PORT}"
  fi
  endpoint="$(ask_value "Public VPN endpoint for clients (IP-or-DNS:port)" "$default_endpoint")"
  write_env_value "AIVPN_SERVER_IP" "$endpoint"

  if confirm "Generate admin UI token?"; then
    local token
    token="$(openssl rand -base64 32)"
    write_env_value "AIVPN_ADMIN_TOKEN" "$token"
    printf '%s\n' "$token" > "$CONFIG_DIR/admin.token"
    chmod 600 "$CONFIG_DIR/admin.token"
    printf '\nAdmin UI token:\n%s\n\n' "$token"
    printf 'Save it now. You will paste it into the Admin token field in the browser.\n'
  else
    remove_env_value "AIVPN_ADMIN_TOKEN"
    rm -f "$CONFIG_DIR/admin.token"
    printf 'Admin UI token disabled. Keep admin UI bound to a trusted interface only.\n'
  fi
}

install_aivpn() {
  ensure_base_requirements
  log "Install ${APP_NAME}"

  if is_installed; then
    warn "${APP_NAME} appears to be installed already."
    print_installation_evidence
    warn "Fresh reinstall will stop containers and remove current settings in $(pwd)/${CONFIG_DIR}/."
    confirm "Continue with fresh reinstall?" || return 0
    compose down --remove-orphans || true
  fi

  prepare_settings_from_scratch
  configure_host_networking
  log "Building and starting Docker Compose services"
  compose up -d --build aivpn-server aivpn-admin-web prometheus grafana

  log "Installed"
  compose ps
  print_access_info
}

update_aivpn() {
  ensure_base_requirements
  log "Update ${APP_NAME}"

  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "This directory is not a git repository."
  local branch upstream remote_name remote_url local_rev remote_rev
  branch="$(git rev-parse --abbrev-ref HEAD)"
  upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
  if [ -z "$upstream" ]; then
    upstream="origin/${branch}"
  fi
  remote_name="${upstream%%/*}"
  remote_url="$(git remote get-url "$remote_name" 2>/dev/null || true)"
  if [ -n "$remote_url" ]; then
    printf 'Update source: %s (%s)\n' "$upstream" "$remote_url"
  else
    printf 'Update source: %s\n' "$upstream"
  fi

  git fetch --prune
  local_rev="$(git rev-parse HEAD)"
  remote_rev="$(git rev-parse "$upstream" 2>/dev/null || true)"
  [ -n "$remote_rev" ] || die "Cannot resolve upstream $upstream."

  if [ "$local_rev" = "$remote_rev" ]; then
    printf 'Already up to date: %s\n' "$local_rev"
    return 0
  fi

  printf 'Local:  %s\nRemote: %s (%s)\n' "$local_rev" "$remote_rev" "$upstream"
  confirm "Update preserving settings in ${CONFIG_DIR}/?" || return 0
  git pull --ff-only
  compose up -d --build aivpn-server aivpn-admin-web prometheus grafana
  compose ps
}

uninstall_aivpn() {
  ensure_base_requirements
  log "Uninstall ${APP_NAME}"
  confirm "Stop and remove AIVPN Docker containers?" || return 0
  compose down --remove-orphans || true

  if confirm "Keep settings in ${CONFIG_DIR}/ and ${ENV_FILE}?"; then
    printf 'Settings preserved.\n'
  else
    rm -rf "$CONFIG_DIR" "$ENV_FILE"
    printf 'Settings removed.\n'
  fi
}

print_access_info() {
  local token_state host
  if grep -q '^AIVPN_ADMIN_TOKEN=' "$ENV_FILE" 2>/dev/null; then
    token_state="enabled"
  else
    token_state="disabled"
  fi
  host="$(server_host_for_urls)"

  printf '\nAdmin UI: http://%s:%s/\n' "$host" "$ADMIN_PORT"
  printf 'Grafana: http://%s:3000/ (default login: admin / admin)\n' "$host"
  printf 'Admin token: %s\n' "$token_state"
  printf 'Metrics: http://127.0.0.1:9100/metrics or through Prometheus\n'
}

firewall_check() {
  log "Firewall and network diagnostics"
  printf 'Default outbound interface: %s\n' "$(default_route_iface || true)"
  printf 'Expected VPN UDP port: %s/udp\n' "$VPN_PORT"
  printf 'Expected admin UI TCP port: %s/tcp\n' "$ADMIN_PORT"
  printf 'Expected VPN subnet for NAT: %s\n\n' "$VPN_SUBNET"

  if command -v tailscale >/dev/null 2>&1; then
    printf 'Tailscale: installed\n'
    printf 'Tailscale IPv4: %s\n' "$(detect_tailscale_ip)"
    tailscale status 2>/dev/null | sed -n '1,8p' || true
    printf '\nTailscale access can be configured separately by binding the admin UI to a Tailscale-only interface or by firewalling the admin port to tailscale0.\n\n'
  else
    printf 'Tailscale: not installed or not in PATH\n\n'
  fi

  if command -v ufw >/dev/null 2>&1; then
    printf 'UFW status:\n'
    run_privileged_or_print ufw status verbose
    printf '\nRecommended rules if UFW is active:\n'
    printf '  sudo ufw allow %s/udp\n' "$VPN_PORT"
    printf '  sudo ufw allow in on tailscale0 to any port %s proto tcp\n\n' "$ADMIN_PORT"
  fi

  if command -v firewall-cmd >/dev/null 2>&1; then
    printf 'firewalld status:\n'
    run_privileged_or_print firewall-cmd --state
    run_privileged_or_print firewall-cmd --get-active-zones
    printf '\nRecommended firewalld rule for VPN:\n'
    printf '  sudo firewall-cmd --add-port=%s/udp --permanent && sudo firewall-cmd --reload\n\n' "$VPN_PORT"
  fi

  if command -v nft >/dev/null 2>&1; then
    printf 'nftables ruleset summary:\n'
    if [ "$(id -u)" -eq 0 ]; then
      nft list ruleset 2>/dev/null | sed -n '1,80p' || true
    elif can_sudo_noninteractive; then
      sudo nft list ruleset 2>/dev/null | sed -n '1,80p' || true
    else
      printf '  skipped; run manually: sudo nft list ruleset\n'
    fi
    printf '\n'
  fi

  if command -v iptables >/dev/null 2>&1; then
    printf 'iptables NAT POSTROUTING:\n'
    if [ "$(id -u)" -eq 0 ]; then
      iptables -t nat -S POSTROUTING 2>/dev/null || true
    elif can_sudo_noninteractive; then
      sudo iptables -t nat -S POSTROUTING 2>/dev/null || true
    else
      printf '  skipped; run manually: sudo iptables -t nat -S POSTROUTING\n'
    fi
    printf '\nRecommended NAT rule, using detected outbound interface:\n'
    local iface
    iface="$(default_route_iface || true)"
    if [ -n "$iface" ]; then
      printf '  sudo sysctl -w net.ipv4.ip_forward=1\n'
      printf '  sudo iptables -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE || sudo iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE\n' "$VPN_SUBNET" "$iface" "$VPN_SUBNET" "$iface"
    else
      printf '  Cannot detect outbound interface automatically.\n'
    fi
  fi

  printf '\nThis script only diagnoses firewall state for now. It does not auto-change firewall rules.\n'
}

main_menu() {
  while true; do
    cat <<'MENU'

AIVPN server manager
1) Install AIVPN
2) Update AIVPN
3) Uninstall AIVPN
4) Check firewall/Tailscale settings
5) Show access info
0) Exit
MENU
    local choice
    read -r -p "Choose: " choice
    case "$choice" in
      1) install_aivpn ;;
      2) update_aivpn ;;
      3) uninstall_aivpn ;;
      4) firewall_check ;;
      5) print_access_info ;;
      0) exit 0 ;;
      *) printf 'Unknown option.\n' ;;
    esac
  done
}

case "${1:-}" in
  install) install_aivpn ;;
  update) update_aivpn ;;
  uninstall) uninstall_aivpn ;;
  firewall-check) firewall_check ;;
  info) print_access_info ;;
  ""|menu) main_menu ;;
  *) die "Usage: $0 [install|update|uninstall|firewall-check|info|menu]" ;;
esac
