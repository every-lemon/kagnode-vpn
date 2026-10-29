#!/usr/bin/env bash
# KagNode Open source VPN server — Ubuntu Server 24.04.
# Built from src/installer.sh and src/manage.py. Upstream installers run as root.
set -Eeuo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
VERSION=@@VERSION@@
BASE=/var/lib/vpn
LOG=''
LAST=Start
STEP=0
TOTAL=15
CHILD=''
UI_RUNTIME=''
UI_OWNER=''
C='' G='' Z='' D=''
LAN_IP='' LAN_NET='' IFACE='' ENDPOINT='' WG_NET='' L2TP_NET='' IKE_NET=''
if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then
  C=$'\033[36m'; G=$'\033[32m'; Z=$'\033[0m'; D=$'\033[2m'
fi
say() { printf '%b\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
header() {
  say "\n${C}╭──────────────────────────────────────────────────────────╮${Z}"
  say "${C}│${Z} KagNode VPN · Ubuntu Server 24.04       v${VERSION} ${C}│${Z}"
  say "${C}│${Z} WireGuard · IKEv2 · L2TP/IPsec · AdGuard Home            ${C}│${Z}"
  say "${C}╰──────────────────────────────────────────────────────────╯${Z}"
}
completed() {
  STEP=$((STEP+1))
  local filled=$((STEP * 26 / TOTAL)) a b
  printf -v a '%*s' "$filled" ''; printf -v b '%*s' "$((26-filled))" ''
  say "  ${G}✓${Z} $1"
  say "  ${C}${a// /━}${D}${b// /┄}${Z} $STEP/$TOTAL"
}
run() {
  local label=$1 start=$SECONDS rc=0
  shift
  LAST=$label
  printf '\n========== %s | %s ==========\n' "$label" "$(date -Is)" >> "$LOG"
  # No conditional around this subshell: preserve errexit inside task functions.
  ( "$@" ) 9>&- >> "$LOG" 2>&1 &
  CHILD=$!
  printf '  → %s\n' "$label"
  wait "$CHILD" || rc=$?
  CHILD=''
  [[ ! -t 1 ]] || printf '\r\033[2K'
  ((rc == 0)) || { printf 'Failed: %s (exit %s)\n' "$label" "$rc" >&2; return "$rc"; }
  completed "$label [$((SECONDS-start))s]"
}
on_exit() {
  local rc=$?
  if [[ -n $UI_RUNTIME && $UI_OWNER == "$BASHPID" ]]; then rm -f -- "$UI_RUNTIME"; fi
  if ((rc != 0)) && [[ -n $LOG ]]; then
    printf '\nStopped at: %s\nPrivate log: %s\nLogs may contain credentials; inspect locally.\n' "$LAST" "$LOG" >&2
  fi
}
trap on_exit EXIT
trap '[[ -z $CHILD ]] || kill "$CHILD" 2>/dev/null || :; exit 130' INT TERM

help_msg() {
  cat <<'HELP'
KagNode Open source VPN server
Usage: sudo bash setup.sh [--plain] [--install|--profiles|--web|--web-status|--reset-clients|--status|--check-adguard|--web-password|--hardening-status|--hardening-queue|--watchdog-status|--watchdog-check|--watchdog-pause|--watchdog-resume|--demo|--help]
No argument: arrow-key menu for installation, users/devices, web access and diagnostics.
Ubuntu Server 24.04 on a physical server or VM; containers unsupported.
--demo previews terminal progress without root or system changes.
--check-adguard diagnoses service, DNS and admin sockets without reinstalling.
Private files and logs: /var/lib/vpn/
Router: forward UDP 500, 4500, 51820 to your server's stable LAN IPv4.
Never forward 53, 1701, 3000, or 8080. IPv4 full tunnel only.
HELP
}
demo() {
  TOTAL=6; LOG=/dev/null
  header
  say '  Demo only — no packages, services or configuration are changed.'
  run 'Check Ubuntu and discover network' sleep 0.2
  run 'Prepare packages and kernel networking' sleep 0.2
  run 'Install AdGuard; pause for browser wizard' sleep 0.2
  run 'Configure IKEv2 and L2TP/IPsec' sleep 0.2
  run 'Configure WireGuard and private profiles' sleep 0.2
  run 'Verify services and display router instructions' sleep 0.2
  say '  Demo complete. Opening menu: 1 Install KagNode VPN · 2 Users/devices · 3 Web access · 4 Diagnostics · 0 Exit'
}
check_platform() {
  (( EUID == 0 )) || die 'Use sudo bash setup.sh.'
  [[ -t 0 ]] || die 'Run from an interactive console or SSH terminal.'
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ $(uname -m) == x86_64 ]] || die 'Initial release supports amd64 only.'
  [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || die 'Ubuntu Server 24.04 required.'
  command -v systemctl >/dev/null || die 'systemd is required.'
  [[ -d /run/systemd/system ]] || die 'systemd must be running.'
  if systemd-detect-virt --container --quiet; then die 'Containers are unsupported; use a physical server or VM.'; fi
}
check_conflicts() {
  if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    die 'Active UFW detected. This installer uses IPsec iptables rules. Resolve the firewall conflict first; UFW was not changed.'
  fi
  systemctl is-active --quiet firewalld && die 'Active firewalld detected. Resolve the firewall conflict first.'
  if [[ -f $BASE/reset-progress.json ]]; then
    python3 - "$BASE/reset-progress.json" <<'RESET_CHECK' || die 'Fresh start was interrupted. Resume setup.sh --fresh-start before continuing.'
import json, sys
if json.load(open(sys.argv[1])).get('stage') != 'complete': raise SystemExit(1)
RESET_CHECK
  fi
  if [[ ! -f /etc/vpn/state.json && ! -f $BASE/reset-progress.json ]]; then
    [[ ! -e /etc/wireguard/wg0.conf && ! -e /etc/ipsec.conf && ! -e /opt/AdGuardHome/AdGuardHome ]] || die 'Existing unmanaged VPN or AdGuard installation found. Use a fresh server.'
    if command -v iptables >/dev/null; then
      local rules
      rules=$(iptables-save)
      if printf '%s\n' "$rules" | grep -Eq '^-A |^:(INPUT|FORWARD|OUTPUT) (DROP|REJECT)'; then
        die 'Existing firewall rules detected. Use a fresh server or resolve the conflict first.'
      fi
    fi
    if command -v nft >/dev/null && [[ -n $(nft list ruleset) ]]; then
      die 'Existing nftables configuration detected. Resolve the conflict first.'
    fi
  fi
  [[ ! -e /etc/wireguard/wg0.conf || -s $BASE/wg-server.pub ]] || die 'Unmanaged WireGuard configuration.'
  [[ ! -e /etc/ipsec.conf || -f $BASE/ipsec-partial || -f $BASE/ipsec-base-installed ]] || die 'Unmanaged IPsec configuration.'
  return 0
}
check_resources() {
  local disk mem
  disk=$(df -Pk / | awk 'NR==2 {print $4}')
  mem=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  ((disk >= 3 * 1024 * 1024)) || die 'At least 3 GiB free disk required for packages and backups.'
  ((mem >= 450 * 1024)) || die 'At least 512 MiB RAM required; 1 GiB recommended.'
}
preflight() {
  check_resources
  ip -4 route show default | grep -q '^default ' || die 'No default IPv4 route.'
  [[ -f /etc/vpn/state.json || ! -e /etc/ipsec.conf ]] || die 'Unmanaged IPsec configuration.'
  modprobe wireguard
  modprobe ppp_generic
  [[ -c /dev/ppp ]] || die 'PPP device unavailable.'
  ip xfrm policy >/dev/null
  ip link add wg-stack-test type wireguard
  ip link delete wg-stack-test
  iptables -t nat -L -n >/dev/null
}
emit_manager() {
  cat <<'PY_RUNTIME'
@@PYTHON_RUNTIME@@
PY_RUNTIME
}
ensure_ui() {
  if command -v python3 >/dev/null; then
    UI_RUNTIME=$(mktemp /tmp/vpn-ui-XXXXXX.py)
    UI_OWNER=$BASHPID
  emit_manager > "$UI_RUNTIME"
  fi
}
ui_choice() {
  if [[ -n $UI_RUNTIME ]]; then python3 "$UI_RUNTIME" ui-choice "$@"; return; fi
  local title=$1 entry answer index=0
  shift
  printf '\n%s\n' "$title" >&2
  local -a keys=()
  for entry in "$@"; do keys+=("${entry%%=*}"); index=$((index+1)); printf ' %s. %s\n' "$index" "${entry#*=}" >&2; done
  read -r -p 'Select [1]: ' answer
  answer=${answer:-1}
  [[ $answer =~ ^[0-9]+$ ]] && ((answer >= 1 && answer <= ${#keys[@]})) || return 2
  printf '%s\n' "${keys[answer-1]}"
}
ui_input() {
  if [[ -n $UI_RUNTIME ]]; then python3 "$UI_RUNTIME" ui-input "$@"; return; fi
  local answer
  read -r -p "$1 [${2:-}]: " answer
  printf '%s\n' "${answer:-${2:-}}"
}
install_runtime() {
  install -d -m 755 /usr/lib/vpn /usr/libexec/vpn
  install -d -m 700 /etc/vpn /var/log/vpn
  install -d -m 711 "$BASE"
  install -d -m 700 "$BASE/upstream" "$BASE/clients" "$BASE/backups"
    printf '%s\n' "$VERSION" > /usr/lib/vpn/VERSION
  install -d -m 755 /usr/bin
  cat > /usr/bin/vpn <<'VPN_LAUNCHER'
#!/bin/sh
case "${1:-}" in
  setup) shift; exec /bin/bash /usr/libexec/vpn/setup.sh "$@" ;;
  update) shift; exec /usr/bin/python3 /usr/lib/vpn/manage.py update "$@" ;;
  --version) exec cat /usr/lib/vpn/VERSION ;;
  *) exec /usr/bin/python3 /usr/lib/vpn/manage.py "$@" ;;
esac
VPN_LAUNCHER
  chmod 755 /usr/bin/vpn
  if [[ ! -L "$BASE/logs" ]]; then
    if [[ -d "$BASE/logs" ]]; then mv "$BASE/logs" "/var/log/vpn/imported-$(date +%s%N)"; fi
    ln -s /var/log/vpn "$BASE/logs"
  fi
  cat > /usr/lib/vpn/release-key.pem <<'RELEASE_PUBLIC_KEY'
@@RELEASE_KEY@@
RELEASE_PUBLIC_KEY
  chmod 644 /usr/lib/vpn/release-key.pem
  emit_manager > "/usr/lib/vpn/manage.py.new"
  chmod 700 "/usr/lib/vpn/manage.py.new"
  mv -f "/usr/lib/vpn/manage.py.new" "/usr/lib/vpn/manage.py"
  if [[ $(readlink -f -- "${BASH_SOURCE[0]}") != "/usr/libexec/vpn/setup.sh" ]]; then
    install -m 700 -- "${BASH_SOURCE[0]}" "/usr/libexec/vpn/setup.sh"
  fi
}
network_wizard() {
  local detected iface address cidr selected public endpoint
  iface=$(ip -4 route show default | awk '/^default / {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')
  detected=$(ip -o -4 addr show dev "$iface" scope global | awk 'NR==1 {print $4}')
  [[ -n $detected ]] || die 'No IPv4 on the default interface.'
  say "  Detected LAN: $detected on $iface"
  address=$(ui_input "Server LAN IPv4" "${detected%/*}")
  address=${address:-${detected%/*}}
  selected=$(ip -o -4 addr show scope global | awk -v wanted="$address" '{split($4,a,"/");if(a[1]==wanted){print $2" "$4;exit}}')
  [[ -n $selected ]] || die 'Selected LAN address is not assigned to this server.'
  read -r iface cidr <<< "$selected"
  public=$(curl -4 -fsS --connect-timeout 5 --max-time 15 https://api.ipify.org || curl -4 -fsS --connect-timeout 5 --max-time 15 https://ipv4.icanhazip.com)
  public=${public//$'\r'/}
  say "  Detected public IPv4: $public"
  endpoint=$(ui_input "Public VPN hostname or IPv4" "$public")
  endpoint=${endpoint:-$public}
  python3 "/usr/lib/vpn/manage.py" configure "$address" "$cidr" "$iface" "$endpoint" "$public"
}
backup_network() {
  local f
  for f in /etc/resolv.conf /etc/sysctl.conf /etc/ipsec.conf /etc/rc.local; do
    if [[ -e $f ]]; then cp -aL -- "$f" "$BASE/backups/$(basename "$f").$(date +%s%N)"; fi
  done
  iptables-save > "$BASE/backups/iptables.$(date +%s%N)"
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-vpn-forward.conf
  sysctl -w net.ipv4.ip_forward=1
}
check_dns_port() {
  python3 "/usr/lib/vpn/manage.py" prepare-dns
}

install_adguard() {
  if [[ ! -x /opt/AdGuardHome/AdGuardHome ]]; then
    curl -fsSL --retry 3 --connect-timeout 10 --max-time 120 https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh -o "$BASE/upstream/adguard-install.sh"
    sh -n "$BASE/upstream/adguard-install.sh"
    sh "$BASE/upstream/adguard-install.sh" -v
  fi
  systemctl enable --now AdGuardHome
}
adguard_ok() {
  python3 "/usr/lib/vpn/manage.py" check-adguard
}

adguard_wizard() {
  LAST='Manual AdGuard browser setup'
  while true; do
    say "\n  ADGUARD HOME — MANUAL SETUP"
    say "  Open http://$LAN_IP:3000 (existing setup: http://$LAN_IP:8080)."
    say "  DNS: select All interfaces / 0.0.0.0, port 53 (or select $LAN_IP)."
    say "  Web administration: port 8080; select $LAN_IP or All interfaces (firewall restricts access to LAN)."
    say '  Ubuntu DNS stub conflicts were handled automatically; host DNS remains available.'
    say '  Choose your administrator login and upstream DNS servers in the wizard.'
    answer=$(ui_choice 'Finish AdGuard in your browser, then continue' 'continue=I have finished the AdGuard wizard; check now' '0=Stop and resume later')
    [[ $answer == continue ]] || exit 0
    if adguard_ok; then break; fi
    say '  Verification failed; see the individual results above. Press Enter to check again after fixing the failing item.'
  done
  completed 'Manual AdGuard setup and DNS verified'
}
prepare_upstream() { :; }
install_ipsec() { python3 /usr/lib/vpn/manage.py native-install; }
write_firewall() {
  cat > "/usr/libexec/vpn/firewall.sh" <<FIREWALL
#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Retain a fail-closed barrier across a firewall rebuild, including failures.
iptables -w -N VPNSTACK-MAINT 2>/dev/null || true
iptables -w -C VPNSTACK-MAINT -j DROP 2>/dev/null || iptables -w -A VPNSTACK-MAINT -j DROP
for source in $WG_NET $IKE_NET $L2TP_NET; do
  for chain in INPUT FORWARD; do
    iptables -w -C "\$chain" -s "\$source" -j VPNSTACK-MAINT 2>/dev/null || iptables -w -I "\$chain" 1 -s "\$source" -j VPNSTACK-MAINT
  done
done
# Dedicated chains. Flush only our own rules; preserve SSH and upstream IPsec.
for chain in VPNSTACK-IN VPNSTACK-FWD VPNSTACK-LAN-IN VPNSTACK-LAN-FWD; do
  iptables -w -N "\$chain" 2>/dev/null || true
  iptables -w -F "\$chain"
done
# Remove duplicate jumps before inserting one at the front.
while iptables -w -C INPUT -j VPNSTACK-IN 2>/dev/null; do iptables -w -D INPUT -j VPNSTACK-IN; done
while iptables -w -C FORWARD -j VPNSTACK-FWD 2>/dev/null; do iptables -w -D FORWARD -j VPNSTACK-FWD; done
iptables -w -I INPUT 4 -j VPNSTACK-IN
iptables -w -I FORWARD 4 -j VPNSTACK-FWD
iptables -w -A VPNSTACK-IN -m conntrack --ctstate INVALID -j DROP
if [[ -f /var/lib/vpn/ssh-disabled ]]; then
  iptables -w -A VPNSTACK-IN -p tcp --dport 22 -j DROP
fi
# Fail closed until authenticated grants are rebuilt by the backend.
iptables -w -A VPNSTACK-LAN-IN -d $LAN_IP -p udp --dport 53 -j RETURN
iptables -w -A VPNSTACK-LAN-IN -d $LAN_IP -p tcp --dport 53 -j RETURN
iptables -w -A VPNSTACK-LAN-IN -p tcp --dport 9000 -j RETURN
iptables -w -A VPNSTACK-LAN-IN -j DROP
for network in $LAN_NET 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
  iptables -w -A VPNSTACK-LAN-FWD -d "\$network" -j DROP
done
iptables -w -A VPNSTACK-LAN-FWD -j DROP
for source in $WG_NET $L2TP_NET $IKE_NET; do
  iptables -w -A VPNSTACK-IN -s "\$source" -j VPNSTACK-LAN-IN
  iptables -w -A VPNSTACK-FWD -s "\$source" -j VPNSTACK-LAN-FWD
done
# Local LAN-address readiness checks arrive through loopback.
iptables -w -A VPNSTACK-IN -i lo -s $LAN_IP -d $LAN_IP -p tcp --dport 9001 -j ACCEPT
iptables -w -A VPNSTACK-IN -i $IFACE -s $LAN_NET -d $LAN_IP -p tcp --dport 9001 -j ACCEPT
# Trust only an explicitly configured HTTPS proxy; validate before shell use.
if [[ -f /etc/vpn/state.json ]]; then
  admin_proxy=\$(/usr/bin/python3 -c 'import json,ipaddress; s=json.load(open("/etc/vpn/state.json")); print(str(ipaddress.IPv4Address(s["trusted_proxy"])) if s.get("admin_mode")=="https" and s.get("trusted_proxy") else "")')
  if [[ -n \$admin_proxy ]]; then iptables -w -A VPNSTACK-IN -s "\$admin_proxy" -d $LAN_IP -p tcp --dport 9001 -j ACCEPT; fi
fi
iptables -w -A VPNSTACK-IN -p tcp --dport 9001 -j DROP
iptables -w -A VPNSTACK-IN -p udp --dport 51820 -j ACCEPT
iptables -w -A VPNSTACK-IN -p udp -m multiport --dports 500,4500 -j ACCEPT
iptables -w -A VPNSTACK-IN -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
iptables -w -A VPNSTACK-IN -p udp --dport 1701 -j DROP
for source in $LAN_NET $WG_NET $L2TP_NET $IKE_NET; do
  iptables -w -A VPNSTACK-IN -s "\$source" -d $LAN_IP -p udp --dport 53 -j ACCEPT
  iptables -w -A VPNSTACK-IN -s "\$source" -d $LAN_IP -p tcp --dport 53 -j ACCEPT
done
for port in 3000 8080; do
  iptables -w -A VPNSTACK-IN -i $IFACE -s $LAN_NET -d $LAN_IP -p tcp --dport "\$port" -j ACCEPT
  iptables -w -A VPNSTACK-IN -p tcp --dport "\$port" -j DROP
done
iptables -w -A VPNSTACK-IN -i lo -j RETURN
iptables -w -A VPNSTACK-IN -p udp --dport 53 -j DROP
iptables -w -A VPNSTACK-IN -p tcp --dport 53 -j DROP
if [[ -f /var/lib/vpn/web-enabled ]]; then
  iptables -w -A VPNSTACK-IN -p tcp --dport 9000 -j ACCEPT
else
  iptables -w -A VPNSTACK-IN -p tcp --dport 9000 -j DROP
fi
iptables -w -A VPNSTACK-IN -j RETURN
iptables -w -A VPNSTACK-FWD -m conntrack --ctstate INVALID -j DROP
for network in $WG_NET $IKE_NET $L2TP_NET; do
  iptables -w -A VPNSTACK-FWD -s "\$network" -j ACCEPT
  iptables -w -A VPNSTACK-FWD -d "\$network" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -w -t nat -C POSTROUTING -s "\$network" -o $IFACE -j MASQUERADE 2>/dev/null || iptables -w -t nat -A POSTROUTING -s "\$network" -o $IFACE -j MASQUERADE
done
iptables -w -A VPNSTACK-FWD -o wg0 -d $WG_NET -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -w -A VPNSTACK-FWD -j RETURN
iptables -w -t nat -C POSTROUTING -s $WG_NET -o $IFACE -j MASQUERADE 2>/dev/null || \\
  iptables -w -t nat -A POSTROUTING -s $WG_NET -o $IFACE -j MASQUERADE
# The stack binds administration and DNS to IPv4 only. Guard the initial
# AdGuard wildcard wizard on IPv6 as well, without changing other IPv6 traffic.
if [[ -f /proc/net/if_inet6 ]]; then
  ip6tables -w -N VPNSTACK6-IN 2>/dev/null || true
  ip6tables -w -F VPNSTACK6-IN
  while ip6tables -w -C INPUT -j VPNSTACK6-IN 2>/dev/null; do ip6tables -w -D INPUT -j VPNSTACK6-IN; done
  ip6tables -w -I INPUT 1 -j VPNSTACK6-IN
  if [[ -f /var/lib/vpn/ssh-disabled ]]; then
    ip6tables -w -A VPNSTACK6-IN -p tcp --dport 22 -j DROP
  fi
  ip6tables -w -A VPNSTACK6-IN -i lo -j RETURN
  ip6tables -w -A VPNSTACK6-IN -p tcp -m multiport --dports 53,3000,8080 -j DROP
  ip6tables -w -A VPNSTACK6-IN -p udp --dport 53 -j DROP
  ip6tables -w -A VPNSTACK6-IN -p tcp -m multiport --dports 9000,9001 -j DROP
  ip6tables -w -A VPNSTACK6-IN -j RETURN
fi
sysctl -q -w net.ipv4.ip_forward=1
if [[ -f "$BASE/policy-installed" ]]; then /usr/bin/python3 "/usr/lib/vpn/manage.py" policy-apply; fi
# Remove the barrier only after managed policies have been applied and verified.
for source in $WG_NET $IKE_NET $L2TP_NET; do
  for chain in INPUT FORWARD; do
    while iptables -w -C "\$chain" -s "\$source" -j VPNSTACK-MAINT 2>/dev/null; do iptables -w -D "\$chain" -s "\$source" -j VPNSTACK-MAINT; done
  done
done
FIREWALL
  chmod 700 "/usr/libexec/vpn/firewall.sh"
  cat > /etc/systemd/system/vpn-firewall.service <<'FIREWALL_SERVICE'
[Unit]
Description=KagNode VPN DNS guards and WireGuard forwarding
After=load-iptables-rules.service netfilter-persistent.service ufw.service
Before=wg-quick@wg0.service
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/libexec/vpn/firewall.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
FIREWALL_SERVICE
  install -d -m 755 /etc/systemd/system/wg-quick@wg0.service.d
  cat > /etc/systemd/system/wg-quick@wg0.service.d/vpn.conf <<'WG_SERVICE'
[Unit]
Requires=vpn-firewall.service
PartOf=vpn-firewall.service
After=vpn-firewall.service load-iptables-rules.service netfilter-persistent.service
[Service]
ExecStartPost=/usr/bin/python3 /usr/lib/vpn/manage.py policy-apply
WG_SERVICE
  systemctl daemon-reload
  systemctl enable vpn-firewall
  systemctl restart vpn-firewall
  # Restarting a required firewall stops wg-quick. Restore the configured tunnel
  # only after the firewall succeeded; its post-start hook verifies live policy.
  if [[ -f /etc/wireguard/wg0.conf ]]; then systemctl start wg-quick@wg0; fi
}
setup_wireguard() {
  local server_key server_pub
  install -d -m 700 /etc/wireguard
  if [[ ! -f /etc/wireguard/wg0.conf ]]; then
    server_key=$(wg genkey)
    server_pub=$(printf '%s\n' "$server_key" | wg pubkey)
    printf '%s\n' "$server_pub" > "$BASE/wg-server.pub"
    cat > /etc/wireguard/wg0.conf.new <<WG_CONF
[Interface]
Address = ${WG_NET%0/24}1/24
ListenPort = 51820
PrivateKey = $server_key
WG_CONF
    chmod 600 /etc/wireguard/wg0.conf.new
    mv /etc/wireguard/wg0.conf.new /etc/wireguard/wg0.conf
  fi
  [[ -s $BASE/wg-server.pub ]] || die 'WireGuard state incomplete; inspect existing configuration before retry.'
  systemctl enable --now wg-quick@wg0
  wg show wg0 >/dev/null
}
final_checks() {
  adguard_ok
  local service
  for service in AdGuardHome ipsec xl2tpd wg-quick@wg0 vpn-firewall; do
    systemctl is-active --quiet "$service"
  done
  [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]
  [[ -s /etc/ipsec.d/ikev2.conf ]]
  wg show wg0 >/dev/null
  iptables -C FORWARD -j VPNSTACK-FWD
  iptables -C VPNSTACK-FWD -s "$WG_NET" -j ACCEPT
  iptables -t nat -C POSTROUTING -s "$WG_NET" -o "$IFACE" -j MASQUERADE
  [[ $(iptables -S FORWARD | awk '/^-A /{print;exit}') == '-A FORWARD -j VPNSTACK-FWD' ]]
  grep -Fq "$LAN_IP" /etc/ppp/options.xl2tpd
  grep -Fq "$LAN_IP" /etc/ipsec.d/ikev2.conf
}
check_clock() {
  local attempt
  if [[ $(timedatectl show --property=NTPSynchronized --value) == yes ]]; then return; fi
  say '  Synchronizing the system clock before contacting Ubuntu repositories…'
  timedatectl set-ntp true || die 'Cannot enable network time synchronization. Check timedatectl status and your installed NTP service, then rerun.'
  # Count attempts instead of using wall-clock deadlines: NTP may step the clock.
  for ((attempt=0; attempt<30; attempt++)); do
    if [[ $(timedatectl show --property=NTPSynchronized --value) == yes ]]; then return; fi
    sleep 1
  done
  timedatectl status >&2 || true
  die 'Clock is not synchronized after 30 seconds. Check NTP connectivity (UDP 123) and the systemd-timesyncd or chrony service, then rerun. APT date checks remain enabled.'
}
install_stack() {
  check_conflicts
  check_resources
  check_clock
  # Bootstrap only when Install VPN is selected; menu/demo do not install packages.
  if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
    say '  Installing required Python 3, curl and CA certificates…'
    env DEBIAN_FRONTEND=noninteractive apt-get -qq -o DPkg::Lock::Timeout=120 update
    env DEBIAN_FRONTEND=noninteractive apt-get -y -qq -o DPkg::Lock::Timeout=120 install python3 curl ca-certificates
  fi
  install_runtime
  exec 8> "$BASE/maintenance.lock"
  flock -n 8 || die 'Watchdog recovery or another update is running. Retry shortly.'
  exec 9> "$BASE/operation.lock"
  flock -n 9 || die 'Another installation or profile operation is running.'
  LOG=$(mktemp "$BASE/logs/install-$(date +%Y%m%d-%H%M%S)-XXXXXX.log")
  STEP=0; TOTAL=19
  header
  if [[ ! -f /etc/vpn/state.json ]]; then network_wizard; fi
  # State is root-only; values are generated with shlex.quote, never user shell text.
  local state_values
  state_values=$(python3 "/usr/lib/vpn/manage.py" state-shell)
  eval "$state_values"
  ip -o -4 addr show dev "$IFACE" | awk -v wanted="$LAN_IP" '{split($4,a,"/");if(a[1]==wanted)ok=1} END {exit !ok}' || die "Saved LAN address $LAN_IP is no longer on $IFACE. Restore the stable address before resuming."
  say "  LAN $LAN_IP · Endpoint $ENDPOINT · Full tunnel IPv4"
  say "  WireGuard $WG_NET · L2TP $L2TP_NET · IKEv2 $IKE_NET"
  say '  Installs packages, runs upstream installers as root, and configures VPN firewall rules.'
  say '  AdGuard setup is manual. Keep a console available and reserve the LAN address in DHCP.'
  local answer
  answer=$(ui_choice 'Start / resume installation?' 'no=Cancel' 'yes=Install KagNode VPN')
  [[ $answer == yes ]] || { flock -u 9; flock -u 8; return; }
  local -a apt=(env DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=a)
  python3 /usr/lib/vpn/manage.py setup-stage review
  run 'Resume interrupted package configuration' "${apt[@]}" dpkg --force-confold --configure -a
  run 'Refresh Ubuntu package lists' "${apt[@]}" apt-get -qq -o DPkg::Lock::Timeout=120 update
  run 'Upgrade installed Ubuntu packages' "${apt[@]}" apt-get -y -qq -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confold upgrade
  run 'Install networking and profile utilities' "${apt[@]}" apt-get -y -qq -o DPkg::Lock::Timeout=120 install ca-certificates curl wget iproute2 iptables wireguard-tools qrencode dnsutils python3 procps kmod ppp openssl util-linux libnss3-tools python3-venv
  python3 /usr/lib/vpn/manage.py setup-stage packages
  run 'Verify resources and kernel networking' preflight
  python3 /usr/lib/vpn/manage.py owner-enroll
  python3 /usr/lib/vpn/manage.py setup-stage owner
  python3 /usr/lib/vpn/manage.py ssh-choice
  run 'Enable Ubuntu security updates' python3 /usr/lib/vpn/manage.py maintenance-install
  run 'Back up settings and protect DNS/admin access' prepare_network
  run 'Free DNS port 53 and verify host resolution' check_dns_port
  run 'Install and start AdGuard Home' install_adguard
  adguard_wizard
  python3 /usr/lib/vpn/manage.py setup-stage adguard
  run 'Download and validate IPsec integration' prepare_upstream
  run 'Configure IKEv2 and L2TP/IPsec' install_ipsec
  run 'Configure persistent firewall and WireGuard' configure_vpn
  run 'Initialize empty client registry' python3 /usr/lib/vpn/manage.py migrate-registry
  python3 /usr/lib/vpn/manage.py setup-stage vpn
  run 'Verify VPN services, forwarding and DNS' final_checks
  python3 "/usr/lib/vpn/manage.py" installed
  cat > "$BASE/README.txt" <<REFERENCE
KagNode VPN $VERSION — Ubuntu Server 24.04
Management: sudo bash /usr/libexec/vpn/setup.sh --profiles
Status: sudo bash /usr/libexec/vpn/setup.sh --status
Private profiles: /var/lib/vpn/clients/
Server-side checks passed; external connections and Apple import still require device testing.
IPv4-only: disable client IPv6 when full-tunnel privacy is needed.
REFERENCE
  run 'Configure authenticated LAN policy' python3 "/usr/lib/vpn/manage.py" policy-install
  run 'Apply appliance service and kernel hardening' python3 "/usr/lib/vpn/manage.py" hardening-install
  run 'Enable downloads and deploy web backend' python3 "/usr/lib/vpn/manage.py" refresh-web
  run 'Enable local health and recovery watchdog' python3 "/usr/lib/vpn/manage.py" watchdog-install
  python3 /usr/lib/vpn/manage.py setup-stage verified
  flock -u 9
  flock -u 8
  : # Package removal is never scheduled automatically.
  python3 "/usr/lib/vpn/manage.py" ports | tee -a "$BASE/README.txt"
  say "\n${G}  KagNode VPN installed. Open Users, devices and profiles to add users, export profiles, or see live bandwidth.${Z}"
  say "  Private installation log: $LOG"
  if [[ -f /var/run/reboot-required ]]; then say '  Ubuntu reports a reboot is required. Reboot manually, then check --status.'; fi
}
prepare_network() { backup_network; write_firewall; }
configure_vpn() { write_firewall; setup_wireguard; }
main() {
  if [[ ${1:-} == --plain ]]; then export VPN_STACK_PLAIN=1; shift; fi
  # Refuse truncated pastes before any installation work.
  bash -n -- "${BASH_SOURCE[0]}" || die 'Incomplete script or Bash syntax error.'
  tail -n 1 -- "${BASH_SOURCE[0]}" | grep -Fxq '# END_VPN_STACK_INSTALLER' || die 'Incomplete script: missing completion marker.'
  case ${1:-} in
    --help|-h) help_msg; return ;;
    --demo) demo; return ;;
    ''|--fresh-start|--install|--profiles|--web|--web-status|--reset-clients|--status|--check-adguard|--watchdog-status|--watchdog-check|--watchdog-pause|--watchdog-resume|--web-password|--hardening-status|--hardening-queue) ;;
    *) help_msg; exit 2 ;;
  esac
  [[ $# -le 1 ]] || die 'Too many arguments.'
  check_platform
  ensure_ui
  command -v flock >/dev/null || die 'util-linux (flock) is required.'
  if [[ ${1:-} == --check-adguard ]]; then
    # Run this file's embedded checker; do not overwrite the installed runtime.
    python3 - "${BASH_SOURCE[0]}" <<'DIAGNOSE'
from pathlib import Path
import sys
code = Path(sys.argv[1]).read_text().split("<<'PY_RUNTIME'\n", 1)[1].split("\nPY_RUNTIME\n", 1)[0]
sys.argv = ['vpn-manager', 'check-adguard']
exec(compile(code, '<embedded VPN manager>', 'exec'), {'__name__': '__main__'})
DIAGNOSE
    return
  fi
  if [[ ${1:-} == --fresh-start ]]; then
    install_runtime
    python3 /usr/lib/vpn/manage.py fresh-start
    install_stack
    return
  fi
  if [[ ${1:-} == --install ]]; then install_stack; return; fi
  if [[ ${1:-} == --hardening-* || ${1:-} == --watchdog-* || ${1:-} == --web-password || ${1:-} == --profiles || ${1:-} == --status || ${1:-} == --web-status || ${1:-} == --reset-clients || ${1:-} == --web ]]; then
    [[ -f /usr/lib/vpn/manage.py && -f /etc/vpn/state.json ]] || die 'Install KagNode VPN first.'
    python3 "/usr/lib/vpn/manage.py" "${1#--}"
    return
  fi
  while true; do
    header
    local choice
    choice=$(ui_choice 'KagNode VPN · Ubuntu 24.04' '1=Install KagNode VPN' '2=Users, devices and profiles' '3=Dashboard and profile delivery' '4=Diagnostics and service status' '0=Exit') || return 0
    case $choice in
      1) if bash "${BASH_SOURCE[0]}" --install; then :; else say "  Installation stopped. See the private log above; select Install KagNode VPN to resume."; fi ;;
      2) if [[ -f /etc/vpn/state.json && -f /usr/lib/vpn/manage.py ]] && command -v python3 >/dev/null; then
           python3 "/usr/lib/vpn/manage.py" profiles
         else say '  Install KagNode VPN first. Returning to the opening menu.'; fi ;;
      3) if [[ -f /usr/lib/vpn/manage.py && -f /etc/vpn/state.json ]]; then python3 "/usr/lib/vpn/manage.py" web; else say '  Install KagNode VPN first.'; fi ;;
      4) if [[ -f /usr/lib/vpn/manage.py && -f /etc/vpn/state.json ]]; then python3 "/usr/lib/vpn/manage.py" status; fi ;;
      0) return ;;
      *) say '  Choose 1, 2 or 0.' ;;
    esac
  done
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
# END_VPN_STACK_INSTALLER
