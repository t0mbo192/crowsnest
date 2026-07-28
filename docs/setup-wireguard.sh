#!/usr/bin/env bash
# Set this Raspberry Pi up as a WireGuard gateway that crowsnest can watch.
#
# The phone connects over WireGuard, so every packet it sends -- on Wi-Fi and on
# cellular -- is forwarded through this box, where crowsnest sees it on wg0 and
# nftables can block it. No iOS app, no Apple Developer membership.
#
# Nothing here is irreversible: --uninstall undoes all of it. Run with --dry-run
# first to read the commands without executing them.
#
# Usage:
#   sudo ./setup-wireguard.sh [--dry-run] [--port 51820] [--iface eth0]
#   sudo ./setup-wireguard.sh --yes          answer yes to every prompt
#   sudo ./setup-wireguard.sh --uninstall
#
# Anything missing is named with the exact command that installs it, and is
# installed only if you say yes.

set -euo pipefail

PORT=51820
WAN_IFACE=""
DRY_RUN=0
UNINSTALL=0
WG_IFACE=wg0
WG_NET_V4="10.6.0.0/24"
SERVER_V4="10.6.0.1"
CLIENT_V4="10.6.0.2"
WG_DIR=/etc/wireguard
# Override with --dns if you run a resolver on the Pi (dnsmasq, Pi-hole).
DNS_SERVER="1.1.1.1"
# Where the phone should look for this Pi. Empty means "use the LAN address",
# which only works at home; --endpoint takes a public address or DDNS name and
# is what makes the tunnel connect over cellular. See docs/cellular.md.
ENDPOINT_HOST=""
# Cellular links sometimes cannot carry WireGuard's default 1420-byte packets.
# See the troubleshooting section of docs/cellular.md before setting this.
MTU=""
QR_ONLY=0
ASSUME_YES=0
# NAT lives in its own table so that dropping crowsnest's table -- which
# `crowsnest unblock --all` does -- cannot take the Pi's routing with it.
NAT_TABLE=crowsnest_nat

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   DRY_RUN=1 ;;
    -y|--yes)    ASSUME_YES=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --port)      PORT="$2"; shift ;;
    --iface)     WAN_IFACE="$2"; shift ;;
    --dns)       DNS_SERVER="$2"; shift ;;
    --endpoint)  ENDPOINT_HOST="$2"; shift ;;
    --mtu)       MTU="$2"; shift ;;
    --qr-only)   QR_ONLY=1 ;;
    -h|--help)   sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

ask() {
  [ "$ASSUME_YES" = 1 ] && return 0
  local reply=""
  printf '%s [y/N] ' "$1"
  # Read the terminal directly: this runs under sudo and may be invoked with its
  # stdin pointed somewhere unhelpful, and silence must not read as consent.
  if { exec 3</dev/tty; } 2>/dev/null; then
    read -r reply <&3 || reply=""
    exec 3<&-
  elif [ -t 0 ]; then
    read -r reply || reply=""
  else
    printf 'no terminal to ask on, assuming no\n'
    return 1
  fi
  case "$reply" in [Yy]|[Yy][Ee][Ss]) return 0 ;; *) return 1 ;; esac
}

run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '  [dry run] %s\n' "$*"
  else
    "$@"
  fi
}

# Writes the phone's config and prints it as a QR code.
#
# Split out because the endpoint is the one setting people need to change after
# the fact: you set this up at home against the Pi's LAN address, then later
# get a public name and want to re-point it without regenerating keys, which
# would invalidate the tunnel already on the phone. --qr-only does exactly that.
emit_phone_config() {
  local phone_key server_pub phone_psk mtu_line

  # --endpoint wins; otherwise the LAN address, which only works at home.
  ENDPOINT="${ENDPOINT_HOST:-${SERVER_HOST:-}}"
  if [ -z "$ENDPOINT" ]; then
    ENDPOINT="<public address or DDNS name of this Pi>"
  fi

  mtu_line=""
  if [ -n "$MTU" ]; then
    mtu_line="
MTU = ${MTU}"
  fi

  if [ "$DRY_RUN" = 1 ]; then
    phone_key="<phone private key>"
    server_pub="<server public key>"
    phone_psk="<pre-shared key>"
  else
    phone_key=$(cat "${WG_DIR}/phone.key")
    server_pub=$(cat "${WG_DIR}/server.pub")
    phone_psk=$(cat "${WG_DIR}/phone.psk")
  fi

  # DNS goes to a public resolver rather than to this Pi, because nothing is
  # listening on ${SERVER_V4}:53 and a phone with no resolver has no internet.
  # Visibility is unaffected: the queries are plaintext UDP/53 and cross the
  # tunnel either way, so crowsnest reads them off the wire rather than from a
  # resolver's log. Running dnsmasq or Pi-hole here and pointing --dns at
  # ${SERVER_V4} is a worthwhile upgrade -- it adds domain-level blocking --
  # but nothing here needs it.
  PHONE_CONF="[Interface]
PrivateKey = ${phone_key}
Address = ${CLIENT_V4}/32
DNS = ${DNS_SERVER}${mtu_line}

[Peer]
PublicKey = ${server_pub}
PresharedKey = ${phone_psk}
Endpoint = ${ENDPOINT}:${PORT}
# Everything, so cellular traffic is covered too.
AllowedIPs = 0.0.0.0/0, ::/0
# Keeps the NAT mapping alive so the Pi can still be reached after a quiet
# spell -- without it an incoming handshake has nowhere to land.
PersistentKeepalive = 25
"

  if [ "$DRY_RUN" = 1 ]; then
    printf '  [dry run] would write %s/phone.conf and print a QR code\n' "$WG_DIR"
    printf '  [dry run] endpoint would be %s:%s\n' "$ENDPOINT" "$PORT"
    return
  fi

  umask 077
  printf '%s' "$PHONE_CONF" > "${WG_DIR}/phone.conf"
  echo
  printf '%s' "$PHONE_CONF" | qrencode -t ansiutf8
  echo
  note "endpoint: ${ENDPOINT}:${PORT}"
  note "also saved to ${WG_DIR}/phone.conf"
}

if [ "$(id -u)" != 0 ] && [ "$DRY_RUN" = 0 ]; then
  echo "This needs root: sudo $0 $*" >&2
  exit 1
fi

# --------------------------------------------------------------- uninstall
if [ "$UNINSTALL" = 1 ]; then
  say "Removing the WireGuard gateway"
  run systemctl disable --now "wg-quick@${WG_IFACE}" 2>/dev/null || true
  run nft delete table inet "$NAT_TABLE" 2>/dev/null || true
  run rm -f /etc/sysctl.d/99-crowsnest-forward.conf
  run sysctl --system >/dev/null 2>&1 || true
  note "Left in place: ${WG_DIR} (your keys and peer configs)."
  note "Delete it yourself if you want them gone: sudo rm -rf ${WG_DIR}"
  note "crowsnest's own nftables table is untouched; use 'crowsnest unblock --all'."
  exit 0
fi

# ---------------------------------------------------------------- QR only
# Re-issue the phone config against a different endpoint, without touching
# keys, NAT or the service. This is the normal way to move from "works at
# home" to "works on cellular".
if [ "$QR_ONLY" = 1 ]; then
  if [ "$DRY_RUN" = 0 ] && [ ! -f "${WG_DIR}/phone.key" ]; then
    echo "No existing setup found in ${WG_DIR}. Run without --qr-only first." >&2
    exit 1
  fi
  SERVER_HOST=$(ip -4 addr show "${WAN_IFACE:-$(ip route show default 2>/dev/null \
    | awk '/default/ {print $5; exit}')}" 2>/dev/null \
    | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}' || true)
  say "Phone configuration"
  emit_phone_config
  echo
  echo "Re-scan this in the WireGuard app, replacing the existing tunnel."
  echo "The keys are unchanged, so the Pi needs no restart."
  exit 0
fi

# ------------------------------------------------------------ prerequisites
say "Checking prerequisites"

PACKAGES=("wireguard-tools:wg" "nftables:nft" "tshark:tshark" "qrencode:qrencode")

find_missing() {
  MISSING=()
  local pkg_cmd pkg cmd
  for pkg_cmd in "${PACKAGES[@]}"; do
    pkg="${pkg_cmd%%:*}"; cmd="${pkg_cmd##*:}"
    if command -v "$cmd" >/dev/null 2>&1; then
      [ "${1:-}" = "quiet" ] || note "found $cmd"
    else
      [ "${1:-}" = "quiet" ] || note "MISSING $cmd (package: $pkg)"
      MISSING+=("$pkg")
    fi
  done
}

find_missing

if [ ${#MISSING[@]} -gt 0 ]; then
  # Offered rather than reported. This script already runs as root, so there is
  # no extra privilege in doing it here -- only the difference between one
  # command and three. What is printed is exactly what runs.
  INSTALL_CMD="apt-get update && apt-get install -y ${MISSING[*]}"
  echo
  echo "  Not installed yet:  ${MISSING[*]}"
  echo
  echo "      $INSTALL_CMD"
  echo
  echo "  tshark will ask whether non-root users may capture. Answering yes, and"
  echo "  then 'sudo usermod -aG wireshark \$USER', lets crowsnest run without sudo."
  echo
  # A dry run is for reading what would happen, so it continues past this --
  # useful for previewing the whole thing from a machine that is not the Pi.
  if [ "$DRY_RUN" = 1 ]; then
    note "[dry run] would offer to run that"
  elif ask "  Run that now?"; then
    echo
    # --yes means unattended, and debconf would otherwise stop on tshark's
    # question and wait for a keypress that is never coming.
    [ "$ASSUME_YES" = 1 ] && export DEBIAN_FRONTEND=noninteractive
    sh -c "$INSTALL_CMD" || {
      echo "that command failed -- install them yourself, then run this again" >&2
      exit 1
    }
    find_missing quiet
    if [ ${#MISSING[@]} -gt 0 ]; then
      echo "still missing after installing: ${MISSING[*]}" >&2
      exit 1
    fi
    note "installed"
  else
    echo
    echo "Nothing was installed. Run this again when you are ready."
    exit 1
  fi
  if [ "$DRY_RUN" = 1 ]; then
    echo
    note "continuing anyway because this is a dry run"
  fi
fi

# Work out which interface reaches the internet, if not given.
if [ -z "$WAN_IFACE" ]; then
  # `|| true` matters: under `set -e` a failing command substitution aborts the
  # script mid-run with no message, which is the worst way to learn that an
  # interface name was wrong.
  WAN_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)
fi
if [ -z "$WAN_IFACE" ]; then
  echo "Could not work out the internet-facing interface. Pass --iface eth0." >&2
  exit 1
fi
note "internet-facing interface: ${WAN_IFACE}"

SERVER_HOST=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null \
  | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}' || true)
note "this Pi on the LAN: ${SERVER_HOST:-unknown}"

# ------------------------------------------------------------------- keys
say "Generating keys"
run install -d -m 700 "$WG_DIR"

if [ -f "${WG_DIR}/server.key" ]; then
  note "server key already exists, keeping it"
else
  run sh -c "umask 077 && wg genkey > '${WG_DIR}/server.key'"
  run sh -c "wg pubkey < '${WG_DIR}/server.key' > '${WG_DIR}/server.pub'"
  note "server key created"
fi

if [ -f "${WG_DIR}/phone.key" ]; then
  note "phone key already exists, keeping it"
else
  run sh -c "umask 077 && wg genkey > '${WG_DIR}/phone.key'"
  run sh -c "wg pubkey < '${WG_DIR}/phone.key' > '${WG_DIR}/phone.pub'"
  run sh -c "umask 077 && wg genpsk > '${WG_DIR}/phone.psk'"
  note "phone key and pre-shared key created"
fi

if [ "$DRY_RUN" = 1 ]; then
  SERVER_KEY="<server private key>"; SERVER_PUB="<server public key>"
  PHONE_KEY="<phone private key>";   PHONE_PUB="<phone public key>"
  PHONE_PSK="<pre-shared key>"
else
  SERVER_KEY=$(cat "${WG_DIR}/server.key"); SERVER_PUB=$(cat "${WG_DIR}/server.pub")
  PHONE_KEY=$(cat "${WG_DIR}/phone.key");   PHONE_PUB=$(cat "${WG_DIR}/phone.pub")
  PHONE_PSK=$(cat "${WG_DIR}/phone.psk")
fi

# ------------------------------------------------------------------ server
say "Writing ${WG_DIR}/${WG_IFACE}.conf"

SERVER_CONF="[Interface]
Address = ${SERVER_V4}/24
ListenPort = ${PORT}
PrivateKey = ${SERVER_KEY}

[Peer]
# iPhone
PublicKey = ${PHONE_PUB}
PresharedKey = ${PHONE_PSK}
AllowedIPs = ${CLIENT_V4}/32
"

if [ "$DRY_RUN" = 1 ]; then
  printf '  [dry run] would write:\n'
  printf '%s\n' "$SERVER_CONF" | sed 's/^/      /'
else
  umask 077
  printf '%s' "$SERVER_CONF" > "${WG_DIR}/${WG_IFACE}.conf"
  note "written"
fi

# ---------------------------------------------------------------- forwarding
say "Enabling IP forwarding"
run sh -c "printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-crowsnest-forward.conf"
run sysctl -p /etc/sysctl.d/99-crowsnest-forward.conf

say "Adding NAT (table inet ${NAT_TABLE}, separate from crowsnest's own)"
run nft add table inet "$NAT_TABLE"
run nft add chain inet "$NAT_TABLE" postrouting \
  '{ type nat hook postrouting priority srcnat ; policy accept ; }'
run nft add rule inet "$NAT_TABLE" postrouting \
  ip saddr "$WG_NET_V4" oifname "$WAN_IFACE" masquerade

# ------------------------------------------------------------------- start
say "Starting WireGuard"
run systemctl enable --now "wg-quick@${WG_IFACE}"

# ------------------------------------------------------------ phone config
say "Phone configuration"
emit_phone_config

cat <<EOF

Next
  1. Install WireGuard from the App Store on the iPhone.
  2. Add a tunnel by scanning the QR code above.
  3. Turn the tunnel on, then confirm traffic is flowing:

       sudo wg show

  4. Watch it:

       sudo crowsnest live -i ${WG_IFACE} --me ${CLIENT_V4}

     --me tells crowsnest which address is the device being watched. Without it
     it would guess, and on a gateway the busiest address is not the phone.

  5. Block something:

       sudo crowsnest block <host> --gateway --client ${CLIENT_V4} --dry-run

EOF

if [ -n "$ENDPOINT_HOST" ]; then
  cat <<EOF
Endpoint
  Set to ${ENDPOINT_HOST}:${PORT}. For this to work away from home that name
  must resolve to your home connection from the outside, and UDP ${PORT} must
  be forwarded to this Pi. See docs/cellular.md, which also covers what to do
  when your ISP does not give you a real public address.

EOF
else
  cat <<EOF
Endpoint
  Set to ${ENDPOINT}:${PORT}, this Pi's LAN address, so the tunnel connects
  only at home. To cover cellular, read docs/cellular.md and then re-issue the
  config without redoing any of the above:

       sudo $0 --qr-only --endpoint <your-name>.duckdns.org

EOF
fi

cat <<EOF
Undo
  sudo $0 --uninstall
EOF
