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
#   sudo ./setup-wireguard.sh --uninstall

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
# NAT lives in its own table so that dropping crowsnest's table -- which
# `crowsnest unblock --all` does -- cannot take the Pi's routing with it.
NAT_TABLE=crowsnest_nat

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   DRY_RUN=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --port)      PORT="$2"; shift ;;
    --iface)     WAN_IFACE="$2"; shift ;;
    --dns)       DNS_SERVER="$2"; shift ;;
    -h|--help)   sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '  [dry run] %s\n' "$*"
  else
    "$@"
  fi
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

# ------------------------------------------------------------ prerequisites
say "Checking prerequisites"

MISSING=()
for pkg_cmd in "wireguard-tools:wg" "nftables:nft" "tshark:tshark" "qrencode:qrencode"; do
  pkg="${pkg_cmd%%:*}"; cmd="${pkg_cmd##*:}"
  if command -v "$cmd" >/dev/null 2>&1; then
    note "found $cmd"
  else
    note "MISSING $cmd (package: $pkg)"
    MISSING+=("$pkg")
  fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo
  echo "Install what's missing, then run this again:"
  echo
  echo "  sudo apt update && sudo apt install -y ${MISSING[*]}"
  echo
  echo "tshark will ask whether non-root users may capture. Answering yes and"
  echo "running 'sudo usermod -aG wireshark \$USER' lets crowsnest run without sudo."
  # A dry run is for reading what would happen, so it continues past this --
  # useful for previewing the whole thing from a machine that is not the Pi.
  if [ "$DRY_RUN" = 0 ]; then
    exit 1
  fi
  echo
  note "continuing anyway because this is a dry run"
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

# Endpoint must be reachable from the phone. On the LAN that is the Pi's own
# address; from outside it needs a public address or dynamic-DNS name and a
# forwarded UDP port -- which is what makes this work on cellular.
ENDPOINT="${SERVER_HOST:-<public address or DDNS name of this Pi>}"

# DNS goes to a public resolver rather than to this Pi, because nothing is
# listening on ${SERVER_V4}:53 and a phone with no resolver has no internet.
# Visibility is unaffected: the queries are plaintext UDP/53 and cross wg0
# either way, so crowsnest reads them off the wire, not from a resolver's log.
# Running dnsmasq or Pi-hole here and pointing this at ${SERVER_V4} is a
# worthwhile upgrade -- it adds domain-level blocking -- but it is not needed
# for any of what follows.
PHONE_CONF="[Interface]
PrivateKey = ${PHONE_KEY}
Address = ${CLIENT_V4}/32
DNS = ${DNS_SERVER}

[Peer]
PublicKey = ${SERVER_PUB}
PresharedKey = ${PHONE_PSK}
Endpoint = ${ENDPOINT}:${PORT}
# Everything, so cellular traffic is covered too.
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"

if [ "$DRY_RUN" = 1 ]; then
  printf '  [dry run] would write %s/phone.conf and print a QR code\n' "$WG_DIR"
else
  umask 077
  printf '%s' "$PHONE_CONF" > "${WG_DIR}/phone.conf"
  echo
  printf '%s' "$PHONE_CONF" | qrencode -t ansiutf8
  echo
  note "also saved to ${WG_DIR}/phone.conf"
fi

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

       sudo crowsnest block <host> --gateway --dry-run

Note
  The endpoint above is ${ENDPOINT}. That works on your own network. For this
  to work on cellular the phone must reach this Pi from outside, which needs a
  public address or dynamic DNS plus UDP ${PORT} forwarded to it. Until then
  the tunnel connects only at home.

  Undo everything with: sudo $0 --uninstall
EOF
