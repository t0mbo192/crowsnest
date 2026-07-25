#!/usr/bin/env bash
#
# Install netwatch as a command on Linux or macOS.
#
#   ./install.sh                 install for the current user
#   ./install.sh --prefix DIR    install the command somewhere else
#   ./install.sh --uninstall     remove it again
#
# netwatch runs from this git clone: it is pure Python, so there is nothing to
# compile and `git pull` is the whole update process. All this does is check the
# dependencies and put a `netwatch` command on your PATH.
#
# It never runs sudo. Anything missing is reported with the command to fix it.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)    BIN_DIR="${2:?--prefix needs a directory}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help)   sed -n '3,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

say()  { printf '  %-19s %s\n' "$1" "$2"; }
fail() { printf '\n[!] %s\n' "$1" >&2; exit 1; }

TARGET="${BIN_DIR}/netwatch"

if [ "$UNINSTALL" = 1 ]; then
    if [ -e "$TARGET" ]; then
        rm -f "$TARGET"
        printf '\nRemoved %s\n' "$TARGET"
        printf 'The clone at %s is untouched; delete it if you want it gone.\n\n' "$REPO_DIR"
    else
        printf '\nNothing to remove at %s\n\n' "$TARGET"
    fi
    exit 0
fi

printf '\nnetwatch setup\n==============\n\n'

# --- platform ----------------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
    Linux)  PLATFORM="Linux" ;;
    Darwin) PLATFORM="macOS" ;;
    *)      PLATFORM="$OS" ;;
esac

# Work out how this system installs things, so the advice below is actionable.
if [ "$PLATFORM" = "macOS" ]; then
    TSHARK_HINT="brew install --cask wireshark"
    MMDB_HINT="pip3 install maxminddb"
elif command -v apt >/dev/null 2>&1; then
    TSHARK_HINT="sudo apt install tshark"
    MMDB_HINT="sudo apt install python3-maxminddb"
elif command -v dnf >/dev/null 2>&1; then
    TSHARK_HINT="sudo dnf install wireshark-cli"
    MMDB_HINT="sudo dnf install python3-maxminddb"
elif command -v pacman >/dev/null 2>&1; then
    TSHARK_HINT="sudo pacman -S wireshark-cli"
    MMDB_HINT="sudo pacman -S python-maxminddb"
elif command -v zypper >/dev/null 2>&1; then
    TSHARK_HINT="sudo zypper install wireshark"
    MMDB_HINT="sudo zypper install python3-maxminddb"
else
    TSHARK_HINT="install the 'tshark' package for your system"
    MMDB_HINT="pip3 install maxminddb"
fi
say "platform" "$PLATFORM"

# --- required ----------------------------------------------------------------
# Try each candidate and keep the first that actually runs and is new enough.
# Merely existing on PATH is not enough: a name can be a stub that fails when
# invoked, which is how Windows ships its Microsoft Store placeholder.
find_python() {
    local name candidate reported
    for name in python3 python; do
        candidate="$(command -v "$name" 2>/dev/null || true)"
        [ -n "$candidate" ] || continue
        reported="$("$candidate" -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)' 2>/dev/null || true)"
        if [ "$reported" = "1" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

PYTHON="$(find_python || true)"
if [ -z "$PYTHON" ]; then
    fail "Python 3.10 or newer not found. Install it and re-run this script."
fi
say "python" "$("$PYTHON" -V 2>&1) at $PYTHON"

if ! command -v tshark >/dev/null 2>&1; then
    printf '\ntshark is required -- netwatch reads packets with it.\n\n'
    printf '    %s\n\n' "$TSHARK_HINT"
    fail "Re-run this script once tshark is installed."
fi
say "tshark" "$(command -v tshark)"

# --- capture permissions -----------------------------------------------------
# Reading saved captures always works; capturing live traffic needs privileges.
if [ "$PLATFORM" = "macOS" ]; then
    if [ -r /dev/bpf0 ]; then
        say "live capture" "ok"
    else
        say "live capture" "needs sudo, or Wireshark's ChmodBPF helper"
    fi
elif getent group wireshark >/dev/null 2>&1; then
    if id -nG "$USER" 2>/dev/null | tr ' ' '\n' | grep -qx wireshark; then
        say "live capture" "ok (in wireshark group)"
    else
        say "live capture" "needs the wireshark group, or sudo"
        printf '        %s\n' "sudo usermod -aG wireshark $USER   (then log out and back in)"
    fi
else
    say "live capture" "needs sudo"
fi

# --- optional: organisation names for bare addresses -------------------------
if "$PYTHON" -c 'import maxminddb' >/dev/null 2>&1; then
    if "$PYTHON" -c "
import sys; sys.path.insert(0, '$REPO_DIR')
import asn_lookup; sys.exit(0 if asn_lookup.available() else 1)" >/dev/null 2>&1; then
        say "ASN database" "ok"
    else
        say "ASN database" "missing -- bare addresses will stay unnamed"
        printf '        %s\n' "netwatch asn --fetch"
    fi
else
    say "maxminddb" "not installed (optional, names address owners)"
    printf '        %s\n' "$MMDB_HINT"
    printf '        %s\n' "netwatch asn --fetch"
fi

# --- the command -------------------------------------------------------------
mkdir -p "$BIN_DIR" || fail "could not create $BIN_DIR"
cat > "$TARGET" <<EOF
#!/usr/bin/env bash
# Generated by netwatch install.sh -- runs netwatch from its git clone.
exec "$PYTHON" "$REPO_DIR/netwatch.py" "\$@"
EOF
chmod +x "$TARGET"
say "command" "$TARGET"

case ":${PATH}:" in
    *":${BIN_DIR}:"*) ON_PATH=1 ;;
    *)                ON_PATH=0 ;;
esac

VERSION="$("$PYTHON" -c "import sys; sys.path.insert(0,'$REPO_DIR'); from netwatch_version import __version__; print(__version__)")"

printf '\nDone -- netwatch %s is installed.\n\n' "$VERSION"
if [ "$ON_PATH" = 0 ]; then
    printf '  %s is not on your PATH yet. Add it:\n\n' "$BIN_DIR"
    printf '      echo '"'"'export PATH="%s:$PATH"'"'"' >> ~/.profile && . ~/.profile\n\n' "$BIN_DIR"
fi
cat <<EOF
  See interfaces      netwatch interfaces
  Watch live          sudo netwatch live -i eth0
  Read a capture      netwatch read capture.pcapng
  Update              cd $REPO_DIR && git pull
  Uninstall           $REPO_DIR/install.sh --uninstall

EOF
