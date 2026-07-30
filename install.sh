#!/usr/bin/env bash
#
# Install crowsnest as a command on Linux or macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/t0mbo192/crowsnest/main/install.sh | bash
#
# or, from a clone:
#
#   ./install.sh                 install for the current user
#   ./install.sh --prefix DIR    put the command somewhere other than ~/.local/bin
#   ./install.sh --yes           answer yes to every prompt (unattended)
#   ./install.sh --uninstall     remove it again
#
# Run from a clone, crowsnest runs from that clone and `git pull` updates it.
# Piped from curl there is no clone, so the source is fetched into
# ~/.local/share/crowsnest first. It is pure Python either way: nothing compiles.
#
# Anything missing -- Python, tshark -- is reported with the exact command that
# would fix it, and installed only if you say yes. Nothing runs unasked.

set -euo pipefail

REPO_URL="https://github.com/t0mbo192/crowsnest.git"
TARBALL_URL="https://codeload.github.com/t0mbo192/crowsnest/tar.gz/refs/heads/main"
SRC_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/crowsnest"
BIN_DIR="${HOME}/.local/bin"
UNINSTALL=0
ASSUME_YES=0

# Spelled out rather than read back out of this file: piped from curl there is
# no file to read, and `--help` that only works one of the two ways is worse
# than none.
usage() {
    cat <<'USAGE'
Install crowsnest as a command on Linux or macOS.

  curl -fsSL https://raw.githubusercontent.com/t0mbo192/crowsnest/main/install.sh | bash

or, from a clone:

  ./install.sh                 install for the current user
  ./install.sh --prefix DIR    put the command somewhere other than ~/.local/bin
  ./install.sh --yes           answer yes to every prompt (unattended)
  ./install.sh --uninstall     remove it again

Run from a clone, crowsnest runs from that clone and `git pull` updates it.
Piped from curl there is no clone, so the source is fetched into
~/.local/share/crowsnest first. It is pure Python either way: nothing compiles.

Anything missing -- Python, tshark -- is reported with the exact command that
would fix it, and installed only if you say yes. Nothing runs unasked.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)    BIN_DIR="${2:?--prefix needs a directory}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        -y|--yes)    ASSUME_YES=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

say()  { printf '  %-19s %s\n' "$1" "$2"; }
fail() { printf '\n[!] %s\n' "$1" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# `curl | bash` leaves stdin holding the rest of this script, so a prompt read
# from stdin would silently swallow script text instead of waiting for an answer.
# The terminal has to be opened directly.
ask() {
    [ "$ASSUME_YES" = 1 ] && return 0
    local reply=""
    printf '%s [y/N] ' "$1"
    # Having a controlling terminal is not the same as /dev/tty existing: piped
    # in with no tty, the file is there but opening it fails, and `[ -r ]` does
    # not catch that -- it let bash print a raw redirection error instead.
    # Attempt the open itself, quietly.
    if { exec 3</dev/tty; } 2>/dev/null; then
        read -r reply <&3 || reply=""
        exec 3<&-
    elif [ -t 0 ]; then
        read -r reply || reply=""
    else
        # Piped in with nothing to ask on. Silence is not consent.
        printf 'no terminal to ask on, assuming no\n'
        return 1
    fi
    case "$reply" in [Yy]|[Yy][Ee][Ss]) return 0 ;; *) return 1 ;; esac
}

# What is printed is exactly what runs -- one string, shown then executed, so
# the two can never drift apart.
offer() {
    local what="$1" cmd="$2" why="${3:-}"
    local shown="${cmd:-(no known command for this system)}"
    if [ -n "$why" ]; then
        printf '\n  %s is required -- %s.\n\n      %s\n\n' "$what" "$why" "$shown"
    else
        printf '\n  %s is required.\n\n      %s\n\n' "$what" "$shown"
    fi
    [ -n "$cmd" ] || return 1
    if ask "  Run that now?"; then
        printf '\n'
        sh -c "$cmd" || fail "that command failed -- install $what yourself, then re-run"
        return 0
    fi
    return 1
}

# --- where the source is ------------------------------------------------------
# Running from a clone means this file sits next to crowsnest.py. Piped from
# curl, BASH_SOURCE is not a file at all -- and process substitution makes it a
# file in /dev/fd with no crowsnest.py beside it, so test for the source itself
# rather than for how we were invoked.
BOOTSTRAP=1
REPO_DIR="$SRC_DIR"
SELF="${BASH_SOURCE[0]:-}"
if [ -n "$SELF" ] && [ -f "$SELF" ]; then
    here="$(cd "$(dirname "$SELF")" 2>/dev/null && pwd)" || here=""
    if [ -n "$here" ] && [ -f "$here/crowsnest.py" ]; then
        BOOTSTRAP=0
        REPO_DIR="$here"
    fi
fi

TARGET="${BIN_DIR}/crowsnest"

# --- uninstall ----------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
    # The desktop launcher belongs to the invoking user, not to root, when this
    # is re-run under sudo to remove a command installed system-wide.
    # `|| true` because pipefail turns a missing getent -- macOS has none -- into
    # a fatal error, aborting an uninstall that was about to succeed.
    uhome="${SUDO_USER:+$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)}" || true
    launcher="${uhome:-$HOME}/.local/share/applications/crowsnest.desktop"
    if [ -e "$launcher" ]; then
        rm -f "$launcher"
        printf '\nRemoved %s\n' "$launcher"
    fi
    if [ -e "$TARGET" ]; then
        rm -f "$TARGET"
        printf 'Removed %s\n' "$TARGET"
    else
        printf '\nNothing to remove at %s\n' "$TARGET"
    fi
    # Only the copy this installer fetched. A clone you made is yours to keep.
    # Checking for crowsnest.py first means a wrong or empty SRC_DIR cannot turn
    # this into a stray rm -rf.
    if [ -f "$SRC_DIR/crowsnest.py" ]; then
        rm -rf "$SRC_DIR"
        printf 'Removed %s\n' "$SRC_DIR"
    fi
    # Only when it really is a clone of your own. Uninstalling by running the
    # fetched copy's own install.sh makes REPO_DIR and SRC_DIR the same path, and
    # claiming it was left alone directly under "Removed" is a plain
    # contradiction.
    if [ "$BOOTSTRAP" = 0 ] && [ "$REPO_DIR" != "$SRC_DIR" ]; then
        printf 'The clone at %s is untouched; delete it if you want it gone.\n' "$REPO_DIR"
    fi
    printf '\n'
    exit 0
fi

printf '\ncrowsnest setup\n==============\n\n'

# --- platform -----------------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
    Linux)  PLATFORM="Linux" ;;
    Darwin) PLATFORM="macOS" ;;
    *)      PLATFORM="$OS" ;;
esac

# How this system installs things, so both the advice and the offer to act on it
# are right for the machine in front of us.
if [ "$PLATFORM" = "macOS" ]; then
    TSHARK_INSTALL="brew install --cask wireshark"
    PYTHON_INSTALL="brew install python"
    MMDB_HINT="pip3 install maxminddb"
    have brew || {
        TSHARK_INSTALL=""
        PYTHON_INSTALL=""
    }
elif have apt-get; then
    TSHARK_INSTALL="sudo apt-get install -y tshark"
    PYTHON_INSTALL="sudo apt-get install -y python3"
    MMDB_HINT="sudo apt install python3-maxminddb"
elif have dnf; then
    TSHARK_INSTALL="sudo dnf install -y wireshark-cli"
    PYTHON_INSTALL="sudo dnf install -y python3"
    MMDB_HINT="sudo dnf install python3-maxminddb"
elif have pacman; then
    TSHARK_INSTALL="sudo pacman -S --noconfirm wireshark-cli"
    PYTHON_INSTALL="sudo pacman -S --noconfirm python"
    MMDB_HINT="sudo pacman -S python-maxminddb"
elif have zypper; then
    TSHARK_INSTALL="sudo zypper install -y wireshark"
    PYTHON_INSTALL="sudo zypper install -y python3"
    MMDB_HINT="sudo zypper install python3-maxminddb"
else
    TSHARK_INSTALL=""
    PYTHON_INSTALL=""
    MMDB_HINT="pip3 install maxminddb"
fi
say "platform" "$PLATFORM"
if [ "$PLATFORM" = "macOS" ] && ! have brew; then
    say "homebrew" "not installed -- see https://brew.sh to have this offer to fix things"
fi

# --- python -------------------------------------------------------------------
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
    offer "Python 3.10 or newer" "$PYTHON_INSTALL" || true
    PYTHON="$(find_python || true)"
    [ -n "$PYTHON" ] || fail "Python 3.10 or newer not found. Install it and re-run."
fi
say "python" "$("$PYTHON" -V 2>&1) at $PYTHON"

# --- tshark -------------------------------------------------------------------
# The macOS cask installs tshark inside the app bundle, where PATH does not
# reach it. crowsnest looks there before giving up, so refusing to install here
# on a machine that has Wireshark would be stricter than the tool itself.
MAC_TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
# Runs in a command substitution, so it must report through its output only:
# anything it assigns is lost with the subshell.
find_tshark() {
    local found
    found="$(command -v tshark 2>/dev/null || true)"
    if [ -z "$found" ] && [ -x "$MAC_TSHARK" ]; then
        found="$MAC_TSHARK"
    fi
    printf '%s\n' "$found"
}

TSHARK="$(find_tshark)"
if [ -z "$TSHARK" ]; then
    offer "tshark" "$TSHARK_INSTALL" "crowsnest reads packets with it" || true
    TSHARK="$(find_tshark)"
    [ -n "$TSHARK" ] || fail "Re-run this script once tshark is installed."
fi
say "tshark" "$TSHARK"
if [ "$TSHARK" = "$MAC_TSHARK" ]; then
    printf '        %s\n' "inside the app bundle -- crowsnest finds it, your shell will not"
fi

# --- the source ---------------------------------------------------------------
if [ "$BOOTSTRAP" = 1 ]; then
    UPDATE_HINT="cd $SRC_DIR && git pull"
    if [ -d "$SRC_DIR/.git" ] && have git; then
        git -C "$SRC_DIR" pull --ff-only --quiet \
            || fail "could not update $SRC_DIR -- delete it and re-run"
        say "source" "$SRC_DIR (updated)"
    elif [ ! -e "$SRC_DIR" ] && have git; then
        mkdir -p "$(dirname "$SRC_DIR")"
        git clone --quiet --depth 1 "$REPO_URL" "$SRC_DIR" \
            || fail "could not clone $REPO_URL"
        say "source" "$SRC_DIR"
    else
        # No git needed: crowsnest is pure Python, so a tarball is the whole
        # program. Updating then means re-running this installer.
        have curl || have wget || fail "need git, curl or wget to fetch crowsnest"
        mkdir -p "$SRC_DIR"
        if have curl; then fetch() { curl -fsSL "$1"; }
        else                fetch() { wget -qO- "$1"; }
        fi
        fetch "$TARBALL_URL" | tar -xz --strip-components=1 -C "$SRC_DIR" \
            || fail "could not download $TARBALL_URL"
        say "source" "$SRC_DIR (no git -- re-run the installer to update)"
        UPDATE_HINT="re-run the install command"
    fi
    [ -f "$REPO_DIR/crowsnest.py" ] || fail "crowsnest.py missing from $REPO_DIR"
else
    UPDATE_HINT="cd $REPO_DIR && git pull"
fi

# --- capture permissions ------------------------------------------------------
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

# --- optional: organisation names for bare addresses --------------------------
if "$PYTHON" -c 'import maxminddb' >/dev/null 2>&1; then
    if "$PYTHON" -c "
import sys; sys.path.insert(0, '$REPO_DIR')
import asn_lookup; sys.exit(0 if asn_lookup.available() else 1)" >/dev/null 2>&1; then
        say "ASN database" "ok"
    else
        say "ASN database" "missing -- bare addresses will stay unnamed"
        printf '        %s\n' "crowsnest asn --fetch"
    fi
else
    say "maxminddb" "not installed (optional, names address owners)"
    printf '        %s\n' "$MMDB_HINT"
    printf '        %s\n' "crowsnest asn --fetch"
fi

# --- the command --------------------------------------------------------------
mkdir -p "$BIN_DIR" || fail "could not create $BIN_DIR"
cat > "$TARGET" <<EOF
#!/usr/bin/env bash
# Generated by crowsnest install.sh -- runs crowsnest from its source directory.
exec "$PYTHON" "$REPO_DIR/crowsnest.py" "\$@"
EOF
chmod +x "$TARGET"
say "command" "$TARGET"

case ":${PATH}:" in
    *":${BIN_DIR}:"*) ON_PATH=1 ;;
    *)                ON_PATH=0 ;;
esac

# --- desktop launcher ---------------------------------------------------------
# On a machine with a screen -- a Pi wired to a monitor, say -- a menu entry
# that opens the dashboard in its own terminal window is the natural way to run
# this. Skipped entirely on a headless box, where it would just be clutter.
DESKTOP_HOME="${SUDO_USER:+$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)}" || true
DESKTOP_HOME="${DESKTOP_HOME:-$HOME}"
DESKTOP_DIR="${DESKTOP_HOME}/.local/share/applications"

if [ "$PLATFORM" = "Linux" ] && [ -d "${DESKTOP_HOME}/.local/share" ]; then
    # Watch whichever interface actually carries the default route. `|| true`
    # because pipefail makes an absent `ip` fatal, which killed the script here
    # -- after the command was installed but before it said so.
    IFACE="$(ip route show default 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')" || true
    IFACE="${IFACE:-eth0}"
    mkdir -p "$DESKTOP_DIR"
    cat > "${DESKTOP_DIR}/crowsnest.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=crowsnest
Comment=Watch which hosts this machine talks to, and what talks to it
Exec=sudo ${TARGET} live -i ${IFACE} --dashboard
Icon=utilities-system-monitor
Terminal=true
Categories=Network;Monitor;System;
EOF
    chmod +x "${DESKTOP_DIR}/crowsnest.desktop" 2>/dev/null || true
    if [ -n "${SUDO_USER:-}" ]; then
        chown "$SUDO_USER" "${DESKTOP_DIR}/crowsnest.desktop" 2>/dev/null || true
    fi
    say "menu entry" "${DESKTOP_DIR}/crowsnest.desktop  (watches ${IFACE})"
fi

VERSION="$("$PYTHON" -c "import sys; sys.path.insert(0,'$REPO_DIR'); from crowsnest_version import __version__; print(__version__)")"

# --- PATH ---------------------------------------------------------------------
if [ "$ON_PATH" = 0 ]; then
    # Name the file this shell will actually read. zsh -- the default on macOS
    # since Catalina -- never reads ~/.profile, so pointing everyone there sends
    # Mac users to a file that is silently ignored, and the command stays missing.
    case "$(basename "${SHELL:-sh}")" in
        zsh)  PROFILE="${ZDOTDIR:-$HOME}/.zprofile" ;;
        bash) [ "$PLATFORM" = "macOS" ] && PROFILE="$HOME/.bash_profile" \
                                        || PROFILE="$HOME/.profile" ;;
        *)    PROFILE="$HOME/.profile" ;;
    esac
    PATH_LINE="export PATH=\"$BIN_DIR:\$PATH\""
    printf '\n  %s is not on your PATH, so `crowsnest` will not be found yet.\n\n' "$BIN_DIR"
    if grep -qsF "$PATH_LINE" "$PROFILE"; then
        say "PATH" "already added to $PROFILE -- open a new terminal"
    elif ask "  Add it to $PROFILE?"; then
        printf '\n# added by crowsnest install.sh\n%s\n' "$PATH_LINE" >> "$PROFILE"
        say "PATH" "added to $PROFILE"
        printf '        %s\n' "open a new terminal, or run: . $PROFILE"
    else
        printf '      echo '"'"'%s'"'"' >> %s && . %s\n' "$PATH_LINE" "$PROFILE" "$PROFILE"
    fi
fi

printf '\nDone -- crowsnest %s is installed.\n\n' "$VERSION"
# Name an interface that exists here: Macs have no eth0, and a first command
# that fails is a poor introduction.
[ "$PLATFORM" = "macOS" ] && EXAMPLE_IFACE="en0" || EXAMPLE_IFACE="${IFACE:-eth0}"
# --dashboard is named here because it is the view people install this for --
# the one in the screenshot. Leaving it out of the only instructions anyone reads
# meant they had to go and find it.
cat <<EOF
  To watch traffic:

    sudo crowsnest live -i $EXAMPLE_IFACE --dashboard

  Press q to leave the dashboard. Drop --dashboard for a plain list that
  prints each host once and then stays quiet. \`crowsnest interfaces\` shows
  what else you could watch, and marks the one your traffic actually uses.

  Reading a saved capture needs no privileges:

    crowsnest read capture.pcapng

  Update:     $UPDATE_HINT
  Uninstall:  $REPO_DIR/install.sh --uninstall

EOF
