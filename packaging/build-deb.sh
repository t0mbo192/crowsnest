#!/usr/bin/env bash
#
# Build a Debian package of crowsnest.
#
#   packaging/build-deb.sh [--output DIR]
#
# Produces dist/crowsnest_<version>_all.deb, which installs like this:
#
#   sudo apt install ./crowsnest_1.0.0_all.deb
#
# apt then pulls tshark in as a dependency, which is the whole point: on Debian
# and Raspberry Pi OS that turns the one real prerequisite into something the
# package manager handles rather than something the user is told to go and do.
#
# Architecture is `all` because crowsnest is pure Python -- nothing is compiled,
# so one package serves the Pi's arm64 and everything else.
#
# Needs dpkg-deb (dpkg >= 1.19 for --root-owner-group) and python3.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/dist"

# A noreply address on purpose: the package is published, and the maintainer
# field would otherwise put a personal email in every copy of it.
MAINTAINER="Tombo192 <t0mbo192@users.noreply.github.com>"
HOMEPAGE="https://github.com/t0mbo192/crowsnest"

while [ $# -gt 0 ]; do
    case "$1" in
        --output) OUT="${2:?--output needs a directory}"; shift 2 ;;
        -h|--help) sed -n '3,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

command -v dpkg-deb >/dev/null 2>&1 || {
    printf 'dpkg-deb not found -- this builds on Debian/Ubuntu.\n' >&2
    exit 1
}

VERSION="$(python3 -c "import sys; sys.path.insert(0, '$ROOT'); from crowsnest_version import __version__; print(__version__)")"

# The module list comes from pyproject.toml rather than being written out again
# here. Keeping a second copy is how the wheel once shipped without blocking.py:
# the import is lazy, so nothing noticed until `crowsnest block` was run.
MODULES="$(python3 - "$ROOT" <<'PY'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
with open(root / "pyproject.toml", "rb") as handle:
    data = tomllib.load(handle)
for module in data["tool"]["setuptools"]["py-modules"]:
    print(f"{module}.py")
PY
)"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/crowsnest"

install -d "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/share/crowsnest" \
           "$PKG/usr/share/doc/crowsnest"

# --- the program --------------------------------------------------------------
# /usr/share rather than /usr/lib: nothing here is architecture-dependent.
missing=0
for module in $MODULES; do
    if [ ! -f "$ROOT/$module" ]; then
        printf 'listed in pyproject.toml but not present: %s\n' "$module" >&2
        missing=1
        continue
    fi
    install -m 644 "$ROOT/$module" "$PKG/usr/share/crowsnest/$module"
done
[ "$missing" = 0 ] || exit 1

cat > "$PKG/usr/bin/crowsnest" <<'EOF'
#!/bin/sh
# Installed by the crowsnest package. crowsnest is pure Python; this runs it.
exec python3 /usr/share/crowsnest/crowsnest.py "$@"
EOF
chmod 755 "$PKG/usr/bin/crowsnest"

# --- control ------------------------------------------------------------------
# python3 (>= 3.10) is a real constraint, not decoration: bookworm ships 3.11 and
# satisfies it, bullseye ships 3.9 and is correctly refused rather than being let
# in to fail at runtime.
#
# tshark is what makes this worth packaging at all. nftables and
# python3-maxminddb are Recommends, so a default install gets working blocking
# and organisation names, and someone who does not want them can say so.
SIZE="$(du -ks "$PKG/usr" | cut -f1)"
cat > "$PKG/DEBIAN/control" <<EOF
Package: crowsnest
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10), tshark
Recommends: python3-maxminddb, nftables
Maintainer: $MAINTAINER
Homepage: $HOMEPAGE
Installed-Size: $SIZE
Description: see which hosts a machine talks to, in plain language
 Wireshark tells you everything; crowsnest tells you who. It reduces captured
 traffic to the question usually being asked: what is this machine talking to,
 and what is talking to it.
 .
 Each host is reported once, when it first appears, split by direction and
 labelled with what it actually is rather than left as a bare address. It reads
 saved captures and watches interfaces live, and can shut a host out with
 nftables.
 .
 Traffic is encrypted, so crowsnest reports which hosts were contacted -- from
 DNS and the TLS server name -- never page content or URLs.
EOF

# --- maintainer scripts -------------------------------------------------------
# Python writes __pycache__ beside the modules the first time they are imported.
# dpkg does not own those files, so it refuses to remove the directory on purge
# and leaves /usr/share/crowsnest behind. Compiling at install time and cleaning
# up at removal is the Debian answer; the rm in postrm covers anything py3clean
# missed, so an uninstall really does leave nothing.
cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    py3compile /usr/share/crowsnest 2>/dev/null || true
fi
EOF

cat > "$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "upgrade" ] || [ "$1" = "deconfigure" ]; then
    py3clean /usr/share/crowsnest 2>/dev/null || true
fi
EOF

cat > "$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    rm -rf /usr/share/crowsnest/__pycache__
    rmdir /usr/share/crowsnest 2>/dev/null || true
fi
EOF

chmod 755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"

# --- documentation ------------------------------------------------------------
# Generated from LICENSE so the two cannot disagree.
{
    printf 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n'
    printf 'Upstream-Name: crowsnest\n'
    printf 'Source: %s\n\n' "$HOMEPAGE"
    printf 'Files: *\n'
    printf 'Copyright: 2026 Tombo192\n'
    printf 'License: MIT\n'
    sed 's/^/ /; s/^ $/ ./' "$ROOT/LICENSE"
    printf '\n'
    printf 'Comment: The ASN database crowsnest can download is not part of this\n'
    printf ' package and is not redistributed by it. IP-to-ASN data by DB-IP\n'
    printf ' (https://db-ip.com) is licensed under CC-BY 4.0.\n'
} > "$PKG/usr/share/doc/crowsnest/copyright"
chmod 644 "$PKG/usr/share/doc/crowsnest/copyright"

# The gateway helper ships too. Watching a phone is a headline feature, and
# without this a packaged install has no way to set the tunnel up -- the script
# would only exist in a git clone the user was told they did not need.
install -d "$PKG/usr/share/doc/crowsnest/examples"
install -m 755 "$ROOT/docs/setup-wireguard.sh" \
    "$PKG/usr/share/doc/crowsnest/examples/setup-wireguard.sh"
install -m 644 "$ROOT/docs/cellular.md" \
    "$PKG/usr/share/doc/crowsnest/examples/cellular.md"

cat > "$STAGE/changelog" <<EOF
crowsnest ($VERSION) stable; urgency=medium

  * Release $VERSION. See $HOMEPAGE/releases for what changed.

 -- $MAINTAINER  $(date -R)
EOF
gzip -9n -c "$STAGE/changelog" > "$PKG/usr/share/doc/crowsnest/changelog.Debian.gz"
chmod 644 "$PKG/usr/share/doc/crowsnest/changelog.Debian.gz"

# --- build --------------------------------------------------------------------
mkdir -p "$OUT"
TARGET="$OUT/crowsnest_${VERSION}_all.deb"
# --root-owner-group so the contents are owned by root without needing fakeroot
# or building as root.
dpkg-deb --build --root-owner-group "$PKG" "$TARGET" >/dev/null

printf '\nBuilt %s\n\n' "$TARGET"
dpkg-deb --info "$TARGET" | sed -n '/Package:/,/^ *$/p' | head -14
printf '\nInstall it with:\n\n    sudo apt install %s\n\n' "$TARGET"
