#!/usr/bin/env python3
"""Name the organisation behind an IP address, offline.

The curated keyword table in crowsnest_core recognises hosts by name, but it can
only cover what someone thought to list, and it needs a hostname in the first
place. Plenty of addresses have neither a useful name nor a PTR record, and used
to show up as "Unknown host". An ASN database fixes that: every routable address
belongs to an autonomous system, and the AS has an owner.

    160.79.104.10   -> Anthropic, PBC
    74.125.9.138    -> Google LLC
    140.82.114.25   -> GitHub, Inc.

Lookups are local, so no address ever leaves the machine, and it works with no
network at all -- which matters for a Pi appliance.

Everything here degrades quietly: with no `maxminddb` module or no database file,
lookups return nothing and crowsnest falls back to its previous behaviour. Fetch a
database with:

    python asn_lookup.py --fetch

Data is DB-IP's IP-to-ASN Lite, licensed CC-BY 4.0 -- see ATTRIBUTION below.
MaxMind's GeoLite2-ASN.mmdb works too, if you already have one.
"""

from __future__ import annotations

import gzip
import os
import shutil
import sys
import threading
import urllib.request
from datetime import date, timedelta

ATTRIBUTION = "IP-to-ASN data by DB-IP (https://db-ip.com) — CC-BY 4.0"

# Recognised database filenames, most preferred first.
DB_FILENAMES = ("dbip-asn-lite.mmdb", "GeoLite2-ASN.mmdb", "dbip-asn.mmdb")

# DB-IP publish a fresh free database each month.
DBIP_URL = "https://download.db-ip.com/free/dbip-asn-lite-{ym}.mmdb.gz"

# The database is around 10 MB. This is the ceiling on what --fetch will write,
# so a wrong or hostile response cannot fill the disk by decompressing.
MAX_DB_BYTES = 256 << 20

_lock = threading.Lock()
_reader = None            # opened maxminddb reader, or False once known bad
_cache: dict[str, tuple[int, str] | None] = {}
_status = "not initialised"


def invoking_user_home() -> str | None:
    """Home of the user who called sudo, when we are running under it.

    Live capture and blocking both need root, so crowsnest normally runs under
    sudo -- where HOME is /root and a database sitting in the real user's home
    is invisible. Without this, the naming that was just set up silently stops
    working the moment it is used the way it is meant to be used.
    """
    user = os.environ.get("SUDO_USER")
    if not user or user == "root":
        return None
    try:
        import pwd
        return pwd.getpwnam(user).pw_dir
    except (ImportError, KeyError):
        return None


def give_back_to_invoker(*paths: str) -> None:
    """Hand files created under sudo back to the user who ran it.

    Live capture and blocking both need root, so anything crowsnest writes while
    doing them lands in the invoking user's home owned by root. Left that way the
    user cannot manage the file crowsnest just made for them, and the next run
    without sudo cannot write it at all. Best effort: failing to chown is never
    worth aborting the operation that succeeded.
    """
    user = os.environ.get("SUDO_USER")
    if not user or user == "root" or os.name == "nt":
        return
    try:
        import pwd
        entry = pwd.getpwnam(user)
    except (ImportError, KeyError):
        return
    for path in paths:
        try:
            os.chown(path, entry.pw_uid, entry.pw_gid)
        except OSError:
            pass


def data_dir() -> str:
    """Where crowsnest keeps its own files."""
    return os.path.join(os.path.expanduser("~"), ".crowsnest")


def legacy_data_dir() -> str:
    """Where this tool kept its files when it was called netwatch.

    Still searched so a database downloaded under the old name keeps working
    instead of being silently orphaned -- it is ~10 MB and nothing about it
    changed with the rename.
    """
    return os.path.join(os.path.expanduser("~"), ".netwatch")


def search_paths() -> list[str]:
    """Every place a database might reasonably live."""
    here = os.path.dirname(os.path.abspath(
        sys.executable if getattr(sys, "frozen", False) else __file__))
    dirs = [data_dir(), legacy_data_dir(), here]
    # Under sudo, HOME is /root, so also look where the real user keeps things.
    invoker = invoking_user_home()
    if invoker:
        dirs[1:1] = [os.path.join(invoker, ".crowsnest"),
                     os.path.join(invoker, ".netwatch")]
    if os.name == "nt":
        dirs.append(os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                                 "crowsnest"))
    else:
        dirs += ["/usr/share/GeoIP", "/var/lib/GeoIP", "/usr/local/share/GeoIP"]

    paths = []
    override = os.environ.get("CROWSNEST_ASN_DB")
    if override:
        paths.append(override)          # explicit wins over everything
    for d in dirs:
        for name in DB_FILENAMES:
            paths.append(os.path.join(d, name))
    return paths


def find_database() -> str | None:
    for path in search_paths():
        if path and os.path.isfile(path):
            return path
    return None


def _open() -> object | None:
    """Open the database once, remembering failure so we don't retry endlessly."""
    global _reader, _status
    if _reader is not None:
        return _reader or None

    try:
        import maxminddb
    except ImportError:
        _reader = False
        _status = ("maxminddb is not installed — ASN names unavailable "
                   "(pip install maxminddb, or apt install python3-maxminddb)")
        return None

    path = find_database()
    if not path:
        _reader = False
        # Name a directory that is actually useful: under sudo, data_dir() is
        # /root/.crowsnest, which is not where anyone would want to put it.
        where = invoking_user_home()
        target = os.path.join(where, ".crowsnest") if where else data_dir()
        _status = ("no ASN database found - run `crowsnest asn --fetch` "
                   f"or put one in {target}")
        return None
    try:
        _reader = maxminddb.open_database(path)
        kind = _reader.metadata().database_type
        _status = f"{kind} — {os.path.basename(path)}"
    except Exception as e:                    # corrupt or unreadable file
        _reader = False
        _status = f"could not open {path}: {e}"
        return None
    return _reader


def available() -> bool:
    with _lock:
        return _open() is not None


def status() -> str:
    with _lock:
        _open()
        return _status


def lookup(ip: str) -> tuple[int, str] | None:
    """(asn, organisation) for an address, or None if it can't be determined."""
    if not ip:
        return None
    with _lock:
        if ip in _cache:
            return _cache[ip]
        reader = _open()
        result = None
        if reader is not None:
            try:
                record = reader.get(ip)
            except (ValueError, OSError):     # not an address the DB accepts
                record = None
            if isinstance(record, dict):
                org = (record.get("autonomous_system_organization") or "").strip()
                asn = record.get("autonomous_system_number")
                if org:
                    result = (int(asn) if asn else 0, org)
        _cache[ip] = result
        return result


def organisation(ip: str) -> str:
    """Just the owning organisation's name, or "" if unknown."""
    found = lookup(ip)
    return found[1] if found else ""


# --------------------------------------------------------------------- fetching
def fetch(dest_dir: str | None = None, months_back: int = 3) -> str:
    """Download the current DB-IP ASN Lite database. Returns the file path.

    The newest month is not always published yet, so this walks back a little.
    """
    dest_dir = dest_dir or data_dir()
    os.makedirs(dest_dir, exist_ok=True)
    target = os.path.join(dest_dir, "dbip-asn-lite.mmdb")

    today = date.today().replace(day=1)
    errors = []
    for back in range(months_back):
        month = today
        for _ in range(back):
            month = (month - timedelta(days=1)).replace(day=1)
        url = DBIP_URL.format(ym=f"{month.year:04d}-{month.month:02d}")
        try:
            print(f"fetching {url}")
            request = urllib.request.Request(
                url, headers={"User-Agent": "crowsnest"})
            with urllib.request.urlopen(request, timeout=180) as response, \
                    open(target + ".gz", "wb") as out:
                shutil.copyfileobj(response, out)
            # Bounded rather than copyfileobj: a compressed file says nothing
            # about how large it becomes, and this one is fetched from the
            # network. The real database is ~10 MB, so anything approaching the
            # cap is not the database.
            written = 0
            with gzip.open(target + ".gz", "rb") as gz, open(target, "wb") as out:
                while True:
                    chunk = gz.read(1 << 20)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_DB_BYTES:
                        raise RuntimeError(
                            f"database is larger than {MAX_DB_BYTES >> 20} MB "
                            "-- refusing it")
                    out.write(chunk)
            os.remove(target + ".gz")
            size = os.path.getsize(target) / (1 << 20)
            # Fetching may well have happened under sudo; the database belongs
            # to the user whose home it is in.
            give_back_to_invoker(dest_dir, target)
            print(f"saved {target}  ({size:.1f} MB)")
            print(ATTRIBUTION)
            return target
        except Exception as e:
            errors.append(f"  {url}: {e}")
    raise RuntimeError("could not download a database:\n" + "\n".join(errors))


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fetch", action="store_true",
                    help="download the current DB-IP ASN Lite database")
    ap.add_argument("ips", nargs="*", help="addresses to look up")
    args = ap.parse_args()

    if args.fetch:
        try:
            fetch()
        except RuntimeError as e:
            sys.exit(str(e))
        return

    print(f"database: {status()}")
    if args.ips:
        print()
        for ip in args.ips:
            found = lookup(ip)
            print(f"  {ip:<40} {found[1] + f'  (AS{found[0]})' if found else '-'}")
    elif available():
        print(ATTRIBUTION)


if __name__ == "__main__":
    main()
