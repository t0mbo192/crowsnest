#!/usr/bin/env python3
"""
netwatch -- see which hosts this machine talks to, in plain language.

Wireshark tells you everything; this tells you who. Every connection is split
into outbound (this machine started it) and inbound (something else did), and
each host is labelled with what it actually is rather than left as an address.

    netwatch live -i eth0                  watch traffic as it happens
    netwatch read capture.pcapng           analyse a saved capture
    netwatch interfaces                    what can I capture on?
    netwatch asn --fetch                   get the database that names owners

Direction comes from the TCP handshake: whoever sends the opening SYN started
the connection. Encrypted traffic still reveals which hosts were contacted --
from DNS and the TLS server name -- but never page content or URLs, which is the
ceiling for anything working from packets.

Needs tshark (from Wireshark). Live capture needs privileges: run under sudo, or
add yourself to the wireshark group.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import queue
import signal
import sys
import threading
import time

import netwatch_core as core
from netwatch_version import __version__

ESC = "\x1b["


# ----------------------------------------------------------------- terminal
def enable_ansi() -> bool:
    """Turn on VT escape handling on Windows. True when colour is usable."""
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            handle = ctypes.windll.kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            return False
    return True


def unicode_ok() -> bool:
    """Whether the terminal can print the glyphs we would like to use.

    A legacy Windows console on a cp1252 codepage turns them into mojibake, so
    the display falls back to ASCII rather than looking broken.
    """
    try:
        "·↑↓".encode(sys.stdout.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError, TypeError):
        return False


def term_width(default: int = 100) -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return int(os.environ.get("COLUMNS", default))


class Style:
    """ANSI colours that vanish when colour is off."""

    DIM, BOLD = "2", "1"
    OUT, IN, GREY = "38;5;75", "38;5;215", "38;5;245"

    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.on or not codes:
            return text
        return f"{ESC}{';'.join(codes)}m{text}{ESC}0m"


class Glyphs:
    def __init__(self, unicode_safe: bool):
        self.out = "↑" if unicode_safe else "^"
        self.inb = "↓" if unicode_safe else "v"
        self.sep = "  ·  " if unicode_safe else "  |  "


# -------------------------------------------------------------------- table
def render_table(rows, width: int, glyphs: Glyphs, style: Style,
                 show_rate: bool) -> list[str]:
    """One line per connection, sized to the terminal."""
    fixed = 4 + 10 + (11 if show_rate else 0) + 3
    flexible = max(28, width - fixed - 2)
    site_w = max(16, int(flexible * 0.54))
    desc_w = max(10, flexible - site_w)

    head = f"  {'':<3}{'SITE / HOST':<{site_w}} {'WHAT IT IS':<{desc_w}} {'DATA':>9}"
    if show_rate:
        head += f" {'RATE':>10}"
    out = [style(head, Style.DIM)]

    for r in rows:
        outbound = r["direction"].startswith("out")
        arrow = glyphs.out if outbound else glyphs.inb
        line = (f"  {arrow:<3}{r['site'][:site_w]:<{site_w}} "
                f"{r['description'][:desc_w]:<{desc_w}} "
                f"{core.human_bytes(r['bytes']):>9}")
        if show_rate:
            rate = r.get("rate", 0)
            line += f" {(core.human_bytes(int(rate)) + '/s') if rate >= 1 else '-':>10}"
        # Inbound is the interesting case on a monitoring screen.
        out.append(style(line, Style.IN) if not outbound else line)
    return out


def summary_line(rows, meta, glyphs: Glyphs, hidden: int) -> str:
    n_out = sum(1 for r in rows if r["direction"].startswith("out"))
    text = (f"  {len(rows)} connections ({n_out} out, {len(rows) - n_out} in)"
            f"{glyphs.sep}{core.human_bytes(meta.get('bytes', 0))} total")
    if hidden > 0:
        text += f"{glyphs.sep}{hidden} more"
    return text


# --------------------------------------------------------------------- live
def cmd_live(args) -> int:
    tshark = core.find_tshark()
    style = Style(enable_ansi() and not args.no_color)
    glyphs = Glyphs(unicode_ok() if args.unicode is None else args.unicode)

    my_ips = set(args.me) or core.own_addresses()
    tracker = core.LiveTracker(my_ips)
    events: queue.Queue = queue.Queue()
    stop = threading.Event()

    threading.Thread(target=core.capture_live,
                     args=(tshark, args.interface, events, stop, args.filter),
                     daemon=True).start()
    if not args.no_names:
        def resolver():
            while not stop.wait(3.0):
                pending = tracker.unnamed_ips()
                if pending:
                    tracker.apply_names(core.resolve_many(pending[:32], budget=6.0))
        threading.Thread(target=resolver, daemon=True).start()

    signal.signal(signal.SIGINT, lambda *_: stop.set())
    started = time.monotonic()
    last_draw = 0.0
    announced: set[tuple] = set()
    fatal = ""

    if args.plain:
        print(f"netwatch live on {args.interface} - this machine "
              f"{', '.join(sorted(my_ips)) or '?'}. Ctrl-C to stop.\n", flush=True)

    while not stop.is_set():
        try:
            kind, payload = events.get(timeout=0.2)
            if kind == "line":
                tracker.feed(payload)
            elif kind == "fatal":
                fatal = payload
                break
            elif kind == "eof":
                break
        except queue.Empty:
            pass

        now = time.monotonic()
        if args.duration and now - started >= args.duration:
            break
        if now - last_draw < args.interval:
            continue
        elapsed = now - last_draw if last_draw else args.interval
        last_draw = now
        rows, meta = tracker.snapshot(elapsed)

        if args.plain:
            for r in rows:
                ident = (r["direction"], r["ip"])
                if ident not in announced:
                    announced.add(ident)
                    word = "->" if r["direction"].startswith("out") else "<-"
                    print(f"  {word} {r['site']:<44} {r['description']}", flush=True)
            continue

        shown = rows if args.top <= 0 else rows[: args.top]
        mins, secs = divmod(int(now - started), 60)
        hours, mins = divmod(mins, 60)
        frame = [
            style(f"netwatch live{glyphs.sep}{args.interface}{glyphs.sep}"
                  f"{hours:02d}:{mins:02d}:{secs:02d}{glyphs.sep}"
                  f"{meta['packets']:,} packets{glyphs.sep}"
                  f"this machine {meta['my_ips'] or '?'}", Style.BOLD),
            "",
        ]
        frame += render_table(shown, term_width(), glyphs, style, show_rate=True)
        if not shown:
            frame.append(style("  (waiting for traffic)", Style.DIM))
        frame += ["", style(summary_line(rows, meta, glyphs, len(rows) - len(shown)),
                            Style.DIM),
                  style("  Ctrl-C to stop", Style.DIM)]
        sys.stdout.write((f"{ESC}H{ESC}2J" if style.on else "\n\n") +
                         "\n".join(frame) + "\n")
        sys.stdout.flush()

    stop.set()
    if fatal:
        hint = ""
        low = fatal.lower()
        if any(w in low for w in ("permission", "denied", "not permitted")):
            hint = ("\n\nLive capture needs privileges. Run under sudo, or add "
                    "yourself to the wireshark group:\n"
                    "    sudo usermod -aG wireshark $USER\n"
                    "then log out and back in. On Windows, use an elevated "
                    "terminal.")
        print(f"\ncapture failed: {fatal}{hint}", file=sys.stderr)
        return 1

    rows, meta = tracker.snapshot(1.0)
    print()
    print_report(rows, meta, args, glyphs, style,
                 title=f"live on {args.interface}, "
                       f"{time.monotonic() - started:.0f}s")
    return 0


# --------------------------------------------------------------------- read
def cmd_read(args) -> int:
    path = args.capture
    if not path:
        newest = newest_capture(core.DROP_DIR)
        if not newest:
            print(f"no capture given, and none found in {core.DROP_DIR}",
                  file=sys.stderr)
            return 1
        path = newest
    if not os.path.isfile(path):
        print(f"no such file: {path}", file=sys.stderr)
        return 1

    result = core.analyze(path, resolve=not args.no_names)
    rows = result["rows"]
    meta = {"packets": result["packets"], "my_ips": result["my_ip"],
            "bytes": sum(r["bytes"] for r in rows)}

    allow = load_allowlist(args.allowlist) if args.allowlist else None
    if allow is not None:
        for r in rows:
            r["allowed"] = host_allowed(r, allow)
        if args.flagged_only:
            rows = [r for r in rows if not r["allowed"]]

    if args.json:
        print(json.dumps({"capture": os.path.basename(path), **meta,
                          "connections": rows}, indent=2))
        return 0
    if args.csv:
        write_csv(args.csv, rows, allow is not None)
        print(f"wrote {args.csv}")
        return 0

    style = Style(enable_ansi() and not args.no_color)
    glyphs = Glyphs(unicode_ok() if args.unicode is None else args.unicode)
    print_report(rows, meta, args, glyphs, style,
                 title=os.path.basename(path), allowlisted=allow is not None)
    return 0


def print_report(rows, meta, args, glyphs: Glyphs, style: Style,
                 title: str, allowlisted: bool = False) -> None:
    width = term_width()
    print(style(f"netwatch {__version__}{glyphs.sep}{title}{glyphs.sep}"
                f"{meta.get('packets', 0):,} packets{glyphs.sep}"
                f"this machine {meta.get('my_ips') or '?'}", Style.BOLD))

    for key, heading in (("out", "SITES THIS MACHINE CONNECTED TO   (outbound)"),
                         ("in", "CONNECTED TO THIS MACHINE         (inbound)")):
        group = [r for r in rows if r["direction"].startswith(key)]
        if args.top > 0:
            group = group[: args.top]
        print()
        print(style(heading, Style.BOLD))
        if not group:
            print(style("  (none)", Style.DIM))
            continue
        for line in render_table(group, width, glyphs, style, show_rate=False):
            print(line)

    if allowlisted:
        flagged = [r for r in rows if not r.get("allowed", True)]
        print()
        if flagged:
            print(style(f"NOT IN ALLOWLIST ({len(flagged)})", Style.BOLD))
            for r in flagged:
                print(style(f"  {r['site']:<44} {r['description']}", Style.IN))
        else:
            print(style("Everything matched the allowlist.", Style.DIM))
    print()
    print(style(summary_line(rows, meta, glyphs, 0), Style.DIM))
    if not core.asn_lookup.available():
        print(style("  (no ASN database: some hosts show as addresses only "
                    "- run `netwatch asn --fetch`)", Style.DIM))


# ---------------------------------------------------------------- allowlist
def load_allowlist(path: str) -> tuple[set[str], set[str]]:
    """(hostnames, addresses). One entry per line, # starts a comment."""
    hosts, ips = set(), set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            entry = line.split("#", 1)[0].strip().lower().rstrip(".").lstrip("*.")
            if not entry:
                continue
            try:
                ipaddress.ip_address(entry)
                ips.add(entry)
            except ValueError:
                hosts.add(entry)
    return hosts, ips


def host_allowed(row: dict, allow: tuple[set[str], set[str]]) -> bool:
    hosts, ips = allow
    if row["ip"] in ips:
        return True
    name = (row.get("name") or "").lower().rstrip(".")
    # Match on label boundaries, so evil-github.com does not pass for github.com.
    return any(name == h or name.endswith("." + h) for h in hosts) if name else False


def write_csv(path: str, rows, allowlisted: bool) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        header = ["direction", "site", "description", "ip", "packets", "bytes"]
        if allowlisted:
            header.append("allowed")
        w.writerow(header)
        for r in rows:
            line = [r["direction"], r["site"], r["description"], r["ip"],
                    r["packets"], r["bytes"]]
            if allowlisted:
                line.append("yes" if r.get("allowed") else "NO")
            w.writerow(line)


def newest_capture(folder: str):
    import glob
    files = glob.glob(os.path.join(folder, "*.pcapng")) + \
        glob.glob(os.path.join(folder, "*.pcap"))
    return max(files, key=os.path.getmtime) if files else None


# ------------------------------------------------------------------ plumbing
def cmd_interfaces(args) -> int:
    print(core.list_interfaces(core.find_tshark()).rstrip())
    return 0


def cmd_asn(args) -> int:
    import asn_lookup
    if args.fetch:
        try:
            asn_lookup.fetch()
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            return 1
        return 0
    print(f"database: {asn_lookup.status()}")
    for ip in args.ips:
        found = asn_lookup.lookup(ip)
        print(f"  {ip:<40} "
              f"{found[1] + f'  (AS{found[0]})' if found else '-'}")
    if asn_lookup.available() and not args.ips:
        print(asn_lookup.ATTRIBUTION)
    return 0


def cmd_update(args) -> int:
    import updater
    result = updater.check(__version__)
    print(f"netwatch {__version__}")
    print(updater.summary(result))
    for key in ("how", "detail", "url", "command", "behind"):
        if result.get(key):
            print(f"  {key}: {result[key]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="netwatch", description=__doc__.strip().split("\n\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run `netwatch <command> -h` for a command's own options.")
    ap.add_argument("--version", action="version", version=f"netwatch {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    def shared(p):
        p.add_argument("--top", type=int, default=20,
                       help="rows per direction, 0 for all (default 20)")
        p.add_argument("--no-names", action="store_true",
                       help="skip reverse-DNS lookups")
        p.add_argument("--no-color", action="store_true", help="disable colour")
        p.add_argument("--ascii", dest="unicode", action="store_false",
                       default=None, help="force plain ASCII (autodetected)")

    live = sub.add_parser("live", help="watch traffic on an interface as it happens")
    live.add_argument("-i", "--interface", required=True,
                      help="interface name or tshark number")
    live.add_argument("--interval", type=float, default=1.0,
                      help="redraw seconds (default 1)")
    live.add_argument("--duration", type=float, default=0,
                      help="stop after N seconds")
    live.add_argument("--filter", default="", metavar="BPF",
                      help="capture filter, e.g. 'not port 22'")
    live.add_argument("--me", action="append", default=[], metavar="IP",
                      help="treat IP as this machine (repeatable)")
    live.add_argument("--plain", action="store_true",
                      help="log each new host instead of redrawing")
    shared(live)
    live.set_defaults(func=cmd_live)

    read = sub.add_parser("read", help="analyse a saved capture file")
    read.add_argument("capture", nargs="?",
                      help=f"a .pcapng/.pcap file (default: newest in {core.DROP_DIR})")
    read.add_argument("--json", action="store_true", help="emit JSON")
    read.add_argument("--csv", metavar="FILE", help="write a CSV report")
    read.add_argument("--allowlist", metavar="FILE",
                      help="flag hosts not listed in FILE")
    read.add_argument("--flagged-only", action="store_true",
                      help="show only hosts missing from the allowlist")
    shared(read)
    read.set_defaults(func=cmd_read)

    ifs = sub.add_parser("interfaces", help="list capture interfaces")
    ifs.set_defaults(func=cmd_interfaces)

    asn = sub.add_parser("asn", help="ASN database status, lookups, download")
    asn.add_argument("--fetch", action="store_true",
                     help="download the DB-IP ASN Lite database")
    asn.add_argument("ips", nargs="*", help="addresses to look up")
    asn.set_defaults(func=cmd_asn)

    upd = sub.add_parser("update", help="check whether a newer netwatch exists")
    upd.set_defaults(func=cmd_update)
    return ap


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except RuntimeError as e:          # tshark missing, or it failed
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:            # piped into head, etc.
        return 0


if __name__ == "__main__":
    sys.exit(main())
