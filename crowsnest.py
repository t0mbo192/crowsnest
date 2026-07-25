#!/usr/bin/env python3
"""
crowsnest -- see which hosts this machine talks to, in plain language.

Wireshark tells you everything; this tells you who. Every connection is split
into outbound (this machine started it) and inbound (something else did), and
each host is labelled with what it actually is rather than left as an address.

    crowsnest live -i eth0                  report each host once, as it appears
    crowsnest read capture.pcapng           analyse a saved capture
    crowsnest interfaces                    what can I capture on?
    crowsnest block 203.0.113.5             stop a host reaching this machine
    crowsnest asn --fetch                   get the database that names owners

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
import re
import signal
import sys
import threading
import time

import crowsnest_core as core
from crowsnest_version import __version__

ESC = "\x1b["

# How long to let reverse DNS answer before reporting a host by address. The
# resolver runs every few seconds, so most names arrive inside this, and the one
# line a host gets is then its most useful one.
NAME_GRACE = 4.0


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


def term_height(default: int = 30) -> int:
    try:
        return os.get_terminal_size().lines
    except OSError:
        return int(os.environ.get("LINES", default))


class Style:
    """ANSI colours that vanish when colour is off."""

    DIM, BOLD = "2", "1"
    OUT, IN, GREY = "38;5;75", "38;5;215", "38;5;245"
    FRAME = "38;5;240"

    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.on or not codes:
            return text
        return f"{ESC}{';'.join(codes)}m{text}{ESC}0m"


class Glyphs:
    def __init__(self, unicode_safe: bool):
        self.unicode = unicode_safe
        self.out = "↑" if unicode_safe else "^"
        self.inb = "↓" if unicode_safe else "v"
        self.sep = "  ·  " if unicode_safe else "  |  "
        # Box drawing, with an ASCII fallback so a plain console still frames.
        if unicode_safe:
            self.tl, self.tr, self.bl, self.br = "╭", "╮", "╰", "╯"
            self.h, self.v = "─", "│"
        else:
            self.tl, self.tr, self.bl, self.br = "+", "+", "+", "+"
            self.h, self.v = "-", "|"


# The lookout's basket at the masthead, above the waterline. Box drawing where
# the terminal can render it, with an ASCII mirror where it cannot -- the shape
# has to survive a plain Pi console as well as a modern terminal.
LOGO_UNICODE = [
    ("  ╭─────╮  ", "nest"),
    ("  │ ◦ ◦ │  ", "nest"),
    ("  ╰──┬──╯  ", "nest"),
    ("  ═══╪═══  ", "spar"),
    ("  ≈≈≈┴≈≈≈  ", "sea"),
]
LOGO_ASCII = [
    "   .-----.  ",
    "   | o o |  ",
    "   '--+--'  ",
    "  ===-+-=== ",
    "  ~~~~+~~~~ ",
]
LOGO_PARTS = ("nest", "nest", "nest", "spar", "sea")


def logo_lines(unicode_safe: bool, style: Style) -> list[str]:
    """The mark, coloured so the basket reads first and the sea recedes."""
    tint = {"nest": Style.OUT, "spar": Style.GREY, "sea": Style.FRAME}
    art = ([text for text, _ in LOGO_UNICODE] if unicode_safe else LOGO_ASCII)
    return [style(text, tint[part]) for text, part in zip(art, LOGO_PARTS)]


# -------------------------------------------------------------------- panels
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def visible_len(text: str) -> int:
    """Width on screen, ignoring colour codes.

    Padding on len() would count the escape sequences, which take no space, and
    every framed line would end up a different length.
    """
    return len(ANSI_RE.sub("", text))


def box(title: str, body: list[str], width: int, glyphs: Glyphs,
        style: Style) -> list[str]:
    """Frame some lines, with the title set into the top edge."""
    inner = max(10, width - 2)
    label = f" {title} " if title else ""
    fill = max(0, inner - len(label) - 1)
    top = f"{glyphs.tl}{glyphs.h}{label}{glyphs.h * fill}{glyphs.tr}"
    edge = style(glyphs.v, Style.FRAME)
    out = [style(top, Style.FRAME)]
    for line in body:
        pad = inner - visible_len(line)
        if pad < 0:                       # only reachable if a caller oversized
            line, pad = ANSI_RE.sub("", line)[:inner], 0
        out.append(edge + line + " " * pad + edge)
    out.append(style(f"{glyphs.bl}{glyphs.h * inner}{glyphs.br}", Style.FRAME))
    return out


def panel_rows(rows: list[dict], width: int, limit: int, style: Style,
               inbound: bool) -> list[str]:
    """The body of a direction panel: host, what it is, volume, rate."""
    inner = max(30, width - 4)
    rate_w, data_w = 10, 9
    flexible = inner - rate_w - data_w - 4
    site_w = max(14, int(flexible * 0.52))
    desc_w = max(10, flexible - site_w)

    body = []
    for r in rows[:limit]:
        rate = r.get("rate", 0)
        rate_text = f"{core.human_bytes(int(rate))}/s" if rate >= 1 else ""
        line = (f" {r['site'][:site_w]:<{site_w}} "
                f"{r['description'][:desc_w]:<{desc_w}} "
                f"{core.human_bytes(r['bytes']):>{data_w}} "
                f"{rate_text:>{rate_w}}")
        body.append(style(line, Style.IN) if inbound else line)
    if not rows:
        body.append(style("  nothing yet", Style.DIM))
    hidden = len(rows) - min(len(rows), limit)
    if hidden > 0:
        body.append(style(f"  ... {hidden} more", Style.DIM))
    return body


def render_dashboard(rows: list[dict], meta: dict, glyphs: Glyphs, style: Style,
                     interface: str, elapsed: float) -> list[str]:
    """The full-screen view: a header with the logo, then one panel each way."""
    width = min(term_width(), 120)
    height = term_height()

    mins, secs = divmod(int(elapsed), 60)
    hours, mins = divmod(mins, 60)
    facts = [
        f"{interface}{glyphs.sep}{hours:02d}:{mins:02d}:{secs:02d}",
        f"{meta['packets']:,} packets{glyphs.sep}"
        f"{core.human_bytes(meta.get('bytes', 0))}",
        f"this machine {meta.get('my_ips') or '?'}",
    ]
    art = logo_lines(glyphs.unicode, style)
    header = []
    for i, line in enumerate(art):
        # Line 0 carries the name; the rest carry a fact each, and any spare
        # logo lines simply have nothing beside them.
        if i == 0:
            right = (style("CROWSNEST", Style.BOLD) +
                     style("   network lookout", Style.DIM))
        else:
            right = facts[i - 1] if i - 1 < len(facts) else ""
        header.append(f" {line}  {right}")

    outbound = [r for r in rows if r["direction"].startswith("out")]
    inbound = [r for r in rows if not r["direction"].startswith("out")]

    # Share the rows left over after the frames between the two panels.
    spare = max(4, height - len(header) - 10)
    out_limit = max(2, min(len(outbound), spare - min(len(inbound), 4)))
    in_limit = max(2, spare - out_limit)

    def hosts(n: int) -> str:
        return f"{n} host" if n == 1 else f"{n} hosts"

    frame = header + [""]
    frame += box(f"OUTBOUND   {hosts(len(outbound))}",
                 panel_rows(outbound, width, out_limit, style, inbound=False),
                 width, glyphs, style)
    frame += box(f"INBOUND   {hosts(len(inbound))}",
                 panel_rows(inbound, width, in_limit, style, inbound=True),
                 width, glyphs, style)
    n_out, n_in = len(outbound), len(inbound)
    frame.append(style(f"  {n_out + n_in} connections "
                       f"({n_out} out, {n_in} in){glyphs.sep}"
                       f"{core.human_bytes(meta.get('bytes', 0))} total"
                       f"{glyphs.sep}Ctrl-C to stop", Style.DIM))
    return frame


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
    first_seen: dict[tuple, float] = {}
    fatal = ""

    if not args.dashboard:
        # Same loopback filtering the summary uses, so the two agree.
        shown_ips = sorted(a for a in my_ips if not a.startswith(("127.", "::1")))
        print(style(f"crowsnest live{glyphs.sep}{args.interface}{glyphs.sep}"
                    f"this machine {', '.join(shown_ips) or '?'}", Style.BOLD))
        print(style("  each host is reported once, when first seen. "
                    "Ctrl-C for a summary.\n", Style.DIM), flush=True)

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

        if not args.dashboard:
            # One line per host, the first time it is seen, and never again.
            # Nothing redraws and nothing repeats.
            for r in rows:
                # Both the address and the displayed name are remembered.
                # Keying on the name alone announced a host twice -- once as a
                # bare address, then again seconds later once reverse DNS had
                # named it. Keying on the address alone would split one site
                # answering on several addresses into several lines.
                keys = {(r["direction"], r["ip"]), (r["direction"], r["site"])}
                if keys & announced:
                    continue
                # Give reverse DNS a moment to answer before settling for an
                # address, so the one line a host gets is its most useful one.
                if not r["name"]:
                    since = first_seen.setdefault((r["direction"], r["ip"]), now)
                    if now - since < NAME_GRACE:
                        continue
                announced |= keys
                outbound = r["direction"].startswith("out")
                arrow = glyphs.out if outbound else glyphs.inb
                line = (f"  {time.strftime('%H:%M:%S')}  {arrow}  "
                        f"{r['site'][:42]:<42} {r['description']}")
                print(style(line, Style.IN) if not outbound else line, flush=True)
            continue

        frame = render_dashboard(rows, meta, glyphs, style, args.interface,
                                 now - started)
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
    print(style(f"crowsnest {__version__}{glyphs.sep}{title}{glyphs.sep}"
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
                    "- run `crowsnest asn --fetch`)", Style.DIM))


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


# -------------------------------------------------------------------- blocking
def _blocking_or_exit() -> None:
    import blocking
    if not blocking.nft_available():
        raise RuntimeError(blocking.unsupported_reason())


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("not a terminal, so nothing was changed. Pass --yes to proceed "
              "without asking.", file=sys.stderr)
        return False
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def cmd_block(args) -> int:
    import blocking
    _blocking_or_exit()
    style = Style(enable_ansi() and not args.no_color)

    addresses: list[str] = []
    for target in args.targets:
        found = blocking.resolve_target(target)
        if len(found) > 1 or found[0] != target:
            print(f"  {target} -> {', '.join(found)}")
        addresses += [a for a in found if a not in addresses]

    # Refuse the addresses whose blocking tends to break the machine.
    problems = blocking.check_targets(addresses)
    if problems and not args.force:
        print(style("\nRefusing to block:", Style.BOLD), file=sys.stderr)
        for address, why in problems.items():
            print(f"  {address}  -- {why}", file=sys.stderr)
        print("\nPass --force if you are certain.", file=sys.stderr)
        addresses = [a for a in addresses if a not in problems]
        if not addresses:
            return 1

    already = {e["address"] for e in blocking.list_blocks()}
    fresh = [a for a in addresses if a not in already]
    for address in addresses:
        if address in already:
            print(f"  {address} is already blocked")
    if not fresh:
        return 0

    print(style("\nThis will run:", Style.BOLD))
    for line in blocking.describe_commands(fresh):
        print(f"  {line}")
    print(style("\nInbound traffic from these hosts will be dropped. Existing "
                "firewall rules are untouched;\ncrowsnest only writes to its own "
                f"'{blocking.TABLE}' table.", Style.DIM))
    if not args.persist:
        print(style("This lasts until reboot. Add --persist to record it for "
                    "`crowsnest blocks --restore`.", Style.DIM))

    if args.dry_run:
        print("\ndry run: nothing was changed.")
        return 0
    if not _confirm("\nApply?", args.yes):
        print("nothing was changed.")
        return 1

    added = blocking.block(fresh)
    for address in added:
        print(style(f"  blocked {address}", Style.IN))
    if args.persist and added:
        blocking.save_record(added)
        print(f"\nrecorded in {blocking.RECORD_PATH}")
        print(blocking.restore_hint())
    return 0


def cmd_unblock(args) -> int:
    import blocking
    _blocking_or_exit()

    if args.all:
        entries = blocking.list_blocks()
        if not entries:
            print("nothing is blocked.")
            return 0
        print(f"This will remove all {len(entries)} block(s) and drop "
              f"crowsnest's '{blocking.TABLE}' table.")
        if not _confirm("Remove them all?", args.yes):
            print("nothing was changed.")
            return 1
        count = blocking.unblock_all()
        blocking.forget_record(None)
        print(f"removed {count} block(s).")
        return 0

    addresses: list[str] = []
    for target in args.targets:
        addresses += [a for a in blocking.resolve_target(target)
                      if a not in addresses]
    removed = blocking.unblock(addresses)
    if not removed:
        print("none of those were blocked.")
        return 0
    blocking.forget_record(removed)
    for address in removed:
        print(f"  unblocked {address}")
    return 0


def cmd_blocks(args) -> int:
    import blocking
    _blocking_or_exit()

    if args.restore:
        recorded = blocking.load_record()
        if not recorded:
            print(f"nothing recorded in {blocking.RECORD_PATH}")
            return 0
        active = {e["address"] for e in blocking.list_blocks()}
        missing = [a for a in recorded if a not in active]
        if not missing:
            print(f"all {len(recorded)} recorded block(s) are already active.")
            return 0
        print("This will reapply:")
        for line in blocking.describe_commands(missing):
            print(f"  {line}")
        if not _confirm("\nApply?", args.yes):
            print("nothing was changed.")
            return 1
        for address in blocking.block(missing):
            print(f"  blocked {address}")
        return 0

    entries = blocking.list_blocks()
    recorded = set(blocking.load_record())
    if not entries:
        print("nothing is blocked.")
        if recorded:
            print(f"{len(recorded)} recorded but not active -- "
                  f"`crowsnest blocks --restore` reapplies them.")
        return 0
    print(f"blocked ({len(entries)}):")
    for entry in entries:
        mark = "  (recorded)" if entry["address"] in recorded else ""
        print(f"  {entry['address']}{mark}")
    return 0


def cmd_update(args) -> int:
    import updater
    result = updater.check(__version__)
    print(f"crowsnest {__version__}")
    print(updater.summary(result))
    for key in ("how", "detail", "url", "command", "behind"):
        if result.get(key):
            print(f"  {key}: {result[key]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="crowsnest", description=__doc__.strip().split("\n\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run `crowsnest <command> -h` for a command's own options.")
    ap.add_argument("--version", action="version", version=f"crowsnest {__version__}")
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
    live.add_argument("--dashboard", action="store_true",
                      help="show a continuously redrawn table with rates, "
                           "instead of reporting each host once")
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

    # Blocking writes firewall rules, so every one of these shows the exact
    # command and asks before changing anything.
    blk = sub.add_parser("block", help="drop inbound traffic from a host (Linux)")
    blk.add_argument("targets", nargs="+", metavar="HOST",
                     help="hostname or address to block")
    blk.add_argument("--persist", action="store_true",
                     help="record it so `crowsnest blocks --restore` can reapply "
                          "after a reboot (blocks are session-only otherwise)")
    blk.add_argument("--dry-run", action="store_true",
                     help="show what would happen and stop")
    blk.add_argument("--yes", action="store_true", help="do not ask first")
    blk.add_argument("--force", action="store_true",
                     help="allow blocking the gateway, DNS or your SSH peer")
    blk.add_argument("--no-color", action="store_true", help="disable colour")
    blk.set_defaults(func=cmd_block)

    unb = sub.add_parser("unblock", help="remove a block")
    unb.add_argument("targets", nargs="*", metavar="HOST")
    unb.add_argument("--all", action="store_true", help="remove every block")
    unb.add_argument("--yes", action="store_true", help="do not ask first")
    unb.set_defaults(func=cmd_unblock)

    bls = sub.add_parser("blocks", help="list blocks, or reapply recorded ones")
    bls.add_argument("--restore", action="store_true",
                     help="reapply blocks recorded with --persist")
    bls.add_argument("--yes", action="store_true", help="do not ask first")
    bls.set_defaults(func=cmd_blocks)

    upd = sub.add_parser("update", help="check whether a newer crowsnest exists")
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
