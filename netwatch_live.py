#!/usr/bin/env python3
"""
netwatch live -- watch connections form in a terminal, in plain language.

Streams packets from an interface via tshark and keeps a live table of who this
machine is talking to, split into outbound (you started it) and inbound
(they did), each host labelled with what it actually is.

    sudo python3 netwatch_live.py --list                # what can I capture on?
    sudo python3 netwatch_live.py -i eth0               # watch it
    sudo python3 netwatch_live.py -i eth0 --top 15
    python3 netwatch_live.py -i eth0 --plain            # no redraw, log new hosts

Needs no display, so it works over SSH on a headless Pi. Analysis comes from
netwatch_core, so descriptions and direction logic match the desktop app.

Live capture needs privileges: run with sudo, or add yourself to the `wireshark`
group (`sudo usermod -aG wireshark $USER`, then log out and back in). On Windows,
run from an elevated terminal.

Note on how this differs from reading a saved capture: analyse() decides which
address is "you" by looking at the whole file, which live traffic can't do, so
this asks the operating system instead and adapts as traffic arrives.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict

from netwatch_core import (
    FIELDS, describe, find_tshark, human_bytes, is_private, is_routable_peer,
    resolve_many, _NO_WINDOW,
)

ESC = "\x1b["
ARROW_OUT, ARROW_IN = "^", "v"          # replaced with arrows when unicode is safe


# --------------------------------------------------------------------- terminal
def enable_ansi() -> bool:
    """Turn on VT escape handling on Windows consoles. True if colour is usable."""
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
    """Whether this terminal can print the glyphs we'd like to use.

    A legacy Windows console with a cp1252 codepage turns them into mojibake,
    so the display falls back to ASCII instead of looking broken.
    """
    try:
        "·↑↓…".encode(sys.stdout.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError, TypeError):
        return False


def term_size() -> tuple[int, int]:
    try:
        size = os.get_terminal_size()
        return size.columns, size.lines
    except OSError:
        return 100, 30


class Paint:
    """Tiny ANSI helper that degrades to plain text."""

    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.on or not codes:
            return text
        return f"{ESC}{';'.join(codes)}m{text}{ESC}0m"

    DIM, BOLD = "2", "1"
    BLUE, ORANGE, GREY, WHITE = "38;5;75", "38;5;215", "38;5;245", "38;5;252"


# ----------------------------------------------------------------- local address
def own_addresses() -> set[str]:
    """Best guess at this machine's own addresses.

    Opens a UDP socket toward a public address and reads back the local end --
    no packets are sent, it just makes the OS pick the outbound interface. Any
    address the kernel reports for this host is added too.
    """
    found: set[str] = set()

    def keep(addr: str) -> bool:
        # Link-local addresses never carry the traffic we care about and only
        # clutter the display, so they are left out.
        try:
            return not ipaddress.ip_address(addr).is_link_local
        except ValueError:
            return False

    for family, probe in ((socket.AF_INET, ("8.8.8.8", 80)),
                          (socket.AF_INET6, ("2001:4860:4860::8888", 80))):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            try:
                s.connect(probe)
                addr = s.getsockname()[0].split("%")[0]
                if keep(addr):
                    found.add(addr)
            finally:
                s.close()
        except OSError:
            pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0].split("%")[0]
            if is_routable_peer(addr) and keep(addr):
                found.add(addr)
    except OSError:
        pass
    return found


# ---------------------------------------------------------------------- tracking
class LiveTracker:
    """Rolling picture of who this machine is talking to."""

    def __init__(self, my_ips: set[str]):
        self.my_ips = set(my_ips)
        self.conns: dict[tuple[str, str], dict] = {}
        self.flows: dict[tuple, dict] = {}
        self.ip_names: dict[str, str] = {}
        self.packets = 0
        self.unknown_hits: dict[str, int] = defaultdict(int)
        self.lock = threading.Lock()

    # Traffic that never matches a known local address usually means the guess
    # was wrong (VPN, bridge, wrong interface). The busiest endpoint that keeps
    # showing up on both sides of flows is almost certainly us.
    def _maybe_adopt(self, src: str, dst: str) -> None:
        for ip in (src, dst):
            self.unknown_hits[ip] += 1
        if self.packets % 200 or self.my_ips:
            return
        best = max(self.unknown_hits, key=self.unknown_hits.get, default="")
        if best:
            self.my_ips.add(best)

    def feed(self, line: str) -> None:
        cols = line.rstrip("\n").split("\t")
        if len(cols) < len(FIELDS):
            cols += [""] * (len(FIELDS) - len(cols))
        (ip_s, ip_d, ip6_s, ip6_d, tsp, tdp, usp, udp_, syn, ack,
         flen, _proto, dqry, da, daaaa, sni, host) = cols[:len(FIELDS)]

        src, dst = (ip_s or ip6_s), (ip_d or ip6_d)
        if not src or not dst:
            return
        try:
            nbytes = int(flen) if flen else 0
        except ValueError:
            nbytes = 0

        with self.lock:
            self.packets += 1

            # Names seen in the clear: DNS answers, TLS SNI, HTTP Host.
            names = [n for n in (sni, host) if n]
            if da or daaaa:
                qname = (dqry.split(";")[0] or "").lower().rstrip(".")
                if qname:
                    for answer in (da + ";" + daaaa).split(";"):
                        if answer:
                            self.ip_names.setdefault(answer, qname)

            if tsp or tdp:
                key = ("tcp", frozenset(((src, tsp), (dst, tdp))))
            elif usp or udp_:
                key = ("udp", frozenset(((src, usp), (dst, udp_))))
            else:
                key = ("ip", frozenset((src, dst)))

            flow = self.flows.get(key)
            if flow is None:
                flow = self.flows[key] = {"initiator": (src, dst), "locked": False}
            if syn == "1" and ack != "1":
                flow["initiator"], flow["locked"] = (src, dst), True

            isrc, idst = flow["initiator"]
            if isrc in self.my_ips and is_routable_peer(idst):
                direction, remote = "out", idst
            elif idst in self.my_ips and is_routable_peer(isrc):
                direction, remote = "in", isrc
            else:
                self._maybe_adopt(src, dst)
                return

            conn = self.conns.get((direction, remote))
            if conn is None:
                conn = self.conns[(direction, remote)] = {
                    "direction": direction, "ip": remote, "name": "",
                    "bytes": 0, "packets": 0, "prev_bytes": 0,
                    "first": time.monotonic(), "last": time.monotonic()}
            conn["bytes"] += nbytes
            conn["packets"] += 1
            conn["last"] = time.monotonic()
            for n in names:
                n = n.lower().rstrip(".")
                if n and not conn["name"]:
                    conn["name"] = n

    def apply_names(self, names: dict[str, str]) -> None:
        with self.lock:
            for (_d, ip), conn in self.conns.items():
                if not conn["name"] and names.get(ip):
                    conn["name"] = names[ip]

    def unnamed_ips(self) -> list[str]:
        with self.lock:
            return [c["ip"] for c in self.conns.values()
                    if not c["name"] and not self.ip_names.get(c["ip"])]

    def snapshot(self, elapsed: float) -> tuple[list[dict], dict]:
        """Rows sorted by volume, plus totals. Also latches per-interval rates."""
        with self.lock:
            rows = []
            for conn in self.conns.values():
                name = conn["name"] or self.ip_names.get(conn["ip"], "")
                local = is_private(conn["ip"])
                delta = conn["bytes"] - conn["prev_bytes"]
                conn["prev_bytes"] = conn["bytes"]
                rows.append({
                    "direction": conn["direction"],
                    "site": name or conn["ip"], "ip": conn["ip"],
                    "description": describe(name, local),
                    "bytes": conn["bytes"], "packets": conn["packets"],
                    "rate": delta / elapsed if elapsed > 0 else 0.0,
                    "idle": time.monotonic() - conn["last"]})
            rows.sort(key=lambda r: -r["bytes"])
            # A machine can hold several addresses (virtual adapters, IPv6);
            # they all count for classification but only the first two are shown.
            mine = sorted(self.my_ips)
            shown = ", ".join(mine[:2]) + (f" +{len(mine) - 2}" if len(mine) > 2 else "")
            meta = {"packets": self.packets,
                    "out": sum(1 for r in rows if r["direction"] == "out"),
                    "in": sum(1 for r in rows if r["direction"] == "in"),
                    "bytes": sum(r["bytes"] for r in rows),
                    "my_ips": shown or "?"}
            return rows, meta


# ---------------------------------------------------------------------- capture
def list_interfaces(tshark: str) -> str:
    proc = subprocess.run([tshark, "-D"], capture_output=True, text=True,
                          creationflags=_NO_WINDOW)
    return proc.stdout or proc.stderr


def capture_lines(tshark: str, interface: str, out: queue.Queue,
                  stop: threading.Event) -> None:
    """Run tshark and push one line per packet. Reports fatal errors as tuples."""
    cmd = [tshark, "-i", interface, "-l", "-n", "-T", "fields",
           "-E", "separator=/t", "-E", "aggregator=;", "-E", "occurrence=a"]
    for field in FIELDS:
        cmd += ["-e", field]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                bufsize=1, creationflags=_NO_WINDOW)
    except OSError as e:
        out.put(("fatal", str(e)))
        return
    try:
        for line in proc.stdout:
            if stop.is_set():
                break
            if line.strip():
                out.put(("line", line))
    finally:
        if proc.poll() is None:
            proc.terminate()
        err = ""
        try:
            err = (proc.stderr.read() or "").strip()
        except Exception:
            pass
        if proc.poll() not in (0, None) and err:
            out.put(("fatal", err))
        out.put(("eof", ""))


def resolver_loop(tracker: LiveTracker, stop: threading.Event) -> None:
    """Fill in host names in the background, never blocking the display."""
    while not stop.wait(3.0):
        pending = tracker.unnamed_ips()
        if pending:
            tracker.apply_names(resolve_many(pending[:32], budget=6.0))


# ----------------------------------------------------------------------- render
def render(rows: list[dict], meta: dict, args, paint: Paint,
           interface: str, elapsed_total: float) -> str:
    cols, lines_avail = term_size()
    arrow_out, arrow_in = (("↑", "↓") if args.unicode
                           else (ARROW_OUT, ARROW_IN))
    sep = "  ·  " if args.unicode else "  |  "
    waiting = "  (waiting for traffic…)" if args.unicode \
        else "  (waiting for traffic...)"
    mins, secs = divmod(int(elapsed_total), 60)
    hours, mins = divmod(mins, 60)

    head = (f"netwatch live{sep}{interface}{sep}"
            f"{hours:02d}:{mins:02d}:{secs:02d}{sep}"
            f"{meta['packets']:,} packets{sep}this machine {meta['my_ips']}")
    out = [paint(head, Paint.BOLD), ""]

    # Widths: give whatever is left to the two text columns.
    fixed = 4 + 10 + 11 + 2
    flexible = max(30, cols - fixed - 4)
    site_w = max(18, int(flexible * 0.52))
    desc_w = max(12, flexible - site_w)
    header = (f"  {'':<3}{'SITE / HOST':<{site_w}} {'WHAT IT IS':<{desc_w}} "
              f"{'DATA':>9} {'RATE':>10}")
    out.append(paint(header, Paint.DIM))

    shown = rows if args.top <= 0 else rows[:args.top]
    for r in shown:
        outbound = r["direction"] == "out"
        arrow = arrow_out if outbound else arrow_in
        site = r["site"][:site_w]
        desc = r["description"][:desc_w]
        rate = f"{human_bytes(int(r['rate']))}/s" if r["rate"] >= 1 else "-"
        row = (f"  {arrow:<3}{site:<{site_w}} {desc:<{desc_w}} "
               f"{human_bytes(r['bytes']):>9} {rate:>10}")
        # Inbound is the interesting case, so it gets the accent colour.
        out.append(paint(row, Paint.ORANGE) if not outbound
                   else paint(row, Paint.WHITE))

    if not shown:
        out.append(paint(waiting, Paint.DIM))

    hidden = len(rows) - len(shown)
    tail = (f"  {len(rows)} connections ({meta['out']} out, {meta['in']} in)"
            f"{sep}{human_bytes(meta['bytes'])} total")
    if hidden > 0:
        tail += f"{sep}{hidden} more"
    out += ["", paint(tail, Paint.DIM),
            paint("  Ctrl-C to stop", Paint.DIM)]
    return "\n".join(out)


def final_summary(rows: list[dict], meta: dict, elapsed: float) -> str:
    out = ["", "=" * 72,
           f"netwatch live summary - {elapsed:.0f}s - "
           f"{meta['packets']:,} packets - {human_bytes(meta['bytes'])}",
           "=" * 72]
    for label, key in (("SITES YOU CONNECTED TO   (outbound)", "out"),
                       ("CONNECTING TO YOU        (inbound)", "in")):
        group = [r for r in rows if r["direction"] == key]
        out += ["", label, "-" * len(label)]
        if not group:
            out.append("  (none)")
        for r in group:
            tail = f"  [{r['ip']}]" if r["site"] != r["ip"] else ""
            out.append(f"  {human_bytes(r['bytes']):>9}  {r['site']}{tail}")
            out.append(f"             {r['description']}")
    return "\n".join(out)


# ------------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(
        description="Watch network connections form in a terminal, in plain language.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--interface", help="interface to capture on (name or tshark number)")
    ap.add_argument("--list", action="store_true", help="list capture interfaces and exit")
    ap.add_argument("--top", type=int, default=20, help="rows to show, 0 for all (default 20)")
    ap.add_argument("--interval", type=float, default=1.0, help="redraw seconds (default 1)")
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds")
    ap.add_argument("--me", action="append", default=[], metavar="IP",
                    help="treat IP as this machine (repeatable; overrides autodetect)")
    ap.add_argument("--plain", action="store_true",
                    help="no full-screen redraw; print each new host as it appears")
    ap.add_argument("--no-color", action="store_true", help="disable colour")
    ap.add_argument("--no-names", action="store_true", help="skip reverse-DNS lookups")
    ap.add_argument("--ascii", dest="unicode", action="store_false",
                    default=None,
                    help="force plain ASCII output (autodetected by default)")
    args = ap.parse_args()
    if args.unicode is None:
        args.unicode = unicode_ok()

    try:
        tshark = find_tshark()
    except RuntimeError as e:
        sys.exit(f"error: {e}")

    if args.list:
        print(list_interfaces(tshark))
        return
    if not args.interface:
        sys.exit("error: give an interface with -i, or use --list to see them.")

    paint = Paint(enable_ansi() and not args.no_color)
    my_ips = set(args.me) or own_addresses()
    tracker = LiveTracker(my_ips)

    events: queue.Queue = queue.Queue()
    stop = threading.Event()
    threading.Thread(target=capture_lines,
                     args=(tshark, args.interface, events, stop),
                     daemon=True).start()
    if not args.no_names:
        threading.Thread(target=resolver_loop, args=(tracker, stop),
                         daemon=True).start()

    signal.signal(signal.SIGINT, lambda *_: stop.set())
    started = time.monotonic()
    last_draw = 0.0
    seen_hosts: set[tuple[str, str]] = set()
    fatal = ""

    if args.plain:
        print(f"netwatch live on {args.interface} — this machine "
              f"{', '.join(sorted(my_ips)) or '?'}. Ctrl-C to stop.\n")

    try:
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
            elapsed_since = now - last_draw if last_draw else args.interval
            last_draw = now
            rows, meta = tracker.snapshot(elapsed_since)

            if args.plain:
                # Only announce hosts we have not mentioned before.
                for r in rows:
                    ident = (r["direction"], r["ip"])
                    if ident in seen_hosts:
                        continue
                    seen_hosts.add(ident)
                    word = "->" if r["direction"] == "out" else "<-"
                    print(f"  {word} {r['site']:<44} {r['description']}")
            else:
                frame = render(rows, meta, args, paint, args.interface,
                               now - started)
                sys.stdout.write(f"{ESC}H{ESC}2J" if paint.on else "\n" * 2)
                sys.stdout.write(frame + "\n")
                sys.stdout.flush()
    finally:
        stop.set()

    if fatal:
        hint = ""
        if re.search(r"permission|denied|not permitted|access", fatal, re.I):
            hint = ("\n\nLive capture needs privileges. Try running with sudo, or"
                    "\nadd yourself to the wireshark group:"
                    "\n    sudo usermod -aG wireshark $USER"
                    "\n(then log out and back in). On Windows, use an elevated"
                    " terminal.")
        sys.exit(f"\ncapture failed: {fatal}{hint}")

    rows, meta = tracker.snapshot(1.0)
    print(final_summary(rows, meta, time.monotonic() - started))


if __name__ == "__main__":
    main()
