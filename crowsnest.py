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

import crowsnest_banner as mark
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


def banner_lines(style: Style) -> list[str]:
    """The wide mark that spells the name, nest picked out from the lettering.

    Drawn in plain ASCII, so unlike the small mark it needs no fallback -- it
    comes out the same on a legacy Windows console as on a modern terminal.
    """
    return [style(line[:mark.MARK_COLS], Style.OUT) +
            style(line[mark.MARK_COLS:], Style.BOLD)
            for line in mark.BANNER.split("\n")]


# How many hosts each panel shows before you ask for more.
DEFAULT_ROWS = 10


# -------------------------------------------------------------------- screen
class Screen:
    """Owns the terminal while the dashboard runs.

    Draws into the alternate screen buffer, so frames replace each other instead
    of scrolling into the scrollback, and the shell comes back exactly as it was
    on exit.

    Screen control is deliberately separate from colour. They were the same flag
    before, so --no-color also stopped the clear, and every interval printed a
    fresh banner down the window instead of redrawing one.
    """

    def __init__(self, enabled: bool):
        self.on = enabled
        self._entered = False
        self._held: list[str] | None = None

    def __enter__(self):
        if self.on:
            # alternate buffer, then hide the cursor
            sys.stdout.write(f"{ESC}?1049h{ESC}?25l")
            sys.stdout.flush()
            self._entered = True
        return self

    def __exit__(self, *_):
        if self._entered:
            sys.stdout.write(f"{ESC}?25h{ESC}?1049l")
            sys.stdout.flush()
            self._entered = False
        elif self._held is not None:
            # Nothing was drawn as we went, so show where things ended up.
            sys.stdout.write("\n".join(self._held) + "\n")
            sys.stdout.flush()
            self._held = None
        return False

    def draw(self, lines: list[str]) -> None:
        """Replace what is on screen, clipped so it can never scroll."""
        if not self.on:
            # Without screen control there is no way to replace a frame, and
            # writing each one produced a column of stacked banners marching
            # down the window. Hold the latest instead and print it on the way
            # out, so a redirected run still ends with something useful.
            self._held = lines
            return
        rows = max(4, term_height() - 1)
        # Clipped both ways. Height alone is not enough: a line wider than the
        # terminal wraps onto an extra screen row, which scrolls the frame and
        # leaves the previous footer stranded above the new one. Trimming here
        # means no renderer above can cause that, whatever it builds.
        cols = term_width()
        body = [visible_trim(line, cols) for line in lines[:rows]]
        # Every line is erased to its end as it is drawn, then everything below
        # the frame is cleared. Without the per-line erase, a line that grew
        # shorter than the one it replaced kept the old tail: as hosts arrived
        # the frame gained a row, the footer shifted down, and the short totals
        # line was written over the long key hints -- leaving the hints showing
        # twice until the frame stopped growing.
        sys.stdout.write(f"{ESC}H" + f"{ESC}K\n".join(body)
                         + f"{ESC}K" + f"{ESC}0J")
        sys.stdout.flush()


class Keys:
    """Single keypresses, without blocking and without a dependency.

    curses would do this, but it is absent on Windows, and the whole point of
    this project is that it installs with no wheels to build.
    """

    def __init__(self, enabled: bool):
        self.on = enabled and sys.stdin.isatty()
        self._fd = None
        self._saved = None

    def __enter__(self):
        if self.on and os.name != "nt":
            try:
                import termios
                import tty
                self._fd = sys.stdin.fileno()
                self._saved = termios.tcgetattr(self._fd)
                tty.setcbreak(self._fd)
            except Exception:
                self.on = False
        return self

    def __exit__(self, *_):
        if self._saved is not None:
            try:
                import termios
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
            except Exception:
                pass
        return False

    def get(self) -> str | None:
        """The next key waiting, or None. Never blocks."""
        if not self.on:
            return None
        try:
            if os.name == "nt":
                import msvcrt
                if not msvcrt.kbhit():
                    return None
                return msvcrt.getwch()
            import select
            if not select.select([sys.stdin], [], [], 0)[0]:
                return None
            return sys.stdin.read(1)
        except Exception:
            return None


class View:
    """What the viewer has asked to see: a filter, and which panels are open."""

    def __init__(self):
        self.search = ""
        self.editing = False
        self.expanded: set[str] = set()

    def matches(self, row: dict) -> bool:
        if not self.search:
            return True
        needle = self.search.lower()
        return needle in f"{row['site']} {row['description']} {row['ip']}".lower()

    def limit(self, which: str, available: int) -> int:
        """Rows to show for a panel: ten, or as many as will fit when opened."""
        return available if which in self.expanded else min(DEFAULT_ROWS, available)

    def handle(self, key: str) -> bool:
        """Apply a keypress. False means quit."""
        if self.editing:
            if key in ("\r", "\n"):
                self.editing = False
            elif key == "\x1b":                     # Esc abandons the search
                self.search, self.editing = "", False
            elif key in ("\x7f", "\b"):
                self.search = self.search[:-1]
            elif key.isprintable():
                self.search += key
            return True
        if key in ("q", "Q"):
            return False
        if key == "/":
            self.editing = True
        elif key in ("o", "O"):
            self.expanded ^= {"out"}
        elif key in ("i", "I"):
            self.expanded ^= {"in"}
        elif key in ("c", "C", "\x1b"):
            self.search = ""
            self.expanded.clear()
        return True


# -------------------------------------------------------------------- panels
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def visible_len(text: str) -> int:
    """Width on screen, ignoring colour codes.

    Padding on len() would count the escape sequences, which take no space, and
    every framed line would end up a different length.
    """
    return len(ANSI_RE.sub("", text))


def visible_trim(text: str, limit: int) -> str:
    """Cut to `limit` columns on screen, keeping the colour codes intact.

    A line wider than the terminal wraps onto a second screen row. The frame is
    sized to fill the screen exactly, so one wrapped line pushes the bottom off,
    the terminal scrolls, and the previous frame's footer is stranded above the
    new one -- the dashboard appears to draw its key hints twice.
    """
    if limit <= 0:
        return ""
    if visible_len(text) <= limit:
        return text
    out, seen, pos, styled = [], 0, 0, False
    for match in ANSI_RE.finditer(text):
        if seen < limit:
            chunk = text[pos:match.start()]
            out.append(chunk[:limit - seen])
            seen += min(len(chunk), limit - seen)
        # Every code is kept, including ones past the cut, so a reset is never
        # the thing that gets dropped and colour cannot leak into what follows.
        out.append(match.group(0))
        styled = True
        pos = match.end()
    if seen < limit:
        out.append(text[pos:][:limit - seen])
    return "".join(out) + (f"{ESC}0m" if styled else "")


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


def panel_widths(width: int) -> tuple[int, int, int, int]:
    """Column widths for a panel: host, description, volume, rate.

    Worked out in one place so the labels above the panels cannot drift out of
    step with the values inside them.
    """
    inner = max(30, width - 4)
    rate_w, data_w = 10, 9
    flexible = inner - rate_w - data_w - 4
    site_w = max(14, int(flexible * 0.52))
    desc_w = max(10, flexible - site_w)
    return site_w, desc_w, data_w, rate_w


def column_labels(width: int, style: Style) -> str:
    """Names for the columns, once, above both panels.

    The two leading spaces stand in for the panel's left border and the space
    after it, so a label sits directly over its column.
    """
    site_w, desc_w, data_w, rate_w = panel_widths(width)
    return style(f"  {'SITE / HOST':<{site_w}} {'WHAT IT IS':<{desc_w}} "
                 f"{'DATA':>{data_w}} {'RATE':>{rate_w}}", Style.DIM)


def panel_rows(rows: list[dict], width: int, limit: int, style: Style,
               inbound: bool, filtered: bool = False) -> list[str]:
    """The body of a direction panel: host, what it is, volume, rate."""
    site_w, desc_w, data_w, rate_w = panel_widths(width)

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
        body.append(style("  nothing matches" if filtered else "  nothing yet",
                          Style.DIM))
    hidden = len(rows) - min(len(rows), limit)
    if hidden > 0:
        body.append(style(f"  ... {hidden} more", Style.DIM))
    return body


def render_dashboard(rows: list[dict], meta: dict, glyphs: Glyphs, style: Style,
                     interface: str, elapsed: float, view: View) -> list[str]:
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
    # The wide mark spells the name itself, so it needs only the tagline beside
    # it. It wants 45 columns though, and on a narrow terminal the facts beside
    # it would run off the edge -- there the small mark and a written name are
    # used instead.
    if width >= mark.WIDTH + max(len(f) for f in facts) + 4:
        art = banner_lines(style)
        captions = [style(f"v{__version__}   network lookout", Style.DIM)]
    else:
        art = logo_lines(glyphs.unicode, style)
        captions = [style("CROWSNEST", Style.BOLD) +
                    style("   network lookout", Style.DIM)]
    captions += facts

    # The mark's lines are ragged, so each is padded out to the widest before
    # the captions go beside it, or the right-hand column would not line up.
    pad = max(visible_len(line) for line in art)
    header = []
    for i, line in enumerate(art):
        # One caption per line of art. Spare lines of art simply have nothing
        # beside them; spare captions are dropped rather than left to overflow.
        right = captions[i] if i < len(captions) else ""
        # The facts on the right grow while a capture runs: the packet count and
        # byte total climb, and a second address appears the moment traffic
        # reveals one. Trimmed to the room actually beside the mark, since an
        # overflowing caption wraps and takes the whole frame with it.
        right = visible_trim(right, width - pad - 3)
        header.append(f" {line}{' ' * (pad - visible_len(line))}  {right}".rstrip())

    all_out = [r for r in rows if r["direction"].startswith("out")]
    all_in = [r for r in rows if not r["direction"].startswith("out")]
    outbound = [r for r in all_out if view.matches(r)]
    inbound = [r for r in all_in if view.matches(r)]

    # Ten rows a panel by default. Opening one gives it whatever the window can
    # spare, and the total is clipped to the height either way, so the frame
    # always fits on one screen instead of scrolling the last one out of view.
    spare = max(4, height - len(header) - 11)

    # What each panel would like: ten by default, everything once opened, and
    # never more rows than it actually has.
    def wanted(rows_here: list[dict], which: str) -> int:
        if which in view.expanded:
            return max(1, len(rows_here))
        return max(1, min(DEFAULT_ROWS, len(rows_here)))

    want_out, want_in = wanted(outbound, "out"), wanted(inbound, "in")

    # If they do not both fit, trim whichever is asking for more. Taking from
    # the greedier one keeps a four-host panel from being cut to two lines
    # because the other one had plenty.
    while want_out + want_in > spare and max(want_out, want_in) > 1:
        if want_out >= want_in:
            want_out -= 1
        else:
            want_in -= 1
    out_limit, in_limit = want_out, want_in

    def hosts(n: int, total: int) -> str:
        shown = f"{n} host" if n == 1 else f"{n} hosts"
        return shown if n == total else f"{shown} of {total}"

    def title(label: str, which: str, shown: int, total: int) -> str:
        state = "open" if which in view.expanded else ""
        return f"{label}   {hosts(shown, total)}" + (f"   [{state}]" if state else "")

    frame = header + ["", column_labels(width, style)]
    frame += box(title("OUTBOUND", "out", len(outbound), len(all_out)),
                 panel_rows(outbound, width, out_limit, style, inbound=False,
                            filtered=bool(view.search)),
                 width, glyphs, style)
    frame += box(title("INBOUND", "in", len(inbound), len(all_in)),
                 panel_rows(inbound, width, in_limit, style, inbound=True,
                            filtered=bool(view.search)),
                 width, glyphs, style)
    frame += footer(outbound, inbound, meta, glyphs, style, view, width)
    return frame


# Dropped from the right as the terminal narrows: better to advertise four keys
# that fit than five that wrap and scroll the frame.
KEY_HINTS = [("/", "search"), ("o", "outbound"), ("i", "inbound"),
             ("c", "reset"), ("q", "quit")]


def footer(outbound: list[dict], inbound: list[dict], meta: dict,
           glyphs: Glyphs, style: Style, view: View, width: int) -> list[str]:
    """Totals, plus what the keys do -- the only place they are advertised."""
    if view.editing:
        edit = (style("  search: ", Style.BOLD) + view.search +
                style("_", Style.BOLD) +
                style("      Enter to keep it, Esc to clear", Style.DIM))
        return [visible_trim(edit, width)]
    left = (f"  {len(outbound) + len(inbound)} shown{glyphs.sep}"
            f"{core.human_bytes(meta.get('bytes', 0))} total")
    if view.search:
        left += f"{glyphs.sep}filter {view.search!r}"
    if view.expanded:
        left += f"{glyphs.sep}{'/'.join(sorted(view.expanded))} open"

    keys = ""
    for key, what in KEY_HINTS:
        piece = f"  {key}  {what}  "
        if len(keys) + len(piece) > width:
            break
        keys += piece
    return [style(visible_trim(left, width), Style.DIM),
            style(keys.rstrip(), Style.DIM)]


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
    # Two separate capabilities: whether escapes work at all, and whether the
    # viewer wants colour. Tying them together meant --no-color also disabled
    # the redraw, so frames stacked instead of replacing each other.
    ansi = enable_ansi()
    style = Style(ansi and not args.no_color)
    glyphs = Glyphs(unicode_ok() if args.unicode is None else args.unicode)
    screen = Screen(ansi and args.dashboard)
    view = View()

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

    if args.dashboard and not ansi:
        for line in (
            "note: this terminal cannot take the escape sequences the dashboard",
            "      needs, so one frame is printed at the end instead of updating",
            "      in place. Drop --dashboard for the live per-host log.",
        ):
            print(line, file=sys.stderr)

    keys_reader = Keys(args.dashboard and ansi)
    with screen, keys_reader:
      while not stop.is_set():
        # Keys are only read in dashboard mode; the quiet log has nothing to
        # search or open, and stealing stdin from it would be rude.
        if args.dashboard:
            pressed = keys_reader.get()
            while pressed is not None:
                if not view.handle(pressed):
                    stop.set()
                    break
                last_draw = 0.0        # respond to the key immediately
                pressed = keys_reader.get()
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

        screen.draw(render_dashboard(rows, meta, glyphs, style, args.interface,
                                    now - started, view))

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


# Excel and LibreOffice treat a cell opening with any of these as a formula, not
# as text, and will offer to run it. Host names come off the wire, so a host that
# calls itself `=cmd|'/c calc'!A1` turns a report into an attack on whoever opens
# it. Prefixing an apostrophe is the standard defence: spreadsheets read it as
# "this is text" and do not show it in the cell.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Stop a spreadsheet treating a captured hostname as a formula."""
    if isinstance(value, str) and value.startswith(_FORMULA_LEAD):
        return "'" + value
    return value


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
            w.writerow([csv_safe(cell) for cell in line])


def newest_capture(folder: str):
    import glob
    files = glob.glob(os.path.join(folder, "*.pcapng")) + \
        glob.glob(os.path.join(folder, "*.pcap"))
    return max(files, key=os.path.getmtime) if files else None


# ------------------------------------------------------------------ plumbing
def cmd_interfaces(args) -> int:
    """List what can be watched, and say which one is worth watching.

    The raw `tshark -D` list is close to useless on Windows: eleven devices with
    GUID names, most of them dead WAN miniports and Hyper-V switches, and nothing
    to say which carries traffic. Picking the wrong one gives an empty dashboard,
    which reads as the program being broken.
    """
    tshark = core.find_tshark()
    style = Style(enable_ansi() and not getattr(args, "no_color", False))
    glyphs = Glyphs(unicode_ok() if getattr(args, "unicode", None) is None
                    else args.unicode)
    found = core.described_interfaces(tshark)
    if not found:
        # Could not parse it, so show what tshark said rather than nothing.
        print(core.list_interfaces(tshark).rstrip())
        return 0

    width = max(len(entry["name"]) for entry in found)
    marker = "<--" if not glyphs.unicode else "←"
    for entry in found:
        addrs = ", ".join(entry["addresses"]) or entry.get("note", "")
        line = f"  {entry['number']:>2}.  {entry['name']:<{width}}  {addrs:<16}"
        if entry["in_use"]:
            print(style(line.rstrip() + f"  {marker} this machine's traffic "
                        "goes this way", Style.OUT))
        else:
            print(line.rstrip())
    knows_addresses = any(entry["addresses"] for entry in found)
    if knows_addresses and not any(entry["in_use"] for entry in found):
        # Addresses were available and none matched, so say so. Without them
        # there is nothing to report -- an advisory about a comparison that never
        # happened is just noise.
        print(style("\n  None of them holds this machine's outbound address. "
                    "Pick the one you", Style.DIM))
        print(style("  expect to carry traffic -- having an address is a good "
                    "sign.", Style.DIM))
    print(style(f"\n  Watch one with its number or its name:", Style.DIM))
    example = next((e for e in found if e["in_use"]), found[0])
    print(style(f"    crowsnest live -i {example['number']} --dashboard",
                Style.DIM))
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


def _rules_module(args):
    """Which blocking module this command should use.

    The two expose the same names on purpose, so everything downstream can call
    the module without caring which it got. What differs is where the rules land:
    blocking guards this machine on the input hook, gateway guards a routed
    device on the forward hook.
    """
    import blocking
    if getattr(args, "gateway", False):
        import gateway
        return gateway
    return blocking


def cmd_block(args) -> int:
    import blocking
    rules = _rules_module(args)
    _blocking_or_exit()
    style = Style(enable_ansi() and not args.no_color)

    # Some hosts break the routed device rather than protect it, and are only
    # identifiable by name -- Apple push runs over a range too wide to
    # enumerate and its addresses rotate. So this is checked on the target as
    # typed, before anything is resolved.
    if getattr(args, "gateway", False) and not args.force:
        refused = [(t, rules.risky_hostname(t)) for t in args.targets]
        refused = [(t, why) for t, why in refused if why]
        if refused:
            print(style("\nRefusing to block:", Style.BOLD), file=sys.stderr)
            for target, why in refused:
                print(f"  {target}  -- {why}", file=sys.stderr)
            print("\nPass --force if you are certain.", file=sys.stderr)
            names = {t for t, _ in refused}
            args.targets = [t for t in args.targets if t not in names]
            if not args.targets:
                return 1

    addresses: list[str] = []
    for target in args.targets:
        found = blocking.resolve_target(target)
        if len(found) > 1 or found[0] != target:
            print(f"  {target} -> {', '.join(found)}")
        addresses += [a for a in found if a not in addresses]

    # Refuse the addresses whose blocking tends to break things.
    if getattr(args, "gateway", False):
        problems = rules.check_targets(addresses, client_ips=args.client)
    else:
        problems = rules.check_targets(addresses)
    if problems and not args.force:
        print(style("\nRefusing to block:", Style.BOLD), file=sys.stderr)
        for address, why in problems.items():
            print(f"  {address}  -- {why}", file=sys.stderr)
        print("\nPass --force if you are certain.", file=sys.stderr)
        addresses = [a for a in addresses if a not in problems]
        if not addresses:
            return 1

    already = {e["address"] for e in rules.list_blocks()}
    fresh = [a for a in addresses if a not in already]
    for address in addresses:
        if address in already:
            print(f"  {address} is already blocked")
    if not fresh:
        return 0

    print(style("\nThis will run:", Style.BOLD))
    for line in rules.describe_commands(fresh):
        print(f"  {line}")
    if getattr(args, "gateway", False):
        print(style("\nThe monitored device will no longer reach these hosts, in "
                    "either direction.\nExisting firewall rules are untouched; "
                    f"crowsnest only writes to its own\n'{rules.TABLE}' table.",
                    Style.DIM))
    else:
        print(style("\nInbound traffic from these hosts will be dropped. Existing "
                    "firewall rules are untouched;\ncrowsnest only writes to its own "
                    f"'{rules.TABLE}' table.", Style.DIM))
    if not args.persist:
        restore = "`crowsnest blocks --gateway --restore`" \
            if getattr(args, "gateway", False) else "`crowsnest blocks --restore`"
        print(style("This lasts until reboot. Add --persist to record it for "
                    f"{restore}.", Style.DIM))

    if args.dry_run:
        print("\ndry run: nothing was changed.")
        return 0
    if not _confirm("\nApply?", args.yes):
        print("nothing was changed.")
        return 1

    added = rules.block(fresh)
    for address in added:
        print(style(f"  blocked {address}", Style.IN))
    if args.persist and added:
        rules.save_record(added)
        print(f"\nrecorded in {rules.RECORD_PATH}")
        print(rules.restore_hint())
    return 0


def cmd_unblock(args) -> int:
    import blocking
    rules = _rules_module(args)
    _blocking_or_exit()

    if args.all:
        entries = rules.list_blocks()
        if not entries:
            print("nothing is blocked.")
            return 0
        # Gateway mode empties its sets and leaves the chain standing, rather
        # than dropping the table -- the wording follows what actually happens.
        what = (f"empty crowsnest's blocked sets"
                if getattr(args, "gateway", False)
                else f"drop crowsnest's '{rules.TABLE}' table")
        print(f"This will remove all {len(entries)} block(s) and {what}.")
        if not _confirm("Remove them all?", args.yes):
            print("nothing was changed.")
            return 1
        count = rules.unblock_all()
        rules.forget_record(None)
        print(f"removed {count} block(s).")
        return 0

    addresses: list[str] = []
    for target in args.targets:
        addresses += [a for a in blocking.resolve_target(target)
                      if a not in addresses]
    removed = rules.unblock(addresses)
    if not removed:
        print("none of those were blocked.")
        return 0
    rules.forget_record(removed)
    for address in removed:
        print(f"  unblocked {address}")
    return 0


def cmd_blocks(args) -> int:
    rules = _rules_module(args)
    _blocking_or_exit()

    if args.restore:
        recorded = rules.load_record()
        if not recorded:
            print(f"nothing recorded in {rules.RECORD_PATH}")
            return 0
        active = {e["address"] for e in rules.list_blocks()}
        missing = [a for a in recorded if a not in active]
        if not missing:
            print(f"all {len(recorded)} recorded block(s) are already active.")
            return 0
        print("This will reapply:")
        for line in rules.describe_commands(missing):
            print(f"  {line}")
        if not _confirm("\nApply?", args.yes):
            print("nothing was changed.")
            return 1
        for address in rules.block(missing):
            print(f"  blocked {address}")
        return 0

    entries = rules.list_blocks()
    recorded = set(rules.load_record())
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

    # --gateway switches which hook the rules land on: without it they protect
    # this machine, with it they protect a device routed through it. Every
    # blocking command takes it, since a block made in one mode has to be
    # listed and removed in the same one.
    def gateway_flag(parser) -> None:
        parser.add_argument("--gateway", action="store_true",
                            help="block for a device routed through this "
                                 "machine (forward chain) rather than for this "
                                 "machine itself")

    # Blocking writes firewall rules, so every one of these shows the exact
    # command and asks before changing anything.
    blk = sub.add_parser("block", help="drop traffic from a host (Linux)")
    blk.add_argument("targets", nargs="+", metavar="HOST",
                     help="hostname or address to block")
    blk.add_argument("--persist", action="store_true",
                     help="record it so `crowsnest blocks --restore` can reapply "
                          "after a reboot (blocks are session-only otherwise)")
    blk.add_argument("--dry-run", action="store_true",
                     help="show what would happen and stop")
    blk.add_argument("--yes", action="store_true", help="do not ask first")
    blk.add_argument("--force", action="store_true",
                     help="allow blocking the gateway, DNS, your SSH peer, or "
                          "a host the monitored device depends on")
    blk.add_argument("--no-color", action="store_true", help="disable colour")
    gateway_flag(blk)
    blk.add_argument("--client", action="append", default=[], metavar="IP",
                     help="address of the device being monitored, so it cannot "
                          "be blocked by accident (repeatable, --gateway only)")
    blk.set_defaults(func=cmd_block)

    unb = sub.add_parser("unblock", help="remove a block")
    unb.add_argument("targets", nargs="*", metavar="HOST")
    unb.add_argument("--all", action="store_true", help="remove every block")
    unb.add_argument("--yes", action="store_true", help="do not ask first")
    gateway_flag(unb)
    unb.set_defaults(func=cmd_unblock)

    bls = sub.add_parser("blocks", help="list blocks, or reapply recorded ones")
    bls.add_argument("--restore", action="store_true",
                     help="reapply blocks recorded with --persist")
    bls.add_argument("--yes", action="store_true", help="do not ask first")
    gateway_flag(bls)
    bls.set_defaults(func=cmd_blocks)

    upd = sub.add_parser("update", help="check whether a newer crowsnest exists")
    upd.set_defaults(func=cmd_update)
    return ap


def owns_the_console() -> bool:
    """True when this console exists only for us.

    Which means Explorer made the window -- someone double-clicked
    crowsnest.exe -- and it closes the instant we return, taking whatever we
    printed with it. Started from a shell, the shell is attached too, so the
    count is higher and the window is not ours to hold open.

    The frozen build is not one process but two: PyInstaller's onefile
    bootloader unpacks the bundle and runs the real program as a child, and both
    stay attached. Measured on a double-clicked crowsnest.exe the count is 2,
    and from a shell it is 4, so the line sits between them. Running from source
    there is no bootloader and the count is 1. Getting this wrong is invisible
    from a terminal, which is how the first attempt shipped.
    """
    if os.name != "nt":
        return False
    alone = 2 if getattr(sys, "frozen", False) else 1
    try:
        import ctypes
        buffer = (ctypes.c_uint * 8)()
        attached = ctypes.windll.kernel32.GetConsoleProcessList(buffer, 8)
        return 0 < attached <= alone
    except Exception:                  # no console, or no kernel32 to ask
        return False


def wait_before_closing() -> None:
    """Keep a double-clicked window open long enough to read."""
    try:
        input("\nPress Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> int:
    # Double-clicked, the console vanishes when this returns. Everything below
    # that prints something worth reading pauses first.
    hold = owns_the_console()

    if hold and len(sys.argv) == 1:
        # argparse would print two lines of usage and exit(2) here, which is
        # not much of an introduction for someone who has just double-clicked
        # an unfamiliar program. Show the whole thing and say what it is.
        build_parser().print_help()
        print("\ncrowsnest is a command line tool -- it does not have a window."
              "\nOpen PowerShell or Terminal and give it one of the commands"
              "\nabove, for example:\n"
              "\n    crowsnest interfaces\n"
              "\nInstalling it puts `crowsnest` on your PATH so you can do that"
              "\nfrom anywhere:\n"
              "\n    irm https://raw.githubusercontent.com/t0mbo192/crowsnest"
              "/main/install.ps1 | iex\n")
        wait_before_closing()
        return 0

    try:
        args = build_parser().parse_args()
    except SystemExit:                 # --help, --version, or a usage error
        if hold:
            wait_before_closing()
        raise

    try:
        return args.func(args)
    except RuntimeError as e:          # tshark missing, or it failed
        print(f"error: {e}", file=sys.stderr)
        if hold:
            wait_before_closing()
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:            # piped into head, etc.
        return 0


if __name__ == "__main__":
    sys.exit(main())
