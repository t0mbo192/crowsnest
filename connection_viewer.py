#!/usr/bin/env python3
"""
Connection Viewer -- a standalone app that reads a Wireshark capture (.pcapng /
.pcap) and shows, in plain language, the connections your computer made and
received:

    * every site / host, split into OUTBOUND (you connected out) and INBOUND
      (something connected to you),
    * a short description of what each host is,
    * a live filter box + direction filter, and
    * an "Export" button to save a simple text printout.

It calls the `tshark` program that ships with Wireshark to read the capture, so
Wireshark must be installed -- but Python does NOT need to be, once this is built
into an .exe with PyInstaller.

Build a standalone .exe:
    pyinstaller --onefile --windowed --name ConnectionViewer connection_viewer.py
"""

from __future__ import annotations

import glob
import ipaddress
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections import defaultdict

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

import updater
from netwatch_version import __version__

# Folder scanned for the newest capture when the app starts with no file.
DROP_DIR = os.path.join(os.path.expanduser("~"), "Documents", "Captures")
# Hide the console window tshark would otherwise flash on Windows.
_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

socket.setdefaulttimeout(2)  # keep reverse-DNS snappy

FIELDS = [
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags.syn", "tcp.flags.ack",
    "frame.len", "_ws.col.Protocol",
    "dns.qry.name", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name", "http.host",
]

# ----------------------------------------------------------------------------
# "What is this host?"  First substring match wins, so order specific -> general.
# ----------------------------------------------------------------------------
DESCRIPTIONS = [
    ("1e100.net", "Google infrastructure"),
    ("googlevideo.com", "YouTube video streaming"),
    ("ytimg", "YouTube (images)"),
    ("youtube", "YouTube"),
    ("google-analytics", "Google Analytics (tracking)"),
    ("googletagmanager", "Google Tag Manager (tracking)"),
    ("doubleclick", "Google / DoubleClick advertising"),
    ("googlesyndication", "Google advertising"),
    ("googleapis", "Google APIs"),
    ("gstatic", "Google static content (CDN)"),
    ("googleusercontent", "Google cloud / user content"),
    ("dns.google", "Google Public DNS"),
    ("gmail", "Google Gmail"),
    ("google", "Google services"),
    ("datadoghq", "Datadog - monitoring / telemetry"),
    ("browser-intake", "Web analytics / telemetry beacon"),
    ("sentry", "Sentry - error tracking"),
    ("mixpanel", "Mixpanel - analytics"),
    ("amplitude", "Amplitude - analytics"),
    ("segment.io", "Segment - analytics"),
    ("windowsupdate", "Windows Update"),
    ("msftconnecttest", "Windows connectivity check"),
    ("msftncsi", "Windows connectivity check"),
    ("windows.net", "Microsoft Azure / Windows"),
    ("azure", "Microsoft Azure cloud"),
    ("office", "Microsoft Office / 365"),
    ("live.com", "Microsoft account (Live)"),
    ("bing", "Microsoft Bing"),
    ("microsoft", "Microsoft services"),
    ("icloud", "Apple iCloud"),
    ("mzstatic", "Apple media / CDN"),
    ("aaplimg", "Apple infrastructure"),
    ("apple.com", "Apple services"),
    ("cloudfront.net", "Amazon CloudFront (CDN)"),
    ("amazonaws", "Amazon AWS cloud"),
    ("amazon", "Amazon"),
    ("akamai", "Akamai (CDN)"),
    ("edgekey", "Akamai (CDN)"),
    ("edgesuite", "Akamai (CDN)"),
    ("fastly", "Fastly (CDN)"),
    ("cloudflare-dns", "Cloudflare DNS"),
    ("cloudflare", "Cloudflare (CDN / security)"),
    ("fbcdn", "Facebook / Meta (CDN)"),
    ("facebook", "Facebook / Meta"),
    ("instagram", "Instagram / Meta"),
    ("whatsapp", "WhatsApp / Meta"),
    ("twimg", "Twitter / X (images)"),
    ("twitter", "Twitter / X"),
    ("tiktok", "TikTok"),
    ("linkedin", "LinkedIn"),
    ("reddit", "Reddit"),
    ("githubusercontent", "GitHub (content)"),
    ("github", "GitHub - code hosting"),
    ("gitlab", "GitLab - code hosting"),
    ("nflxvideo", "Netflix (video CDN)"),
    ("netflix", "Netflix streaming"),
    ("spotify", "Spotify audio streaming"),
    ("twitch", "Twitch streaming"),
    ("slack", "Slack messaging"),
    ("discord", "Discord messaging"),
    ("zoom.us", "Zoom video calls"),
    ("tailscale", "Tailscale VPN (mesh networking)"),
    ("wireguard", "WireGuard VPN"),
    ("pool.ntp", "Time sync (NTP)"),
    ("time.", "Time sync (NTP)"),
    ("ubuntu", "Ubuntu / Canonical"),
    ("mozilla", "Mozilla / Firefox"),
    ("firefox", "Mozilla / Firefox"),
    ("pi.hole", "Pi-hole (local DNS / ad-block)"),
    ("fritz.box", "Router (FRITZ!Box)"),
    ("gateway", "Router / gateway"),
]


def describe(host: str, local: bool) -> str:
    h = (host or "").lower()
    for needle, desc in DESCRIPTIONS:
        if needle in h:
            return desc
    if local:
        return "Local network device"
    if not host:
        return "Unknown host (no name)"
    return "Website / service"


# ----------------------------------------------------------------------------
# Capture analysis (self-contained: dissect -> direction-split connections)
# ----------------------------------------------------------------------------
def find_tshark() -> str:
    exe = shutil.which("tshark")
    if exe:
        return exe
    for c in (r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe"):
        if os.path.isfile(c):
            return c
    raise RuntimeError("Couldn't find tshark. Install Wireshark (or add it to PATH).")


def run_tshark(tshark: str, capture: str) -> str:
    cmd = [tshark, "-r", capture, "-T", "fields",
           "-E", "separator=/t", "-E", "aggregator=;", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, creationflags=_NO_WINDOW)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed:\n{proc.stderr.strip()}")
    return proc.stdout


def _vals(field: str) -> list[str]:
    return [v for v in field.split(";") if v]


def is_routable_peer(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_multicast or a.is_unspecified or ip == "255.255.255.255":
        return False
    if a.version == 4 and a.is_private and ip.endswith(".255"):
        return False
    return True


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


_rdns_cache: dict[str, str] = {}


def resolve_many(ips, budget: float = 8.0, workers: int = 16) -> dict[str, str]:
    """Reverse-DNS a batch of IPs at once, giving up after `budget` seconds.

    socket.gethostbyaddr() goes through the system resolver, which ignores
    socket.setdefaulttimeout() -- one address with no working PTR server can
    stall for ~9s. Serially that adds up to a frozen app, so the lookups run in
    parallel daemon threads under a single overall deadline. Anything that
    doesn't answer in time is cached as a miss and simply stays an IP address.
    """
    todo = [ip for ip in dict.fromkeys(ips) if ip and ip not in _rdns_cache]
    if todo:
        work: queue.Queue = queue.Queue()
        for ip in todo:
            work.put(ip)
        found: dict[str, str] = {}
        lock = threading.Lock()

        def drain() -> None:
            while True:
                try:
                    ip = work.get_nowait()
                except queue.Empty:
                    return
                try:
                    name = socket.gethostbyaddr(ip)[0].lower()
                except OSError:
                    name = ""
                with lock:
                    found[ip] = name

        threads = [threading.Thread(target=drain, daemon=True)
                   for _ in range(min(workers, len(todo)))]
        for t in threads:
            t.start()
        deadline = time.monotonic() + budget
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))
        with lock:
            _rdns_cache.update(found)
        # Cache the ones that never came back so we don't retry them every load.
        for ip in todo:
            _rdns_cache.setdefault(ip, "")
    return {ip: _rdns_cache.get(ip, "") for ip in ips}


def fill_names(rows: list[dict], budget: float = 8.0) -> bool:
    """Fill in rows we only have an IP for. True if any name was found."""
    unknown = [r["ip"] for r in rows if not r["name"]]
    if not unknown:
        return False
    names = resolve_many(unknown, budget=budget)
    changed = False
    for r in rows:
        name = names.get(r["ip"], "")
        if name and not r["name"]:
            r["name"] = r["site"] = name
            r["description"] = describe(name, r["local"])
            changed = True
    return changed


class _Flow:
    __slots__ = ("packets", "bytes", "hostnames", "initiator", "locked")

    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.hostnames: set[str] = set()
        self.initiator = None
        self.locked = False


def analyze(capture: str, resolve: bool = True) -> dict:
    """Dissect a capture into direction-split connections.

    resolve=False skips reverse-DNS entirely, which keeps this fast (~1s); the
    GUI uses that, then fills names in afterwards on a background thread.
    """
    output = run_tshark(find_tshark(), capture)
    flows: dict[tuple, _Flow] = {}
    ip_hits: dict[str, int] = defaultdict(int)
    ip_to_name: dict[str, str] = {}
    total = 0

    for line in output.splitlines():
        c = line.split("\t")
        if len(c) < len(FIELDS):
            c += [""] * (len(FIELDS) - len(c))
        (ip_s, ip_d, ip6_s, ip6_d, tsp, tdp, usp, udp_, syn, ack,
         flen, proto, dqry, da, daaaa, sni, host) = c
        src, dst = (ip_s or ip6_s), (ip_d or ip6_d)
        if not src or not dst:
            continue
        total += 1
        try:
            nbytes = int(flen) if flen else 0
        except ValueError:
            nbytes = 0
        for ip in (src, dst):
            if is_routable_peer(ip):
                ip_hits[ip] += 1

        answers = _vals(da) + _vals(daaaa)
        if answers and dqry:
            qname = _vals(dqry)[0].lower().rstrip(".")
            for ip in answers:
                ip_to_name.setdefault(ip, qname)

        if tsp or tdp:
            l4, sp, dp = "tcp", tsp, tdp
        elif usp or udp_:
            l4, sp, dp = "udp", usp, udp_
        else:
            l4, sp, dp = "other", "", ""
        key = (proto, frozenset((src, dst))) if l4 == "other" \
            else (l4, frozenset(((src, sp), (dst, dp))))

        fl = flows.get(key) or flows.setdefault(key, _Flow())
        fl.packets += 1
        fl.bytes += nbytes
        for name in _vals(sni) + _vals(host):
            nm = name.lower().rstrip(".")
            if nm and not is_routable_peer(nm.split(":")[0]):
                fl.hostnames.add(nm)
        if l4 == "tcp" and syn == "1" and ack != "1":
            fl.initiator, fl.locked = (src, dst), True
        elif not fl.locked and fl.initiator is None:
            fl.initiator = (src, dst)

    if not ip_hits:
        return {"packets": total, "my_ip": "", "rows": []}

    def top(v6: bool) -> str:
        best, n = "", -1
        for ip, hits in ip_hits.items():
            if ((":" in ip) == v6) and hits > n:
                best, n = ip, hits
        return best
    my_ips = {ip for ip in (top(False), top(True)) if ip}

    agg: dict[tuple, dict] = {}
    for fl in flows.values():
        if not fl.initiator:
            continue
        isrc, idst = fl.initiator
        if isrc in my_ips and is_routable_peer(idst):
            direction, remote = "outbound", idst
        elif idst in my_ips and is_routable_peer(isrc):
            direction, remote = "inbound", isrc
        else:
            continue
        a = agg.setdefault((direction, remote),
                           {"packets": 0, "bytes": 0, "hostnames": set()})
        a["packets"] += fl.packets
        a["bytes"] += fl.bytes
        a["hostnames"] |= fl.hostnames

    rows = []
    for (direction, ip), a in agg.items():
        # Names known from the capture itself (TLS SNI / HTTP Host / DNS answers).
        # Anything still unnamed is left to fill_names(), which is slow enough
        # that the GUI runs it separately once the table is already on screen.
        name = sorted(a["hostnames"])[0] if a["hostnames"] else ip_to_name.get(ip, "")
        local = is_private(ip)
        rows.append({
            "direction": direction, "site": name or ip, "ip": ip, "name": name,
            "description": describe(name, local),
            "packets": a["packets"], "bytes": a["bytes"], "local": local,
        })
    if resolve:
        fill_names(rows)
    # Outbound first, then by bytes desc.
    rows.sort(key=lambda r: (r["direction"] != "outbound", -r["bytes"]))
    return {"packets": total, "my_ip": ", ".join(sorted(my_ips)), "rows": rows}


def make_text(capture: str, meta: dict, rows: list[dict]) -> str:
    L = [f"Capture:  {os.path.basename(capture)}",
         f"Your machine:  {meta.get('my_ip') or '(unknown)'}     "
         f"packets analyzed: {meta.get('packets', 0)}",
         "Note: encrypted traffic reveals which hosts were contacted, "
         "not page content.", ""]
    for direction, title in (("outbound", "SITES YOU CONNECTED TO   (outbound)"),
                             ("inbound", "CONNECTING TO YOU        (inbound)")):
        L += ["=" * 78, title, "=" * 78]
        group = [r for r in rows if r["direction"] == direction]
        if not group:
            L.append("  (none)")
        for r in group:
            tail = f"  [{r['ip']}]" if r["site"] != r["ip"] else ""
            L.append(f"  {r['packets']:>6}  {r['bytes']:>11,}  "
                     f"{r['site']}{tail}")
            L.append(f"          {r['description']}")
        L.append("")
    return "\n".join(L)


# ----------------------------------------------------------------------------
# Theme
#
# Built on ttk's "clam" theme because it is the only stock theme that honours
# colour configuration on every platform -- the Windows default ("vista")
# silently ignores most of it. No third-party theme packages, so this still
# runs on a bare Raspberry Pi and bundles cleanly with PyInstaller.
# ----------------------------------------------------------------------------
PALETTES = {
    "dark": {
        "bg":        "#15171c",   # window background
        "surface":   "#1e2128",   # cards, table, inputs
        "surface2":  "#252932",   # table stripe / hover
        "border":    "#2f343f",
        "text":      "#e7eaf0",
        "muted":     "#8b93a3",
        "accent":    "#5b9cff",   # outbound / primary
        "accent_fg": "#ffffff",
        "inbound":   "#ff9d5c",   # inbound stands out on a monitoring screen
        "good":      "#4ec9a5",
        "heading":   "#232730",
    },
    "light": {
        "bg":        "#f4f6f9",
        "surface":   "#ffffff",
        "surface2":  "#f7f9fc",
        "border":    "#dfe4ec",
        "text":      "#1b1f28",
        "muted":     "#69717f",
        "accent":    "#2f6fed",
        "accent_fg": "#ffffff",
        "inbound":   "#c2570f",
        "good":      "#12855f",
        "heading":   "#eef1f6",
    },
}

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".netwatch.json")


def load_prefs() -> dict:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_prefs(prefs: dict) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(prefs, f)
    except OSError:
        pass


def pick_font(candidates: list[str], fallback: str) -> str:
    try:
        available = set(tkfont.families())
    except tk.TclError:
        return fallback
    for name in candidates:
        if name in available:
            return name
    return fallback


def dark_titlebar(root: tk.Tk, enabled: bool) -> None:
    """Match the Windows title bar to the theme. No-op elsewhere."""
    if os.name != "nt":
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1 if enabled else 0)
        # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (19 on older Windows 10 builds)
        for attr in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attr, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass


def human_bytes(n: int) -> str:
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


def apply_theme(root: tk.Tk, style: ttk.Style, mode: str) -> dict:
    """Paint every widget style for the chosen mode; returns the palette."""
    c = PALETTES[mode]
    ui = pick_font(["Segoe UI", "Inter", "DejaVu Sans", "Helvetica"], "TkDefaultFont")
    mono = pick_font(["Cascadia Mono", "Consolas", "DejaVu Sans Mono"], "TkFixedFont")

    style.theme_use("clam")
    root.configure(bg=c["bg"])

    style.configure(".", background=c["bg"], foreground=c["text"],
                    fieldbackground=c["surface"], borderwidth=0, font=(ui, 10))
    style.configure("TFrame", background=c["bg"])
    style.configure("Card.TFrame", background=c["surface"])
    style.configure("TLabel", background=c["bg"], foreground=c["text"])
    style.configure("Card.TLabel", background=c["surface"], foreground=c["text"])
    style.configure("Title.TLabel", font=(ui, 15, "bold"), foreground=c["text"])
    style.configure("Muted.TLabel", foreground=c["muted"], font=(ui, 9))
    style.configure("CardMuted.TLabel", background=c["surface"],
                    foreground=c["muted"], font=(ui, 8))
    style.configure("Stat.TLabel", background=c["surface"], foreground=c["text"],
                    font=(ui, 17, "bold"))
    style.configure("StatAccent.TLabel", background=c["surface"],
                    foreground=c["accent"], font=(ui, 17, "bold"))
    style.configure("StatIn.TLabel", background=c["surface"],
                    foreground=c["inbound"], font=(ui, 17, "bold"))

    # Buttons -- flat, with a visible hover state.
    style.configure("TButton", background=c["surface2"], foreground=c["text"],
                    borderwidth=0, focuscolor=c["surface2"], padding=(12, 7),
                    font=(ui, 9))
    style.map("TButton",
              background=[("pressed", c["border"]), ("active", c["border"])])
    style.configure("Accent.TButton", background=c["accent"],
                    foreground=c["accent_fg"], padding=(14, 7), font=(ui, 9, "bold"))
    style.map("Accent.TButton", background=[("pressed", c["accent"]),
                                            ("active", c["accent"])])

    style.configure("TEntry", fieldbackground=c["surface"], foreground=c["text"],
                    insertcolor=c["text"], borderwidth=1, padding=6)
    style.map("TEntry", bordercolor=[("focus", c["accent"])])
    style.configure("TCheckbutton", background=c["bg"], foreground=c["muted"],
                    focuscolor=c["bg"], font=(ui, 9),
                    indicatorbackground=c["surface"],
                    indicatorforeground=c["accent_fg"],
                    indicatormargin=(0, 0, 6, 0), borderwidth=0)
    style.map("TCheckbutton", foreground=[("active", c["text"])],
              indicatorbackground=[("selected", c["accent"]),
                                   ("active", c["surface2"])])

    # Segmented direction control (radiobuttons drawn as toggle buttons).
    style.configure("Toolbutton", background=c["surface2"], foreground=c["muted"],
                    borderwidth=0, padding=(14, 6), font=(ui, 9))
    style.map("Toolbutton",
              background=[("selected", c["accent"]), ("active", c["border"])],
              foreground=[("selected", c["accent_fg"]), ("active", c["text"])])

    # Table.
    style.configure("Treeview", background=c["surface"], fieldbackground=c["surface"],
                    foreground=c["text"], borderwidth=0, rowheight=30, font=(ui, 10))
    style.map("Treeview", background=[("selected", c["accent"])],
              foreground=[("selected", c["accent_fg"])])
    style.configure("Treeview.Heading", background=c["heading"],
                    foreground=c["muted"], relief="flat", borderwidth=0,
                    padding=(10, 9), font=(ui, 9, "bold"))
    style.map("Treeview.Heading", background=[("active", c["border"])])

    style.configure("Vertical.TScrollbar", background=c["surface2"],
                    troughcolor=c["bg"], borderwidth=0, arrowcolor=c["muted"])
    style.map("Vertical.TScrollbar", background=[("active", c["border"])])
    style.configure("TProgressbar", background=c["accent"], troughcolor=c["bg"],
                    borderwidth=0)

    dark_titlebar(root, mode == "dark")
    return {"c": c, "ui": ui, "mono": mono}


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
COLUMNS = [
    ("dir",     "Direction", 110, False),
    ("site",    "Site / host", 300, True),
    ("desc",    "What it is", 260, True),
    ("ip",      "IP address", 150, False),
    ("packets", "Packets", 90, False),
    ("bytes",   "Data", 100, False),
]
NUMERIC_COLS = {"packets", "bytes"}


class App:
    def __init__(self, root: tk.Tk, initial: str | None = None):
        self.root = root
        self.capture = None
        self.meta: dict = {}
        self.all_rows: list[dict] = []
        self.q: queue.Queue = queue.Queue()
        self.update_q: queue.Queue = queue.Queue()   # update check, own channel
        self._busy = False
        self._sort_col = "bytes"
        self._sort_desc = True
        self._update = None

        self.prefs = load_prefs()
        self.mode = self.prefs.get("theme", "dark")
        self.style = ttk.Style(root)
        self.theme = apply_theme(root, self.style, self.mode)

        root.title(f"netwatch {__version__} — Connection Viewer")
        root.geometry("1180x740")
        root.minsize(900, 520)

        self._build_header()
        self._build_stats()
        self._build_controls()
        self._build_table()
        self._build_statusbar()
        # Wired up only once every widget exists -- setting the placeholder text
        # above would otherwise fire refresh() before the table is built.
        self.filter_var.trace_add("write", lambda *_: self.refresh())

        self._start_update_check()
        if initial:
            self.load(initial)

    # ------------------------------------------------------------------ build
    def _build_header(self):
        bar = ttk.Frame(self.root, padding=(18, 16, 18, 10))
        bar.pack(fill="x")
        left = ttk.Frame(bar)
        left.pack(side="left")
        ttk.Label(left, text="netwatch", style="Title.TLabel").pack(anchor="w")
        self.info = ttk.Label(left, text="No capture loaded", style="Muted.TLabel")
        self.info.pack(anchor="w", pady=(2, 0))

        right = ttk.Frame(bar)
        right.pack(side="right")
        self.theme_btn = ttk.Button(right, text=self._theme_label(),
                                    command=self.toggle_theme, width=10)
        self.theme_btn.pack(side="right")
        ttk.Button(right, text="Export", command=self.export
                   ).pack(side="right", padx=(0, 8))
        ttk.Button(right, text="Open Capture", style="Accent.TButton",
                   command=self.choose).pack(side="right", padx=(0, 8))
        # Stays hidden unless a newer version is actually found.
        self.update_btn = ttk.Button(right, text="", command=self._show_update)


    def _build_stats(self):
        wrap = ttk.Frame(self.root, padding=(18, 0, 18, 12))
        wrap.pack(fill="x")
        self.stat_vars = {}
        specs = [("total", "CONNECTIONS", "Stat.TLabel"),
                 ("out", "OUTBOUND", "StatAccent.TLabel"),
                 ("inb", "INBOUND", "StatIn.TLabel"),
                 ("data", "DATA", "Stat.TLabel")]
        for i, (key, label, vstyle) in enumerate(specs):
            card = ttk.Frame(wrap, style="Card.TFrame", padding=(16, 12))
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 10, 0))
            wrap.columnconfigure(i, weight=1)
            var = tk.StringVar(value="—")
            ttk.Label(card, textvariable=var, style=vstyle).pack(anchor="w")
            ttk.Label(card, text=label, style="CardMuted.TLabel").pack(anchor="w")
            self.stat_vars[key] = var

    def _build_controls(self):
        bar = ttk.Frame(self.root, padding=(18, 0, 18, 10))
        bar.pack(fill="x")

        self.filter_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.filter_var, width=34)
        entry.pack(side="left")
        self._placeholder(entry, "Filter by site, description or IP…")

        seg = ttk.Frame(bar)
        seg.pack(side="left", padx=(12, 0))
        self.dir_var = tk.StringVar(value="all")
        for value, text in (("all", "All"), ("outbound", "Outbound"),
                            ("inbound", "Inbound")):
            ttk.Radiobutton(seg, text=text, value=value, variable=self.dir_var,
                            style="Toolbutton", command=self.refresh
                            ).pack(side="left", padx=(0, 2))

        self.resolve_var = tk.BooleanVar(value=self.prefs.get("resolve", True))
        ttk.Checkbutton(bar, text="Look up host names", variable=self.resolve_var
                        ).pack(side="left", padx=(14, 0))

        self.count_label = ttk.Label(bar, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")

    def _placeholder(self, entry: ttk.Entry, text: str):
        """Grey hint text that clears on focus."""
        c = self.theme["c"]
        entry.insert(0, text)
        entry.configure(foreground=c["muted"])
        self._ph_active = True

        def on_focus_in(_):
            if self._ph_active:
                entry.delete(0, "end")
                entry.configure(foreground=c["text"])
                self._ph_active = False

        def on_focus_out(_):
            if not entry.get():
                self._ph_active = True
                entry.configure(foreground=c["muted"])
                entry.insert(0, text)

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
        self._filter_entry = entry
        self._filter_placeholder = text

    def _build_table(self):
        frame = ttk.Frame(self.root, padding=(18, 0, 18, 0))
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in COLUMNS],
                                 show="headings", selectmode="browse")
        for key, title, width, stretch in COLUMNS:
            anchor = "e" if key in NUMERIC_COLS else "w"
            self.tree.heading(key, text=title, anchor=anchor,
                              command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, stretch=stretch, anchor=anchor)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._tag_rows()

    def _tag_rows(self):
        c = self.theme["c"]
        self.tree.tag_configure("odd", background=c["surface"])
        self.tree.tag_configure("even", background=c["surface2"])
        self.tree.tag_configure("in", foreground=c["inbound"])
        self.tree.tag_configure("out", foreground=c["text"])

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, padding=(18, 8, 18, 12))
        bar.pack(fill="x", side="bottom")
        self.status = ttk.Label(bar, text="Open a capture to begin.",
                                style="Muted.TLabel")
        self.status.pack(side="left")
        # Packed only while working -- an idle indeterminate bar still paints a
        # stray chunk, which reads as "something is running" when nothing is.
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=170)

    # ----------------------------------------------------------------- updates
    def _start_update_check(self):
        """Ask in the background whether a newer netwatch exists.

        Purely advisory -- nothing is downloaded, and a failed check is silent
        apart from the status bar. Runs off the main thread so a slow network
        can never stall the window.
        """
        def worker():
            try:
                self.update_q.put(updater.check(__version__))
            except Exception:
                self.update_q.put({"status": "unknown"})

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(400, self._poll_update)

    def _poll_update(self):
        try:
            result = self.update_q.get_nowait()
        except queue.Empty:
            self.root.after(400, self._poll_update)
            return
        self._update = result
        if result.get("status") != "update":
            return
        if result.get("how") == "git":
            n = result.get("behind", 0)
            label = f"● Update: {n} commit{'' if n == 1 else 's'}"
        else:
            label = f"● Update: v{result.get('version')}"
        self.update_btn.config(text=label, style="Accent.TButton")
        self.update_btn.pack(side="right", padx=(0, 8))

    def _show_update(self):
        """Explain how to take the update -- we never apply it silently."""
        r = self._update or {}
        if r.get("how") == "git":
            n = r.get("behind", 0)
            body = (f"{n} new commit{'' if n == 1 else 's'} available.\n\n"
                    f"Latest: {r.get('detail', '')}\n\n"
                    f"Update with:\n    git pull\n\n"
                    f"Then restart netwatch.")
            messagebox.showinfo("Update available", body)
            return
        version = r.get("version", "")
        if messagebox.askyesno(
                "Update available",
                f"netwatch v{version} is available "
                f"(you have {__version__}).\n\n"
                f"Open the download page in your browser?"):
            webbrowser.open(r.get("url") or updater.RELEASES_PAGE)

    # ------------------------------------------------------------------ theme
    def _theme_label(self) -> str:
        return "Light mode" if self.mode == "dark" else "Dark mode"

    def toggle_theme(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.theme = apply_theme(self.root, self.style, self.mode)
        self.theme_btn.config(text=self._theme_label())
        self._tag_rows()
        c = self.theme["c"]
        if getattr(self, "_ph_active", False):
            self._filter_entry.configure(foreground=c["muted"])
        else:
            self._filter_entry.configure(foreground=c["text"])
        self.refresh()
        self.prefs["theme"] = self.mode
        save_prefs(self.prefs)

    # ---------------------------------------------------------------- actions
    def choose(self):
        path = filedialog.askopenfilename(
            title="Open capture",
            filetypes=[("Captures", "*.pcapng *.pcap *.cap"), ("All files", "*.*")])
        if path:
            self.load(path)

    def load(self, path: str):
        """Kick off analysis on a background thread so the window stays live."""
        if not os.path.isfile(path):
            messagebox.showerror("Open capture", f"No such file:\n{path}")
            return
        if self._busy:
            return
        self.capture = path
        self.prefs["resolve"] = bool(self.resolve_var.get())
        save_prefs(self.prefs)
        self._set_busy(True, f"Reading {os.path.basename(path)} …")
        threading.Thread(target=self._parse_worker, args=(path,),
                         daemon=True).start()
        self.root.after(80, self._poll)

    # Workers run off the main thread and only ever hand results to the queue --
    # every widget and row update happens back in _poll on the main thread.
    def _parse_worker(self, path: str):
        try:
            self.q.put(("parsed", analyze(path, resolve=False)))
        except Exception as e:
            self.q.put(("error", str(e) or e.__class__.__name__))

    def _names_worker(self, ips: list[str]):
        try:
            self.q.put(("names", resolve_many(ips)))
        except Exception:
            self.q.put(("names", {}))

    def _poll(self):
        try:
            msg = self.q.get_nowait()
        except queue.Empty:
            self.root.after(80, self._poll)
            return

        kind = msg[0]
        if kind == "error":
            self._set_busy(False)
            messagebox.showerror("Analysis failed", msg[1])
            return

        if kind == "parsed":
            self.meta = msg[1]
            self.all_rows = self.meta["rows"]
            self.info.config(
                text=f"{os.path.basename(self.capture)}   ·   "
                     f"this machine {self.meta['my_ip'] or '?'}   ·   "
                     f"{self.meta['packets']} packets")
            self.refresh()   # table is usable now; names arrive next
            unresolved = [r["ip"] for r in self.all_rows if not r["name"]]
            if unresolved and self.resolve_var.get():
                self.status.config(
                    text=f"Looking up {len(unresolved)} host name(s) …")
                threading.Thread(target=self._names_worker, args=(unresolved,),
                                 daemon=True).start()
                self.root.after(80, self._poll)
            else:
                self._set_busy(False)
            return

        if kind == "names":
            names = msg[1]
            found = 0
            for r in self.all_rows:
                name = names.get(r["ip"], "")
                if name and not r["name"]:
                    r["name"] = r["site"] = name
                    r["description"] = describe(name, r["local"])
                    found += 1
            if found:
                self.refresh()
            self._set_busy(False)

    def _set_busy(self, busy: bool, text: str | None = None):
        self._busy = busy
        if text:
            self.status.config(text=text)
        if busy:
            self.progress.pack(side="right")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self.status.config(
                text=f"{len(self.all_rows)} connections" if self.all_rows
                else "Open a capture to begin.")

    # --------------------------------------------------------------- display
    def _filter_text(self) -> str:
        if getattr(self, "_ph_active", False):
            return ""
        return self.filter_var.get().strip().lower()

    def _visible_rows(self) -> list[dict]:
        text = self._filter_text()
        want = self.dir_var.get()
        rows = []
        for r in self.all_rows:
            if want != "all" and r["direction"] != want:
                continue
            if text and text not in (
                    f"{r['site']} {r['description']} {r['ip']}").lower():
                continue
            rows.append(r)
        # Sorting works on the underlying values, not the formatted strings.
        keys = {"dir": lambda r: r["direction"], "site": lambda r: r["site"].lower(),
                "desc": lambda r: r["description"].lower(),
                "ip": lambda r: r["ip"], "packets": lambda r: r["packets"],
                "bytes": lambda r: r["bytes"]}
        rows.sort(key=keys[self._sort_col], reverse=self._sort_desc)
        return rows

    def sort_by(self, col: str):
        if self._sort_col == col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = col
            self._sort_desc = col in NUMERIC_COLS
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        rows = self._visible_rows()
        for i, r in enumerate(rows):
            outbound = r["direction"] == "outbound"
            self.tree.insert(
                "", "end",
                values=("↑  Outbound" if outbound else "↓  Inbound",
                        r["site"], r["description"], r["ip"],
                        f"{r['packets']:,}", human_bytes(r["bytes"])),
                tags=("out" if outbound else "in",
                      "odd" if i % 2 else "even"))

        for key, title, _w, _s in COLUMNS:
            arrow = ""
            if key == self._sort_col:
                arrow = "  ▼" if self._sort_desc else "  ▲"
            self.tree.heading(key, text=title + arrow)

        n_out = sum(1 for r in rows if r["direction"] == "outbound")
        n_in = len(rows) - n_out
        total_bytes = sum(r["bytes"] for r in self.all_rows)
        self.stat_vars["total"].set(str(len(self.all_rows)))
        self.stat_vars["out"].set(
            str(sum(1 for r in self.all_rows if r["direction"] == "outbound")))
        self.stat_vars["inb"].set(
            str(sum(1 for r in self.all_rows if r["direction"] == "inbound")))
        self.stat_vars["data"].set(human_bytes(total_bytes) if total_bytes else "—")
        self.count_label.config(
            text=f"showing {len(rows)} of {len(self.all_rows)}"
                 f"   ·   {n_out} out, {n_in} in")

    def export(self):
        if not self.all_rows:
            messagebox.showinfo("Export", "Open a capture first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save printout", defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(make_text(self.capture, self.meta, self._visible_rows()))
        except OSError as e:
            messagebox.showerror("Export", f"Couldn't write file:\n{e}")
            return
        messagebox.showinfo("Export", f"Saved printout to:\n{path}")


def _newest(folder: str):
    files = glob.glob(os.path.join(folder, "*.pcapng")) + \
        glob.glob(os.path.join(folder, "*.pcap"))
    return max(files, key=os.path.getmtime) if files else None


def main():
    initial = None
    if len(sys.argv) > 1 and sys.argv[1].strip() and os.path.isfile(sys.argv[1]):
        initial = sys.argv[1]
    else:
        try:
            os.makedirs(DROP_DIR, exist_ok=True)
            initial = _newest(DROP_DIR)
        except OSError:
            pass
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.25)
    except tk.TclError:
        pass
    App(root, initial)
    root.mainloop()


if __name__ == "__main__":
    for _n in ("stdout", "stderr"):
        if getattr(sys, _n) is None:
            setattr(sys, _n, open(os.devnull, "w"))
    main()
