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
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

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
# GUI
# ----------------------------------------------------------------------------
class App:
    def __init__(self, root: tk.Tk, initial: str | None = None):
        self.root = root
        self.capture = None
        self.meta: dict = {}
        self.all_rows: list[dict] = []
        self._sort = {}
        self.q: queue.Queue = queue.Queue()
        self._busy = False

        root.title("Connection Viewer")
        root.geometry("1000x640")
        root.minsize(760, 420)

        self._build_toolbar()
        self._build_filterbar()
        self._build_table()
        self._build_statusbar()

        if initial:
            self.load(initial)

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(8, 8))
        bar.pack(fill="x")
        ttk.Button(bar, text="Open Capture…", command=self.choose).pack(side="left")
        ttk.Button(bar, text="Export…", command=self.export).pack(side="left", padx=(6, 0))
        self.resolve_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Look up host names",
                        variable=self.resolve_var).pack(side="left", padx=(12, 0))
        self.info = ttk.Label(bar, text="", foreground="#555")
        self.info.pack(side="left", padx=(12, 0))

    def _build_filterbar(self):
        bar = ttk.Frame(self.root, padding=(8, 0))
        bar.pack(fill="x")
        ttk.Label(bar, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.refresh())
        ent = ttk.Entry(bar, textvariable=self.filter_var, width=32)
        ent.pack(side="left", padx=(4, 0))
        ttk.Label(bar, text="Direction:").pack(side="left", padx=(12, 0))
        self.dir_var = tk.StringVar(value="All")
        ttk.OptionMenu(bar, self.dir_var, "All", "All", "Outbound", "Inbound",
                       command=lambda *_: self.refresh()).pack(side="left")
        ttk.Button(bar, text="Clear", command=self._clear_filter).pack(side="left", padx=(8, 0))
        self.count_label = ttk.Label(bar, text="", foreground="#555")
        self.count_label.pack(side="right")

    def _build_table(self):
        frame = ttk.Frame(self.root, padding=(8, 6))
        frame.pack(fill="both", expand=True)
        cols = ("dir", "site", "desc", "ip", "packets", "bytes")
        titles = {"dir": "Direction", "site": "Site / host", "desc": "What it is",
                  "ip": "IP address", "packets": "Packets", "bytes": "Bytes"}
        widths = {"dir": 90, "site": 240, "desc": 250, "ip": 150,
                  "packets": 70, "bytes": 90}
        self.numeric = {"packets", "bytes"}
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col in cols:
            self.tree.heading(col, text=titles[col],
                              command=lambda c=col: self.sort(c))
            self.tree.column(col, width=widths[col],
                             anchor="e" if col in self.numeric else "w",
                             stretch=col in ("site", "desc"))
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        bold = tkfont.nametofont("TkDefaultFont").copy()
        self.tree.tag_configure("inbound", foreground="#b9450b")
        self.tree.tag_configure("outbound", foreground="#0b5cad")

    # -------- actions --------
    def choose(self):
        path = filedialog.askopenfilename(
            title="Open capture",
            filetypes=[("Captures", "*.pcapng *.pcap *.cap"), ("All files", "*.*")])
        if path:
            self.load(path)

    def _build_statusbar(self):
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", side="bottom")
        self.status = ttk.Label(bar, text="Open a capture to begin.",
                                anchor="w", padding=(10, 3))
        self.status.pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self.progress.pack(side="right", padx=8, pady=3)

    def load(self, path: str):
        """Kick off analysis on a background thread so the window stays live."""
        if not os.path.isfile(path):
            messagebox.showerror("Open capture", f"No such file:\n{path}")
            return
        if self._busy:
            return
        self.capture = path
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
                     f"you = {self.meta['my_ip'] or '?'}   ·   "
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
            self.progress.start(12)
        else:
            self.progress.stop()
            self.status.config(text="Ready")

    def _clear_filter(self):
        self.filter_var.set("")
        self.dir_var.set("All")

    def _visible_rows(self):
        text = self.filter_var.get().strip().lower()
        want = self.dir_var.get().lower()
        rows = []
        for r in self.all_rows:
            if want != "all" and r["direction"] != want:
                continue
            if text and text not in (
                    r["site"] + " " + r["description"] + " " + r["ip"]).lower():
                continue
            rows.append(r)
        return rows

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        rows = self._visible_rows()
        for r in rows:
            self.tree.insert(
                "", "end",
                values=(r["direction"], r["site"], r["description"], r["ip"],
                        r["packets"], f"{r['bytes']:,}"),
                tags=(r["direction"],))
        n_out = sum(1 for r in rows if r["direction"] == "outbound")
        n_in = len(rows) - n_out
        self.count_label.config(
            text=f"showing {len(rows)} of {len(self.all_rows)}   "
                 f"({n_out} outbound, {n_in} inbound)")

    def sort(self, col: str):
        numeric = col in self.numeric
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        key = ((lambda t: float(t[0].replace(",", "") or 0)) if numeric
               else (lambda t: t[0].lower()))
        rev = self._sort.get(col, not numeric)
        items.sort(key=key, reverse=rev)
        for i, (_, k) in enumerate(items):
            self.tree.move(k, "", i)
        self._sort[col] = not rev

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
