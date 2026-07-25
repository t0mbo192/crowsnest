#!/usr/bin/env python3
"""netwatch analysis core -- shared by every front end.

Turns packet data into a list of connections, split by direction, with a
plain-English description of what each host is. Deliberately free of any GUI
import so this works on a headless machine: the desktop app
(connection_viewer.py) and the live terminal view (netwatch_live.py) both build
on it.

Direction comes from the TCP handshake -- whoever sends the opening SYN started
the connection. Flows with no handshake (UDP, or already in progress when the
capture began) fall back to whichever end was seen first.
"""

from __future__ import annotations

import ipaddress
import os
import queue
import shutil
import socket
import subprocess
import threading
import time
from collections import defaultdict

import asn_lookup

# Hide the console window tshark would otherwise flash on Windows.
_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

socket.setdefaulttimeout(2)  # keep reverse-DNS snappy

# Folder scanned for the newest capture when a front end is opened with no file.
DROP_DIR = os.path.join(os.path.expanduser("~"), "Documents", "Captures")

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


def describe(host: str, local: bool, ip: str = "") -> str:
    """Say what a host is, in plain language.

    The keyword table comes first because it describes what a host is *for* --
    "Datadog - monitoring / telemetry" is more use than the name of whoever owns
    the address range. ASN data then covers everything the table misses, which is
    most of the internet, and is the only thing that can name an address with no
    hostname at all. Both are optional: with neither, this degrades to the
    generic labels it always used.
    """
    h = (host or "").lower()
    for needle, desc in DESCRIPTIONS:
        if needle in h:
            return desc
    if local:
        return "Local network device"
    org = asn_lookup.organisation(ip) if ip else ""
    if org:
        return org
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
            r["description"] = describe(name, r["local"], r["ip"])
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
            "description": describe(name, local, ip),
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


def human_bytes(n: int) -> str:
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"
