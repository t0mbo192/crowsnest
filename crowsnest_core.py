#!/usr/bin/env python3
"""crowsnest analysis core.

Turns packet data into a list of connections, split by direction, with a
plain-English description of what each host is. Two entry points: analyze() for
a saved capture, and LiveTracker for a live interface. Pure standard library
apart from the optional ASN lookup, and no terminal or display assumptions, so
it runs anywhere.

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
from functools import lru_cache

import asn_lookup

# Hide the console window tshark would otherwise flash on Windows.
_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

socket.setdefaulttimeout(2)  # keep reverse-DNS snappy

# A connection nothing has been seen on for this long is finished, and its entry
# is dead weight. Checked every so many packets rather than on a timer.
FLOW_IDLE = 300.0
FLOW_RETIRE_EVERY = 2000

# Folder scanned for the newest capture when a front end is opened with no file.
DROP_DIR = os.path.join(os.path.expanduser("~"), "Documents", "Captures")

FIELDS = [
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags.syn", "tcp.flags.ack",
    "frame.len",
    "dns.qry.name", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name", "http.host",
]

# ----------------------------------------------------------------------------
# "What is this host?"  First substring match wins, so order specific -> general.
# ----------------------------------------------------------------------------
DESCRIPTIONS = [
    # --- mobile ------------------------------------------------------------
    # First, because several would otherwise be swallowed by a general entry
    # further down: "push.apple.com" contains "apple.com" and would read as
    # "Apple services", which is the wrong thing to be told about the one host
    # on a phone that must never be blocked.
    #
    # A phone sitting in a pocket doing nothing emits a different mix from a
    # laptop: attribution SDKs, crash reporters and ad networks bundled into
    # apps rather than chosen by anyone. Those are worth naming because they
    # are the ones someone would want to stop.
    ("push.apple.com", "Apple Push Notification service"),
    ("courier.push.apple.com", "Apple Push Notification service"),
    ("albert.apple.com", "Apple device activation"),
    ("gs.apple.com", "Apple device authentication"),
    ("apple-dns.net", "Apple services (DNS)"),
    ("gsp-ssl.ls.apple.com", "Apple location services"),
    ("gspe", "Apple location services"),
    ("weather-data.apple.com", "Apple Weather"),
    ("captive.apple.com", "Apple connectivity check"),
    ("itunes.apple.com", "App Store / iTunes"),
    ("appattest", "Apple App Attest (anti-fraud)"),
    ("mtalk.google.com", "Android push notifications"),
    ("android.clients.google.com", "Google Play services"),
    ("app-measurement.com", "Google/Firebase analytics (tracking)"),
    ("firebaseinstallations", "Firebase (app identity)"),
    ("firebaseremoteconfig", "Firebase Remote Config"),
    ("crashlytics", "Firebase Crashlytics - crash reporting"),
    ("appsflyer", "AppsFlyer - install attribution (tracking)"),
    ("adjust.com", "Adjust - install attribution (tracking)"),
    ("branch.io", "Branch - deep links / attribution (tracking)"),
    ("kochava", "Kochava - install attribution (tracking)"),
    ("singular.net", "Singular - install attribution (tracking)"),
    ("onesignal", "OneSignal - push / analytics"),
    ("bugsnag", "Bugsnag - crash reporting"),
    ("instabug", "Instabug - in-app feedback / diagnostics"),
    ("applovin", "AppLovin advertising"),
    ("unityads", "Unity Ads"),
    ("unity3d", "Unity Ads"),
    ("ironsrc", "ironSource advertising"),
    ("vungle", "Vungle advertising"),
    ("chartboost", "Chartboost advertising"),
    ("inmobi", "InMobi advertising"),
    ("mopub", "MoPub advertising"),
    ("tiktokv", "TikTok"),
    ("byteoversea", "TikTok / ByteDance"),
    ("snapchat", "Snapchat"),
    ("sc-cdn", "Snapchat (CDN)"),
    ("threads.net", "Threads / Meta"),
    ("cdninstagram", "Instagram / Meta (CDN)"),
    ("whatsapp.net", "WhatsApp / Meta"),
    ("spotifycdn", "Spotify (CDN)"),

    # --- general -----------------------------------------------------------
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
    # Both desktop platforms install Wireshark somewhere PATH does not reach:
    # inside the app bundle on macOS, under Program Files on Windows. Looking
    # there beats telling someone to install what they have already got.
    for c in ("/Applications/Wireshark.app/Contents/MacOS/tshark",
              r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe"):
        if os.path.isfile(c):
            return c
    raise RuntimeError("Couldn't find tshark. Install Wireshark (or add it to PATH).")


def _field_args(tshark: str) -> list[str]:
    # -n disables tshark's own name resolution: it would do blocking DNS lookups
    # per address while dissecting, and crowsnest resolves names itself.
    cmd = [tshark, "-n", "-T", "fields", "-E", "separator=/t",
           "-E", "aggregator=;", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    return cmd


def stream_tshark(tshark: str, capture: str):
    """Yield one line per packet *while* tshark is still dissecting.

    Reading incrementally instead of collecting all output first lets parsing
    overlap with dissection, and keeps a large capture from being held in memory
    twice over.
    """
    cmd = _field_args(tshark)[:1] + ["-r", capture] + _field_args(tshark)[1:]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1 << 16, creationflags=_NO_WINDOW)
    try:
        yield from proc.stdout
    finally:
        proc.stdout.close()
        err = (proc.stderr.read() or "").strip()
        proc.stderr.close()
        if proc.wait() != 0:
            raise RuntimeError(f"tshark failed:\n{err}")


def run_tshark(tshark: str, capture: str) -> str:
    """All of tshark's output at once. Prefer stream_tshark for large captures."""
    return "".join(stream_tshark(tshark, capture))


def _vals(field: str) -> list[str]:
    return [v for v in field.split(";") if v]


# ipaddress.ip_address() is expensive -- parsing one costs several hundred
# nanoseconds and a capture asks the same questions about the same few hundred
# addresses tens of thousands of times, so the answers are cached. lru_cache
# rather than a plain dict because a long run on a busy link meets far more
# distinct addresses than a short one, and an unbounded cache is a slow leak.
@lru_cache(maxsize=16384)
def is_routable_peer(ip: str) -> bool:
    """A real other end: not multicast, broadcast or unspecified."""
    try:
        a = ipaddress.ip_address(ip)
        ok = not (a.is_multicast or a.is_unspecified or ip == "255.255.255.255")
        if ok and a.version == 4 and a.is_private and ip.endswith(".255"):
            ok = False              # subnet broadcast, e.g. 192.168.1.255
    except ValueError:
        ok = False
    return ok


@lru_cache(maxsize=16384)
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
    flows: dict[tuple, _Flow] = {}
    ip_hits: dict[str, int] = defaultdict(int)
    ip_to_name: dict[str, str] = {}
    total = 0
    n_fields = len(FIELDS)

    for line in stream_tshark(find_tshark(), capture):
        c = line.rstrip("\n").split("\t")
        if len(c) < n_fields:
            c += [""] * (n_fields - len(c))
        (ip_s, ip_d, ip6_s, ip6_d, tsp, tdp, usp, udp_, syn, ack,
         flen, dqry, da, daaaa, sni, host) = c
        src, dst = (ip_s or ip6_s), (ip_d or ip6_d)
        if not src or not dst:
            continue
        total += 1
        try:
            nbytes = int(flen) if flen else 0
        except ValueError:
            nbytes = 0
        # Counted unvalidated: working out which addresses are routable is only
        # needed for the few hundred unique ones, not on every packet.
        ip_hits[src] += 1
        ip_hits[dst] += 1

        if (da or daaaa) and dqry:
            qname = dqry.partition(";")[0].lower().rstrip(".")
            if qname:
                for answer in _vals(da) + _vals(daaaa):
                    ip_to_name.setdefault(answer, qname)

        if tsp or tdp:
            l4, sp, dp = "tcp", tsp, tdp
        elif usp or udp_:
            l4, sp, dp = "udp", usp, udp_
        else:
            l4, sp, dp = "ip", "", ""
        # An order-independent key without building a frozenset per packet.
        end_a, end_b = (src, sp), (dst, dp)
        key = (l4, end_a, end_b) if end_a <= end_b else (l4, end_b, end_a)

        fl = flows.get(key)
        if fl is None:
            fl = flows[key] = _Flow()
        fl.packets += 1
        fl.bytes += nbytes
        if sni or host:
            for name in _vals(sni) + _vals(host):
                nm = name.lower().rstrip(".")
                if nm and not is_routable_peer(nm.partition(":")[0]):
                    fl.hostnames.add(nm)
        if syn == "1" and ack != "1" and l4 == "tcp":
            fl.initiator, fl.locked = (src, dst), True
        elif not fl.locked and fl.initiator is None:
            fl.initiator = (src, dst)

    if not ip_hits:
        return {"packets": total, "my_ip": "", "rows": []}

    def top(v6: bool) -> str:
        best, n = "", -1
        for ip, hits in ip_hits.items():
            if ((":" in ip) == v6) and hits > n and is_routable_peer(ip):
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
    # Names are known by now, so several addresses for one host can be folded
    # into a single entry.
    rows = merge_by_host(rows)
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


def merge_by_host(rows: list[dict]) -> list[dict]:
    """Combine entries that are the same host reached at different addresses.

    A busy site answers on several addresses, so keying on the address alone
    reports one host several times over -- github.com twice, the same name and
    the same description, which reads as a duplicate because it is one. Rows are
    keyed on the hostname where one is known, and on the address only when it is
    not. The busiest address is kept as the representative, and "addresses"
    records how many were folded in.
    """
    merged: dict[tuple[str, str], dict] = {}
    for row in sorted(rows, key=lambda r: -r["bytes"]):
        key = (row["direction"], row["name"] or row["ip"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(row, addresses=1)
            continue
        existing["packets"] += row["packets"]
        existing["bytes"] += row["bytes"]
        if "rate" in existing:
            existing["rate"] = existing.get("rate", 0.0) + row.get("rate", 0.0)
        existing["addresses"] += 1
    out = list(merged.values())
    out.sort(key=lambda r: -r["bytes"])
    return out


def human_bytes(n: int) -> str:
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


# ----------------------------------------------------------------------------
# Live capture
# ----------------------------------------------------------------------------
def list_interfaces(tshark: str) -> str:
    proc = subprocess.run([tshark, "-D"], capture_output=True, text=True,
                          creationflags=_NO_WINDOW)
    return proc.stdout or proc.stderr


def own_addresses() -> set[str]:
    """Best guess at this machine's own addresses.

    Opens a UDP socket toward a public address and reads back the local end --
    nothing is sent, it just makes the OS choose an outbound interface. Anything
    the kernel reports for this host is added too. Link-local addresses are left
    out, since they never carry the traffic we care about.
    """
    found: set[str] = set()

    def keep(addr: str) -> bool:
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
                addr = s.getsockname()[0].partition("%")[0]
                if keep(addr):
                    found.add(addr)
            finally:
                s.close()
        except OSError:
            pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0].partition("%")[0]
            if is_routable_peer(addr) and keep(addr):
                found.add(addr)
    except OSError:
        pass
    return found


def capture_live(tshark: str, interface: str, out: queue.Queue,
                 stop: threading.Event, bpf: str = "") -> None:
    """Stream packets from an interface, one queued line each.

    Fatal problems are queued as ("fatal", message) rather than raised, since
    this runs on a worker thread.
    """
    base = _field_args(tshark)
    cmd = [base[0], "-i", interface, "-l"]
    if bpf:
        cmd += ["-f", bpf]
    cmd += base[1:]
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
        try:
            err = (proc.stderr.read() or "").strip()
        except Exception:
            err = ""
        if proc.poll() not in (0, None) and err:
            out.put(("fatal", err))
        out.put(("eof", ""))


class LiveTracker:
    """Rolling picture of who this machine is talking to.

    analyze() can read a whole capture before deciding which address is this
    machine. Live traffic has no such luxury, so the caller supplies a best
    guess and this adapts if the traffic disagrees.
    """

    __slots__ = ("my_ips", "conns", "flows", "ip_names", "packets", "bytes",
                 "dropped_flows", "_unknown", "_clock", "_lock")

    def __init__(self, my_ips):
        self.my_ips = set(my_ips)
        self.conns: dict[tuple[str, str], dict] = {}
        # key -> [initiator, locked, last seen]. One entry per connection, and a
        # busy resolver opens a fresh source port per query, so this is the one
        # structure that would grow without limit if nothing retired it.
        self.flows: dict[tuple, list] = {}
        self.ip_names: dict[str, str] = {}
        self.packets = 0
        self.bytes = 0
        self.dropped_flows = 0
        self._unknown: dict[str, int] = defaultdict(int)
        self._clock = time.monotonic()
        self._lock = threading.Lock()

    def _retire_flows(self) -> None:
        """Forget connections nothing has been seen on for a while.

        Called on a packet count rather than a timer, so it costs nothing on an
        idle link -- where nothing is accumulating anyway. The clock is read
        here rather than per packet: at tens of thousands of packets a second
        that would be a syscall per packet, and a five minute threshold does not
        need better than this resolution.
        """
        self._clock = now = time.monotonic()
        cutoff = now - FLOW_IDLE
        stale = [key for key, flow in self.flows.items() if flow[2] < cutoff]
        for key in stale:
            del self.flows[key]
        self.dropped_flows += len(stale)

    def feed(self, line: str) -> None:
        # Parsing happens outside the lock and only state changes are
        # serialised, so a busy interface cannot stall whoever is drawing.
        c = line.rstrip("\n").split("\t")
        if len(c) < 16:
            c += [""] * (16 - len(c))
        (ip_s, ip_d, ip6_s, ip6_d, tsp, tdp, usp, udp_, syn, ack,
         flen, dqry, da, daaaa, sni, host) = c[:16]
        src, dst = (ip_s or ip6_s), (ip_d or ip6_d)
        if not src or not dst:
            return
        try:
            nbytes = int(flen) if flen else 0
        except ValueError:
            nbytes = 0

        if tsp or tdp:
            l4, sp, dp = "tcp", tsp, tdp
        elif usp or udp_:
            l4, sp, dp = "udp", usp, udp_
        else:
            l4, sp, dp = "ip", "", ""
        end_a, end_b = (src, sp), (dst, dp)
        key = (l4, end_a, end_b) if end_a <= end_b else (l4, end_b, end_a)
        opening = syn == "1" and ack != "1" and l4 == "tcp"
        names = [n.lower().rstrip(".") for n in (sni, host) if n]

        with self._lock:
            self.packets += 1
            self.bytes += nbytes

            if (da or daaaa) and dqry:
                qname = dqry.partition(";")[0].lower().rstrip(".")
                if qname:
                    for answer in _vals(da) + _vals(daaaa):
                        self.ip_names.setdefault(answer, qname)

            flow = self.flows.get(key)
            if flow is None:
                flow = self.flows[key] = [(src, dst), False, self._clock]
            else:
                flow[2] = self._clock
            if opening:
                flow[0], flow[1] = (src, dst), True
            if self.packets % FLOW_RETIRE_EVERY == 0:
                self._retire_flows()

            isrc, idst = flow[0]
            if isrc in self.my_ips and is_routable_peer(idst):
                direction, remote = "out", idst
            elif idst in self.my_ips and is_routable_peer(isrc):
                direction, remote = "in", isrc
            else:
                # Nothing matched a local address, so the guess may be wrong
                # (VPN, bridge, wrong interface). Adopt the busiest endpoint.
                if not self.my_ips:
                    self._unknown[src] += 1
                    self._unknown[dst] += 1
                    if self.packets % 200 == 0:
                        best = max(self._unknown, key=self._unknown.get,
                                   default="")
                        if best:
                            self.my_ips.add(best)
                            # Its only purpose was that guess; it can go now.
                            self._unknown.clear()
                return

            conn = self.conns.get((direction, remote))
            if conn is None:
                conn = self.conns[(direction, remote)] = {
                    "direction": direction, "ip": remote, "name": "",
                    "bytes": 0, "packets": 0, "prev_bytes": 0}
            conn["bytes"] += nbytes
            conn["packets"] += 1
            if names and not conn["name"]:
                conn["name"] = names[0]

    def apply_names(self, names: dict[str, str]) -> None:
        with self._lock:
            for conn in self.conns.values():
                if not conn["name"] and names.get(conn["ip"]):
                    conn["name"] = names[conn["ip"]]

    def unnamed_ips(self) -> list[str]:
        with self._lock:
            return [c["ip"] for c in self.conns.values()
                    if not c["name"] and not self.ip_names.get(c["ip"])]

    def snapshot(self, elapsed: float) -> tuple[list[dict], dict]:
        """Rows sorted by volume, plus totals. Latches per-interval rates."""
        with self._lock:
            rows = []
            for conn in self.conns.values():
                name = conn["name"] or self.ip_names.get(conn["ip"], "")
                local = is_private(conn["ip"])
                delta = conn["bytes"] - conn["prev_bytes"]
                conn["prev_bytes"] = conn["bytes"]
                rows.append({
                    "direction": conn["direction"], "ip": conn["ip"],
                    "site": name or conn["ip"], "name": name,
                    "description": describe(name, local, conn["ip"]),
                    "bytes": conn["bytes"], "packets": conn["packets"],
                    "rate": delta / elapsed if elapsed > 0 else 0.0,
                    "local": local})
            rows = merge_by_host(rows)
            # Loopback is always ours and tells the reader nothing.
            mine = sorted(a for a in self.my_ips
                          if not a.startswith(("127.", "::1")))
            extra = f" +{len(mine) - 2}" if len(mine) > 2 else ""
            meta = {"packets": self.packets, "bytes": self.bytes,
                    "out": sum(1 for r in rows if r["direction"] == "out"),
                    "in": sum(1 for r in rows if r["direction"] == "in"),
                    "my_ips": ", ".join(mine[:2]) + extra}
            return rows, meta
