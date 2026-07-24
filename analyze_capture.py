#!/usr/bin/env python3
"""
analyze_capture.py -- Turn a Wireshark capture into a readable list of the
websites/hosts and remote locations your computer connected to.

Because most traffic is encrypted (HTTPS/QUIC), we can't see page content or full
URLs. But we CAN see which hosts were contacted, via four plaintext signals:

  * DNS queries          (dns.qry.name)                         -> domains looked up
  * TLS SNI              (tls...extensions_server_name)         -> HTTPS hostnames
  * QUIC SNI             (quic...extensions_server_name)        -> HTTP/3 hostnames
  * HTTP Host header     (http.host)                            -> plain-HTTP hosts

We also list every external IP endpoint, label it with the domain that resolved
to it (learned from DNS answers in the same capture) or reverse DNS, and can
optionally geolocate it.

This shells out to `tshark` (bundled with Wireshark) for the packet dissection,
so it needs no extra Python packages.

Usage:
    python analyze_capture.py capture.pcapng
    python analyze_capture.py capture.pcapng --csv report.csv
    python analyze_capture.py capture.pcapng --geoip      # opt-in, see note below
    python analyze_capture.py capture.pcapng --rdns       # reverse-DNS unlabeled IPs

--geoip sends the list of *external* IP addresses to the free ip-api.com service
to look up country/city/ISP. That shares those IPs with a third party, so it's
off by default. Everything else runs entirely on your machine.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.request
from collections import defaultdict

# Fields we pull out of every packet, in order. Tab-separated on output;
# fields that can hold several values (like a DNS answer's A records) are
# joined with ';' via the aggregator setting below.
FIELDS = [
    "ip.src", "ipv6.src",
    "ip.dst", "ipv6.dst",
    "frame.len",
    "_ws.col.Protocol",
    "dns.qry.name",
    "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name",
    "http.host",
]


def find_tshark() -> str:
    """Locate tshark on PATH or in the standard Windows install location."""
    exe = shutil.which("tshark")
    if exe:
        return exe
    for candidate in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ):
        if os.path.isfile(candidate):
            return candidate
    sys.exit(
        "ERROR: couldn't find tshark. Install Wireshark, or add its folder to PATH."
    )


def run_tshark(tshark: str, capture: str) -> str:
    """Dissect the capture and return one tab-separated row per packet."""
    cmd = [tshark, "-r", capture, "-T", "fields",
           "-E", "separator=/t", "-E", "aggregator=;", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(f"ERROR: tshark failed:\n{e.stderr}")
    except FileNotFoundError:
        sys.exit(f"ERROR: couldn't execute tshark at {tshark}")
    return proc.stdout


def is_public(ip: str) -> bool:
    """True for routable internet addresses (skip private/loopback/multicast)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_multicast
                or addr.is_link_local or addr.is_reserved or addr.is_unspecified)


def split_vals(field: str) -> list[str]:
    """Split an aggregated tshark field ('a;b;c') into individual values."""
    return [v for v in field.split(";") if v]


# Common two-label public suffixes, so a.b.foo.co.uk folds to foo.co.uk rather
# than the useless co.uk. This isn't the full Public Suffix List (that needs a
# separate download), but it covers the suffixes seen in everyday traffic.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.in", "net.in", "org.in", "gen.in", "firm.in",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "web.za",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.kr", "or.kr", "ne.kr",
    "com.mx", "com.tr", "com.sg", "com.hk", "com.tw", "com.my", "com.ph",
    "com.pk", "com.ua", "com.ar", "com.co", "com.pl", "com.ru", "com.sa",
}


def root_domain(host: str) -> str:
    """Fold a hostname to its registrable root: a.b.github.com -> github.com."""
    host = host.strip().lower().rstrip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip_literal(name: str) -> bool:
    """True if name is a bare IP address, optionally with a :port suffix.

    Filters out things like the SSDP multicast host '239.255.255.250:1900',
    which the http.host field reports but which is not a website.
    """
    cand = name
    if ":" in name:
        head, _, tail = name.rpartition(":")
        if tail.isdigit():
            cand = head.strip("[]")
    try:
        ipaddress.ip_address(cand)
        return True
    except ValueError:
        return False


def load_allowlist(path: str) -> tuple[set[str], set[str]]:
    """Read an allowlist file -> (allowed hostnames, allowed IPs).

    One entry per line; '#' starts a comment. Entries may be root domains
    (github.com), specific hosts (api.github.com), '*.example.com' wildcards,
    or literal IPs. A host matches an entry if it equals it or is a subdomain.
    """
    allow_hosts: set[str] = set()
    allow_ips: set[str] = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            entry = line.split("#", 1)[0].strip().lower().rstrip(".")
            entry = entry.lstrip("*.")  # treat *.example.com as example.com
            if not entry:
                continue
            try:
                ipaddress.ip_address(entry)
                allow_ips.add(entry)
            except ValueError:
                allow_hosts.add(entry)
    return allow_hosts, allow_ips


def host_allowed(host: str, allow_hosts: set[str]) -> bool:
    """True if host equals, or is a subdomain of, any allowlist entry."""
    host = host.strip().lower().rstrip(".")
    return any(host == e or host.endswith("." + e) for e in allow_hosts)


class Report:
    def __init__(self) -> None:
        self.hosts: dict[str, int] = defaultdict(int)        # hostname -> hit count
        self.host_source: dict[str, set[str]] = defaultdict(set)  # how we saw it
        self.ip_to_name: dict[str, str] = {}                 # IP -> domain (from DNS)
        self.endpoints: dict[str, dict] = {}                 # IP -> {packets,bytes,proto}

    def note_host(self, name: str, source: str) -> None:
        name = name.strip().lower().rstrip(".")
        # Skip reverse-DNS PTR pseudo-names -- these are your PC looking up the
        # name for an IP, not a website you actually connected to.
        if name.endswith((".in-addr.arpa", ".ip6.arpa")):
            return
        # Skip bare IP hosts (e.g. the SSDP multicast '239.255.255.250:1900').
        if is_ip_literal(name):
            return
        if name:
            self.hosts[name] += 1
            self.host_source[name].add(source)

    def note_endpoint(self, ip: str, nbytes: int, proto: str) -> None:
        ep = self.endpoints.setdefault(ip, {"packets": 0, "bytes": 0, "protos": set()})
        ep["packets"] += 1
        ep["bytes"] += nbytes
        if proto:
            ep["protos"].add(proto)


def parse(output: str) -> Report:
    r = Report()
    for line in output.splitlines():
        cols = line.split("\t")
        if len(cols) < len(FIELDS):
            cols += [""] * (len(FIELDS) - len(cols))
        (ip_src, ip6_src, ip_dst, ip6_dst, frame_len, proto,
         dns_qry, dns_a, dns_aaaa, tls_sni, http_host) = cols

        src = ip_src or ip6_src
        dst = ip_dst or ip6_dst
        try:
            nbytes = int(frame_len) if frame_len else 0
        except ValueError:
            nbytes = 0

        # Hostnames from the plaintext signals. TLS SNI covers both HTTPS
        # (TLS-over-TCP) and HTTP/3 (QUIC embeds the same TLS handshake).
        for name in split_vals(tls_sni):
            r.note_host(name, "TLS/QUIC SNI")
        for name in split_vals(http_host):
            r.note_host(name, "HTTP host")
        for name in split_vals(dns_qry):
            r.note_host(name, "DNS query")

        # Learn IP -> domain from DNS answers: the queried name resolved to
        # each returned A/AAAA address.
        answers = split_vals(dns_a) + split_vals(dns_aaaa)
        if answers and dns_qry:
            qname = split_vals(dns_qry)[0].strip().lower().rstrip(".")
            for ip in answers:
                r.ip_to_name.setdefault(ip, qname)

        # Tally external endpoints (the "remote" side of each packet).
        for ip in (dst, src):
            if is_public(ip):
                r.note_endpoint(ip, nbytes, proto)
    return r


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except (socket.herror, socket.gaierror, OSError):
        return ""


def geolocate(ips: list[str]) -> dict[str, str]:
    """Look up country/city/ISP via ip-api.com (opt-in). Returns IP -> label."""
    result: dict[str, str] = {}
    for i in range(0, len(ips), 100):  # API allows 100 IPs per batch request
        batch = ips[i:i + 100]
        payload = json.dumps(
            [{"query": ip, "fields": "query,status,country,city,isp"} for ip in batch]
        ).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch", data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                for row in json.load(resp):
                    if row.get("status") == "success":
                        parts = [row.get("city"), row.get("country"), row.get("isp")]
                        result[row["query"]] = ", ".join(p for p in parts if p)
        except Exception as e:  # network hiccup shouldn't kill the whole report
            print(f"  (geoip lookup failed for a batch: {e})", file=sys.stderr)
    return result


def label_ip(ip: str, r: Report, do_rdns: bool) -> str:
    if ip in r.ip_to_name:
        return r.ip_to_name[ip]
    if do_rdns:
        return reverse_dns(ip)
    return ""


def group_by_root(r: Report) -> dict[str, dict]:
    """Fold hostnames under their root domain -> {root: {count, subs, sources}}."""
    groups: dict[str, dict] = {}
    for name, count in r.hosts.items():
        root = root_domain(name)
        g = groups.setdefault(
            root, {"count": 0, "subs": defaultdict(int), "sources": set()})
        g["count"] += count
        g["subs"][name] += count
        g["sources"] |= r.host_source[name]
    return groups


def endpoint_status(ip: str, label: str,
                    allow_hosts: set[str], allow_ips: set[str]) -> str:
    """Classify an endpoint against the allowlist: ok / flagged / unknown."""
    if ip in allow_ips:
        return "ok"
    if label and host_allowed(label, allow_hosts):
        return "ok"
    if not label:
        return "unknown"          # no hostname -> can't check it by name
    return "flagged"


def print_report(r: Report, do_rdns: bool, geo: dict[str, str],
                 allow_hosts: set[str], allow_ips: set[str],
                 has_allowlist: bool, flagged_only: bool = False) -> None:
    groups = group_by_root(r)

    suffix = "  (flagged only)" if flagged_only else "  (grouped by root domain)"
    print("\n" + "=" * 70)
    print("WEBSITES / HOSTS CONNECTED TO" + suffix)
    print("=" * 70)
    if not groups:
        print("  (none found -- no DNS/TLS/HTTP hostnames in this capture)")

    flagged_hosts: list[tuple[str, str, int]] = []   # (host, root, count)
    shown_hosts = 0
    for root, g in sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        subs = sorted(g["subs"].items(), key=lambda kv: (-kv[1], kv[0]))
        not_ok = ([h for h, _ in subs if not host_allowed(h, allow_hosts)]
                  if has_allowlist else [])
        for h, c in subs:
            if h in not_ok:
                flagged_hosts.append((h, root, c))
        # In flagged-only mode, skip fully-allowed groups and show only the
        # offending subdomains within a group.
        if flagged_only and not not_ok:
            continue
        display_subs = [(h, c) for h, c in subs if h in not_ok] if flagged_only else subs
        tag = ""
        if has_allowlist:
            tag = "  [OK]" if not not_ok else f"  [FLAGGED: {len(not_ok)} not allowed]"
        print(f"\n  {root}  ({g['count']} hits){tag}")
        for h, c in display_subs:
            mark = "  <-- not in allowlist" if h in not_ok else ""
            srcs = ", ".join(sorted(r.host_source[h]))
            print(f"      {c:>4}x  {h:<44} [{srcs}]{mark}")
        shown_hosts += 1
    if flagged_only and shown_hosts == 0 and groups:
        print("  (no flagged hosts -- everything matched the allowlist)")

    label = "EXTERNAL IP ENDPOINTS -- FLAGGED ONLY" if flagged_only \
        else "EXTERNAL IP ENDPOINTS (remote locations)"
    print("\n" + "=" * 70)
    print(label)
    print("=" * 70)
    header = f"  {'packets':>7}  {'bytes':>10}  {'IP address':<39}  host / location"
    print(header)
    print("  " + "-" * (len(header) - 2))
    flagged_eps: list[tuple[str, str, dict]] = []
    shown_eps = 0
    for ip, ep in sorted(r.endpoints.items(), key=lambda kv: -kv[1]["bytes"]):
        host = label_ip(ip, r, do_rdns)
        loc = f"{host}  ({geo[ip]})" if (ip in geo and host) else (geo.get(ip, host))
        status = endpoint_status(ip, host, allow_hosts, allow_ips) if has_allowlist else "ok"
        mark = {"flagged": "  [!]", "unknown": "  [?]"}.get(status, "")
        if status == "flagged":
            flagged_eps.append((ip, host, ep))
        # Flagged-only hides confirmed-allowed endpoints; anything not confirmed
        # allowed ([!] flagged and [?] unknown) still shows, since an unlabeled
        # IP is exactly what you'd want to eyeball.
        if flagged_only and status == "ok":
            continue
        print(f"  {ep['packets']:>7}  {ep['bytes']:>10}  {ip:<39}  {loc}{mark}")
        shown_eps += 1
    if flagged_only and shown_eps == 0:
        print("  (no flagged or unverifiable endpoints)")

    # Consolidated summary. Redundant in flagged-only mode (the whole report is
    # already the flagged list), so only print it in the full report.
    if has_allowlist and not flagged_only:
        print("\n" + "=" * 70)
        print("FLAGGED -- NOT IN ALLOWLIST")
        print("=" * 70)
        if not flagged_hosts and not flagged_eps:
            print("  Nothing flagged: every host matched the allowlist.")
        if flagged_hosts:
            print("  Hostnames:")
            for h, root, c in sorted(flagged_hosts, key=lambda x: (-x[2], x[0])):
                print(f"      {c:>4}x  {h:<44} (root: {root})")
        if flagged_eps:
            print("  IP endpoints with no allowlisted hostname:")
            for ip, host, ep in sorted(flagged_eps, key=lambda x: -x[2]["bytes"]):
                print(f"      {ip:<39} {host}")

    if has_allowlist:
        print("\n  Legend:  [!] endpoint not in allowlist   "
              "[?] endpoint host unknown (couldn't verify)")

    if has_allowlist:
        print(f"\n  {len(flagged_hosts)} flagged hostnames, {len(flagged_eps)} flagged "
              f"endpoints out of {len(r.hosts)} hosts / {len(r.endpoints)} endpoints.\n")
    else:
        print(f"\n  {len(r.endpoints)} external endpoints, "
              f"{len(r.hosts)} distinct hostnames, {len(groups)} root domains.\n")


def write_csv(path: str, r: Report, do_rdns: bool, geo: dict[str, str],
              allow_hosts: set[str], allow_ips: set[str],
              has_allowlist: bool, flagged_only: bool = False) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "root_domain", "count_or_packets",
                    "bytes", "allowed", "detail"])
        for name, count in sorted(r.hosts.items(), key=lambda kv: (-kv[1], kv[0])):
            ok = host_allowed(name, allow_hosts) if has_allowlist else True
            if flagged_only and ok:
                continue
            allowed = "" if not has_allowlist else ("yes" if ok else "NO")
            w.writerow(["host", name, root_domain(name), count, "", allowed,
                        ", ".join(sorted(r.host_source[name]))])
        for ip, ep in sorted(r.endpoints.items(), key=lambda kv: -kv[1]["bytes"]):
            label = label_ip(ip, r, do_rdns)
            status = endpoint_status(ip, label, allow_hosts, allow_ips) if has_allowlist else "ok"
            if flagged_only and status == "ok":
                continue
            detail = f"{label} ({geo[ip]})" if (ip in geo and label) else geo.get(ip, label)
            allowed = "" if not has_allowlist else {
                "ok": "yes", "flagged": "NO", "unknown": "unknown"}[status]
            w.writerow(["endpoint", ip, root_domain(label) if label else "",
                        ep["packets"], ep["bytes"], allowed, detail])
    print(f"Wrote CSV report to {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="path to a .pcap / .pcapng file")
    ap.add_argument("--csv", metavar="FILE", help="also write the report to CSV")
    ap.add_argument("--rdns", action="store_true",
                    help="reverse-DNS lookup IPs with no domain (adds network calls)")
    ap.add_argument("--geoip", action="store_true",
                    help="geolocate external IPs via ip-api.com (shares IPs w/ 3rd party)")
    ap.add_argument("--allowlist", metavar="FILE",
                    help="file of allowed domains/IPs; anything else is flagged")
    ap.add_argument("--flagged-only", action="store_true",
                    help="show only what's NOT in the allowlist (needs --allowlist)")
    args = ap.parse_args()

    if not os.path.isfile(args.capture):
        sys.exit(f"ERROR: no such file: {args.capture}")
    if args.flagged_only and not args.allowlist:
        sys.exit("ERROR: --flagged-only needs --allowlist (nothing to flag against).")

    allow_hosts: set[str] = set()
    allow_ips: set[str] = set()
    has_allowlist = bool(args.allowlist)
    if has_allowlist:
        if not os.path.isfile(args.allowlist):
            sys.exit(f"ERROR: no such allowlist file: {args.allowlist}")
        allow_hosts, allow_ips = load_allowlist(args.allowlist)
        print(f"Loaded allowlist: {len(allow_hosts)} domains, {len(allow_ips)} IPs.")

    tshark = find_tshark()
    print(f"Reading {args.capture} with {tshark} ...")
    output = run_tshark(tshark, args.capture)
    r = parse(output)

    geo: dict[str, str] = {}
    if args.geoip:
        print(f"Sending {len(r.endpoints)} external IPs to ip-api.com for geolocation ...")
        geo = geolocate(list(r.endpoints.keys()))

    print_report(r, args.rdns, geo, allow_hosts, allow_ips,
                 has_allowlist, args.flagged_only)
    if args.csv:
        write_csv(args.csv, r, args.rdns, geo, allow_hosts, allow_ips,
                  has_allowlist, args.flagged_only)


if __name__ == "__main__":
    main()
