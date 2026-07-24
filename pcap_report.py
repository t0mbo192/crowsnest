#!/usr/bin/env python3
"""
pcap_report.py -- read a Wireshark capture and show, in plain language:

    * SITES YOU CONNECTED TO   (outbound -- your machine started the connection)
    * CONNECTING TO YOU        (inbound  -- something else started it)

Direction is decided from the TCP handshake: whoever sends the opening SYN is
the initiator. For traffic with no handshake (UDP, or a flow already in progress
when the capture began) the first packet seen decides.

Run with a capture file, or with nothing -- then it grabs the newest .pcapng
from your drop folder (Documents\\Captures). Results open in a small window.
Uses only the Python standard library + the tshark bundled with Wireshark.
"""

from __future__ import annotations

import glob
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
from collections import defaultdict

# Where you drop capture files when you run this with no arguments.
DROP_DIR = os.path.join(os.path.expanduser("~"), "Documents", "Captures")

FIELDS = [
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags.syn", "tcp.flags.ack",
    "frame.len", "_ws.col.Protocol",
    "dns.qry.name", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name", "http.host",
]

socket.setdefaulttimeout(2)  # keep reverse-DNS snappy


# --------------------------------------------------------------------- helpers
def find_tshark() -> str:
    exe = shutil.which("tshark")
    if exe:
        return exe
    for c in (r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe"):
        if os.path.isfile(c):
            return c
    raise RuntimeError("Couldn't find tshark. Install Wireshark or add it to PATH.")


def run_tshark(tshark: str, capture: str) -> str:
    cmd = [tshark, "-r", capture, "-T", "fields",
           "-E", "separator=/t", "-E", "aggregator=;", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed:\n{proc.stderr.strip()}")
    return proc.stdout


def split_vals(field: str) -> list[str]:
    return [v for v in field.split(";") if v]


def is_routable_peer(ip: str) -> bool:
    """A real other-end address: skip multicast / broadcast / unspecified."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_multicast or a.is_unspecified or ip == "255.255.255.255":
        return False
    # Subnet-directed broadcast (e.g. 192.168.0.255 on a /24) -- LAN chatter,
    # not a host you connected to.
    if a.version == 4 and a.is_private and ip.endswith(".255"):
        return False
    return True


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


_rdns_cache: dict[str, str] = {}


def rdns(ip: str) -> str:
    if ip not in _rdns_cache:
        try:
            _rdns_cache[ip] = socket.gethostbyaddr(ip)[0].lower()
        except OSError:
            _rdns_cache[ip] = ""
    return _rdns_cache[ip]


# --------------------------------------------------------------------- analysis
class Flow:
    __slots__ = ("packets", "bytes", "protos", "hostnames", "initiator", "locked")

    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.protos: set[str] = set()
        self.hostnames: set[str] = set()
        self.initiator: tuple[str, str] | None = None  # (src, dst)
        self.locked = False                            # True once a SYN pinned it


def analyze(capture: str) -> dict:
    output = run_tshark(find_tshark(), capture)

    flows: dict[tuple, Flow] = {}
    ip_hits: dict[str, int] = defaultdict(int)  # to find "your" IP
    ip_to_name: dict[str, str] = {}             # remote IP -> domain (from DNS)
    looked_up: set[str] = set()                 # domains seen in DNS queries
    total_packets = 0

    for line in output.splitlines():
        c = line.split("\t")
        if len(c) < len(FIELDS):
            c += [""] * (len(FIELDS) - len(c))
        (ip_s, ip_d, ip6_s, ip6_d, tsp, tdp, usp, udp_,
         syn, ack, flen, proto, dqry, da, daaaa, sni, host) = c

        src, dst = (ip_s or ip6_s), (ip_d or ip6_d)
        if not src or not dst:
            continue
        total_packets += 1
        try:
            nbytes = int(flen) if flen else 0
        except ValueError:
            nbytes = 0

        for ip in (src, dst):
            if is_routable_peer(ip):
                ip_hits[ip] += 1

        # DNS: learn IP<->name and what was looked up.
        for name in split_vals(dqry):
            n = name.lower().rstrip(".")
            if not n.endswith((".in-addr.arpa", ".ip6.arpa")):
                looked_up.add(n)
        answers = split_vals(da) + split_vals(daaaa)
        if answers and dqry:
            qname = split_vals(dqry)[0].lower().rstrip(".")
            for ip in answers:
                ip_to_name.setdefault(ip, qname)

        # Flow key: direction-independent, so both halves land together.
        if tsp or tdp:
            l4, sport, dport = "tcp", tsp, tdp
        elif usp or udp_:
            l4, sport, dport = "udp", usp, udp_
        else:
            l4, sport, dport = "other", "", ""
        if l4 == "other":
            key = (proto, frozenset((src, dst)))
        else:
            key = (l4, frozenset(((src, sport), (dst, dport))))

        fl = flows.get(key)
        if fl is None:
            fl = flows[key] = Flow()
        fl.packets += 1
        fl.bytes += nbytes
        if proto:
            fl.protos.add(proto)
        for name in split_vals(sni) + split_vals(host):
            nm = name.lower().rstrip(".")
            if nm and not is_routable_peer(nm.split(":")[0]):
                fl.hostnames.add(nm)

        # Decide the initiator. A SYN without ACK is definitive and locks it.
        if l4 == "tcp" and syn == "1" and ack != "1":
            fl.initiator = (src, dst)
            fl.locked = True
        elif not fl.locked and fl.initiator is None:
            fl.initiator = (src, dst)

    if not ip_hits:
        return {"packets": total_packets, "my_ip": "", "outbound": [],
                "inbound": [], "looked_up": [], "other": 0}

    # "You" = the address present in the most packets (v4 and v6 picked apart).
    def top(family) -> str:
        best, n = "", -1
        for ip, hits in ip_hits.items():
            v6 = ":" in ip
            if (family == "v6") == v6 and hits > n:
                best, n = ip, hits
        return best
    my_ips = {ip for ip in (top("v4"), top("v6")) if ip}

    outbound: dict[str, dict] = {}
    inbound: dict[str, dict] = {}
    other = 0
    for fl in flows.values():
        if not fl.initiator:
            continue
        isrc, idst = fl.initiator
        if isrc in my_ips and is_routable_peer(idst):
            bucket, remote = outbound, idst
        elif idst in my_ips and is_routable_peer(isrc):
            bucket, remote = inbound, isrc
        else:
            other += 1
            continue
        agg = bucket.setdefault(
            remote, {"packets": 0, "bytes": 0, "protos": set(), "hostnames": set()})
        agg["packets"] += fl.packets
        agg["bytes"] += fl.bytes
        agg["protos"] |= fl.protos
        agg["hostnames"] |= fl.hostnames

    def rows(bucket, resolve_names):
        out = []
        for ip, a in bucket.items():
            if a["hostnames"]:
                name = sorted(a["hostnames"])[0]
            elif ip in ip_to_name:
                name = ip_to_name[ip]
            elif resolve_names:
                name = rdns(ip)
            else:
                name = ""
            out.append({"ip": ip, "name": name, "packets": a["packets"],
                        "bytes": a["bytes"], "local": is_private(ip),
                        "protos": ", ".join(sorted(a["protos"]))})
        out.sort(key=lambda r: -r["bytes"])
        return out

    out_rows = rows(outbound, resolve_names=True)
    in_rows = rows(inbound, resolve_names=True)

    # Domains looked up but not already shown as an outbound connection.
    shown = {r["name"] for r in out_rows if r["name"]}
    dns_only = sorted(d for d in looked_up
                      if d not in shown and not any(d in s for s in shown))

    return {"packets": total_packets, "my_ip": ", ".join(sorted(my_ips)),
            "outbound": out_rows, "inbound": in_rows,
            "looked_up": dns_only, "other": other}


# ------------------------------------------------------------------ formatting
def format_report(capture: str, res: dict) -> str:
    L = []
    L.append(f"Capture:  {os.path.basename(capture)}")
    L.append(f"Your machine:  {res['my_ip'] or '(unknown)'}      "
             f"packets analyzed: {res['packets']}")
    L.append("Note: encrypted traffic reveals which hosts were contacted, "
             "not page content.")

    def section(title, rows, who_col):
        L.append("")
        L.append("=" * 74)
        L.append(title)
        L.append("=" * 74)
        if not rows:
            L.append("  (none)")
            return
        L.append(f"  {'packets':>8}  {'bytes':>11}  {who_col}")
        L.append("  " + "-" * 70)
        for r in rows:
            label = r["name"] or r["ip"]
            tail = f"  [{r['ip']}]" if r["name"] else ""
            if r["local"]:
                tail += "  (local network)"
            L.append(f"  {r['packets']:>8}  {r['bytes']:>11,}  {label}{tail}")

    section("SITES YOU CONNECTED TO   (outbound)", res["outbound"], "site")
    section("CONNECTING TO YOU        (inbound)", res["inbound"], "who")

    if not res["inbound"]:
        L.append("  Nothing started a connection to your machine in this capture.")

    if res["looked_up"]:
        L.append("")
        L.append("Also looked up via DNS (no separate connection captured):")
        L.append("  " + ", ".join(res["looked_up"][:40]))
        if len(res["looked_up"]) > 40:
            L.append(f"  … and {len(res['looked_up']) - 40} more")

    if res["other"]:
        L.append("")
        L.append(f"({res['other']} local/broadcast flows not involving your "
                 f"machine were ignored.)")
    return "\n".join(L)


# ---------------------------------------------------------------- entry points
def newest_capture(folder: str) -> str | None:
    files = glob.glob(os.path.join(folder, "*.pcapng")) + \
        glob.glob(os.path.join(folder, "*.pcap"))
    return max(files, key=os.path.getmtime) if files else None


def show_window(title: str, text: str) -> None:
    import tkinter as tk
    from tkinter import scrolledtext, font as tkfont
    root = tk.Tk()
    root.title(title)
    root.geometry("880x640")
    mono = tkfont.nametofont("TkFixedFont").copy()
    mono.configure(size=11)
    st = scrolledtext.ScrolledText(root, wrap="none", font=mono, padx=12, pady=10)
    st.insert("1.0", text)
    st.configure(state="disabled")
    st.pack(fill="both", expand=True)
    root.mainloop()


def main() -> None:
    # Pick the capture: explicit argument, else newest in the drop folder.
    capture = None
    if len(sys.argv) > 1 and sys.argv[1].strip() and os.path.isfile(sys.argv[1]):
        capture = sys.argv[1]
    else:
        os.makedirs(DROP_DIR, exist_ok=True)
        capture = newest_capture(DROP_DIR)

    if not capture:
        msg = (f"No capture found.\n\nDrop a .pcapng file into:\n{DROP_DIR}\n\n"
               "then run this again.")
        try:
            show_window("Capture Report", msg)
        except Exception:
            print(msg)
        return

    try:
        res = analyze(capture)
        report = format_report(capture, res)
    except Exception as e:
        report = f"Could not analyze:\n{capture}\n\n{e}"

    print(report)  # harmless when a console is attached; ignored under pythonw
    try:
        show_window(f"Capture Report — {os.path.basename(capture)}", report)
    except Exception:
        pass  # no display available: the printed text above is the output


if __name__ == "__main__":
    # pythonw.exe has no console -> stdout/stderr are None; make print() a no-op.
    for _n in ("stdout", "stderr"):
        if getattr(sys, _n) is None:
            setattr(sys, _n, open(os.devnull, "w"))
    main()
