#!/usr/bin/env python3
"""Stop a host from reaching this machine, using nftables.

crowsnest watches a passive copy of traffic, so a block stops everything that
comes *after* it -- it cannot prevent the contact that revealed the host in the
first place. That suits a peer that keeps knocking; it is not an inline firewall.

Everything lives in crowsnest's own nftables table, so existing firewall rules are
never read, rewritten or flushed:

    table inet crowsnest {
      chain input { type filter hook input priority -10; policy accept;
                    ip saddr 203.0.113.5 drop }
    }

Because the table is ours alone, listing shows only crowsnest's blocks and
removing one cannot disturb anything else.

Blocks are session-scoped: they vanish on reboot, which is the escape hatch if
one locks something out. Recording them (see save_record) lets `crowsnest blocks
--restore` put them back deliberately.

Three addresses are refused unless explicitly forced, because blocking them
tends to break the machine rather than protect it: the default gateway, whatever
is answering DNS, and the peer of the current SSH session.

Linux only for now. nft_available() is the gate; every caller degrades politely
elsewhere.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess

TABLE = "crowsnest"
CHAIN = "input"
# Slightly ahead of the usual filter hook, so a drop lands before other accepts.
CHAIN_SPEC = "type filter hook input priority -10 ; policy accept ;"

RECORD_DIR = os.path.join(os.path.expanduser("~"), ".crowsnest")
RECORD_PATH = os.path.join(RECORD_DIR, "blocks.json")


class BlockError(RuntimeError):
    """Anything that stops a block being applied, with a readable reason."""


# --------------------------------------------------------------- availability
def nft_path() -> str | None:
    return shutil.which("nft")


def nft_available() -> bool:
    return os.name != "nt" and nft_path() is not None


def unsupported_reason() -> str:
    """Why blocking cannot run here, phrased for a user."""
    if os.name == "nt":
        return ("blocking currently supports Linux (nftables) only; Windows "
                "firewall support is not implemented yet")
    if nft_path() is None:
        return ("nft was not found. On Debian or Raspberry Pi OS: "
                "sudo apt install nftables")
    return ""


# ------------------------------------------------------------------ execution
def run_nft(args: list[str], dry_run: bool = False,
            runner=subprocess.run) -> str:
    """Run one nft command. The single place this module touches the system.

    `runner` is injectable so the logic above it can be tested without a
    firewall. With dry_run the command is only described, never executed.
    """
    cmd = [nft_path() or "nft"] + args
    if dry_run:
        return "[dry run] " + " ".join(cmd)
    proc = runner(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "").strip()
        if "permission denied" in message.lower() or os.geteuid() != 0:
            raise BlockError(f"nft needs root: try sudo. ({message})")
        raise BlockError(f"nft failed: {message}")
    return proc.stdout or ""


def describe_commands(addresses: list[str]) -> list[str]:
    """The exact nft commands a block would run, for showing before applying."""
    nft = nft_path() or "nft"
    out = [f"{nft} add table inet {TABLE}",
           f"{nft} add chain inet {TABLE} {CHAIN} {{ {CHAIN_SPEC} }}"]
    for address in addresses:
        family = "ip6" if ":" in address else "ip"
        out.append(f"{nft} add rule inet {TABLE} {CHAIN} "
                   f"{family} saddr {address} drop")
    return out


def ensure_table(dry_run: bool = False, runner=subprocess.run) -> None:
    """Create crowsnest's table and chain. Safe to repeat."""
    run_nft(["add", "table", "inet", TABLE], dry_run, runner)
    run_nft(["add", "chain", "inet", TABLE, CHAIN, "{", *CHAIN_SPEC.split(), "}"],
            dry_run, runner)


# -------------------------------------------------------------------- targets
def resolve_target(target: str) -> list[str]:
    """Addresses to block for a target, which may be a hostname or an address.

    A hostname is resolved to the addresses it has *now*. nftables filters on
    addresses, so a host that later moves or answers on more addresses will not
    stay blocked -- callers should say so.
    """
    target = target.strip()
    if not target:
        raise BlockError("no target given")
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror as e:
        raise BlockError(f"could not resolve {target!r}: {e}") from None
    found: list[str] = []
    for info in infos:
        address = info[4][0].partition("%")[0]
        if address not in found:
            found.append(address)
    if not found:
        raise BlockError(f"{target!r} resolved to no addresses")
    return found


def default_gateways() -> list[str]:
    """Gateway addresses from the routing table."""
    found = []
    for args in (["ip", "route", "show", "default"],
                 ["ip", "-6", "route", "show", "default"]):
        if not shutil.which(args[0]):
            continue
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        for match in re.finditer(r"via\s+(\S+)", proc.stdout or ""):
            found.append(match.group(1))
    return found


def dns_servers() -> list[str]:
    """Nameservers this machine is using."""
    found = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        found.append(parts[1])
    except OSError:
        pass
    return found


def ssh_peer() -> str | None:
    """The address this SSH session came from, if we are inside one."""
    for name in ("SSH_CONNECTION", "SSH_CLIENT"):
        value = os.environ.get(name)
        if value:
            parts = value.split()
            if parts:
                return parts[0]
    return None


def protected_addresses() -> dict[str, str]:
    """Addresses that must not be blocked casually, mapped to why."""
    protected: dict[str, str] = {}
    for address in default_gateways():
        protected.setdefault(address, "this machine's default gateway "
                                      "- blocking it cuts all connectivity")
    for address in dns_servers():
        protected.setdefault(address, "a DNS server this machine uses "
                                      "- blocking it breaks name resolution")
    peer = ssh_peer()
    if peer:
        protected.setdefault(peer, "the peer of your current SSH session "
                                   "- blocking it locks you out")
    return protected


def check_targets(addresses: list[str]) -> dict[str, str]:
    """Which of these addresses are protected, and why. Empty when all fine."""
    protected = protected_addresses()
    problems = {}
    for address in addresses:
        if address in protected:
            problems[address] = protected[address]
            continue
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            problems[address] = "not a valid address"
            continue
        if parsed.is_loopback:
            problems[address] = "loopback - blocking it breaks local services"
    return problems


# ------------------------------------------------------------------- applying
def block(addresses: list[str], dry_run: bool = False,
          runner=subprocess.run) -> list[str]:
    """Drop inbound traffic from each address. Returns those newly blocked."""
    ensure_table(dry_run, runner)
    already = {entry["address"] for entry in list_blocks(runner=runner)} \
        if not dry_run else set()
    added = []
    for address in addresses:
        if address in already:
            continue
        family = "ip6" if ":" in address else "ip"
        run_nft(["add", "rule", "inet", TABLE, CHAIN,
                 family, "saddr", address, "drop"], dry_run, runner)
        added.append(address)
    return added


def unblock(addresses: list[str], dry_run: bool = False,
            runner=subprocess.run) -> list[str]:
    """Remove the rules for these addresses. Returns those actually removed."""
    removed = []
    for entry in list_blocks(runner=runner):
        if entry["address"] in addresses:
            run_nft(["delete", "rule", "inet", TABLE, CHAIN,
                     "handle", str(entry["handle"])], dry_run, runner)
            removed.append(entry["address"])
    return removed


def unblock_all(dry_run: bool = False, runner=subprocess.run) -> int:
    """Drop crowsnest's whole table, leaving other firewall rules untouched."""
    entries = list_blocks(runner=runner)
    if entries:
        run_nft(["delete", "table", "inet", TABLE], dry_run, runner)
    return len(entries)


def parse_ruleset(text: str) -> list[dict]:
    """Pull blocked addresses and rule handles out of `nft -a list table` output.

    Handles are what `nft delete rule` needs to remove one rule precisely.
    """
    entries = []
    for line in text.splitlines():
        match = re.search(
            r"\bip6?\s+saddr\s+(\S+)\s+drop\b.*?#\s*handle\s+(\d+)", line)
        if match:
            entries.append({"address": match.group(1),
                            "handle": int(match.group(2))})
    return entries


def list_blocks(runner=subprocess.run) -> list[dict]:
    """Everything crowsnest is currently blocking. Empty if the table is absent."""
    try:
        output = run_nft(["-a", "list", "table", "inet", TABLE], False, runner)
    except BlockError:
        return []      # no table yet, or nft cannot be read -- nothing blocked
    return parse_ruleset(output)


# -------------------------------------------------------------------- records
def load_record() -> list[str]:
    try:
        with open(RECORD_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return [str(a) for a in data.get("blocked", [])]
    except (OSError, ValueError, AttributeError):
        return []


def save_record(addresses: list[str]) -> None:
    """Remember these so `crowsnest blocks --restore` can reapply them."""
    existing = load_record()
    merged = existing + [a for a in addresses if a not in existing]
    os.makedirs(RECORD_DIR, exist_ok=True)
    with open(RECORD_PATH, "w", encoding="utf-8") as f:
        json.dump({"blocked": merged}, f, indent=2)


def forget_record(addresses: list[str] | None = None) -> None:
    remaining = [] if addresses is None else \
        [a for a in load_record() if a not in addresses]
    os.makedirs(RECORD_DIR, exist_ok=True)
    with open(RECORD_PATH, "w", encoding="utf-8") as f:
        json.dump({"blocked": remaining}, f, indent=2)


def restore_hint() -> str:
    """How to make recorded blocks come back after a reboot.

    Printed rather than installed: crowsnest does not add system services on your
    behalf.
    """
    return (
        "To reapply recorded blocks automatically after a reboot, install a\n"
        "systemd unit that runs the restore for you:\n\n"
        "  sudo tee /etc/systemd/system/crowsnest-blocks.service >/dev/null <<'UNIT'\n"
        "  [Unit]\n"
        "  Description=Reapply crowsnest blocks\n"
        "  After=network-pre.target nftables.service\n"
        "  [Service]\n"
        "  Type=oneshot\n"
        f"  ExecStart={shutil.which('crowsnest') or 'crowsnest'} blocks --restore --yes\n"
        "  [Install]\n"
        "  WantedBy=multi-user.target\n"
        "  UNIT\n"
        "  sudo systemctl enable crowsnest-blocks.service\n")
