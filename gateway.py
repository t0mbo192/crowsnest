#!/usr/bin/env python3
"""Block hosts on behalf of a device routed through this machine.

blocking.py protects the machine crowsnest runs on: rules go on the input hook
and match `ip saddr`, which is right for a server someone is knocking on. A
device routed through this box -- a phone on a WireGuard tunnel, a TV on a
guest network -- is a different shape. Its traffic is *forwarded*, so it never
reaches the input hook at all, and the traffic worth stopping is outbound: the
device reaching a tracker, not a tracker reaching the device.

So this is blocking.py's sibling, not its replacement:

    blocking.py   input hook,   ip saddr X drop   protects this machine
    gateway.py    forward hook, either direction  protects the routed device

Rules live in the same `crowsnest` table but a separate `forward` chain, so
this machine's own firewall is still never read or rewritten, and the two modes
cannot disturb each other.

Addresses are held in named nftables sets rather than one rule each. A set is
the better fit: blocking becomes `add element` and unblocking `delete element`,
with no rule handles to track, and the ruleset stays four rules wide however
many hosts are blocked -- which matters when a device can accumulate hundreds
over a week.

The public names here deliberately mirror blocking.py's, so the command line can
pick a module and then treat them the same.

Linux only, like blocking.py. blocking.nft_available() is still the gate.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil

import blocking

TABLE = blocking.TABLE
CHAIN = "forward"
SET4 = "blocked4"
SET6 = "blocked6"

# Priority -10 for the same reason blocking.py uses it on input: a drop should
# land before whatever accepts the forward hook already has.
CHAIN_SPEC = "type filter hook forward priority -10 ; policy accept ;"

# Its own record, so `blocks --restore` cannot reapply an input-chain block into
# the forward chain or the other way round.
RECORD_PATH = os.path.join(blocking.RECORD_DIR, "gateway-blocks.json")


class BlockError(blocking.BlockError):
    """Anything that stops a gateway block being applied."""


# ---------------------------------------------------------------- guardrails
# Hostnames that break the routed device rather than protect it. Matched as
# substrings against the target *as typed*, before it is resolved, because
# these are recognisable by name and emphatically not by address -- Apple push
# runs over a range far too wide to enumerate, and the addresses rotate.
RISKY_HOSTNAMES = [
    ("push.apple.com", "carries every notification on the device -- blocking "
                       "it silently stops all push, not just one app's"),
    ("courier.push.apple.com", "carries every notification on the device"),
    ("apple-dns.net", "Apple's own resolver -- blocking it breaks iCloud, "
                      "the App Store and Find My"),
    ("time.apple.com", "clock sync -- a device with a wrong clock fails TLS "
                       "on almost every site"),
    ("albert.apple.com", "device activation -- blocking it can leave the "
                         "device unable to re-activate after a reset"),
    ("gs.apple.com", "device activation and authentication"),
    ("mtalk.google.com", "Android push -- blocking it stops all notifications"),
    ("android.clients.google.com", "Play services -- breaks app updates "
                                   "and push"),
]


def risky_hostname(target: str) -> str:
    """Why this hostname should not be blocked, or "" if it is fine.

    Checked on the name rather than the resolved addresses, since that is the
    only form in which these are identifiable.
    """
    lowered = target.strip().lower()
    for needle, reason in RISKY_HOSTNAMES:
        if needle in lowered:
            return reason
    return ""


def check_targets(addresses: list[str], client_ips: list[str] | None = None,
                  protected=None) -> dict[str, str]:
    """Which addresses must not be blocked, and why. Empty when all fine.

    blocking.check_targets() guards the machine crowsnest runs on, and those
    guards still apply here -- blocking this box's own gateway still cuts its
    connectivity. What this adds is the routed device's own address: blocking it
    cuts that device off entirely, and it is an easy mistake to make because the
    device appears in crowsnest's own output, right there to be blocked.
    """
    problems = dict(blocking.check_targets(addresses)) if protected is None \
        else {a: protected[a] for a in addresses if a in protected}

    for address in client_ips or []:
        if address in addresses and address not in problems:
            problems[address] = ("the address of the device being monitored "
                                 "-- blocking it cuts that device off "
                                 "completely")
    return problems


# ------------------------------------------------------------------ commands
def _set_for(address: str) -> str:
    return SET6 if ":" in address else SET4


def describe_commands(addresses: list[str]) -> list[str]:
    """The exact nft commands a gateway block would run, for showing first.

    crowsnest prints these and waits for a yes before touching anything; this
    keeps that promise for the forward chain too.
    """
    nft = blocking.nft_path() or "nft"
    out = [f"{nft} add table inet {TABLE}",
           f"{nft} add set inet {TABLE} {SET4} {{ type ipv4_addr ; flags interval ; }}",
           f"{nft} add set inet {TABLE} {SET6} {{ type ipv6_addr ; flags interval ; }}",
           f"{nft} add chain inet {TABLE} {CHAIN} {{ {CHAIN_SPEC} }}"]
    # Both directions: daddr stops the device reaching the host, saddr stops the
    # host reaching back on a connection the device did not start.
    for setname, family in ((SET4, "ip"), (SET6, "ip6")):
        out.append(f"{nft} add rule inet {TABLE} {CHAIN} "
                   f"{family} daddr @{setname} drop")
        out.append(f"{nft} add rule inet {TABLE} {CHAIN} "
                   f"{family} saddr @{setname} drop")
    for address in addresses:
        out.append(f"{nft} add element inet {TABLE} {_set_for(address)} "
                   f"{{ {address} }}")
    return out


def _runner(runner):
    def run(args: list[str], dry_run: bool = False) -> str:
        if runner is None:
            return blocking.run_nft(args, dry_run)
        return blocking.run_nft(args, dry_run, runner)
    return run


def _rules_present(runner=None) -> bool:
    """True if the forward chain already carries our drop rules."""
    try:
        text = _runner(runner)(["list", "chain", "inet", TABLE, CHAIN])
    except blocking.BlockError:
        return False
    return f"@{SET4}" in text


def ensure_gateway(dry_run: bool = False, runner=None) -> None:
    """Create the table, sets, chain and drop rules. Safe to repeat."""
    run = _runner(runner)
    run(["add", "table", "inet", TABLE], dry_run)
    run(["add", "set", "inet", TABLE, SET4,
         "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}"], dry_run)
    run(["add", "set", "inet", TABLE, SET6,
         "{", "type", "ipv6_addr", ";", "flags", "interval", ";", "}"], dry_run)
    run(["add", "chain", "inet", TABLE, CHAIN, "{", *CHAIN_SPEC.split(), "}"],
        dry_run)

    # `nft add rule` appends unconditionally rather than being idempotent, and
    # every block calls this, so without the check the chain would grow by four
    # rules per block.
    if not dry_run and _rules_present(runner):
        return
    for setname, family in ((SET4, "ip"), (SET6, "ip6")):
        run(["add", "rule", "inet", TABLE, CHAIN,
             family, "daddr", f"@{setname}", "drop"], dry_run)
        run(["add", "rule", "inet", TABLE, CHAIN,
             family, "saddr", f"@{setname}", "drop"], dry_run)


# ------------------------------------------------------------------ applying
def block(addresses: list[str], dry_run: bool = False, runner=None) -> list[str]:
    """Stop the routed device reaching each address. Returns those newly added."""
    ensure_gateway(dry_run, runner)
    run = _runner(runner)
    already = set() if dry_run else {e["address"] for e in list_blocks(runner=runner)}
    added = []
    for address in addresses:
        if address in already:
            continue
        run(["add", "element", "inet", TABLE, _set_for(address),
             "{", address, "}"], dry_run)
        added.append(address)
    return added


def unblock(addresses: list[str], dry_run: bool = False, runner=None) -> list[str]:
    """Remove these addresses from the blocked sets. Returns those removed."""
    run = _runner(runner)
    present = {e["address"] for e in list_blocks(runner=runner)}
    removed = []
    for address in addresses:
        if address not in present:
            continue
        run(["delete", "element", "inet", TABLE, _set_for(address),
             "{", address, "}"], dry_run)
        removed.append(address)
    return removed


def unblock_all(dry_run: bool = False, runner=None) -> int:
    """Empty both sets, leaving the chain and its rules standing.

    blocking.unblock_all() drops the whole table, which is right for the input
    chain but here would tear down the forward chain too and need it rebuilt on
    the next block. Flushing the sets clears every block just as completely.
    """
    run = _runner(runner)
    count = len(list_blocks(runner=runner))
    for setname in (SET4, SET6):
        run(["flush", "set", "inet", TABLE, setname], dry_run)
    return count


def parse_set(text: str) -> list[str]:
    """Pull addresses out of `nft list set` output.

    nft wraps a long element list across lines, so the block between the braces
    is matched whole and split afterwards rather than read line by line -- doing
    it by line silently returns only the first few on a busy gateway.
    """
    match = re.search(r"elements\s*=\s*\{(.*?)\}", text, re.DOTALL)
    if not match:
        return []
    found = []
    for chunk in match.group(1).split(","):
        address = chunk.strip()
        if not address:
            continue
        # Elements can carry a timeout or comment; the address is the first word.
        address = address.split()[0]
        try:
            ipaddress.ip_network(address, strict=False)
        except ValueError:
            continue
        found.append(address)
    return found


def list_blocks(runner=None) -> list[dict]:
    """Everything currently blocked for the routed device.

    Returns the same shape as blocking.list_blocks() so the command line can
    treat the two interchangeably. There is no handle: a set element is removed
    by value, which is one of the reasons sets are the better fit here.
    """
    run = _runner(runner)
    found = []
    for setname in (SET4, SET6):
        try:
            text = run(["list", "set", "inet", TABLE, setname])
        except blocking.BlockError:
            continue          # set not created yet -- nothing blocked
        found += [{"address": a} for a in parse_set(text)]
    return found


# -------------------------------------------------------------------- records
def load_record() -> list[str]:
    try:
        with open(RECORD_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return [str(a) for a in data.get("blocked", [])]
    except (OSError, ValueError, AttributeError):
        return []


def save_record(addresses: list[str]) -> None:
    """Remember these so `crowsnest blocks --gateway --restore` can reapply them."""
    existing = load_record()
    merged = existing + [a for a in addresses if a not in existing]
    _write_record(merged)


def forget_record(addresses: list[str] | None = None) -> None:
    remaining = [] if addresses is None else \
        [a for a in load_record() if a not in addresses]
    _write_record(remaining)


def _write_record(addresses: list[str]) -> None:
    os.makedirs(blocking.RECORD_DIR, exist_ok=True)
    with open(RECORD_PATH, "w", encoding="utf-8") as f:
        json.dump({"blocked": addresses}, f, indent=2)


def restore_hint() -> str:
    """How to make recorded gateway blocks come back after a reboot.

    Printed rather than installed: crowsnest does not add system services on
    your behalf. This matters more on a gateway than on a laptop, since the
    whole point of the box is to run unattended.
    """
    return (
        "To reapply recorded gateway blocks automatically after a reboot,\n"
        "install a systemd unit that runs the restore for you:\n\n"
        "  sudo tee /etc/systemd/system/crowsnest-gateway.service >/dev/null <<'UNIT'\n"
        "  [Unit]\n"
        "  Description=Reapply crowsnest gateway blocks\n"
        "  After=network-pre.target nftables.service\n"
        "  [Service]\n"
        "  Type=oneshot\n"
        f"  ExecStart={shutil.which('crowsnest') or 'crowsnest'} blocks "
        "--gateway --restore --yes\n"
        "  [Install]\n"
        "  WantedBy=multi-user.target\n"
        "  UNIT\n"
        "  sudo systemctl enable crowsnest-gateway.service\n")
