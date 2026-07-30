# Blocking a host

Linux only. Blocking writes nftables rules, and macOS filters with pf — crowsnest
says so rather than failing oddly. Windows is not supported either.

## For this machine

```bash
sudo crowsnest block 203.0.113.5      # shows the rule, asks, then applies
sudo crowsnest blocks                  # what is blocked now
sudo crowsnest unblock 203.0.113.5     # or --all
```

Every one of those **prints the exact `nft` command and waits for a yes**.
`--dry-run` shows what would happen and stops.

Rules go into crowsnest's own `crowsnest` nftables table, so your existing
firewall config is never read, rewritten, or flushed — and removing a block
cannot disturb anything else.

Blocks last **until reboot**. That is deliberate: a reboot is your escape hatch
if you shut out something you needed. `--persist` records a block so
`crowsnest blocks --restore` can reapply it, and prints the systemd unit to do
that automatically — crowsnest will not install a service behind your back.

### What it refuses

Three things are refused unless you pass `--force`, because blocking them breaks
the machine rather than protecting it:

| Refused | Why |
|---|---|
| your default gateway | cuts all connectivity |
| any DNS server in use | breaks name resolution (on a Pi-hole box, for the whole network) |
| your current SSH peer | locks you out of a headless machine |

That last one is why blocking is safe to drive over SSH.

### What blocking can and cannot do

crowsnest watches a passive copy of traffic, so a block stops everything *after*
it — it cannot prevent the first contact that revealed the host. That suits a
peer that keeps knocking; it is not an inline firewall.

Blocking a *hostname* blocks the addresses it resolves to **right now**, so a
host that moves will need blocking again.

## For a device routed through this machine

When the Pi is a gateway — see [cellular.md](cellular.md) and
[setup-wireguard.sh](setup-wireguard.sh) — forwarded traffic never reaches the
input hook the ordinary rules sit on, so blocking needs `--gateway`:

```bash
sudo crowsnest block graph.facebook.com --gateway --client 10.6.0.2 --dry-run
```

| | chain | matches | protects |
|---|---|---|---|
| default | input | `ip saddr` | this machine |
| `--gateway` | forward | both directions | the routed device |

Addresses go into nftables named sets rather than one rule each, so the ruleset
stays four rules wide however many hosts accumulate.

Unlike blocking for this machine, a gateway block is **inline**: the traffic is
passing through, so a blocked host is never reached at all rather than merely
being stopped after the first contact.

### Two extra guardrails

`--client` names the device's own address so it cannot be cut off by accident —
an easy mistake, since the device is right there in crowsnest's own output.

And a handful of hostnames are refused because blocking them breaks the device
rather than protecting it:

| Refused | Why |
|---|---|
| `*.push.apple.com`, `mtalk.google.com` | carry every notification on the device; blocking stops all push, and nothing about the symptom points here |
| `albert.apple.com`, `gs.apple.com` | device activation and authentication |
| `time.apple.com` | a device with a wrong clock fails TLS almost everywhere |
| `*.apple-dns.net` | breaks iCloud, the App Store and Find My |

Those are matched on the name as typed, before it is resolved — Apple push runs
over a range too wide to enumerate and its addresses rotate.
