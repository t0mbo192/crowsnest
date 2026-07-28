# crowsnest

**Wireshark tells you everything. crowsnest tells you who.**

A terminal tool that reduces network traffic to the one question you usually
actually have: *what is my machine talking to, and what is talking to it?*

![the crowsnest dashboard](docs/dashboard.png)

By default it does not draw a dashboard at all. It reports each host **once**,
when it first appears, and then says nothing:

```
crowsnest live  ·  eth0  ·  this machine 192.168.1.120
  each host is reported once, when first seen. Ctrl-C for a summary.

  08:22:13  ↑  github.com                     GitHub - code hosting
  08:22:13  ↑  ord37s57-in-f10.1e100.net      Google infrastructure
  08:22:13  ↑  browser-intake-datadoghq.com   Datadog - monitoring / telemetry
  08:22:14  ↑  20.42.65.92                    Microsoft Corporation
  08:22:19  ↓  laptop.lan                     Local network device
  08:22:24  ↓  203.0.113.5                    DigitalOcean, LLC
```

`--dashboard` gives you the framed view above, with transfer rates, a search
box, and panels you can open and close.

Four things it does that a packet list does not:

- **Reports each host once.** One line when a host first appears, then silence.
  Nothing redraws, nothing scrolls past, nothing repeats — the opposite of a
  monitor you have to keep staring at.
- **Splits by direction.** Outbound means this machine started the connection;
  inbound means something else did. Taken from the TCP handshake — whoever sends
  the opening SYN is the initiator.
- **Says what each host is.** A curated table names what a host is *for*
  ("Datadog - monitoring / telemetry"), and an offline ASN database names the
  owner of everything else, so bare addresses stop being dead ends.
- **Lets you shut a host out.** `crowsnest block` writes an nftables rule, with
  guardrails so you cannot cut your own connectivity by accident.

> **On encryption:** modern traffic is HTTPS, so crowsnest reports *which hosts*
> were contacted, from DNS and the TLS server name. Never page content or URLs.
> That is the ceiling for anything working from packets, not a limitation here.

## Install

**Debian, Ubuntu and Raspberry Pi OS** have a package. Download
`crowsnest_<version>_all.deb` from
[Releases](https://github.com/t0mbo192/crowsnest/releases) and:

```bash
sudo apt install ./crowsnest_1.1.0_all.deb
```

apt pulls in `tshark` itself, so there is no prerequisite to go and install
first — that one command ends with a working `crowsnest`. It also brings in
`nftables` and `python3-maxminddb`, so blocking and organisation names work out
of the box (`--no-install-recommends` if you would rather they did not).
`sudo apt purge crowsnest` removes it completely.

Everywhere else, one line.

**Linux and macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/t0mbo192/crowsnest/main/install.sh | bash
```

**Windows**

```powershell
irm https://raw.githubusercontent.com/t0mbo192/crowsnest/main/install.ps1 | iex
```

Either one fetches crowsnest, puts a `crowsnest` command on your PATH, and offers
to install anything missing. Nothing is installed behind your back: the exact
command is printed and run only if you say yes, so a machine with
[Wireshark](https://www.wireshark.org) already on it is never asked anything.
Wireshark is the one real prerequisite — crowsnest reads packets with its
`tshark`.

The source lands in `~/.local/share/crowsnest` (`%LOCALAPPDATA%\Programs\crowsnest`
on Windows) and the command in `~/.local/bin`, per-user, no administrator rights
and nothing machine-wide. `git` is used if you have it, so `git pull` updates
you; a plain download is used if you do not, and re-running the line updates
instead.

To read the script before running it, clone and run it — it behaves identically:

```bash
git clone https://github.com/t0mbo192/crowsnest.git
cd crowsnest && ./install.sh          # .\install.ps1 on Windows
```

Run that way, crowsnest runs from your clone and `git pull` is the update.

| | Linux / macOS | Windows |
|---|---|---|
| unattended | `--yes` | `-Yes` |
| install elsewhere | `--prefix DIR` | `-Prefix DIR` |
| use a downloaded binary | — | `-Exe .\crowsnest.exe` (no Python needed) |
| remove it again | `--uninstall` | `-Uninstall` |

To pass one of those through the Windows one-liner, use the script block form:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/t0mbo192/crowsnest/main/install.ps1))) -Uninstall
```

**With pip, on any platform**

crowsnest is a normal Python package, so if you would rather not use the scripts:

```bash
pipx install git+https://github.com/t0mbo192/crowsnest.git
```

`pipx` is the safe choice — plain `pip install` into a system Python is blocked
on Debian and Raspberry Pi OS ([PEP 668](https://peps.python.org/pep-0668/)).
Add `[asn]` (`pipx install "crowsnest[asn] @ git+..."`) to pull in `maxminddb`
at the same time.

**Then**, once installed, fetch the database that turns bare addresses into
organisation names (~10 MB, one time):

```bash
crowsnest asn --fetch
```

## Use

```bash
crowsnest interfaces                      # what can I capture on?
sudo crowsnest live -i eth0               # watch traffic as it happens
crowsnest read capture.pcapng             # analyse a saved capture
crowsnest read                            # ...or the newest one in ~/Documents/Captures
crowsnest asn 8.8.8.8                     # who owns an address?
crowsnest update                          # is there a newer crowsnest?
```

Interface names differ by platform — `eth0` or `wlan0` on Linux, `en0` for Wi-Fi
on a Mac. `crowsnest interfaces` lists what is actually there. On macOS, live
capture needs `sudo` unless Wireshark's ChmodBPF helper is installed, and
`crowsnest block` does not apply: it writes nftables rules, and macOS filters
with pf.

In the dashboard: `/` search, `o` and `i` open or close a panel, `c` reset,
`q` quit. Ten hosts a panel until you open one.

`live` takes `--dashboard` for the framed view with transfer rates,
`--filter 'not port 22'` for a capture filter, `--duration N` to stop
automatically, `--top N` for the summary length, and `--me IP` if it picks the
wrong local address. Ctrl-C prints a full inbound/outbound summary.

`read` takes `--json` and `--csv FILE` for scripting, and `--allowlist FILE`
with optional `--flagged-only` to surface anything not on an approved list (see
[allowlist.example.txt](allowlist.example.txt)).

Both take `--no-names` to skip reverse DNS, `--no-color`, and `--ascii`.

### Blocking a host (Linux)

Once you can see who is reaching the machine, you can shut them out:

```bash
sudo crowsnest block 203.0.113.5        # shows the rule, asks, then applies
sudo crowsnest blocks                    # what is blocked now
sudo crowsnest unblock 203.0.113.5       # or --all
```

Every one of those **prints the exact `nft` command and waits for a yes**.
`--dry-run` shows what would happen and stops. Rules go into crowsnest's own
`crowsnest` nftables table, so your existing firewall config is never read,
rewritten, or flushed — and removing a block cannot disturb anything else.

Blocks last **until reboot**. That is deliberate: a reboot is your escape hatch
if you shut out something you needed. `--persist` records a block so
`crowsnest blocks --restore` can reapply it, and prints the systemd unit to do
that automatically — crowsnest will not install a service behind your back.

crowsnest refuses to block three things unless you pass `--force`, because
blocking them breaks the machine rather than protecting it:

| Refused | Why |
|---|---|
| your default gateway | cuts all connectivity |
| any DNS server in use | breaks name resolution (on a Pi-hole box, for the whole network) |
| your current SSH peer | locks you out of a headless machine |

> **What blocking can and cannot do.** crowsnest watches a passive copy of
> traffic, so a block stops everything *after* it — it cannot prevent the first
> contact that revealed the host. That suits a peer that keeps knocking; it is
> not an inline firewall. Blocking a *hostname* blocks the addresses it resolves
> to **right now**, so a host that moves will need blocking again.

Live capture needs privileges — run under `sudo`, or
`sudo usermod -aG wireshark $USER` and log back in.

### Watching another device

Point crowsnest at a router interface and it reports what everything *behind*
that interface is talking to — a phone, a TV, a games console, anything that
cannot run crowsnest itself. On a Raspberry Pi acting as a WireGuard gateway:

```bash
sudo crowsnest live -i wg0 --me 10.6.0.2
```

`--me` matters here. crowsnest normally works out which address is the machine
it is watching by taking the busiest endpoint, and on a gateway that is the
gateway itself. Naming the device's address makes *outbound* mean "from that
device", which is what you want to read.

[docs/setup-wireguard.sh](docs/setup-wireguard.sh) sets a Pi up that way —
prerequisites, keys, forwarding, NAT, and a QR code for the phone. It has
`--dry-run` and `--uninstall`, and installs nothing on its own.

That gets you a tunnel that works at home. [docs/cellular.md](docs/cellular.md)
covers the rest: giving the Pi a name that reaches it from outside, what to do
when your ISP will not let anything in, and how to tell the difference.

Blocking needs `--gateway`, because forwarded traffic never reaches the input
hook the ordinary rules sit on:

```bash
sudo crowsnest block graph.facebook.com --gateway --client 10.6.0.2 --dry-run
```

| | chain | matches | protects |
|---|---|---|---|
| default | input | `ip saddr` | this machine |
| `--gateway` | forward | both directions | the routed device |

Addresses go into nftables named sets rather than one rule each, so the ruleset
stays four rules wide however many hosts accumulate.

Two guardrails are added on top of the usual ones. `--client` names the
device's own address so it cannot be cut off by accident — an easy mistake,
since the device is right there in crowsnest's own output. And a handful of
hostnames are refused because blocking them breaks the device rather than
protecting it:

| Refused | Why |
|---|---|
| `*.push.apple.com`, `mtalk.google.com` | carry every notification on the device; blocking stops all push, and nothing about the symptom points here |
| `albert.apple.com`, `gs.apple.com` | device activation and authentication |
| `time.apple.com` | a device with a wrong clock fails TLS almost everywhere |
| `*.apple-dns.net` | breaks iCloud, the App Store and Find My |

Those are matched on the name as typed, before it is resolved — Apple push runs
over a range too wide to enumerate and its addresses rotate.

Unlike blocking for this machine, a gateway block is **inline**: the traffic is
passing through, so a blocked host is never reached at all rather than merely
being stopped after the first contact.

## What is here

| File | |
|---|---|
| [crowsnest.py](crowsnest.py) | The command line: every subcommand and all terminal output. |
| [crowsnest_core.py](crowsnest_core.py) | Analysis — direction, host names, descriptions, live tracking. No terminal or display assumptions. |
| [crowsnest_banner.py](crowsnest_banner.py) | The mark at the top of the dashboard. |
| [asn_lookup.py](asn_lookup.py) | Names the organisation behind an address, offline. |
| [blocking.py](blocking.py) | Writes and removes nftables rules, with guardrails. |
| [gateway.py](gateway.py) | The same, on the forward chain, for a device routed through this machine. |
| [docs/setup-wireguard.sh](docs/setup-wireguard.sh) | Sets a Raspberry Pi up as a WireGuard gateway to watch. |
| [updater.py](updater.py) | Checks for a newer version. |
| [install.sh](install.sh) / [install.ps1](install.ps1) | Installers for Linux/macOS and Windows, runnable straight from a URL. |
| [packaging/build-deb.sh](packaging/build-deb.sh) | Builds the Debian package. Takes its file list from `pyproject.toml` so the two cannot drift. |
| [pyproject.toml](pyproject.toml) | Package metadata, for the `pip`/`pipx` route. |
| [test_core.py](test_core.py) / [test_blocking.py](test_blocking.py) / [test_gateway.py](test_gateway.py) / [test_dashboard.py](test_dashboard.py) | 101 tests, no network or capture needed. The dashboard ones replay real frames through a small terminal emulator, since a redraw bug is only visible once the escape sequences have been applied to a screen. |

Standard library only, apart from the optional `maxminddb`. No display, no web
server, no daemon.

## Performance

Reading a capture streams tshark's output and parses it as it arrives, so
dissection and analysis overlap. On a 67,878-packet, 88 MB capture:

| | |
|---|---|
| Total | **1.67 s** |
| Throughput | **~40,000 packets/s** |

Most of that is tshark. The work on top of it is small: address classification
is memoised, flow keys avoid per-packet allocation, and tshark's own name
resolution is switched off since crowsnest does its own, concurrently and under a
deadline.

## Updating

crowsnest tells you on startup when a newer version exists, and never installs
anything itself.

| Install | Update |
|---|---|
| `install.sh` / `install.ps1` from a clone | `git pull` — the shim points at the clone |
| `pipx` | `pipx upgrade crowsnest` |
| `crowsnest.exe` | download the new one from Releases |

Check any time with `crowsnest update`.

## Releasing

The version lives in [crowsnest_version.py](crowsnest_version.py). Pushing a tag
does the rest:

```bash
git tag v1.0.1 && git push origin main --tags
```

[The workflow](.github/workflows/ci.yml) tests every pull request on Linux,
Windows and macOS, and builds the `.deb` on every push — installing it on a
runner that has no tshark, then purging it and checking nothing is left behind,
because packaging breaks quietly and release time is too late to find out. On a
version tag it also builds `crowsnest.exe`, smoke-tests it, and publishes a
Release carrying the exe, the `.deb` and the wheel. It fails if the tag
disagrees with the version in source, so a mislabelled build cannot ship.
Rehearse from the Actions tab with `dry_run` left on.

## Privacy

Captures contain real addresses and browsing history, so `*.pcap*` is
git-ignored and never committed. ASN lookups are local — no address leaves the
machine, and crowsnest works with no network at all.

## Licence

crowsnest is [MIT](LICENSE).

The ASN database is not part of this repository and is not redistributed by it;
`crowsnest asn --fetch` downloads it from the publisher. DB-IP's licence requires
attribution:

> IP-to-ASN data by [DB-IP](https://db-ip.com) — licensed under
> [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/).

MaxMind's GeoLite2-ASN works instead if you have it, under its own
[licence](https://www.maxmind.com/en/geolite2/eula).
