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

Every route gives you a `crowsnest` command on your PATH. All of them need
[Wireshark](https://www.wireshark.org) installed, because crowsnest reads packets
with its `tshark`.

**Linux and macOS**

```bash
git clone https://github.com/t0mbo192/crowsnest.git
cd crowsnest && ./install.sh
```

Checks what you have, tells you the right command for anything missing (it never
runs `sudo` itself), and installs a `crowsnest` shim into `~/.local/bin`. Because
the shim points at the clone, `git pull` updates the command. `./install.sh
--uninstall` removes it; `--prefix DIR` puts it elsewhere.

**Windows**

```powershell
git clone https://github.com/t0mbo192/crowsnest.git
cd crowsnest; .\install.ps1
```

Installs to `%LOCALAPPDATA%\Programs\crowsnest` and adds that to your **user**
PATH — no administrator rights, nothing machine-wide. Open a new terminal
afterwards. Use `.\install.ps1 -Exe .\crowsnest.exe` to install a downloaded
binary instead of running from source (no Python needed), and
`.\install.ps1 -Uninstall` to remove both the command and the PATH entry.

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

## What is here

| File | |
|---|---|
| [crowsnest.py](crowsnest.py) | The command line: every subcommand and all terminal output. |
| [crowsnest_core.py](crowsnest_core.py) | Analysis — direction, host names, descriptions, live tracking. No terminal or display assumptions. |
| [crowsnest_banner.py](crowsnest_banner.py) | The mark at the top of the dashboard. |
| [asn_lookup.py](asn_lookup.py) | Names the organisation behind an address, offline. |
| [blocking.py](blocking.py) | Writes and removes nftables rules, with guardrails. |
| [updater.py](updater.py) | Checks for a newer version. |
| [install.sh](install.sh) / [install.ps1](install.ps1) | Installers for Linux/macOS and Windows. |
| [pyproject.toml](pyproject.toml) | Package metadata, for the `pip`/`pipx` route. |
| [test_core.py](test_core.py) / [test_blocking.py](test_blocking.py) | 48 tests, no network or capture needed. |

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

[The workflow](.github/workflows/release.yml) builds `crowsnest.exe`, smoke-tests
it, and publishes a Release. It fails if the tag disagrees with the version in
source, so a mislabelled build cannot ship. Rehearse from the Actions tab with
`dry_run` left on.

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
