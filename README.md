# netwatch

**Wireshark tells you everything. netwatch tells you who.**

A terminal tool that reduces network traffic to the one question you usually
actually have: *what is my machine talking to, and what is talking to it?*

```
netwatch live  ·  eth0  ·  00:00:10  ·  2,795 packets  ·  this machine 192.168.0.120

     SITE / HOST                         WHAT IT IS                    DATA       RATE
  ↑  github.com                          GitHub - code hosting      616.8 KB 148.7 KB/s
  ↑  ord37s57-in-f10.1e100.net           Google infrastructure        2.3 MB 243.5 KB/s
  ↑  browser-intake-datadoghq.com        Datadog - monitoring         17.8 KB   2.4 KB/s
  ↑  20.42.65.92                         Microsoft Corporation        14.7 KB          -
  ↓  laptop.lan                          Local network device          4.2 KB   1.1 KB/s

  18 connections (14 out, 4 in)  ·  2.9 MB total  ·  10 more
```

Three things it does that a packet list does not:

- **Splits by direction.** Outbound means this machine started the connection;
  inbound means something else did. Taken from the TCP handshake — whoever sends
  the opening SYN is the initiator.
- **Says what each host is.** A curated table names what a host is *for*
  ("Datadog - monitoring / telemetry"), and an offline ASN database names the
  owner of everything else, so bare addresses stop being dead ends.
- **Aggregates per host,** not per packet or per port pair.

> **On encryption:** modern traffic is HTTPS, so netwatch reports *which hosts*
> were contacted, from DNS and the TLS server name. Never page content or URLs.
> That is the ceiling for anything working from packets, not a limitation here.

## Install

**Raspberry Pi / Linux**

```bash
sudo apt install tshark python3-maxminddb
git clone https://github.com/t0mbo192/netwatch.git
cd netwatch && ./install-pi.sh
```

**Windows** — download `netwatch.exe` from
[Releases](https://github.com/t0mbo192/netwatch/releases), or run from source
with Python 3.10+. Either way you need
[Wireshark](https://www.wireshark.org) installed, since netwatch reads packets
with its `tshark`.

Then fetch the database that turns addresses into organisation names (~10 MB,
one time):

```bash
netwatch asn --fetch
```

## Use

```bash
netwatch interfaces                      # what can I capture on?
sudo netwatch live -i eth0               # watch traffic as it happens
netwatch read capture.pcapng             # analyse a saved capture
netwatch read                            # ...or the newest one in ~/Documents/Captures
netwatch asn 8.8.8.8                     # who owns an address?
netwatch update                          # is there a newer netwatch?
```

`live` takes `--top N`, `--interval`, `--duration`, `--filter 'not port 22'` for a
capture filter, `--plain` to log each new host instead of redrawing, and `--me IP`
if it picks the wrong local address. Ctrl-C prints a full summary.

`read` takes `--json` and `--csv FILE` for scripting, and `--allowlist FILE`
with optional `--flagged-only` to surface anything not on an approved list (see
[allowlist.example.txt](allowlist.example.txt)).

Both take `--no-names` to skip reverse DNS, `--no-color`, and `--ascii`.

Live capture needs privileges — run under `sudo`, or
`sudo usermod -aG wireshark $USER` and log back in.

## What is here

| File | |
|---|---|
| [netwatch.py](netwatch.py) | The command line: every subcommand and all terminal output. |
| [netwatch_core.py](netwatch_core.py) | Analysis — direction, host names, descriptions, live tracking. No terminal or display assumptions. |
| [asn_lookup.py](asn_lookup.py) | Names the organisation behind an address, offline. |
| [updater.py](updater.py) | Checks for a newer version. |

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
resolution is switched off since netwatch does its own, concurrently and under a
deadline.

## Updating

netwatch tells you on startup when a newer version exists, and never installs
anything itself.

| Install | Update |
|---|---|
| git clone (Pi) | `git pull`, then restart |
| `netwatch.exe` | download the new one from Releases |

Check any time with `netwatch update`.

## Releasing

The version lives in [netwatch_version.py](netwatch_version.py). Pushing a tag
does the rest:

```bash
git tag v1.0.1 && git push origin main --tags
```

[The workflow](.github/workflows/release.yml) builds `netwatch.exe`, smoke-tests
it, and publishes a Release. It fails if the tag disagrees with the version in
source, so a mislabelled build cannot ship. Rehearse from the Actions tab with
`dry_run` left on.

## Privacy

Captures contain real addresses and browsing history, so `*.pcap*` is
git-ignored and never committed. ASN lookups are local — no address leaves the
machine, and netwatch works with no network at all.

## Licence

netwatch is [MIT](LICENSE).

The ASN database is not part of this repository and is not redistributed by it;
`netwatch asn --fetch` downloads it from the publisher. DB-IP's licence requires
attribution:

> IP-to-ASN data by [DB-IP](https://db-ip.com) — licensed under
> [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/).

MaxMind's GeoLite2-ASN works instead if you have it, under its own
[licence](https://www.maxmind.com/en/geolite2/eula).
