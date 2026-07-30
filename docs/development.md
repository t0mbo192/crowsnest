# Working on crowsnest

Standard library only, apart from the optional `maxminddb`. No display, no web
server, no daemon. Nothing compiles.

## What is in here

| File | |
|---|---|
| [crowsnest.py](../crowsnest.py) | The command line: every subcommand and all terminal output. |
| [crowsnest_core.py](../crowsnest_core.py) | Analysis — direction, host names, descriptions, live tracking. No terminal or display assumptions. |
| [crowsnest_banner.py](../crowsnest_banner.py) | The mark at the top of the dashboard. |
| [asn_lookup.py](../asn_lookup.py) | Names the organisation behind an address, offline. |
| [blocking.py](../blocking.py) | Writes and removes nftables rules, with guardrails. |
| [gateway.py](../gateway.py) | The same, on the forward chain, for a device routed through this machine. |
| [updater.py](../updater.py) | Checks for a newer version. |
| [install.sh](../install.sh) / [install.ps1](../install.ps1) | Installers, runnable straight from a URL. |
| [packaging/build-deb.sh](../packaging/build-deb.sh) | Builds the Debian package. Takes its file list from `pyproject.toml` so the two cannot drift. |
| [setup-wireguard.sh](setup-wireguard.sh) | Sets a Raspberry Pi up as a WireGuard gateway to watch. |

## Tests

```bash
python -m unittest discover -p "test_*.py"
```

125 tests, no network or capture file needed.

| | |
|---|---|
| `test_core.py` | Direction from the TCP handshake, host merging, flow retirement. |
| `test_blocking.py` / `test_gateway.py` | Which addresses a target expands to, which are refused, the exact `nft` commands produced. |
| `test_dashboard.py` | Replays real frames through a small terminal emulator, because a redraw bug is only visible once the escape sequences have been applied to a screen. |
| `test_untrusted.py` | Hostile hostnames arriving off the wire. |
| `test_cli.py` | What happens when the program is started rather than typed — a double-clicked exe. |

CI runs them on Linux, Windows and macOS, and builds the `.deb` on every push:
installing it on a runner that has no tshark, then purging it and checking
nothing is left behind, because packaging breaks quietly and release time is too
late to find out.

## Names off the wire are not trusted

Every hostname crowsnest shows is chosen by whoever sent the packet — a TLS
server name and an HTTP Host header are arbitrary strings, and a PTR record is
written by whoever runs the reverse zone for an address that contacted you.

So `crowsnest_core.clean_name()` strips control characters, bidirectional
overrides and zero-width characters, and caps the length, at the point packets
enter — not at each place that prints, where one omission puts it all back.

Without it, a host calling itself `evil.com\rgithub.com` prints on a terminal as
`github.com`, and `describe()` agrees with it because the text matches. Escape
sequences in the same place could retitle the window or repaint the screen.

`--csv` output gets the same care: a hostname opening with `=`, `+`, `-` or `@`
is prefixed so a spreadsheet reads it as text rather than a formula to run.

## Performance

Reading a capture streams tshark's output and parses it as it arrives, so
dissection and analysis overlap. On a 67,878-packet, 88 MB capture: **1.67 s**,
about **40,000 packets/s**.

Most of that is tshark. The work on top of it is small: address classification is
memoised, flow keys avoid per-packet allocation, and tshark's own name resolution
is switched off since crowsnest does its own, concurrently and under a deadline.

## Releasing

The version lives in [crowsnest_version.py](../crowsnest_version.py). Pushing a
tag does the rest:

```bash
git tag v1.1.5 && git push origin main --tags
```

CI builds `crowsnest.exe`, the `.deb` and the wheel, smoke-tests the binary, and
publishes a Release. It fails if the tag disagrees with the version in source, so
a mislabelled build cannot ship. Rehearse from the Actions tab with `dry_run`
left on.

The [Homebrew tap](https://github.com/t0mbo192/homebrew-tap) follows along by
itself: it checks for a new release every six hours, rewrites its formula, builds
and runs it, and only then commits. A tag is the last manual step.

**Write the release notes by hand.** GitHub's generated notes are built from pull
requests, and commits go straight to `main` here, so they come out as a bare
compare link:

```bash
gh release edit v1.1.5 --notes-file notes.md
```
