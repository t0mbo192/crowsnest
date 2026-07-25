# netwatch

**Wireshark, simplified.** Point it at a packet capture and it tells you — in
plain English — every site your machine connected to, everything that connected
back to it, and what each of those hosts actually *is*.

Wireshark shows you *everything*; that's the problem. `netwatch` distills a
`.pcapng` down to the blatant facts:

- **Outbound** — sites *you* connected to
- **Inbound** — hosts that connected to *you*
- **A short description** of each host (CDN, telemetry, Google, VPN, streaming,
  local device …)
- **Filtering** by text or direction

![netwatch](docs/screenshot.png)

It reads captures with `tshark` (bundled with Wireshark), works out which machine
is "you" from the traffic, and decides direction from the TCP handshake —
whoever sends the opening SYN started the connection.

> **Encryption note:** modern traffic is HTTPS, so netwatch shows *which hosts*
> were contacted (from DNS and the TLS SNI), never page content or URLs. That's
> the ceiling for any capture-based tool.

## Components

| File | What it is |
|------|-----------|
| `connection_viewer.py` | **The main app** — a desktop GUI with dark and light themes: a sortable, filterable table of inbound/outbound connections, each host tagged with a plain-English description. Builds into a standalone `.exe`. |
| `analyze_capture.py` | CLI: hosts grouped by root domain, allowlist flagging, optional GeoIP, CSV export. Headless-friendly. |
| `pcap_report.py` | Prints a simple two-section (outbound / inbound) text report. |
| `analyze_gui.py` | An earlier, fuller GUI (allowlist, GeoIP, flagged-only). |

## Requirements

- **Wireshark**, which provides `tshark` — <https://www.wireshark.org>.
  On Debian / Raspberry Pi OS: `sudo apt install tshark`
- **Python 3.10+** (only to run from source or rebuild the `.exe`)
- **Tkinter**, for the GUI. It ships with Python on Windows and macOS; on
  Debian / Raspberry Pi OS install it with `sudo apt install python3-tk`.

No third-party Python packages are required — everything runs on the standard
library, which keeps installation on a Raspberry Pi to the two `apt` lines above.

## Usage

Capture traffic in Wireshark (or any tool that saves a `.pcapng`), then:

```bash
# Desktop GUI
python connection_viewer.py                     # opens a window; Open a capture

# CLI report (grouped hosts + endpoints)
python analyze_capture.py capture.pcapng --rdns

# Simple inbound/outbound text report
python pcap_report.py capture.pcapng
```

### Build the standalone app

```bash
pip install pyinstaller
python -m PyInstaller --onefile --windowed --name ConnectionViewer connection_viewer.py
# -> dist/ConnectionViewer.exe  (no Python needed to run; still needs Wireshark for tshark)
```

## Running on a Raspberry Pi

The intended deployment is a Pi acting as a network monitor on an attached
display:

```bash
sudo apt install tshark python3-tk
git clone https://github.com/t0mbo192/netwatch.git
cd netwatch
python3 connection_viewer.py
```

The dark theme is the default, which suits an always-on monitor, and the stat
cards are sized to read from across a room. Your theme choice is remembered in
`~/.netwatch.json`.

On a **headless** Pi, use the command-line tools instead — `analyze_capture.py`
and `pcap_report.py` print to the console and need no display. A headless build
of the direction + descriptions view is a natural next step.

## Privacy

Capture files contain your real IP addresses and browsing, so `*.pcapng` /
`*.pcap` are git-ignored and never committed. Host descriptions come from a small
built-in keyword table — nothing leaves your machine unless you explicitly pass
`--geoip` to `analyze_capture.py`.

## License

[MIT](LICENSE)
