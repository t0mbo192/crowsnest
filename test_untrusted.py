#!/usr/bin/env python3
"""Tests for data that arrives from somewhere hostile.

Every hostname crowsnest shows is chosen by whoever sent the packet: the TLS
server name and the HTTP Host header are attacker-controlled strings, a DNS
query name nearly so, and a PTR record is written by whoever runs the reverse
zone for an address that contacted you.

The tool's whole job is to say truthfully who a machine talked to, on a
terminal, so text that can rewrite the terminal or misrepresent itself is a
correctness problem before it is a security one.

    python -m unittest test_untrusted -v
"""

from __future__ import annotations

import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import crowsnest as c
import crowsnest_core as core


def packet(sni: str = "", host: str = "", dns_name: str = "",
           answer: str = "", src: str = "203.0.113.9",
           dst: str = "192.168.1.10") -> str:
    """One packet the way tshark emits it: tab separated, in FIELDS order."""
    fields = [src, dst, "", "",
              "443", "51000", "", "",
              "1", "0",
              "1400",
              dns_name, answer, "",
              sni, host]
    return "\t".join(fields) + "\n"


def seen_as(payload: str, field: str = "sni") -> str:
    """Feed one hostile packet through the live path, return the stored name."""
    tracker = core.LiveTracker({"192.168.1.10"})
    tracker.feed(packet(**{field: payload}))
    rows, _ = tracker.snapshot(1.0)
    return rows[0]["site"] if rows else ""


class TestCleanName(unittest.TestCase):
    def test_escape_sequences_are_removed(self):
        self.assertNotIn("\x1b", core.clean_name("evil.com\x1b]0;retitled\x07"))

    def test_carriage_return_cannot_hide_the_real_name(self):
        """`evil.com\\rgithub.com` prints as github.com on a terminal."""
        cleaned = core.clean_name("evil.com\rgithub.com")
        self.assertNotIn("\r", cleaned)
        self.assertIn("evil.com", cleaned)

    def test_bidi_override_is_removed(self):
        """Reorders what is displayed without changing the string."""
        self.assertNotIn("‮", core.clean_name("evil.com‮gnp.xyz"))

    def test_zero_width_characters_are_removed(self):
        self.assertEqual(core.clean_name("git​hub.com"), "github.com")

    def test_length_is_capped(self):
        self.assertEqual(len(core.clean_name("a" * 5000)), core.MAX_NAME)

    def test_ordinary_names_are_untouched(self):
        for name in ("github.com", "r5---sn-4g5e6nsz.googlevideo.com",
                     "browser-intake-datadoghq.com", "_dns.resolver.arpa"):
            self.assertEqual(core.clean_name(name), name)

    def test_international_domains_survive(self):
        """Stripping controls must not mean stripping anything non-ASCII."""
        for name in ("münchen.de", "räksmörgås.se", "日本.jp"):
            self.assertEqual(core.clean_name(name), name)


class TestHostileNamesThroughTheLivePath(unittest.TestCase):
    """The sanitising has to happen where packets enter, not at each printer."""

    PAYLOADS = {
        "window title": "evil.com\x1b]0;pwned\x07",
        "alternate screen": "evil.com\x1b[?1049h",
        "hide cursor": "evil.com\x1b[?25l",
        "screen clear": "evil.com\x1b[2J",
        "carriage return": "evil.com\rgithub.com",
        "newline": "evil.com\nnot-a-real-line",
        "bidi override": "evil.com‮gnp.xyz",
    }

    def test_no_control_characters_are_stored(self):
        for label, payload in self.PAYLOADS.items():
            with self.subTest(payload=label):
                site = seen_as(payload)
                bad = [ch for ch in site
                       if ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f]
                self.assertEqual(bad, [], f"{site!r}")

    def test_http_host_header_is_cleaned_too(self):
        self.assertNotIn("\x1b", seen_as("evil.com\x1b[2J", field="host"))

    def test_dns_query_names_are_cleaned(self):
        tracker = core.LiveTracker({"192.168.1.10"})
        tracker.feed(packet(dns_name="evil.com\x1b[2J", answer="198.51.100.7"))
        self.assertNotIn("\x1b", "".join(tracker.ip_names.values()))

    def test_reverse_dns_is_cleaned(self):
        """A PTR record is written by whoever owns the reverse zone."""
        with mock.patch("socket.gethostbyaddr",
                        return_value=("evil.com\x1b]0;x\x07", [], [])):
            found = core.resolve_many(["198.51.100.7"], budget=2.0)
        self.assertNotIn("\x1b", found.get("198.51.100.7", ""))

    def test_nothing_hostile_reaches_a_rendered_frame(self):
        for label, payload in self.PAYLOADS.items():
            with self.subTest(payload=label):
                tracker = core.LiveTracker({"192.168.1.10"})
                tracker.feed(packet(sni=payload))
                rows, meta = tracker.snapshot(1.0)
                with mock.patch.multiple(c,
                                         term_width=lambda default=100: 100,
                                         term_height=lambda default=30: 30):
                    frame = c.render_dashboard(rows, meta, c.Glyphs(True),
                                               c.Style(True), "eth0", 5.0,
                                               c.View())
                # The frame legitimately contains colour codes; nothing else.
                for line in frame:
                    stripped = c.ANSI_RE.sub("", line)
                    bad = [ch for ch in stripped
                           if ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f]
                    self.assertEqual(bad, [], f"{line!r}")


class TestCsvIsNotAFormula(unittest.TestCase):
    """A report is opened in a spreadsheet, which runs what looks like a formula."""

    def rows_for(self, site):
        return [{"direction": "out", "site": site, "description": "Website",
                 "ip": "203.0.113.9", "packets": 4, "bytes": 1400}]

    def written(self, site):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "report.csv")
            c.write_csv(path, self.rows_for(site), False)
            return Path(path).read_text(encoding="utf-8")

    def test_formula_lead_is_defused(self):
        for hostile in ("=cmd|'/c calc'!A1", "+1+1", "-1+1", "@SUM(1)"):
            with self.subTest(cell=hostile):
                body = self.written(hostile)
                cell = list(csv.reader(io.StringIO(body)))[1][1]
                self.assertTrue(cell.startswith("'"), cell)
                self.assertIn(hostile, cell)

    def test_ordinary_hostnames_are_not_touched(self):
        body = self.written("github.com")
        self.assertEqual(list(csv.reader(io.StringIO(body)))[1][1], "github.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
