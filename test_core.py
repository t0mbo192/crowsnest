#!/usr/bin/env python3
"""Tests for the analysis core.

Packets are fed in as tshark would emit them -- tab separated fields in the
order of core.FIELDS -- so these exercise the real parsing path without needing
tshark, a capture file, or an interface.

    python -m unittest test_core -v
"""

from __future__ import annotations

import unittest
from unittest import mock

import crowsnest_core as core


class FakeClock:
    """A clock we can wind forward, so a five minute idle window takes no time."""

    def __init__(self, start: float = 1000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def packet(**fields) -> str:
    """One line of tshark field output, named rather than positional."""
    columns = [""] * len(core.FIELDS)
    index = {name: i for i, name in enumerate(core.FIELDS)}
    for name, value in fields.items():
        columns[index[name]] = str(value)
    return "\t".join(columns)


def outbound_syn(sport: int, dst: str = "203.0.113.9") -> str:
    return packet(**{"ip.src": "192.168.1.50", "ip.dst": dst,
                     "tcp.srcport": sport, "tcp.dstport": 443,
                     "tcp.flags.syn": 1, "frame.len": 80})


class TestFlowRetirement(unittest.TestCase):
    """The flow table is the one structure that grew without limit.

    A resolver opens a fresh source port per query, so every query used to add
    an entry that was never released -- about 8 MB an hour on a real box, which
    only mattered if you left it running for days, which is exactly what a
    monitor is for.
    """

    def test_flow_table_plateaus_instead_of_growing(self):
        clock = FakeClock()
        with mock.patch("time.monotonic", clock):
            tracker = core.LiveTracker({"192.168.1.50"})
            port = 0
            # Ten minutes at a hundred new connections a second.
            for _ in range(600):
                clock.advance(1.0)
                for _ in range(100):
                    port += 1
                    tracker.feed(outbound_syn(20000 + port % 40000))
            held = len(tracker.flows)
        # Bounded by the idle window's worth of traffic, not by the whole run.
        self.assertLess(held, 100 * core.FLOW_IDLE * 1.2)
        self.assertGreater(tracker.dropped_flows, 0)

    def test_active_flows_are_kept(self):
        """Retiring must not forget a connection still carrying traffic."""
        clock = FakeClock()
        with mock.patch("time.monotonic", clock):
            tracker = core.LiveTracker({"192.168.1.50"})
            for _ in range(core.FLOW_RETIRE_EVERY * 3):
                clock.advance(0.01)
                tracker.feed(outbound_syn(5555))       # the same connection
            self.assertEqual(len(tracker.flows), 1)
            self.assertEqual(tracker.dropped_flows, 0)

    def test_idle_flow_is_dropped_but_its_host_is_remembered(self):
        """Retiring a flow must not lose the host from the report."""
        clock = FakeClock()
        with mock.patch("time.monotonic", clock):
            tracker = core.LiveTracker({"192.168.1.50"})
            tracker.feed(outbound_syn(6000))
            clock.advance(core.FLOW_IDLE + 60)
            for _ in range(core.FLOW_RETIRE_EVERY):
                tracker.feed(outbound_syn(7000))
            rows, _ = tracker.snapshot(1.0)
        self.assertGreater(tracker.dropped_flows, 0)
        self.assertEqual([r["ip"] for r in rows], ["203.0.113.9"])


class TestDirection(unittest.TestCase):
    def test_syn_sender_is_the_initiator(self):
        tracker = core.LiveTracker({"192.168.1.50"})
        tracker.feed(outbound_syn(4001))
        rows, meta = tracker.snapshot(1.0)
        self.assertEqual(rows[0]["direction"], "out")
        self.assertEqual(meta["out"], 1)

    def test_inbound_when_the_other_end_sends_the_syn(self):
        tracker = core.LiveTracker({"192.168.1.50"})
        tracker.feed(packet(**{"ip.src": "203.0.113.9", "ip.dst": "192.168.1.50",
                               "tcp.srcport": 44000, "tcp.dstport": 22,
                               "tcp.flags.syn": 1, "frame.len": 80}))
        rows, meta = tracker.snapshot(1.0)
        self.assertEqual(rows[0]["direction"], "in")
        self.assertEqual(meta["in"], 1)

    def test_a_later_syn_ack_does_not_flip_the_direction(self):
        tracker = core.LiveTracker({"192.168.1.50"})
        tracker.feed(outbound_syn(4002))
        # The reply carries SYN and ACK; only a bare SYN names the initiator.
        tracker.feed(packet(**{"ip.src": "203.0.113.9", "ip.dst": "192.168.1.50",
                               "tcp.srcport": 443, "tcp.dstport": 4002,
                               "tcp.flags.syn": 1, "tcp.flags.ack": 1,
                               "frame.len": 80}))
        rows, _ = tracker.snapshot(1.0)
        self.assertEqual([r["direction"] for r in rows], ["out"])


class TestMergeByHost(unittest.TestCase):
    """One host means one row, however many addresses answer for it."""

    def row(self, name, ip, nbytes, direction="out"):
        return {"direction": direction, "site": name or ip, "ip": ip,
                "name": name, "description": "x", "bytes": nbytes,
                "packets": 1, "rate": 0.0, "local": False}

    def test_several_addresses_for_one_name_collapse(self):
        merged = core.merge_by_host([
            self.row("github.com", "140.82.121.4", 100),
            self.row("github.com", "140.82.112.3", 50),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["bytes"], 150)
        self.assertEqual(merged[0]["addresses"], 2)
        # The busiest address represents the group.
        self.assertEqual(merged[0]["ip"], "140.82.121.4")

    def test_unnamed_addresses_stay_separate(self):
        """Two nameless hosts are two hosts, even under one owner."""
        merged = core.merge_by_host([
            self.row("", "203.0.113.1", 10),
            self.row("", "203.0.113.2", 20),
        ])
        self.assertEqual(len(merged), 2)

    def test_directions_never_merge(self):
        merged = core.merge_by_host([
            self.row("host.test", "203.0.113.1", 10, "out"),
            self.row("host.test", "203.0.113.1", 20, "in"),
        ])
        self.assertEqual(len(merged), 2)


class TestDescribe(unittest.TestCase):
    def test_keyword_table_wins_over_the_address_owner(self):
        """What a host is *for* beats who owns its address range."""
        with mock.patch.object(core.asn_lookup, "organisation",
                               return_value="Datadog, Inc."):
            self.assertEqual(
                core.describe("browser-intake-datadoghq.com", False, "34.120.5.11"),
                "Datadog - monitoring / telemetry")

    def test_owner_used_when_no_keyword_matches(self):
        with mock.patch.object(core.asn_lookup, "organisation",
                               return_value="Fastly, Inc."):
            self.assertEqual(core.describe("debian.org", False, "151.101.0.1"),
                             "Fastly, Inc.")

    def test_local_before_lookup(self):
        self.assertEqual(core.describe("", True, "192.168.1.24"),
                         "Local network device")

    def test_falls_back_when_nothing_is_known(self):
        with mock.patch.object(core.asn_lookup, "organisation", return_value=""):
            self.assertEqual(core.describe("", False, "203.0.113.9"),
                             "Unknown host (no name)")


class TestAddressClassification(unittest.TestCase):
    def test_broadcast_and_multicast_are_not_peers(self):
        for address in ("255.255.255.255", "224.0.0.251", "192.168.1.255",
                        "0.0.0.0", "not-an-address"):
            self.assertFalse(core.is_routable_peer(address), address)

    def test_ordinary_addresses_are_peers(self):
        for address in ("203.0.113.9", "192.168.1.24", "2001:db8::1"):
            self.assertTrue(core.is_routable_peer(address), address)

    def test_classification_cache_is_bounded(self):
        """An unbounded memo is a slow leak on a long run."""
        self.assertIsNotNone(core.is_routable_peer.cache_info().maxsize)
        self.assertIsNotNone(core.is_private.cache_info().maxsize)


class TestFindTshark(unittest.TestCase):
    """Wireshark installs off PATH on both desktop platforms."""

    def test_path_is_preferred(self):
        with mock.patch.object(core.shutil, "which", return_value="/opt/homebrew/bin/tshark"):
            self.assertEqual(core.find_tshark(), "/opt/homebrew/bin/tshark")

    def test_macos_app_bundle_is_searched(self):
        # The Homebrew cask installs the app, whose tshark lives inside the
        # bundle and is not on PATH -- so crowsnest claimed it was missing.
        bundled = "/Applications/Wireshark.app/Contents/MacOS/tshark"
        with mock.patch.object(core.shutil, "which", return_value=None), \
             mock.patch("os.path.isfile", side_effect=lambda p: p == bundled):
            self.assertEqual(core.find_tshark(), bundled)

    def test_windows_install_is_still_searched(self):
        installed = r"C:\Program Files\Wireshark\tshark.exe"
        with mock.patch.object(core.shutil, "which", return_value=None), \
             mock.patch("os.path.isfile", side_effect=lambda p: p == installed):
            self.assertEqual(core.find_tshark(), installed)

    def test_absent_everywhere_says_so(self):
        with mock.patch.object(core.shutil, "which", return_value=None), \
             mock.patch("os.path.isfile", return_value=False):
            with self.assertRaises(RuntimeError) as caught:
                core.find_tshark()
        self.assertIn("Wireshark", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
