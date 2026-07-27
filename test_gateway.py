#!/usr/bin/env python3
"""Tests for gateway blocking.

Same approach as test_blocking.py: the system call is mocked out, so the
decision-making is exercised without nft, root, or a Pi. What these cannot
prove is that nftables behaves as expected on a real gateway -- run
`crowsnest block <host> --gateway --dry-run` there first, then check that a
blocked host actually stops loading on the phone.

    python -m unittest test_gateway -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import blocking
import gateway


class FakeRunner:
    """Stands in for subprocess.run, recording calls and replaying output.

    Extends test_blocking.py's version with per-command responses, because a
    gateway listing reads two sets in one operation and they must not return
    the same thing.
    """

    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "",
                 responses: list[tuple[str, str]] | None = None):
        self.calls: list[list[str]] = []
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.responses = responses or []

    def __call__(self, cmd, capture_output=True, text=True):
        self.calls.append(list(cmd))
        out = self.stdout
        for needle, text_out in self.responses:
            if needle in cmd:
                out = text_out
                break
        return subprocess.CompletedProcess(cmd, self.returncode, out, self.stderr)

    @property
    def nft_args(self) -> list[list[str]]:
        return [call[1:] for call in self.calls]

    def ran(self, *fragments: str) -> bool:
        """True if some call contains all of these arguments."""
        return any(all(f in call for f in fragments) for call in self.calls)


SET_OUTPUT_V4 = """\
table inet crowsnest {
\tset blocked4 {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { 203.0.113.5, 198.51.100.9 }
\t}
}
"""

# nft wraps a long element list across lines. This is the shape that made a
# line-by-line parser report only the first few.
SET_OUTPUT_WRAPPED = """\
table inet crowsnest {
\tset blocked4 {
\t\ttype ipv4_addr
\t\telements = { 203.0.113.5, 198.51.100.9,
\t\t\t     192.0.2.7, 192.0.2.8,
\t\t\t     192.0.2.9 }
\t}
}
"""

SET_OUTPUT_V6 = """\
table inet crowsnest {
\tset blocked6 {
\t\ttype ipv6_addr
\t\telements = { 2001:db8::1 }
\t}
}
"""

EMPTY_SET_OUTPUT = """\
table inet crowsnest {
\tset blocked4 {
\t\ttype ipv4_addr
\t}
}
"""


def patched_nft():
    return mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft")


class TestParseSet(unittest.TestCase):
    def test_reads_elements(self):
        self.assertEqual(gateway.parse_set(SET_OUTPUT_V4),
                         ["203.0.113.5", "198.51.100.9"])

    def test_reads_elements_wrapped_across_lines(self):
        self.assertEqual(
            gateway.parse_set(SET_OUTPUT_WRAPPED),
            ["203.0.113.5", "198.51.100.9", "192.0.2.7", "192.0.2.8", "192.0.2.9"])

    def test_ipv6_elements(self):
        self.assertEqual(gateway.parse_set(SET_OUTPUT_V6), ["2001:db8::1"])

    def test_empty_set(self):
        self.assertEqual(gateway.parse_set(EMPTY_SET_OUTPUT), [])

    def test_no_set_at_all(self):
        self.assertEqual(gateway.parse_set(""), [])

    def test_junk_elements_are_skipped(self):
        text = "elements = { 203.0.113.5, not-an-address, 198.51.100.9 }"
        self.assertEqual(gateway.parse_set(text), ["203.0.113.5", "198.51.100.9"])


class TestGuardrails(unittest.TestCase):
    def test_apple_push_is_refused(self):
        # The one that matters most on a phone: blocking push stops every
        # notification on the device, and nothing about the symptom points here.
        reason = gateway.risky_hostname("1-courier.push.apple.com")
        self.assertIn("notification", reason)

    def test_activation_and_time_are_refused(self):
        self.assertTrue(gateway.risky_hostname("albert.apple.com"))
        self.assertTrue(gateway.risky_hostname("time.apple.com"))

    def test_ordinary_hostname_is_allowed(self):
        self.assertEqual(gateway.risky_hostname("graph.facebook.com"), "")
        self.assertEqual(gateway.risky_hostname("app-measurement.com"), "")

    def test_risky_check_is_case_insensitive(self):
        self.assertTrue(gateway.risky_hostname("PUSH.APPLE.COM"))

    def test_client_tunnel_address_is_protected(self):
        # Easy mistake: the phone appears in crowsnest's own output, so it is
        # right there to be blocked, and blocking it cuts the phone off entirely.
        problems = gateway.check_targets(
            ["10.6.0.2", "203.0.113.5"], client_ips=["10.6.0.2"], protected={})
        self.assertIn("10.6.0.2", problems)
        self.assertIn("cuts that device off", problems["10.6.0.2"])
        self.assertNotIn("203.0.113.5", problems)

    def test_this_box_guardrails_still_apply(self):
        problems = gateway.check_targets(
            ["192.168.1.50"], client_ips=["10.6.0.2"],
            protected={"192.168.1.50": "an address of this machine itself"})
        self.assertIn("192.168.1.50", problems)


class TestCommands(unittest.TestCase):
    def test_describe_produces_valid_nft_syntax(self):
        with patched_nft():
            lines = gateway.describe_commands(["203.0.113.5", "2001:db8::1"])
        joined = "\n".join(lines)
        self.assertIn("add table inet crowsnest", joined)
        self.assertIn("add chain inet crowsnest forward", joined)
        self.assertIn("hook forward", joined)
        # Both directions, or a blocked host can still reach the phone.
        self.assertIn("ip daddr @blocked4 drop", joined)
        self.assertIn("ip saddr @blocked4 drop", joined)
        self.assertIn("ip6 daddr @blocked6 drop", joined)
        # v4 and v6 addresses go to their own sets, or nft rejects the element.
        self.assertIn("add element inet crowsnest blocked4 { 203.0.113.5 }", joined)
        self.assertIn("add element inet crowsnest blocked6 { 2001:db8::1 }", joined)

    def test_block_sets_up_then_adds_element(self):
        runner = FakeRunner()
        with patched_nft(), mock.patch.object(gateway, "list_blocks",
                                              return_value=[]):
            added = gateway.block(["203.0.113.5"], runner=runner)
        self.assertEqual(added, ["203.0.113.5"])
        self.assertTrue(runner.ran("add", "table", "crowsnest"))
        self.assertTrue(runner.ran("add", "chain", "forward"))
        self.assertTrue(runner.ran("add", "element", "blocked4", "203.0.113.5"))

    def test_block_routes_ipv6_to_the_v6_set(self):
        runner = FakeRunner()
        with patched_nft(), mock.patch.object(gateway, "list_blocks",
                                              return_value=[]):
            gateway.block(["2001:db8::1"], runner=runner)
        self.assertTrue(runner.ran("add", "element", "blocked6", "2001:db8::1"))
        self.assertFalse(runner.ran("add", "element", "blocked4", "2001:db8::1"))

    def test_block_skips_addresses_already_blocked(self):
        runner = FakeRunner()
        with patched_nft(), mock.patch.object(gateway, "list_blocks",
                                              return_value=[{"address": "203.0.113.5"}]):
            added = gateway.block(["203.0.113.5"], runner=runner)
        self.assertEqual(added, [])
        self.assertFalse(runner.ran("add", "element"))

    def test_drop_rules_are_not_duplicated_when_already_present(self):
        """nft appends rules, so re-running setup must not stack them up.

        Every block calls ensure_gateway, so a duplicate here would grow the
        chain by four rules per block.
        """
        already = ("chain forward {\n  type filter hook forward priority -10;\n"
                   "  ip daddr @blocked4 drop\n  ip saddr @blocked4 drop\n}")
        runner = FakeRunner(responses=[("chain", already)])
        with patched_nft(), mock.patch.object(gateway, "list_blocks",
                                              return_value=[]):
            gateway.block(["203.0.113.5"], runner=runner)
        self.assertFalse(runner.ran("add", "rule"))
        self.assertTrue(runner.ran("add", "element", "203.0.113.5"))

    def test_drop_rules_are_created_when_missing(self):
        runner = FakeRunner(responses=[("chain", "chain forward {\n}")])
        with patched_nft(), mock.patch.object(gateway, "list_blocks",
                                              return_value=[]):
            gateway.block(["203.0.113.5"], runner=runner)
        self.assertTrue(runner.ran("add", "rule", "daddr", "@blocked4"))
        self.assertTrue(runner.ran("add", "rule", "saddr", "@blocked6"))

    def test_unblock_deletes_the_element(self):
        runner = FakeRunner()
        with patched_nft(), mock.patch.object(gateway, "list_blocks",
                                              return_value=[{"address": "203.0.113.5"}]):
            removed = gateway.unblock(["203.0.113.5"], runner=runner)
        self.assertEqual(removed, ["203.0.113.5"])
        self.assertTrue(runner.ran("delete", "element", "blocked4", "203.0.113.5"))

    def test_unblock_ignores_addresses_not_blocked(self):
        runner = FakeRunner()
        with patched_nft(), mock.patch.object(gateway, "list_blocks",
                                              return_value=[]):
            self.assertEqual(gateway.unblock(["203.0.113.5"], runner=runner), [])
        self.assertFalse(runner.ran("delete", "element"))

    def test_unblock_all_flushes_sets_and_keeps_the_table(self):
        """Dropping the table would take the forward chain with it.

        blocking.unblock_all() deletes the whole crowsnest table, which is right
        for the input chain but here would tear down the plumbing and, on a Pi
        also doing NAT in a separate table, leave a confusing half-state.
        """
        runner = FakeRunner()
        with patched_nft(), mock.patch.object(gateway, "list_blocks",
                                              return_value=[{"address": "203.0.113.5"}]):
            count = gateway.unblock_all(runner=runner)
        self.assertEqual(count, 1)
        self.assertTrue(runner.ran("flush", "set", "blocked4"))
        self.assertTrue(runner.ran("flush", "set", "blocked6"))
        self.assertFalse(runner.ran("delete", "table"))

    def test_list_blocks_reads_both_families(self):
        runner = FakeRunner(responses=[("blocked4", SET_OUTPUT_V4),
                                       ("blocked6", SET_OUTPUT_V6)])
        with patched_nft():
            found = gateway.list_blocks(runner=runner)
        # Same shape as blocking.list_blocks(), so the CLI can treat the two
        # interchangeably. No handle: a set element is removed by value.
        self.assertEqual(found, [{"address": "203.0.113.5"},
                                 {"address": "198.51.100.9"},
                                 {"address": "2001:db8::1"}])

    def test_list_blocks_empty_when_nothing_set_up(self):
        runner = FakeRunner(returncode=1, stderr="No such file or directory")
        with patched_nft(), mock.patch("os.geteuid", return_value=0, create=True):
            self.assertEqual(gateway.list_blocks(runner=runner), [])

    def test_dry_run_executes_nothing(self):
        runner = FakeRunner()
        with patched_nft():
            gateway.block(["203.0.113.5"], dry_run=True, runner=runner)
        self.assertEqual(runner.calls, [])


class TestRecords(unittest.TestCase):
    """Gateway blocks record separately from this machine's own.

    Sharing one file would let `blocks --restore` reapply an input-chain block
    into the forward chain, or the reverse -- silently blocking the wrong
    traffic in the wrong direction.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        patcher = mock.patch.object(gateway, "RECORD_PATH",
                                    os.path.join(self.tmp, "gateway-blocks.json"))
        patcher.start()
        self.addCleanup(patcher.stop)
        dir_patcher = mock.patch.object(blocking, "RECORD_DIR", self.tmp)
        dir_patcher.start()
        self.addCleanup(dir_patcher.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_record_path_differs_from_blockings(self):
        self.assertNotEqual(gateway.RECORD_PATH, blocking.RECORD_PATH)

    def test_save_then_load(self):
        gateway.save_record(["203.0.113.5", "198.51.100.9"])
        self.assertEqual(gateway.load_record(), ["203.0.113.5", "198.51.100.9"])

    def test_save_does_not_duplicate(self):
        gateway.save_record(["203.0.113.5"])
        gateway.save_record(["203.0.113.5", "198.51.100.9"])
        self.assertEqual(gateway.load_record(), ["203.0.113.5", "198.51.100.9"])

    def test_forget_one(self):
        gateway.save_record(["203.0.113.5", "198.51.100.9"])
        gateway.forget_record(["203.0.113.5"])
        self.assertEqual(gateway.load_record(), ["198.51.100.9"])

    def test_forget_all(self):
        gateway.save_record(["203.0.113.5"])
        gateway.forget_record(None)
        self.assertEqual(gateway.load_record(), [])

    def test_missing_record_is_empty_not_an_error(self):
        self.assertEqual(gateway.load_record(), [])

    def test_restore_hint_targets_the_gateway_chain(self):
        # A unit that ran the plain restore would rebuild the wrong chain.
        self.assertIn("--gateway", gateway.restore_hint())


class TestInterfaceParity(unittest.TestCase):
    """gateway mirrors blocking's public names on purpose.

    cmd_block and friends pick a module and then call it without caring which,
    so a name present on one and missing from the other becomes an AttributeError
    at the moment someone is trying to block something.
    """

    SHARED = ["TABLE", "block", "unblock", "unblock_all", "list_blocks",
              "check_targets", "describe_commands", "load_record",
              "save_record", "forget_record", "restore_hint", "RECORD_PATH"]

    def test_gateway_exposes_everything_blocking_does(self):
        for name in self.SHARED:
            self.assertTrue(hasattr(blocking, name), f"blocking lacks {name}")
            self.assertTrue(hasattr(gateway, name), f"gateway lacks {name}")

    def test_list_blocks_shapes_match(self):
        """Both return dicts carrying an "address" key."""
        runner = FakeRunner(responses=[("blocked4", SET_OUTPUT_V4),
                                       ("blocked6", "")])
        with patched_nft():
            entries = gateway.list_blocks(runner=runner)
        self.assertTrue(all("address" in e for e in entries))
        parsed = blocking.parse_ruleset(
            "\t\tip saddr 203.0.113.5 drop # handle 4\n")
        self.assertTrue(all("address" in e for e in parsed))


if __name__ == "__main__":
    unittest.main(verbosity=2)
