#!/usr/bin/env python3
"""Tests for the blocking logic.

This code writes firewall rules on Linux, and is developed on Windows where nft
does not exist, so everything below exercises the decision-making with the
system call mocked out: which addresses a target expands to, which are refused,
the exact commands produced, and how nft's output is read back.

What these cannot prove is that nftables behaves as expected on a real machine.
That needs a Linux box -- run `crowsnest block <host> --dry-run` there first.

    python -m unittest test_blocking -v
"""

from __future__ import annotations

import io
import subprocess
import unittest
from unittest import mock

import blocking


class FakeRunner:
    """Stands in for subprocess.run, recording calls and replaying output."""

    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = ""):
        self.calls: list[list[str]] = []
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, cmd, capture_output=True, text=True):
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, self.returncode,
                                          self.stdout, self.stderr)

    @property
    def nft_args(self) -> list[list[str]]:
        """Each call with the nft binary path stripped, for easier assertions."""
        return [call[1:] for call in self.calls]


REAL_NFT_OUTPUT = """\
table inet crowsnest { # handle 7
\tchain input { # handle 1
\t\ttype filter hook input priority -10; policy accept;
\t\tip saddr 203.0.113.5 drop # handle 4
\t\tip saddr 198.51.100.9 drop # handle 5
\t\tip6 saddr 2001:db8::1 drop # handle 6
\t}
}
"""


class TestParseRuleset(unittest.TestCase):
    def test_reads_addresses_and_handles(self):
        entries = blocking.parse_ruleset(REAL_NFT_OUTPUT)
        self.assertEqual(
            entries,
            [{"address": "203.0.113.5", "handle": 4},
             {"address": "198.51.100.9", "handle": 5},
             {"address": "2001:db8::1", "handle": 6}])

    def test_ipv6_recognised(self):
        entries = blocking.parse_ruleset(
            "\t\tip6 saddr 2001:db8::dead:beef drop # handle 12\n")
        self.assertEqual(entries[0]["address"], "2001:db8::dead:beef")
        self.assertEqual(entries[0]["handle"], 12)

    def test_ignores_unrelated_rules(self):
        text = ("\t\tip saddr 10.0.0.1 accept # handle 2\n"      # not a drop
                "\t\tip daddr 10.0.0.2 drop # handle 3\n"        # daddr, not saddr
                "\t\tip saddr 10.0.0.3 drop # handle 4\n")       # the only match
        entries = blocking.parse_ruleset(text)
        self.assertEqual([e["address"] for e in entries], ["10.0.0.3"])

    def test_empty_output(self):
        self.assertEqual(blocking.parse_ruleset(""), [])


class TestResolveTarget(unittest.TestCase):
    def test_plain_ipv4_passes_through(self):
        self.assertEqual(blocking.resolve_target("203.0.113.5"), ["203.0.113.5"])

    def test_plain_ipv6_passes_through(self):
        self.assertEqual(blocking.resolve_target("2001:db8::1"), ["2001:db8::1"])

    def test_hostname_expands_to_addresses(self):
        fake = [(2, 1, 6, "", ("203.0.113.5", 0)),
                (2, 1, 6, "", ("203.0.113.6", 0)),
                (2, 1, 6, "", ("203.0.113.5", 0))]     # duplicate is dropped
        with mock.patch("socket.getaddrinfo", return_value=fake):
            self.assertEqual(blocking.resolve_target("example.test"),
                             ["203.0.113.5", "203.0.113.6"])

    def test_unresolvable_hostname_explains(self):
        import socket
        with mock.patch("socket.getaddrinfo",
                        side_effect=socket.gaierror("no such host")):
            with self.assertRaises(blocking.BlockError) as caught:
                blocking.resolve_target("nope.invalid")
        self.assertIn("could not resolve", str(caught.exception))

    def test_empty_target_rejected(self):
        with self.assertRaises(blocking.BlockError):
            blocking.resolve_target("   ")


class TestGuardrails(unittest.TestCase):
    def test_gateway_is_protected(self):
        with mock.patch.object(blocking, "default_gateways",
                               return_value=["192.168.1.1"]), \
             mock.patch.object(blocking, "dns_servers", return_value=[]), \
             mock.patch.object(blocking, "ssh_peer", return_value=None),              mock.patch.object(blocking, "local_addresses", return_value=[]):
            problems = blocking.check_targets(["192.168.1.1", "203.0.113.5"])
        self.assertIn("192.168.1.1", problems)
        self.assertIn("gateway", problems["192.168.1.1"])
        self.assertNotIn("203.0.113.5", problems)

    def test_dns_server_is_protected(self):
        # On a box that serves DNS for a network -- a Pi-hole, say -- blocking
        # the resolver takes name resolution down for everything, not just here.
        with mock.patch.object(blocking, "default_gateways", return_value=[]), \
             mock.patch.object(blocking, "dns_servers",
                               return_value=["192.168.1.50"]), \
             mock.patch.object(blocking, "ssh_peer", return_value=None),              mock.patch.object(blocking, "local_addresses", return_value=[]):
            problems = blocking.check_targets(["192.168.1.50"])
        self.assertIn("192.168.1.50", problems)
        self.assertIn("DNS", problems["192.168.1.50"])

    def test_ssh_peer_is_protected(self):
        with mock.patch.object(blocking, "default_gateways", return_value=[]), \
             mock.patch.object(blocking, "dns_servers", return_value=[]), \
             mock.patch.object(blocking, "ssh_peers", return_value=["10.1.2.3"]), \
             mock.patch.object(blocking, "local_addresses", return_value=[]):
            problems = blocking.check_targets(["10.1.2.3"])
        self.assertIn("locks that session out", problems["10.1.2.3"])

    def test_ssh_peer_found_when_sudo_clears_the_environment(self):
        """The bug that mattered most: sudo wipes SSH_CONNECTION.

        Blocking only ever runs under sudo, because nft needs root, so relying
        on that variable meant the lock-yourself-out guardrail never fired in
        practice. The peer must still be found with the environment empty.
        """
        established = ("  sl  local_address rem_address   st\n"
                       "   0: 3201A8C0:0016 7801A8C0:E1D1 01\n")

        def fake_open(path, *args, **kwargs):
            if path == "/proc/net/tcp":
                return io.StringIO(established)
            raise OSError("not available in this test")

        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch.object(blocking, "_environ_of", return_value={}), \
             mock.patch.object(blocking, "_parent_of", return_value=None), \
             mock.patch("builtins.open", side_effect=fake_open):
            peers = blocking.ssh_peers()
        # 3201A8C0 = 192.168.1.50 port 22; 7801A8C0 = 192.168.1.120
        self.assertEqual(peers, ["192.168.1.120"])

    def test_ssh_peer_found_via_parent_process_environment(self):
        """Under sudo our own environ is bare, but the shell above it is not."""
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch.object(blocking, "_environ_of",
                               return_value={"SSH_CONNECTION":
                                             "192.168.1.120 5 192.168.1.50 22"}), \
             mock.patch.object(blocking, "_parent_of", return_value=None), \
             mock.patch.object(blocking, "_peers_from_established_ssh",
                               return_value=[]):
            self.assertEqual(blocking.ssh_peers(), ["192.168.1.120"])

    def test_proc_net_tcp_address_decoding(self):
        # Stored little-endian per 4-byte word, which is easy to get backwards.
        self.assertEqual(blocking._hex_to_address("3201A8C0"), "192.168.1.50")
        self.assertEqual(blocking._hex_to_address("0100007F"), "127.0.0.1")

    def test_own_address_is_protected(self):
        # Found on a real Pi: the machine's own LAN address was allowed through.
        with mock.patch.object(blocking, "default_gateways", return_value=[]),              mock.patch.object(blocking, "dns_servers", return_value=[]),              mock.patch.object(blocking, "ssh_peer", return_value=None),              mock.patch.object(blocking, "local_addresses",
                               return_value=["192.168.1.50"]):
            problems = blocking.check_targets(["192.168.1.50", "203.0.113.5"])
        self.assertIn("192.168.1.50", problems)
        self.assertIn("this machine itself", problems["192.168.1.50"])
        self.assertNotIn("203.0.113.5", problems)

    def test_local_addresses_parses_ip_output(self):
        # Real `ip -o addr show` output from the Raspberry Pi.
        sample = (
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
            "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n"
            "2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever\n"
        )
        with mock.patch.object(blocking.shutil, "which", return_value="/sbin/ip"), \
             mock.patch("subprocess.run",
                        return_value=subprocess.CompletedProcess([], 0, sample, "")):
            found = blocking.local_addresses()
        self.assertEqual(found, ["127.0.0.1", "192.168.1.50", "fe80::1"])

    def test_loopback_is_protected(self):
        with mock.patch.object(blocking, "protected_addresses", return_value={}):
            problems = blocking.check_targets(["127.0.0.1", "::1"])
        self.assertIn("127.0.0.1", problems)
        self.assertIn("::1", problems)

    def test_ordinary_address_is_allowed(self):
        with mock.patch.object(blocking, "protected_addresses", return_value={}):
            self.assertEqual(blocking.check_targets(["203.0.113.5"]), {})

    def test_ssh_peer_read_from_environment(self):
        with mock.patch.dict("os.environ",
                             {"SSH_CONNECTION": "10.1.2.3 55character 10.0.0.5 22"},
                             clear=False):
            self.assertEqual(blocking.ssh_peer(), "10.1.2.3")


class TestCommands(unittest.TestCase):
    def test_describe_produces_valid_nft_syntax(self):
        with mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft"):
            lines = blocking.describe_commands(["203.0.113.5", "2001:db8::1"])
        self.assertIn("add table inet crowsnest", lines[0])
        self.assertIn("add chain inet crowsnest input", lines[1])
        # v4 uses "ip saddr", v6 must use "ip6 saddr" or nft rejects the rule.
        self.assertIn("ip saddr 203.0.113.5 drop", lines[2])
        self.assertIn("ip6 saddr 2001:db8::1 drop", lines[3])

    def test_block_creates_table_then_rule(self):
        runner = FakeRunner(stdout="")
        with mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft"), \
             mock.patch.object(blocking, "list_blocks", return_value=[]):
            added = blocking.block(["203.0.113.5"], runner=runner)
        self.assertEqual(added, ["203.0.113.5"])
        self.assertEqual(runner.nft_args[0], ["add", "table", "inet", "crowsnest"])
        self.assertIn("chain", runner.nft_args[1])
        self.assertEqual(
            runner.nft_args[2],
            ["add", "rule", "inet", "crowsnest", "input",
             "ip", "saddr", "203.0.113.5", "drop"])

    def test_block_skips_addresses_already_blocked(self):
        runner = FakeRunner()
        with mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft"), \
             mock.patch.object(blocking, "list_blocks",
                               return_value=[{"address": "203.0.113.5",
                                              "handle": 4}]):
            added = blocking.block(["203.0.113.5"], runner=runner)
        self.assertEqual(added, [])
        # only the table/chain setup ran, no duplicate rule
        self.assertEqual(len(runner.nft_args), 2)

    def test_unblock_deletes_by_handle(self):
        runner = FakeRunner()
        with mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft"), \
             mock.patch.object(blocking, "list_blocks",
                               return_value=[{"address": "203.0.113.5", "handle": 4},
                                             {"address": "198.51.100.9", "handle": 5}]):
            removed = blocking.unblock(["198.51.100.9"], runner=runner)
        self.assertEqual(removed, ["198.51.100.9"])
        self.assertEqual(
            runner.nft_args[0],
            ["delete", "rule", "inet", "crowsnest", "input", "handle", "5"])

    def test_unblock_all_drops_only_crowsnest_table(self):
        runner = FakeRunner()
        with mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft"), \
             mock.patch.object(blocking, "list_blocks",
                               return_value=[{"address": "203.0.113.5", "handle": 4}]):
            count = blocking.unblock_all(runner=runner)
        self.assertEqual(count, 1)
        # Deleting our own table cannot disturb anyone else's rules.
        self.assertEqual(runner.nft_args[0],
                         ["delete", "table", "inet", "crowsnest"])

    def test_dry_run_executes_nothing(self):
        runner = FakeRunner()
        with mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft"):
            blocking.block(["203.0.113.5"], dry_run=True, runner=runner)
        self.assertEqual(runner.calls, [])

    def test_failure_surfaces_nft_message(self):
        runner = FakeRunner(returncode=1, stderr="Error: Could not process rule")
        with mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft"), \
             mock.patch("os.geteuid", return_value=0, create=True):
            with self.assertRaises(blocking.BlockError) as caught:
                blocking.run_nft(["add", "table", "inet", "crowsnest"],
                                 runner=runner)
        self.assertIn("Could not process rule", str(caught.exception))

    def test_missing_table_means_nothing_blocked(self):
        runner = FakeRunner(returncode=1, stderr="No such file or directory")
        with mock.patch.object(blocking, "nft_path", return_value="/usr/sbin/nft"), \
             mock.patch("os.geteuid", return_value=0, create=True):
            self.assertEqual(blocking.list_blocks(runner=runner), [])


class TestPortability(unittest.TestCase):
    def test_windows_is_reported_unsupported(self):
        with mock.patch("os.name", "nt"):
            self.assertFalse(blocking.nft_available())
            self.assertIn("Linux", blocking.unsupported_reason())

    def test_nft_found_in_sbin_when_not_on_path(self):
        # Found on a real Pi: nftables was installed, but /usr/sbin is not on a
        # non-root user's PATH on Debian, so which() alone reported it missing
        # and the CLI told the user to install what they already had.
        def exists(path):
            return path == "/usr/sbin/nft"
        with mock.patch("os.name", "posix"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch.object(blocking.shutil, "which", return_value=None), \
             mock.patch("os.path.isfile", side_effect=exists), \
             mock.patch("os.access", return_value=True):
            self.assertEqual(blocking.nft_path(), "/usr/sbin/nft")
            self.assertTrue(blocking.nft_available())

    def test_path_wins_over_sbin_fallback(self):
        with mock.patch.object(blocking.shutil, "which",
                               return_value="/usr/local/bin/nft"):
            self.assertEqual(blocking.nft_path(), "/usr/local/bin/nft")

    def test_missing_nft_explains_how_to_install(self):
        # Pinned to Linux: the apt hint is only right there, and this suite runs
        # on all three platforms in CI.
        with mock.patch("os.name", "posix"), \
             mock.patch("sys.platform", "linux"), \
             mock.patch.object(blocking, "nft_path", return_value=None):
            self.assertFalse(blocking.nft_available())
            self.assertIn("apt install nftables", blocking.unsupported_reason())

    def test_macos_is_reported_unsupported_without_apt_advice(self):
        # macOS filters with pf, so "sudo apt install nftables" is advice that
        # cannot be followed -- it reads as though blocking were one step away.
        with mock.patch("os.name", "posix"), \
             mock.patch("sys.platform", "darwin"):
            self.assertFalse(blocking.nft_available())
            reason = blocking.unsupported_reason()
            self.assertIn("pf", reason)
            self.assertNotIn("apt", reason)

    def test_macos_stays_unsupported_even_if_something_called_nft_exists(self):
        with mock.patch("os.name", "posix"), \
             mock.patch("sys.platform", "darwin"), \
             mock.patch.object(blocking, "nft_path", return_value="/usr/local/bin/nft"):
            self.assertFalse(blocking.nft_available())

    def test_availability_and_reason_never_disagree(self):
        """A caller that can block must get no reason, and vice versa."""
        for name, platform, nft in (("nt", "win32", "nft.exe"),
                                    ("posix", "darwin", None),
                                    ("posix", "darwin", "/usr/local/bin/nft"),
                                    ("posix", "linux", None),
                                    ("posix", "linux", "/usr/sbin/nft")):
            with self.subTest(platform=platform, nft=nft):
                with mock.patch("os.name", name), \
                     mock.patch("sys.platform", platform), \
                     mock.patch.object(blocking, "nft_path", return_value=nft):
                    self.assertEqual(blocking.nft_available(),
                                     blocking.unsupported_reason() == "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
