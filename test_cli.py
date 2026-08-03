#!/usr/bin/env python3
"""Tests for how the command behaves when it is started, not typed.

Double-clicking crowsnest.exe gives it a console of its own, which Windows
closes the moment the program returns. A command line tool run that way prints
two lines of usage into a window that disappears before anyone can read it, and
looks for all the world like a crash.

    python -m unittest test_cli -v
"""

from __future__ import annotations

import argparse
import ctypes
import io
import sys
import types
import unittest
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from unittest import mock

import crowsnest as c


def run_main(argv, held):
    """Run main() with the console either ours or a shell's. Returns what happened."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(c, "owns_the_console", return_value=held), \
         mock.patch.object(sys, "argv", argv), \
         mock.patch.object(c, "input", create=True, return_value="") as paused:
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = c.main()
            raised = None
        except SystemExit as e:
            code, raised = None, e.code
    return {"code": code, "exit": raised, "paused": paused.called,
            "out": out.getvalue(), "err": err.getvalue()}


@contextmanager
def attached(count, frozen):
    """Pretend Windows reports `count` processes on our console.

    A whole stand-in module goes into sys.modules rather than `mock.patch`ing
    ctypes.windll, and for a specific reason: mock.patch resolves its target by
    importing, and with os.name already patched to "nt" that import takes
    ctypes' Windows branch, which on Linux dies reaching for
    _ctypes.FormatError. This trap has now caught two CI runs. Substituting the
    module means no import happens under the patched name at all, on any
    platform.
    """
    stand_in = types.SimpleNamespace(c_uint=ctypes.c_uint, windll=mock.Mock())
    stand_in.windll.kernel32.GetConsoleProcessList.return_value = count
    with mock.patch("os.name", "nt"), \
         mock.patch.object(sys, "frozen", frozen, create=True), \
         mock.patch.dict(sys.modules, {"ctypes": stand_in}):
        yield


class TestConsoleOwnership(unittest.TestCase):
    def test_never_holds_the_window_off_windows(self):
        """No Explorer, no orphaned console -- and no ctypes call to make."""
        with mock.patch("os.name", "posix"):
            self.assertFalse(c.owns_the_console())

    def test_counts_measured_on_a_real_double_click(self):
        """The frozen build is a bootloader plus a child, so its own console
        holds two processes, not one. Both numbers were measured rather than
        assumed: 2 double-clicked, 4 from a shell.
        """
        cases = [
            (1, False, True,  "source, own console"),
            (2, False, False, "source, started from a shell"),
            (2, True,  True,  "frozen exe, double-clicked"),
            (4, True,  False, "frozen exe, from a shell"),
            (1, True,  True,  "frozen onedir, own console"),
        ]
        for count, frozen, expected, label in cases:
            with self.subTest(case=label):
                with attached(count, frozen):
                    self.assertEqual(c.owns_the_console(), expected)

    def test_a_missing_console_is_not_an_error(self):
        """Frozen with no console attached, asking must fail quietly.

        The import is blocked rather than ctypes.windll being mocked: patching
        os.name to "nt" makes a *fresh* import of ctypes take its Windows
        branch, which on Linux dies reaching for _ctypes.FormatError. That is
        how this test failed on two of the three CI platforms and passed on the
        one it was written on.
        """
        with mock.patch("os.name", "nt"), \
             mock.patch.dict(sys.modules, {"ctypes": None}):
            self.assertFalse(c.owns_the_console())


class TestDoubleClicked(unittest.TestCase):
    def test_shows_the_full_help_rather_than_two_lines_of_usage(self):
        result = run_main(["crowsnest"], held=True)
        self.assertEqual(result["code"], 0)
        for expected in ("interfaces", "read", "live", "command line tool"):
            self.assertIn(expected, result["out"])

    def test_waits_before_closing(self):
        self.assertTrue(run_main(["crowsnest"], held=True)["paused"])

    def test_says_how_to_install_it_properly(self):
        """Someone who double-clicked the exe has not put it on their PATH."""
        self.assertIn("install.ps1", run_main(["crowsnest"], held=True)["out"])

    def test_a_usage_error_also_waits(self):
        """Otherwise the reason it refused is the thing that flashes past."""
        # A real usage error. `crowsnest live` with no -i is no longer one:
        # it asks which interface instead.
        result = run_main(["crowsnest", "live", "--duration", "soon"], held=True)
        self.assertTrue(result["paused"])


FOUND = [
    {"number": 1, "name": "Local Area Connection* 10", "note": "",
     "addresses": [], "in_use": False, "device": r"\Device\NPF_A"},
    {"number": 9, "name": "Ethernet", "note": "",
     "addresses": ["192.168.0.120"], "in_use": True, "device": r"\Device\NPF_B"},
]


def choose(answers, found=FOUND, a_tty=True):
    """Run the interface chooser against scripted answers."""
    out = io.StringIO()
    with mock.patch.object(c.core, "described_interfaces", return_value=found), \
         mock.patch.object(sys.stdin, "isatty", return_value=a_tty), \
         mock.patch.object(c, "input", create=True, side_effect=answers):
        with redirect_stdout(out):
            picked = c.choose_interface("tshark", c.Style(False), c.Glyphs(False))
    return picked, out.getvalue()


class TestChoosingAnInterface(unittest.TestCase):
    """Reading a number off one command and retyping it into another is a step
    where a dead adapter gets picked and the empty result reads as a crash.
    """

    def test_the_list_is_shown_before_asking(self):
        _, shown = choose([""])
        self.assertIn("Ethernet", shown)
        self.assertIn("Local Area Connection* 10", shown)

    def test_enter_takes_the_interface_carrying_traffic(self):
        self.assertEqual(choose([""])[0], "9")

    def test_a_number_is_accepted(self):
        self.assertEqual(choose(["1"])[0], "1")

    def test_a_name_is_accepted(self):
        """tshark takes names too, and the list is where the names come from."""
        self.assertEqual(choose(["Ethernet"])[0], "Ethernet")

    def test_a_number_that_does_not_exist_asks_again(self):
        picked, shown = choose(["42", "9"])
        self.assertEqual(picked, "9")
        self.assertIn("no interface 42", shown)

    def test_giving_up_is_not_a_traceback(self):
        with self.assertRaises(RuntimeError):
            choose([KeyboardInterrupt()])

    def test_no_terminal_means_say_what_to_pass(self):
        """Guessing could quietly watch the wrong interface for hours."""
        with self.assertRaises(RuntimeError) as caught:
            choose([""], a_tty=False)
        self.assertIn("-i 9", str(caught.exception))

    def test_no_default_when_nothing_is_marked(self):
        plain = [dict(FOUND[0])]
        picked, shown = choose(["1"], found=plain)
        self.assertEqual(picked, "1")
        self.assertNotIn("[", shown.split("Number or name")[-1])


class TestHelpSaysHowToStart(unittest.TestCase):
    """`-h` is where someone looks to find out how to run the thing.

    It listed eight subcommands and never used the word "dashboard", so the
    view in the screenshot -- the reason most people install this -- was
    undiscoverable from the help.
    """

    def help_for(self, *argv):
        out = io.StringIO()
        parser = c.build_parser()
        with redirect_stdout(out):
            if argv:
                # Reach the subparser the way argparse stores it.
                actions = [a for a in parser._actions
                           if isinstance(a, argparse.
                                         _SubParsersAction)][0]
                actions.choices[argv[0]].print_help()
            else:
                parser.print_help()
        return out.getvalue()

    def test_top_level_help_shows_how_to_open_the_dashboard(self):
        text = self.help_for()
        self.assertIn("--dashboard", text)
        self.assertIn("crowsnest live --dashboard", text)

    def test_top_level_help_says_how_to_leave_it(self):
        """A full-screen view you cannot get out of is its own problem."""
        self.assertIn("q to leave", self.help_for())

    def test_live_help_leads_with_the_two_views(self):
        text = self.help_for("live")
        self.assertIn("crowsnest live --dashboard", text)
        self.assertIn("full-screen", text)

    def test_live_help_explains_the_interface_question(self):
        self.assertIn("asks which to watch", self.help_for("live"))

    def test_the_subcommand_summary_mentions_the_dashboard(self):
        """The one line beside `live` in the command list is often all that
        gets read."""
        self.assertIn("--dashboard", self.help_for())


class TestStartedFromAShell(unittest.TestCase):
    """The window belongs to the shell, so holding it would be an imposition."""

    def test_no_arguments_still_errors_the_normal_way(self):
        result = run_main(["crowsnest"], held=False)
        self.assertEqual(result["exit"], 2)
        self.assertFalse(result["paused"])

    def test_usage_errors_do_not_wait(self):
        self.assertFalse(
            run_main(["crowsnest", "live", "--duration", "soon"],
                     held=False)["paused"])

    def test_version_does_not_wait(self):
        result = run_main(["crowsnest", "--version"], held=False)
        self.assertEqual(result["exit"], 0)
        self.assertFalse(result["paused"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
