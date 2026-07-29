#!/usr/bin/env python3
"""Tests for how the command behaves when it is started, not typed.

Double-clicking crowsnest.exe gives it a console of its own, which Windows
closes the moment the program returns. A command line tool run that way prints
two lines of usage into a window that disappears before anyone can read it, and
looks for all the world like a crash.

    python -m unittest test_cli -v
"""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
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


class TestConsoleOwnership(unittest.TestCase):
    def test_never_holds_the_window_off_windows(self):
        """No Explorer, no orphaned console -- and no ctypes call to make."""
        with mock.patch("os.name", "posix"):
            self.assertFalse(c.owns_the_console())

    def test_a_missing_console_is_not_an_error(self):
        """Frozen with no console attached, asking must fail quietly."""
        with mock.patch("os.name", "nt"), \
             mock.patch("ctypes.windll", create=True,
                        side_effect=AttributeError("no windll")):
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
        result = run_main(["crowsnest", "live"], held=True)   # -i is required
        self.assertTrue(result["paused"])


class TestStartedFromAShell(unittest.TestCase):
    """The window belongs to the shell, so holding it would be an imposition."""

    def test_no_arguments_still_errors_the_normal_way(self):
        result = run_main(["crowsnest"], held=False)
        self.assertEqual(result["exit"], 2)
        self.assertFalse(result["paused"])

    def test_usage_errors_do_not_wait(self):
        self.assertFalse(run_main(["crowsnest", "live"], held=False)["paused"])

    def test_version_does_not_wait(self):
        result = run_main(["crowsnest", "--version"], held=False)
        self.assertEqual(result["exit"], 0)
        self.assertFalse(result["paused"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
