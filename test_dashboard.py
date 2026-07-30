#!/usr/bin/env python3
"""Tests for what the dashboard actually puts on screen.

The renderer had no tests, and two defects lived in that gap: a frame line wider
than the terminal (which wraps, costing a screen row, which scrolls the frame),
and a redraw that never erased to end of line (so a line replaced by a shorter
one kept the old tail, showing the key hints twice).

Checking the rendered strings is not enough for the second one -- it is only
visible once the escape sequences have been applied to a screen. So the redraw
tests replay Screen.draw's real output through a small terminal emulator and
assert on what a viewer would see.

    python -m unittest test_dashboard -v
"""

from __future__ import annotations

import io
import re
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

import crowsnest as c
import crowsnest_banner as mark

SGR = re.compile(r"\x1b\[[0-9;]*m")


class VT:
    """A screen that wraps and scrolls the way a terminal does.

    Wrapping follows VT behaviour: reaching the right margin does not wrap, the
    next character does. A line of exactly the terminal width is therefore fine,
    and a line one column over costs an extra row -- which is the distinction
    the width tests below depend on.
    """

    def __init__(self, cols: int, rows: int):
        self.w, self.h = cols, rows
        self.buf = [[" "] * cols for _ in range(rows)]
        self.r = self.c = 0

    def _scroll(self) -> None:
        while self.r >= self.h:
            self.buf.pop(0)
            self.buf.append([" "] * self.w)
            self.r -= 1

    def write(self, data: str) -> None:
        i = 0
        while i < len(data):
            if data.startswith("\x1b[H", i):
                self.r = self.c = 0
                i += 3
                continue
            if data.startswith("\x1b[K", i):            # erase to end of line
                for x in range(self.c, self.w):
                    self.buf[self.r][x] = " "
                i += 3
                continue
            if data.startswith("\x1b[0J", i):           # erase below
                for x in range(self.c, self.w):
                    self.buf[self.r][x] = " "
                for y in range(self.r + 1, self.h):
                    self.buf[y] = [" "] * self.w
                i += 4
                continue
            match = SGR.match(data, i)
            if match:
                i = match.end()
                continue
            ch = data[i]
            i += 1
            if ch == "\n":
                self.r += 1
                self.c = 0
                self._scroll()
                continue
            if self.c >= self.w:
                self.r += 1
                self.c = 0
                self._scroll()
            self.buf[self.r][self.c] = ch
            self.c += 1

    def lines(self) -> list[str]:
        return ["".join(row).rstrip() for row in self.buf]


def a_row(i: int) -> dict:
    return {"direction": "out" if i % 2 == 0 else "in",
            "site": f"host{i}.example.net", "description": "Website / service",
            "ip": f"203.0.113.{i}", "name": f"host{i}.example.net",
            "bytes": 2048 * (i + 1), "rate": 700, "packets": 4, "local": False}


def mark_fits(cols, lines):
    """Would the big mark be chosen at this size, encoding aside?"""
    with mock.patch.object(mark, "encodable", return_value=True):
        return c.fits_big_banner(cols, lines, unicode_ok=True)


def sized(cols: int, lines: int):
    """Pin the terminal size for the duration of a `with` block."""
    return mock.patch.multiple(c,
                               term_width=lambda default=100: cols,
                               term_height=lambda default=30: lines)


def a_frame(cols: int, lines: int, n: int, packets: int = 0,
            ips: str = "192.168.1.10", view: c.View | None = None):
    meta = {"packets": packets, "bytes": packets * 700, "my_ips": ips}
    return c.render_dashboard([a_row(i) for i in range(n)], meta,
                              c.Glyphs(True), c.Style(True), "eth0", 90.0,
                              view or c.View())


class TestVisibleTrim(unittest.TestCase):
    def test_short_text_is_untouched(self):
        self.assertEqual(c.visible_trim("hello", 10), "hello")

    def test_cut_to_the_visible_width(self):
        self.assertEqual(c.visible_trim("abcdefgh", 3), "abc")

    def test_colour_codes_do_not_count_towards_the_width(self):
        text = c.Style(True)("abcdefgh", c.Style.DIM)
        trimmed = c.visible_trim(text, 3)
        self.assertEqual(c.visible_len(trimmed), 3)

    def test_colour_is_closed_so_it_cannot_leak(self):
        text = c.Style(True)("abcdefgh", c.Style.DIM)
        self.assertTrue(c.visible_trim(text, 3).endswith("\x1b[0m"))

    def test_nothing_fits_in_no_room(self):
        self.assertEqual(c.visible_trim("abc", 0), "")


class TestFrameFitsTheTerminal(unittest.TestCase):
    """A line wider than the screen wraps, and a wrapped line scrolls the frame."""

    # Longest realistic right-hand facts: the packet count and byte total climb
    # all run, and a second address appears as soon as traffic reveals one.
    LONG_IPS = "192.168.0.50, 2601:249:8f00:1a30:dea6:32ff:fe1c:9b42"

    def test_no_line_is_wider_than_the_terminal(self):
        for cols in range(60, 131, 5):
            for packets in (0, 1_004, 1_204_887):
                for ips in ("192.168.1.10", self.LONG_IPS):
                    with self.subTest(cols=cols, packets=packets):
                        with sized(cols, 30):
                            frame = a_frame(cols, 30, 8, packets, ips)
                        for line in frame:
                            self.assertLessEqual(c.visible_len(line), cols,
                                                 f"{line!r}")

    def test_frame_is_never_taller_than_the_screen(self):
        for cols, lines in ((80, 24), (100, 30), (120, 40), (72, 20)):
            for n in (0, 5, 10, 20, 40):
                with self.subTest(size=f"{cols}x{lines}", hosts=n):
                    with sized(cols, lines):
                        frame = a_frame(cols, lines, n)
                    self.assertLessEqual(len(frame), max(4, lines - 1))

    def test_an_opened_panel_still_fits(self):
        view = c.View()
        view.expanded.add("out")
        with sized(80, 24):
            frame = a_frame(80, 24, 40, view=view)
        self.assertLessEqual(len(frame), 23)

    def test_narrow_terminal_drops_key_hints_rather_than_wrapping(self):
        with sized(40, 24):
            frame = a_frame(40, 24, 4)
        keys = [l for l in frame if "search" in c.ANSI_RE.sub("", l)]
        self.assertTrue(keys)
        self.assertLessEqual(c.visible_len(keys[0]), 40)
        self.assertNotIn("quit", c.ANSI_RE.sub("", keys[0]))


class TestWhichMarkIsDrawn(unittest.TestCase):
    """The big mark is only usable where it genuinely fits, and can be printed.

    It is 80 columns and 10 rows against the plain one's 45 and 4, and it is
    drawn with block characters that do not exist in cp1252. Each of those is a
    separate reason to fall back, and getting any of them wrong is either a
    clipped frame or a UnicodeEncodeError.
    """

    def test_needs_the_columns(self):
        """Room for the mark plus a caption column -- not for the longest fact.

        Demanding the longest fact fit untrimmed made the mark unreachable on a
        machine with WSL and Hyper-V, whose three local addresses want 43
        columns of caption when the dashboard never uses more than 120.
        """
        self.assertFalse(mark_fits(mark.WIDTH + c.MIN_CAPTION + 2, 40))
        self.assertTrue(mark_fits(mark.WIDTH + c.MIN_CAPTION + 3, 40))
        self.assertFalse(mark_fits(100, 40))

    def test_a_long_address_list_does_not_hide_the_mark(self):
        """The case from the field: three local addresses, 120 column terminal."""
        with sized(120, 30), mock.patch.object(mark, "encodable",
                                               return_value=True):
            frame = a_frame(120, 30, 4, packets=48216,
                            ips="172.27.208.1, 192.168.0.120 +1")
        drawn = c.ANSI_RE.sub("", "".join(frame))
        self.assertIn("█", drawn)

    def test_a_trimmed_fact_is_marked_as_trimmed(self):
        """A cut address must not read as a whole one."""
        with sized(120, 30), mock.patch.object(mark, "encodable",
                                               return_value=True):
            frame = a_frame(120, 30, 4, packets=48216,
                            ips="172.27.208.1, 192.168.0.120 +1")
        machine = [c.ANSI_RE.sub("", l) for l in frame if "this machine" in l]
        self.assertTrue(machine)
        self.assertTrue(machine[0].rstrip().endswith("…"), machine[0])

    def test_needs_the_rows(self):
        """Wide but short is the case that clipped the footer off."""
        self.assertFalse(mark_fits(160, 24))
        self.assertTrue(mark_fits(160, mark.HEIGHT + c.ROWS_BESIDES_MARK))

    def test_falls_back_when_the_output_cannot_carry_it(self):
        """A redirected stdout on Windows encodes with the locale code page."""
        with mock.patch.object(mark, "encodable", return_value=False):
            self.assertFalse(c.fits_big_banner(200, 60, True))

    def test_encodable_is_answered_from_the_stream(self):
        """StringIO's encoding attribute is read-only, hence the stand-in."""
        legacy = types.SimpleNamespace(encoding="cp1252")
        self.assertFalse(mark.encodable(mark.BANNER, legacy))
        self.assertTrue(mark.encodable(mark.BANNER_ASCII, legacy))

    def test_an_unknown_encoding_is_not_a_crash(self):
        self.assertFalse(
            mark.encodable(mark.BANNER, types.SimpleNamespace(encoding="nonsense")))

    def test_falls_back_in_ascii_mode(self):
        with mock.patch.object(mark, "encodable", return_value=True):
            self.assertFalse(c.fits_big_banner(200, 60, False))

    def test_the_plain_mark_is_pure_ascii(self):
        """So it cannot be the thing that fails to encode."""
        self.assertTrue(mark.BANNER_ASCII.isascii())

    def test_no_blank_rows_are_carried_into_the_frame(self):
        """A triple-quoted string hands you a blank first and last line."""
        self.assertTrue(mark.BIG_LINES[0].strip())
        self.assertTrue(mark.BIG_LINES[-1].strip())

    def test_the_frame_still_fits_wherever_the_big_mark_is_chosen(self):
        for cols, lines in ((109, 28), (120, 28), (120, 30), (160, 40),
                            (200, 60), (120, 24), (100, 40), (80, 24)):
            with self.subTest(size=f"{cols}x{lines}"):
                with sized(cols, lines), \
                     mock.patch.object(mark, "encodable", return_value=True):
                    frame = a_frame(cols, lines, 12)
                self.assertLessEqual(len(frame), max(4, lines - 1))
                for line in frame:
                    self.assertLessEqual(c.visible_len(line), cols)


class TestRedraw(unittest.TestCase):
    """What is on screen after successive frames, not what was rendered."""

    def replay(self, cols: int, lines: int) -> VT:
        vt = VT(cols, lines)
        screen = c.Screen(True)
        for n in range(0, 16):
            # The trigger from the field: my_ips gains a second address once
            # traffic reveals one, so the header facts lengthen mid-run.
            ips = ("192.168.0.50" if n < 4 else
                   "192.168.0.50, 2601:249:8f00:1a30:dea6:32ff:fe1c:9b42")
            with sized(cols, lines):
                frame = a_frame(cols, lines, n, packets=n * 811, ips=ips)
                out = io.StringIO()
                with redirect_stdout(out):
                    screen.draw(frame)
            vt.write(out.getvalue())
        return vt

    def test_key_hints_appear_once_not_twice(self):
        """The reported bug: the hints showed twice while the frame grew."""
        for cols, lines in ((80, 24), (100, 30), (120, 40), (72, 20)):
            with self.subTest(size=f"{cols}x{lines}"):
                on_screen = [l for l in self.replay(cols, lines).lines()
                             if "q  quit" in l]
                self.assertEqual(len(on_screen), 1, on_screen)

    def test_no_stale_tail_survives_a_shorter_line(self):
        """A short line replacing a long one must erase what it does not cover."""
        for cols, lines in ((80, 24), (100, 30)):
            with self.subTest(size=f"{cols}x{lines}"):
                totals = [l for l in self.replay(cols, lines).lines()
                          if "shown" in l and "total" in l]
                self.assertEqual(len(totals), 1, totals)
                # "15 shown - 1.3 MB total" and nothing after it.
                self.assertTrue(totals[0].rstrip().endswith("total"), totals[0])

    def test_each_line_is_erased_as_it_is_drawn(self):
        with sized(80, 24):
            frame = a_frame(80, 24, 6)
            out = io.StringIO()
            with redirect_stdout(out):
                c.Screen(True).draw(frame)
        written = out.getvalue()
        # One erase per drawn line, plus the clear below the frame.
        self.assertEqual(written.count("\x1b[K"), len(frame))
        self.assertTrue(written.endswith("\x1b[0J"))
        self.assertTrue(written.startswith("\x1b[H"))

    def test_nothing_is_written_when_the_screen_is_off(self):
        with sized(80, 24):
            frame = a_frame(80, 24, 3)
            out = io.StringIO()
            with redirect_stdout(out):
                c.Screen(False).draw(frame)
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
