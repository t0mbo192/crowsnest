"""ASCII banner for crowsnest."""

import os
import sys

CYAN = "\033[36m"
DIM = "\033[2m"
RESET = "\033[0m"

BANNER = r""" _|_                                     _
|___|   __ _ _ _____ __ ______ _  ___ __| |_
  |    / _| '_/ _ \ V  V (_-< ' \/ -_|_-<  _|
  |    \__|_| \___/\_/\_//__/_||_\___/__/\__|"""

# Columns left of this belong to the mast and nest, the rest to the lettering.
# Kept beside the art so a caller can tint the two parts separately.
MARK_COLS = 6

WIDTH = max(len(line) for line in BANNER.split("\n"))


def _use_colour():
    """Colour only for a real terminal that has not opted out."""
    return os.environ.get("NO_COLOR") is None and sys.stdout.isatty()


def banner(tagline=None, colour=None):
    """Return the crowsnest banner, optionally with a dim tagline beneath it."""
    if colour is None:
        colour = _use_colour()
    art = CYAN + BANNER + RESET if colour else BANNER
    if tagline:
        art += "\n  " + (DIM + tagline + RESET if colour else tagline)
    return art


if __name__ == "__main__":
    from crowsnest_version import __version__
    print(banner("v%s  ·  what is my machine talking to?" % __version__))
