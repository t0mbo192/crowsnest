"""ASCII banner for crowsnest."""

import os
import sys

CYAN = "\033[36m"
DIM = "\033[2m"
RESET = "\033[0m"



# The plain one. Four lines, 45 columns, nothing above ASCII -- so it survives a
# legacy Windows console and being redirected to a file, and it leaves room for
# the panels underneath. Used whenever the big one below will not fit or will not
# encode.
BANNER_ASCII = r""" _|_                                     _
|___|   __ _ _ _____ __ ______ _  ___ __| |_
  |    / _| '_/ _ \ V  V (_-< ' \/ -_|_-<  _|
  |    \__|_| \___/\_/\_//__/_||_\___/__/\__|"""

# The big one. Needs a wide terminal, a tall one, and an output encoding that can
# carry block-drawing characters -- crowsnest checks all three and uses
# BANNER_ASCII when any of them is missing.
BANNER = r"""
   ██████╗██████╗  ██████╗ ██╗    ██╗███████╗███╗   ██╗███████╗███████╗████████╗
  ██╔════╝██╔══██╗██╔═══██╗██║    ██║██╔════╝████╗  ██║██╔════╝██╔════╝╚══██╔══╝
  ██║     ██████╔╝██║   ██║██║ █╗ ██║███████╗██╔██╗ ██║█████╗  ███████╗   ██║
  ██║     ██╔══██╗██║   ██║██║███╗██║╚════██║██║╚██╗██║██╔══╝  ╚════██║   ██║
  ╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝███████║██║ ╚████║███████╗███████║   ██║
   ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝

               ☠═══════════════════════════════════════☠
                     "KEEP YER EYES ON THE HORIZON"
               ☠═══════════════════════════════════════☠
"""

# Columns left of this belong to the mast and nest of BANNER_ASCII, the rest to
# the lettering. Kept beside the art so a caller can tint the two parts
# separately. The big banner has no mast, so it is tinted as one piece.
MARK_COLS = 6

# Blank first and last lines come free with a triple-quoted string. Left in they
# would each cost a row of the dashboard and shift the captions down beside
# nothing.
BIG_LINES = [line for line in BANNER.strip("\n").split("\n")]
ASCII_LINES = BANNER_ASCII.split("\n")

WIDTH = max(len(line) for line in BIG_LINES)
HEIGHT = len(BIG_LINES)
ASCII_WIDTH = max(len(line) for line in ASCII_LINES)


def encodable(text, stream=None):
    """Whether a stream can actually carry these characters.

    The big banner uses block-drawing characters and a skull, neither of which
    exists in cp1252. On Windows a redirected stdout encodes with the locale code
    page, so printing it there raises UnicodeEncodeError and takes the program
    with it. Cheaper to ask first.
    """
    if stream is None:
        stream = sys.stdout
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


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
