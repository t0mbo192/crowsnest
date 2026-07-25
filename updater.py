"""Tell the user when a newer crowsnest exists.

Two routes, matching how crowsnest actually gets deployed:

  * **Running from a git clone** (the Raspberry Pi) -- compares the checkout
    against its upstream branch. Updating is `git pull`; the app is pure Python
    so there is no build step.
  * **Running as an installed build** (the Windows .exe) -- reads the latest
    GitHub Release and compares version numbers. Updating means downloading the
    installer and running it.

Nothing is ever downloaded or installed automatically. This module only reports
what it finds; the user decides what to do. Every function is safe to call from
a background thread and returns a "unknown" status rather than raising when
GitHub is unreachable, git is missing, or the repository is private and no token
is available.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "t0mbo192/crowsnest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
API_TIMEOUT = 6

# Hide the console window git would flash on Windows.
_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def parse_version(text: str) -> tuple[int, ...]:
    """'v1.12.3' -> (1, 12, 3). Unparseable input sorts lowest."""
    match = re.search(r"(\d+(?:\.\d+)*)", text or "")
    if not match:
        return (0,)
    return tuple(int(part) for part in match.group(1).split("."))


def is_newer(candidate: str, current: str) -> bool:
    return parse_version(candidate) > parse_version(current)


def find_token() -> str | None:
    """A GitHub token, if one is available.

    Only needed while the repository is private -- the Releases API refuses
    anonymous reads. Checked in order: explicit crowsnest variable, the
    conventional GitHub ones, then the app's own prefs file.
    """
    for name in ("CROWSNEST_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        token = os.environ.get(name)
        if token:
            return token.strip()
    home = os.path.expanduser("~")
    # The second name is the pre-rename location, still read so a token saved
    # under the old name keeps working.
    for name in (".crowsnest.json", ".netwatch.json"):
        try:
            with open(os.path.join(home, name), encoding="utf-8") as f:
                token = json.load(f).get("github_token")
            if token:
                return token.strip()
        except (OSError, ValueError, AttributeError):
            continue
    return None


def app_dir() -> str:
    """Directory the app is running from, whether as source or a frozen exe."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def git_root(start: str | None = None) -> str | None:
    """The git checkout this file lives in, or None if it isn't one."""
    path = start or app_dir()
    while True:
        if os.path.isdir(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def _git(root: str, *args: str, timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(("git", *args), cwd=root, capture_output=True,
                              text=True, timeout=timeout, creationflags=_NO_WINDOW)
        return proc.returncode, (proc.stdout or proc.stderr).strip()
    except (OSError, subprocess.SubprocessError):
        return 1, "git unavailable"


def check_git(root: str) -> dict:
    """Compare a checkout against its upstream. Needs network for the fetch."""
    code, _ = _git(root, "fetch", "--quiet")
    if code != 0:
        return {"status": "unknown", "how": "git",
                "detail": "could not reach the remote"}
    code, out = _git(root, "rev-list", "--count", "HEAD..@{upstream}")
    if code != 0 or not out.isdigit():
        return {"status": "unknown", "how": "git",
                "detail": "no upstream branch configured"}
    behind = int(out)
    if behind == 0:
        return {"status": "current", "how": "git"}
    _, subject = _git(root, "log", "-1", "--format=%s", "@{upstream}")
    return {"status": "update", "how": "git", "behind": behind,
            "detail": subject, "command": "git pull"}


def check_releases(current: str, repo: str = REPO,
                   token: str | None = None) -> dict:
    """Compare the running version against the latest GitHub Release."""
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json",
                 "User-Agent": f"crowsnest/{current}"})
    token = token or find_token()
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
            data = json.load(response)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Private repo without a usable token, or no releases published yet.
            detail = ("no releases published yet, or the repository is private "
                      "and no token was found")
        else:
            detail = f"GitHub returned {e.code}"
        return {"status": "unknown", "how": "release", "detail": detail}
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        return {"status": "unknown", "how": "release", "detail": str(e)}

    latest = (data.get("tag_name") or data.get("name") or "").strip()
    if not latest:
        return {"status": "unknown", "how": "release",
                "detail": "release has no tag"}
    if not is_newer(latest, current):
        return {"status": "current", "how": "release", "version": latest}

    asset_url = ""
    for asset in data.get("assets") or []:
        if (asset.get("name") or "").lower().endswith(".exe"):
            asset_url = asset.get("browser_download_url") or ""
            break
    return {"status": "update", "how": "release",
            "version": latest.lstrip("vV"),
            "url": data.get("html_url") or RELEASES_PAGE,
            "asset": asset_url, "detail": data.get("name") or ""}


def check(current: str | None = None, repo: str = REPO,
         token: str | None = None) -> dict:
    """Check for a newer crowsnest by whichever route fits this install.

    Returns a dict with a "status" of "update", "current" or "unknown", plus
    whatever context that route can offer. Never raises.
    """
    if current is None:
        from crowsnest_version import __version__ as current
    try:
        root = git_root()
        if root:
            result = check_git(root)
            # A checkout with no upstream is still worth comparing to Releases.
            if result["status"] != "unknown":
                return result
        return check_releases(current, repo, token)
    except Exception as e:                      # never break the caller
        return {"status": "unknown", "how": "none", "detail": str(e)}


def summary(result: dict) -> str:
    """One line suitable for a status bar or console."""
    status = result.get("status")
    if status == "current":
        return "crowsnest is up to date."
    if status == "update":
        if result.get("how") == "git":
            n = result.get("behind", 0)
            return (f"Update available: {n} new commit{'' if n == 1 else 's'} "
                    f"— run `git pull`")
        return f"Update available: v{result.get('version')}"
    return f"Update check skipped ({result.get('detail', 'unavailable')})."


if __name__ == "__main__":
    from crowsnest_version import __version__
    outcome = check(__version__)
    print(f"crowsnest {__version__}")
    print(summary(outcome))
    for key in ("how", "detail", "url", "command", "behind"):
        if outcome.get(key):
            print(f"  {key}: {outcome[key]}")
