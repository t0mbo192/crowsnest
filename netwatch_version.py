"""Single source of truth for the netwatch version.

Bumping this is what starts a release: commit the change, tag it `v<version>`,
and CI builds and publishes the Windows installer. Kept in its own module so
build scripts and the update checker can read it without importing tkinter.
"""

__version__ = "1.0.0"
