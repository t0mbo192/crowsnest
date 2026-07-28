"""Single source of truth for the crowsnest version.

Bumping this is what starts a release: commit the change, tag it `v<version>`,
and CI builds and publishes crowsnest.exe. Kept in its own module so
build scripts and the update checker can read it without pulling in the
rest of crowsnest.
"""

__version__ = "1.1.1"
