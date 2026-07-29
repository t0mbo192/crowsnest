"""Single source of truth for the crowsnest version.

Bumping this is what starts a release: commit the change, tag it `v<version>`,
and CI builds and publishes crowsnest.exe, the Debian package and the wheel. The
Homebrew tap notices the new release and updates its formula on its own, so the
tag is the last manual step. CI refuses to publish if the tag and this number
disagree, which is the whole reason there is only one of them.

Kept in its own module so build scripts and the update checker can read it
without pulling in the rest of crowsnest.
"""

__version__ = "1.1.4"
