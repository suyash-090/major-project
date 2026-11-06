"""Server-Side Request Forgery on target_app's /linkcheck route.

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class LinkCheckerSSRF(Challenge):
    name = "Link Checker SSRF"
    key = "ssrf"
    category = "Web"
    difficulty = "Hard"
    points = 200
    description = (
        "The staff link checker makes the server fetch any URL you give it, "
        "with no limits. Point it at the internal-only page at /internal/ops "
        "(which your own browser can't reach) to make the server read the "
        "flag for you."
    )
