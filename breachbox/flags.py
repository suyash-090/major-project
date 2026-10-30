"""Per-student flag generation.

Every student gets their own flag for each challenge, so a flag one student
captures can never be shared with another. The flag is derived, not stored:

    flag{<key>_<HMAC-SHA256(FLAG_SECRET, "<token>:<key>")[:16]>}

where <token> is the student's personal token and <key> identifies the
challenge. The only thing the two zones share is FLAG_SECRET (a config value,
not a network link or a shared database), so breachbox_app can verify a flag
without ever talking to target_app. target_app has an identical copy of
make_flag(), so both sides always agree on a student's flags.
"""

import hashlib
import hmac
import os

# Same default lives in target_app. In Docker both services are given the same
# FLAG_SECRET via the environment; change it there for a real deployment.
FLAG_SECRET = os.environ.get("FLAG_SECRET", "breachbox-dev-flag-secret-change-me")

# Stable key per challenge. These must match the keys target_app uses when it
# hands out flags, and the `key` on each Challenge subclass.
CHALLENGE_KEYS = {
    "Staff Portal Login Bypass": "sqli",
    "Staff Feedback Reflected XSS": "xss",
    "Support Ticket IDOR": "idor",
    "Diagnostics Command Injection": "cmdi",
    "Report Viewer Path Traversal": "ptraversal",
    "Chained: Ticket Leak to Staff Console": "chained",
}


def make_flag(token: str, key: str, secret: str = None) -> str:
    """The exact flag a given student should capture for a given challenge."""
    secret = secret if secret is not None else FLAG_SECRET
    digest = hmac.new(
        secret.encode(), f"{token}:{key}".encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"flag{{{key}_{digest}}}"
