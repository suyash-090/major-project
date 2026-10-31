"""Stored (persistent) XSS on target_app's /noticeboard route.

The flag is per-student and verified by the base class; see breachbox/flags.py.
"""

from breachbox.challenges.base import Challenge


class StoredXssNoticeboard(Challenge):
    name = "Staff Noticeboard Stored XSS"
    key = "sxss"
    category = "Web"
    difficulty = "Medium"
    points = 150
    description = (
        "The staff noticeboard saves each note and then renders it on the "
        "board with no escaping. Post a note containing a script payload: it "
        "is stored once and then runs in the browser of everyone who opens the "
        "board afterwards, not just yours. That persistence is what makes "
        "stored XSS more dangerous than the reflected kind on the feedback page."
    )
