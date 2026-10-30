"""
Challenge discovery and flag-checking tests. Pure logic: no app, no database,
no network, so they run fast and in isolation.

Flags are per-student now: each one is HMAC(FLAG_SECRET, "<token>:<key>"), so
these tests build the expected flag for a sample token with the same helper
the app uses (make_flag), then check that the challenge accepts it, rejects a
wrong one, and rejects a flag meant for a different challenge or a different
student. That last check is the anti-sharing guarantee at the unit level.
"""

import pytest

from breachbox.challenges.base import Challenge, discover_challenges
from breachbox.flags import make_flag

CHALLENGE_NAMES = [
    "Staff Portal Login Bypass",
    "Staff Feedback Reflected XSS",
    "Support Ticket IDOR",
    "Diagnostics Command Injection",
    "Report Viewer Path Traversal",
    "Chained: Ticket Leak to Staff Console",
]

# A stand-in for one student's personal token.
TOKEN = "testtoken1234567"


def _by_name():
    return {cls.name: cls for cls in discover_challenges()}


def test_discovers_exactly_the_six_live_challenges():
    assert set(_by_name()) == set(CHALLENGE_NAMES)


def test_placeholder_and_reference_modules_are_not_discovered():
    names = set(_by_name())
    # The abstract base's default name must never show up as a real challenge.
    assert "Unnamed Challenge" not in names
    # The underscore-prefixed reference module is skipped by the loader.
    assert all("reference" not in name.lower() for name in names)


@pytest.mark.parametrize("name", CHALLENGE_NAMES)
def test_correct_flag_is_accepted(name):
    cls = _by_name()[name]
    flag = make_flag(TOKEN, cls.key)
    assert cls().check_solution(flag, TOKEN) is True


@pytest.mark.parametrize("name", CHALLENGE_NAMES)
def test_surrounding_whitespace_is_tolerated(name):
    cls = _by_name()[name]
    padded = "  " + make_flag(TOKEN, cls.key) + "\n"
    assert cls().check_solution(padded, TOKEN) is True


@pytest.mark.parametrize("name", CHALLENGE_NAMES)
def test_wrong_or_empty_flag_is_rejected(name):
    challenge = _by_name()[name]()
    assert challenge.check_solution("flag{definitely_not_it}", TOKEN) is False
    assert challenge.check_solution("", TOKEN) is False


@pytest.mark.parametrize("name", CHALLENGE_NAMES)
def test_flag_check_is_case_sensitive(name):
    cls = _by_name()[name]
    flag = make_flag(TOKEN, cls.key)
    assert cls().check_solution(flag.upper(), TOKEN) is False


def test_each_flag_only_solves_its_own_challenge():
    classes = _by_name()
    for name, cls in classes.items():
        for other_name, other_cls in classes.items():
            if other_name == name:
                continue
            other_flag = make_flag(TOKEN, other_cls.key)
            assert cls().check_solution(other_flag, TOKEN) is False, (
                f"{other_name!r} flag wrongly solved {name!r}"
            )


def test_a_flag_from_another_token_is_rejected():
    # Anti-sharing at the unit level: a flag built from a different student's
    # token never validates, even for the right challenge.
    cls = _by_name()["Staff Portal Login Bypass"]
    someone_elses_flag = make_flag("a-different-students-token", cls.key)
    assert cls().check_solution(someone_elses_flag, TOKEN) is False


def test_every_challenge_has_valid_metadata():
    for cls in discover_challenges():
        cls.validate_metadata()  # raises ValueError on bad category/difficulty/key
        assert cls.points > 0
        assert cls.category in Challenge.VALID_CATEGORIES
        assert cls.difficulty in Challenge.VALID_DIFFICULTIES
        assert cls.key  # per-student flags need a stable key
