"""
Challenge discovery and flag-checking tests. These are pure logic: no app,
no database, no network, so they run fast and in isolation.

The plaintext flags below are the real ones. They live in target_app on
purpose (this is a deliberately vulnerable teaching target), so repeating them
here is not a leak, and it lets these tests double as a cross-check that the
scoring side (breachbox) and the vulnerable side (target_app) agree on every
flag: a challenge only "passes" if hashing its real flag matches the hash the
challenge class stores.
"""

import pytest

from breachbox.challenges.base import Challenge, discover_challenges

CORRECT_FLAGS = {
    "Staff Portal Login Bypass": "flag{sql1_st4ff_p0rt4l_byp4ss_2026}",
    "Staff Feedback Reflected XSS": "flag{r3fl3ct3d_xss_st4ff_f33db4ck_2026}",
    "Support Ticket IDOR": "flag{1d0r_t1ck3t_3num3r4t10n_2026}",
    "Diagnostics Command Injection": "flag{cmd1_p1ng_ut1l1ty_1nj3ct10n_2026}",
    "Report Viewer Path Traversal": "flag{p4th_tr4v3rs4l_r3p0rt_v13w3r_2026}",
    "Chained: Ticket Leak to Staff Console": "flag{ch41n3d_1d0r_t0_st4ff_c0ns0l3_2026}",
}

CHALLENGE_NAMES = list(CORRECT_FLAGS)


def _by_name():
    return {cls.name: cls for cls in discover_challenges()}


def test_discovers_exactly_the_six_live_challenges():
    assert set(_by_name()) == set(CORRECT_FLAGS)


def test_placeholder_and_reference_modules_are_not_discovered():
    names = set(_by_name())
    # The abstract base's default name must never show up as a real challenge.
    assert "Unnamed Challenge" not in names
    # The underscore-prefixed reference module is skipped by the loader.
    assert all("reference" not in name.lower() for name in names)


@pytest.mark.parametrize("name", CHALLENGE_NAMES)
def test_correct_flag_is_accepted(name):
    assert _by_name()[name]().check_solution(CORRECT_FLAGS[name]) is True


@pytest.mark.parametrize("name", CHALLENGE_NAMES)
def test_surrounding_whitespace_is_tolerated(name):
    padded = "  " + CORRECT_FLAGS[name] + "\n"
    assert _by_name()[name]().check_solution(padded) is True


@pytest.mark.parametrize("name", CHALLENGE_NAMES)
def test_wrong_or_empty_flag_is_rejected(name):
    challenge = _by_name()[name]()
    assert challenge.check_solution("flag{definitely_not_it}") is False
    assert challenge.check_solution("") is False


@pytest.mark.parametrize("name", CHALLENGE_NAMES)
def test_flag_check_is_case_sensitive(name):
    assert _by_name()[name]().check_solution(CORRECT_FLAGS[name].upper()) is False


def test_each_flag_only_solves_its_own_challenge():
    classes = _by_name()
    for name, challenge_cls in classes.items():
        for other_name, other_flag in CORRECT_FLAGS.items():
            if other_name == name:
                continue
            assert challenge_cls().check_solution(other_flag) is False, (
                f"{other_name!r} flag wrongly solved {name!r}"
            )


def test_every_challenge_has_valid_metadata():
    for cls in discover_challenges():
        cls.validate_metadata()  # raises ValueError on a bad category/difficulty
        assert cls.points > 0
        assert cls.category in Challenge.VALID_CATEGORIES
        assert cls.difficulty in Challenge.VALID_DIFFICULTIES
