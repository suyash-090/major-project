"""
Anti-brute-force rate limiting.

Unit tests cover the RateLimiter class directly; integration tests prove the
two shared limiters are actually wired into the login form and the flag
submission endpoint, which is what protects the portal during the dry run.
"""

import time

from breachbox.ratelimit import RateLimiter

SQLI_FLAG = "flag{sql1_st4ff_p0rt4l_byp4ss_2026}"


# ---- RateLimiter unit tests -------------------------------------------------

def test_allows_up_to_max_then_blocks():
    limiter = RateLimiter(max_attempts=3, window_seconds=100)
    for _ in range(3):
        allowed, retry_after = limiter.check("k")
        assert allowed is True
        assert retry_after == 0
        limiter.record("k")
    allowed, retry_after = limiter.check("k")
    assert allowed is False
    assert retry_after >= 1


def test_check_does_not_itself_count_as_an_attempt():
    limiter = RateLimiter(max_attempts=2, window_seconds=100)
    for _ in range(10):
        assert limiter.check("k")[0] is True  # checking never records


def test_reset_clears_a_blocked_key():
    limiter = RateLimiter(max_attempts=1, window_seconds=100)
    limiter.record("k")
    assert limiter.check("k")[0] is False
    limiter.reset("k")
    assert limiter.check("k")[0] is True


def test_keys_are_independent():
    limiter = RateLimiter(max_attempts=1, window_seconds=100)
    limiter.record("a")
    assert limiter.check("a")[0] is False
    assert limiter.check("b")[0] is True  # a different key is unaffected


def test_old_attempts_outside_the_window_are_pruned():
    limiter = RateLimiter(max_attempts=2, window_seconds=100)
    # Two hits that are already older than the window should be dropped.
    limiter._hits["k"] = [time.time() - 200, time.time() - 150]
    assert limiter.check("k")[0] is True


def test_retry_after_is_within_the_window():
    limiter = RateLimiter(max_attempts=1, window_seconds=50)
    limiter.record("k")
    allowed, retry_after = limiter.check("k")
    assert allowed is False
    assert 1 <= retry_after <= 51


# ---- integration: flag submission limiter (10 per window) -------------------

def test_flag_submission_is_rate_limited(client, solver, cid):
    challenge_id = cid()
    wrong = {"challenge_id": challenge_id, "flag": "flag{wrong}", "writeup_text": "x"}
    for _ in range(10):
        assert client.post("/api/submit", data=wrong).status_code == 200
    resp = client.post("/api/submit", data=wrong)
    assert resp.status_code == 429
    assert "too many" in resp.get_json()["error"].lower()


# ---- integration: login limiter (5 per window) ------------------------------

def test_correct_login_reaches_the_dashboard(client, make_student):
    make_student("good", "pw")
    resp = client.post(
        "/auth/login", data={"display_name": "good", "password": "pw"}
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_login_locks_out_after_too_many_wrong_attempts(client, make_student):
    make_student("victim", "correct-pw")
    for _ in range(5):
        resp = client.post(
            "/auth/login", data={"display_name": "victim", "password": "wrong"}
        )
        assert resp.status_code == 302

    # The 6th try, even with the CORRECT password, is blocked: it is sent back
    # to the login page instead of through to the dashboard.
    resp = client.post(
        "/auth/login", data={"display_name": "victim", "password": "correct-pw"}
    )
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]
    assert "/dashboard" not in resp.headers["Location"]
