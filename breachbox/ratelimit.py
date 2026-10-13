"""
Tiny in-memory attempt limiter, used to slow down brute-force style abuse of
the login form and the flag-submission endpoint.

This is intentionally simple: a fixed window of timestamps per key, held in
process memory. It is NOT durable across a restart and NOT shared across
multiple worker processes, which is fine for this teaching app running on a
single Flask dev server. If BreachBox ever moved to a real multi-process
deployment, this would become a Redis counter instead.
"""

import threading
import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, max_attempts, window_seconds):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits = defaultdict(list)
        self._lock = threading.Lock()

    def _prune(self, key, now):
        cutoff = now - self.window_seconds
        self._hits[key] = [t for t in self._hits[key] if t > cutoff]

    def check(self, key):
        """Return (allowed, retry_after_seconds) without recording an attempt."""
        now = time.time()
        with self._lock:
            self._prune(key, now)
            hits = self._hits[key]
            if len(hits) >= self.max_attempts:
                retry_after = int(self.window_seconds - (now - hits[0])) + 1
                return False, max(retry_after, 1)
            return True, 0

    def record(self, key):
        """Count one failed attempt against the key."""
        now = time.time()
        with self._lock:
            self._hits[key].append(now)

    def reset(self, key):
        """Clear a key's history, e.g. after a successful login or solve."""
        with self._lock:
            self._hits.pop(key, None)


# Shared limiters. Login: 5 failed tries per IP+name per 5 minutes. Flag
# submission: 10 wrong guesses per student+challenge per 5 minutes.
login_limiter = RateLimiter(max_attempts=5, window_seconds=300)
flag_limiter = RateLimiter(max_attempts=10, window_seconds=300)
