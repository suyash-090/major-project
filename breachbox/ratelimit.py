"""In-memory attempt limiter for the login form and flag submissions. It's a
fixed window of timestamps per key, kept in memory, which is fine for the
single-process dev server we run this on."""

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
        now = time.time()
        with self._lock:
            self._hits[key].append(now)

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)


# Login: 5 tries per IP+name in 5 min. Flag: 10 wrong guesses per student+challenge in 5 min.
login_limiter = RateLimiter(max_attempts=5, window_seconds=300)
flag_limiter = RateLimiter(max_attempts=10, window_seconds=300)
