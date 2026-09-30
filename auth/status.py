"""Short-lived cache for the per-request ``verified`` recheck.

The session only ever holds the user id; ``verified`` is re-read from
Mongo on every request. To avoid hammering the database within a single
burst of requests, the result is cached for ``TTL_SECONDS``. A
successful resend invalidates the entry immediately instead of waiting
for the TTL to lapse.
"""

import threading
import time

TTL_SECONDS = 5

mongo = None


class VerifiedCache:
    def __init__(self, ttl=TTL_SECONDS):
        self._ttl = ttl
        self._store = {}
        self._lock = threading.Lock()

    def get_verified(self, user_id):
        with self._lock:
            entry = self._store.get(user_id)
            if entry is not None and (time.monotonic() - entry[1]) < self._ttl:
                return entry[0]
        user = mongo.db.users.find_one({"id": user_id}, projection={"verified": 1})
        verified = bool(user and user.get("verified"))
        with self._lock:
            self._store[user_id] = (verified, time.monotonic())
        return verified

    def invalidate(self, user_id):
        with self._lock:
            self._store.pop(user_id, None)

    def clear(self):
        with self._lock:
            self._store.clear()


cache = VerifiedCache()


def is_verified(user_id):
    return cache.get_verified(user_id)


def invalidate(user_id):
    cache.invalidate(user_id)


def reset():
    cache.clear()

