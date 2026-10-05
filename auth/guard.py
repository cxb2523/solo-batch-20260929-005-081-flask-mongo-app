"""Centralised auth decisions for registration, e-mail verification and login.

Everything that used to be scattered across the login / register / verify
views lives here and is mounted once via ``app.before_request``.  Views only
take care of presentation.

Invariants enforced here:

* The session carries nothing but the user id.  ``verified`` is re-checked
  against Mongo on every request (through a 5 second TTL cache); stale flags
  stored anywhere else are never trusted.
* Verification tokens bind both ``user_id`` and ``expires``.  Re-issuing a
  token atomically invalidates the previous one via ``find_one_and_update``
  so that concurrent resends have exactly one winner.
* Legacy plaintext passwords are upgraded to bcrypt hashes at the moment of
  a successful login.  The upgrade is idempotent and never locks anyone out.
"""

import time
import uuid
from datetime import datetime, timezone

from flask import g, redirect, request, session, url_for
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pymongo import ReturnDocument

from user import User

VERIFIED_CACHE_TTL = 5.0
TOKEN_TTL_SECONDS = 3600

DEFAULT_PUBLIC_ENDPOINTS = frozenset({
    "index",
    "static",
    "login",
    "register",
    "confirm_email",
})

_MISS = object()


class _TTLCache:
    """Tiny in-process TTL cache keyed by user id."""

    def __init__(self, ttl, clock=time.monotonic):
        self.ttl = ttl
        self.clock = clock
        self._store = {}

    def get(self, key, default=_MISS):
        entry = self._store.get(key)
        if entry is None:
            return default
        stamped_at, value = entry
        if self.clock() - stamped_at > self.ttl:
            self._store.pop(key, None)
            return default
        return value

    def set(self, key, value):
        self._store[key] = (self.clock(), value)

    def invalidate(self, key):
        self._store.pop(key, None)

    def clear(self):
        self._store.clear()


class AuthGuard:
    """Owns every auth decision; mounted with ``app.before_request``."""

    def __init__(self, db, bcrypt, secret_key, salt="",
                 token_ttl=TOKEN_TTL_SECONDS,
                 cache_ttl=VERIFIED_CACHE_TTL,
                 public_endpoints=DEFAULT_PUBLIC_ENDPOINTS):
        # ``db`` may be a database object or a zero-arg provider callable.
        self._db_source = db
        self.bcrypt = bcrypt
        self.secret_key = secret_key
        self.salt = salt
        self.token_ttl = token_ttl
        self.public_endpoints = set(public_endpoints)
        self._verified_cache = _TTLCache(cache_ttl)

    # -- mounting ------------------------------------------------------

    def init_app(self, app):
        app.before_request(self.before_request)
        app.extensions["auth_guard"] = self

    @property
    def db(self):
        source = self._db_source
        return source() if callable(source) else source

    # -- request guard ---------------------------------------------------

    def before_request(self):
        """Resolve the caller's identity fresh on every request."""
        g.user_id = None
        g.verified = False
        user_id = session.get("user_id")
        if user_id is not None:
            verified = self.get_verified(user_id)
            if verified is None:
                # The user no longer exists - drop the stale session.
                session.clear()
            else:
                g.user_id = user_id
                g.verified = verified
        endpoint = request.endpoint
        if endpoint is None or endpoint in self.public_endpoints:
            return None
        if g.user_id is None:
            return redirect(url_for("login", next=request.path))
        return None

    def current_user(self):
        """Memoised per-request User object for the logged-in user."""
        if g.user_id is None:
            return None
        user = getattr(g, "_auth_user", None)
        if user is None:
            doc = self.db.users.find_one({"id": g.user_id}, {"_id": 0})
            if doc is None:
                return None
            user = User(
                doc.get("title", ""),
                doc.get("first_name", ""),
                doc.get("last_name", ""),
                doc.get("email", ""),
                doc.get("id", ""),
                g.verified,
            )
            g._auth_user = user
        return user

    # -- verified re-check (TTL cached) -----------------------------------

    def _fetch_verified(self, user_id):
        doc = self.db.users.find_one({"id": user_id}, {"verified": 1})
        if doc is None:
            return None
        return bool(doc.get("verified", False))

    def get_verified(self, user_id):
        cached = self._verified_cache.get(user_id)
        if cached is not _MISS:
            return cached
        value = self._fetch_verified(user_id)
        self._verified_cache.set(user_id, value)
        return value

    def invalidate_verified(self, user_id):
        self._verified_cache.invalidate(user_id)

    # -- verification tokens ------------------------------------------------

    def _serializer(self):
        return URLSafeTimedSerializer(self.secret_key)

    def generate_verification_token(self, user_id):
        payload = {
            "user_id": user_id,
            "expires": int(time.time()) + int(self.token_ttl),
            "nonce": uuid.uuid4().hex,
        }
        return self._serializer().dumps(payload, salt=self.salt)

    def read_verification_token(self, token):
        """Return the bound user id, or None when invalid/expired."""
        try:
            payload = self._serializer().loads(token, salt=self.salt)
        except BadSignature:
            return None
        if not isinstance(payload, dict):
            return None
        user_id = payload.get("user_id")
        expires = payload.get("expires", 0)
        if not user_id or expires < time.time():
            return None
        return user_id

    def _fetch_token_doc(self, user_id):
        return self.db.users.find_one({"id": user_id}, {"verification_token": 1})

    def issue_verification_token(self, user_id):
        """Atomically replace any previous token for this user.

        The read-modify-write goes through a single ``find_one_and_update``
        filtered on the previously stored token, so when two resends race
        exactly one of them wins; the loser gets ``None``.  A successful
        resend invalidates the user's verified-cache entry immediately.
        """
        current = self._fetch_token_doc(user_id)
        if current is None:
            return None
        old_token = current.get("verification_token")
        new_token = self.generate_verification_token(user_id)
        updated = self.db.users.find_one_and_update(
            {"id": user_id, "verification_token": old_token},
            {"$set": {"verification_token": new_token}},
            return_document=ReturnDocument.AFTER,
        )
        if updated is None:
            # Lost a concurrent race - the other writer's token won.
            return None
        self.invalidate_verified(user_id)
        self.record_event(user_id, "verification_token_issued")
        return new_token

    def confirm_email(self, token):
        """Mark the token's user verified; old tokens are never trusted."""
        user_id = self.read_verification_token(token)
        if user_id is None:
            return None
        confirmed = self.db.users.find_one_and_update(
            {"id": user_id, "verification_token": token},
            {"$set": {"verified": True}, "$unset": {"verification_token": ""}},
            return_document=ReturnDocument.AFTER,
        )
        if confirmed is None:
            return None
        self.invalidate_verified(user_id)
        self.record_event(user_id, "email_verified")
        return user_id

    # -- passwords -----------------------------------------------------------

    @staticmethod
    def _is_bcrypt_hash(stored):
        return isinstance(stored, str) and stored.startswith(("$2a$", "$2b$", "$2y$"))

    def check_password(self, user_doc, plaintext):
        """Verify a password, upgrading legacy plaintext on success.

        Idempotent: once upgraded, the stored hash verifies the same
        plaintext, so repeated logins behave identically and no legacy
        user is ever locked out.
        """
        stored = user_doc.get("password", "")
        if self._is_bcrypt_hash(stored):
            return bool(self.bcrypt.check_password_hash(stored, plaintext))
        if stored != plaintext:
            return False
        new_hash = self.bcrypt.generate_password_hash(plaintext).decode("utf-8")
        self.db.users.update_one(
            {"id": user_doc.get("id"), "password": stored},
            {"$set": {"password": new_hash}},
        )
        self.record_event(user_doc.get("id"), "password_upgraded")
        return True

    # -- registration ----------------------------------------------------------

    def email_taken(self, email):
        return self.db.users.find_one({"email": email}) is not None

    def register_user(self, title, first_name, last_name, email, password):
        """Create a user and issue its first verification token.

        Returns ``(user, token)`` or ``None`` when the e-mail is taken.
        """
        if self.email_taken(email):
            return None
        user = User(title, first_name, last_name, email)
        doc = user.dict()
        doc["password"] = self.bcrypt.generate_password_hash(password).decode("utf-8")
        self.db.users.insert_one(doc)
        self.record_event(user.id, "registered")
        token = self.issue_verification_token(user.id)
        return user, token

    # -- timeline ----------------------------------------------------------------

    def record_event(self, user_id, event, detail=None):
        self.db.auth_events.insert_one({
            "user_id": user_id,
            "event": event,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc),
        })

    def timeline_events(self, user_id, limit=100):
        """State transitions for the user, most recent first."""
        return list(
            self.db.auth_events.find({"user_id": user_id})
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(limit)
        )
