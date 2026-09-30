"""Email verification tokens.

A token is bound to both ``user_id`` and ``expires``. The signed payload
carries the same pair, and every issued token is recorded in the
``verification_tokens`` collection (one document per user). Reissuing a
token atomically supersedes the previous value with
``find_one_and_replace``; concurrent issuers end up with exactly one
winner because ``user_id`` is unique-indexed.
"""

import hashlib
import os
import hmac
from datetime import datetime, timedelta, timezone

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

DEFAULT_EXPIRY_SECONDS = 3600

mongo = None


def _serializer(secret_key, salt):
    return URLSafeTimedSerializer(secret_key, salt=salt)


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_indexes():
    if mongo is None:
        return
    mongo.db.verification_tokens.create_index("user_id", unique=True)


def make_signed_token(user_id, expires, nonce, secret_key, salt):
    """Sign ``{user_id, expires, nonce}`` so the token is bound to both."""
    payload = {
        "user_id": user_id,
        "expires": int(expires.timestamp()),
        "nonce": nonce,
    }
    return _serializer(secret_key, salt).dumps(payload)


def issue_token(user_id, secret_key, salt, expires_in=DEFAULT_EXPIRY_SECONDS):
    """Atomically issue (or replace) the user's verification token.

    Concurrent calls can never leave two live tokens: ``user_id`` is
    unique, the upsert owns the single document, and a racer that loses
    the upsert retries with a plain replace, so the last writer is the
    sole winner.
    """
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=expires_in)
    nonce = os.urandom(16).hex()
    token = make_signed_token(user_id, expires, nonce, secret_key, salt)
    doc = {
        "user_id": user_id,
        "token_hash": _hash_token(token),
        "expires": expires,
        "issued_at": now,
    }
    collection = mongo.db.verification_tokens
    try:
        collection.find_one_and_replace(
            {"user_id": user_id}, doc, upsert=True
        )
    except Exception:
        collection.find_one_and_replace({"user_id": user_id}, doc)
    return token


def read_signed_token(token, secret_key, salt, max_age):
    """Validate the signature and the ``expires`` inside the token."""
    try:
        payload = _serializer(secret_key, salt).loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(payload, dict):
        return None
    user_id = payload.get("user_id")
    expires_ts = payload.get("expires")
    nonce = payload.get("nonce")
    if not user_id or not isinstance(expires_ts, (int, float)) or not nonce:
        return None
    expires = datetime.fromtimestamp(expires_ts, tz=timezone.utc)
    if expires < datetime.now(timezone.utc):
        return None
    return user_id, expires


def consume_token(token, secret_key, salt, max_age=DEFAULT_EXPIRY_SECONDS):
    """Return the ``user_id`` only if the token is the current live one.

    The signature, bound to ``user_id`` + ``expires``, is checked first;
    the stored document is then checked by constant-time hash compare
    and its own ``expires`` value, so any superseded token is dead.
    """
    parsed = read_signed_token(token, secret_key, salt, max_age)
    if parsed is None:
        return None
    user_id, _expires = parsed
    stored = mongo.db.verification_tokens.find_one({"user_id": user_id})
    if not stored:
        return None
    stored_expires = stored.get("expires")
    if stored_expires is not None:
        if stored_expires.tzinfo is None:
            stored_expires = stored_expires.replace(tzinfo=timezone.utc)
        if stored_expires < datetime.now(timezone.utc):
            return None
    if not hmac.compare_digest(stored.get("token_hash", ""), _hash_token(token)):
        return None
    return user_id

