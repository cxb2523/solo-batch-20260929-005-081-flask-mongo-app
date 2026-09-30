"""Append-only record of each user's authentication state migrations."""

from datetime import datetime, timezone

from pymongo import ReturnDocument

mongo = None

COLLECTION = "auth_timeline"

EVENT_REGISTERED = "registered"
EVENT_VERIFICATION_SENT = "verification_email_sent"
EVENT_VERIFICATION_RESENT = "verification_email_resent"
EVENT_VERIFIED = "email_verified"
EVENT_LOGIN = "login"
EVENT_LOGIN_FAILED = "login_failed"
EVENT_PASSWORD_MIGRATED = "password_migrated"

EVENT_LABELS = {
    EVENT_REGISTERED: "Registered (unverified)",
    EVENT_VERIFICATION_SENT: "Verification email sent",
    EVENT_VERIFICATION_RESENT: "Verification email resent (old token revoked)",
    EVENT_VERIFIED: "Email verified",
    EVENT_LOGIN: "Login",
    EVENT_LOGIN_FAILED: "Login failed",
    EVENT_PASSWORD_MIGRATED: "Legacy plaintext password replaced with hash",
}


def ensure_indexes():
    if mongo is None:
        return
    mongo.db[COLLECTION].create_index([("user_id", 1), ("seq", -1)])


def record_event(user_id, event, detail=None):
    """Append an event; the monotonically increasing ``seq`` keeps the
    reverse ordering deterministic even for identical timestamps."""
    counter = mongo.db.counters.find_one_and_update(
        {"_id": COLLECTION},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    event_doc = {
        "user_id": user_id,
        "event": event,
        "detail": detail or "",
        "timestamp": datetime.now(timezone.utc),
        "seq": counter["seq"],
    }
    mongo.db[COLLECTION].insert_one(event_doc)
    return event_doc


def events_for_user(user_id, limit=100):
    """Return the user's migrations, newest first."""
    return list(
        mongo.db[COLLECTION]
        .find({"user_id": user_id}, {"_id": 0})
        .sort("seq", -1)
        .limit(limit)
    )

