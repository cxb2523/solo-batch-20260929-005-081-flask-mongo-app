"""Password checking with transparent legacy plaintext migration.

Old user documents may store a plaintext password. The first successful
login against such a document swaps it for a bcrypt hash at that moment.
The migration is idempotent: repeat triggers change nothing afterwards
and nobody is ever locked out (a failed write still lets the login
through).
"""

import hmac
import re

mongo = None
bcrypt = None

_BCRYPT_RE = re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$")


def _is_bcrypt_hash(value):
    return isinstance(value, str) and bool(_BCRYPT_RE.match(value))


def _check_legacy(stored, supplied):
    """Constant-time compare against a legacy plaintext password."""
    if not isinstance(stored, str) or not isinstance(supplied, str):
        return False
    return hmac.compare_digest(stored.encode("utf-8"), supplied.encode("utf-8"))


def verify_password(user, supplied_password):
    """Return True and, if needed, migrate a plaintext password to a hash."""
    stored = user.get("password", "")
    if _is_bcrypt_hash(stored):
        return bcrypt.check_password_hash(stored, supplied_password), False

    if not _check_legacy(stored, supplied_password):
        return False, False

    hashed = bcrypt.generate_password_hash(supplied_password).decode("utf-8")
    try:
        result = mongo.db.users.update_one(
            {"id": user["id"], "password": stored},
            {"$set": {"password": hashed}},
        )
        migrated = bool(result.modified_count or result.matched_count)
    except Exception:
        migrated = False
    return True, migrated
