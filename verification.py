"""Backwards-compatible shim.

Token logic now lives in ``auth.tokens`` and is bound to ``user_id`` and
``expires`` rather than a bare email. These helpers re-export the new
functions for any code still importing the old module paths.
"""

from auth.tokens import (
    DEFAULT_EXPIRY_SECONDS,
    consume_token as confirm_token,
    issue_token as generate_confirmation_token,
)

__all__ = [
    "generate_confirmation_token",
    "confirm_token",
    "DEFAULT_EXPIRY_SECONDS",
]
