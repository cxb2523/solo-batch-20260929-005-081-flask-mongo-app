"""Centralised authentication: guard, session, tokens, cache, timeline."""

from . import guard, credentials, tokens, status, timeline
from .guard import (
    current_user,
    login_session,
    logout_session,
    init_app as init_auth,
)


def init_extensions(mongo, bcrypt):
    """Wire the auth package to the app's MongoDB and bcrypt handles."""
    tokens.mongo = mongo
    status.mongo = mongo
    timeline.mongo = mongo
    credentials.mongo = mongo
    credentials.bcrypt = bcrypt
    timeline.ensure_indexes()
    tokens.ensure_indexes()


__all__ = [
    "guard",
    "credentials",
    "tokens",
    "status",
    "timeline",
    "init_auth",
    "init_extensions",
    "current_user",
    "login_session",
    "logout_session",
]
