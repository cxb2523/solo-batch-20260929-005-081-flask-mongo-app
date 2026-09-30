"""Centralised request guard.

All permission decisions that used to be scattered across register,
email verification and login live here and are mounted once through
``before_request``. Views only handle presentation and their own
side effects.

The session holds nothing but the user id; ``verified`` is rechecked in
Mongo on every request (through the five-second TTL cache in
``auth.status``), so stale flags left in the session are never trusted.
"""

from flask import (
    Blueprint,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.local import LocalProxy

from user import Anonymous, User
from . import status, timeline

mongo = None

SESSION_USER_KEY = "user_id"

# Endpoints reachable without a session. Everything else requires login.
PUBLIC_ENDPOINTS = {
    "static",
    "index",
    "login",
    "register",
    "confirm_email",
}

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def current_user():
    return getattr(g, "current_user", Anonymous())


current_user = LocalProxy(current_user)


def login_session(user):
    """Store only the user id in the session."""
    session.clear()
    session[SESSION_USER_KEY] = user["id"] if isinstance(user, dict) else user.id


def logout_session():
    session.pop(SESSION_USER_KEY, None)


def _load_user(user_id):
    return mongo.db.users.find_one({"id": user_id}, {"_id": 0})


def _is_login_request():
    return request.endpoint == "login" and request.method == "GET"


def guard_before_request():
    user_id = session.get(SESSION_USER_KEY)
    g.current_user = Anonymous()

    if user_id:
        user_data = _load_user(user_id)
        if user_data:
            # Never trust any flag carried by the session: recheck Mongo.
            user_data["verified"] = status.is_verified(user_id)
            g.current_user = User.make_from_dict(user_data)
        else:
            # User no longer exists: drop the dead session marker.
            session.pop(SESSION_USER_KEY, None)

    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        # Authenticated users hitting the login form go to the profile;
        # the original POST login flow is left untouched.
        if _is_login_request() and g.current_user.is_authenticated:
            return redirect(url_for("profile"))
        return None

    if not g.current_user.is_authenticated:
        return redirect(url_for("login", next=request.path))
    return None



@auth_bp.route("/timeline", methods=["GET"])
def auth_timeline():
    """Reverse-chronological state migrations for the current user."""
    events = timeline.events_for_user(g.current_user.id)
    for event in events:
        event["label"] = timeline.EVENT_LABELS.get(event["event"], event["event"])
    return render_template("auth/timeline.html", events=events)


def init_app(app):
    app.before_request(guard_before_request)
    app.register_blueprint(auth_bp)
    app.context_processor(
        lambda: {"current_user": current_user}
    )

