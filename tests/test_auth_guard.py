"""Tests for the centralised auth guard (auth/guard.py + auth/routes.py)."""

import threading
import time
from types import SimpleNamespace

import mongomock
import pytest
from flask import Flask, g, jsonify
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer

from auth.guard import AuthGuard
from auth.routes import init_auth_routes

SECRET = "test-secret"
SALT = "test-salt"


@pytest.fixture
def env(tmp_path, monkeypatch):
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "login.html").write_text("login {{ error }}")
    (templates / "register.html").write_text("register {{ error }}")
    (templates / "confirm.html").write_text("confirm {{ success }}")

    app = Flask(__name__, template_folder=str(templates))
    app.secret_key = SECRET
    app.config["TESTING"] = True

    db = mongomock.MongoClient()["auth_guard_test"]
    bcrypt = Bcrypt(app)
    guard = AuthGuard(db, bcrypt=bcrypt, secret_key=SECRET, salt=SALT)
    guard.init_app(app)
    init_auth_routes(app)

    @app.get("/")
    def index():
        return "index"

    @app.get("/profile")
    def profile():
        return "profile"

    @app.get("/protected")
    def protected():
        return "protected"

    @app.get("/whoami")
    def whoami():
        return jsonify(user_id=g.user_id, verified=g.verified)

    sent = []
    monkeypatch.setattr(
        "auth.routes.send_registration_email",
        lambda user, token: sent.append((user, token)),
    )

    return SimpleNamespace(
        app=app, db=db, guard=guard, bcrypt=bcrypt,
        sent=sent, client=app.test_client(),
    )


def register_user(env, email="user@example.com", password="pw"):
    result = env.guard.register_user("Mr", "Test", "User", email, password)
    assert result is not None
    return result


def login(env, email="user@example.com", password="pw"):
    return env.client.post("/login", data={"email": email, "pass": password})


# -- session / per-request re-check -----------------------------------------


def test_session_contains_only_user_id(env):
    env.client.post("/register", data={
        "email": "user@example.com", "title": "Mr",
        "first_name": "Test", "last_name": "User", "pass": "pw",
    })
    with env.client.session_transaction() as sess:
        assert set(sess.keys()) == {"user_id"}


def test_session_verified_flag_is_never_trusted(env):
    user, _ = register_user(env)
    login(env)
    with env.client.session_transaction() as sess:
        sess["verified"] = True  # forged stale flag
    data = env.client.get("/whoami").get_json()
    assert data["user_id"] == user.id
    assert data["verified"] is False


def test_verified_rechecked_from_mongo_each_request(env):
    user, _ = register_user(env)
    login(env)
    assert env.client.get("/whoami").get_json()["verified"] is False
    env.db.users.update_one({"id": user.id}, {"$set": {"verified": True}})
    env.guard._verified_cache.ttl = 0.05  # shorten the 5s TTL for the test
    time.sleep(0.06)
    assert env.client.get("/whoami").get_json()["verified"] is True


def test_stale_session_cleared_when_user_missing(env):
    user, _ = register_user(env)
    login(env)
    env.db.users.delete_one({"id": user.id})
    env.guard.invalidate_verified(user.id)  # simulate TTL passage
    resp = env.client.get("/protected")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
    with env.client.session_transaction() as sess:
        assert "user_id" not in sess


def test_guard_redirects_anonymous_to_login(env):
    resp = env.client.get("/protected")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
    assert "next=" in resp.headers["Location"]


# -- login response structure (unchanged for old clients) ---------------------


def test_login_response_structure_unchanged(env):
    register_user(env)
    # Bad password -> redirect back to /login?error=1
    resp = env.client.post("/login", data={"email": "user@example.com", "pass": "bad"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login?error=1")
    # Unknown email -> same
    resp = env.client.post("/login", data={"email": "ghost@example.com", "pass": "pw"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login?error=1")
    # Success -> redirect to profile
    resp = login(env)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/profile")
    # Unsafe next -> 400
    resp = env.client.post(
        "/login?next=https://evil.example.com/x",
        data={"email": "user@example.com", "pass": "pw"},
    )
    assert resp.status_code == 400


def test_login_get_renders_and_redirects_when_authenticated(env):
    register_user(env)
    resp = env.client.get("/login")
    assert resp.status_code == 200
    login(env)
    resp = env.client.get("/login")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")


# -- legacy plaintext password upgrade ----------------------------------------


def insert_legacy_user(env, user_id="legacy1", email="old@example.com", password="secret"):
    env.db.users.insert_one({
        "id": user_id, "email": email, "password": password,
        "verified": True, "title": "", "first_name": "Old", "last_name": "User",
    })


def test_legacy_plaintext_password_upgraded_on_success(env):
    insert_legacy_user(env)
    doc = env.db.users.find_one({"id": "legacy1"})
    assert env.guard.check_password(doc, "secret") is True
    stored = env.db.users.find_one({"id": "legacy1"})["password"]
    assert stored.startswith("$2")
    assert stored != "secret"
    # Idempotent: repeated triggers keep succeeding, hash stays stable
    doc = env.db.users.find_one({"id": "legacy1"})
    assert env.guard.check_password(doc, "secret") is True
    assert env.db.users.find_one({"id": "legacy1"})["password"] == stored
    # Wrong password still rejected
    assert env.guard.check_password(doc, "wrong") is False


def test_legacy_user_logs_in_through_route_and_is_not_locked_out(env):
    insert_legacy_user(env)
    resp = login(env, email="old@example.com", password="secret")
    assert resp.headers["Location"].endswith("/profile")
    assert env.db.users.find_one({"id": "legacy1"})["password"].startswith("$2")
    # Second login after the upgrade works exactly the same
    env.client.get("/logout")
    resp = login(env, email="old@example.com", password="secret")
    assert resp.headers["Location"].endswith("/profile")
    events = [e["event"] for e in env.guard.timeline_events("legacy1")]
    assert "password_upgraded" in events


# -- verification tokens -------------------------------------------------------


def test_token_binds_user_id_and_expires(env):
    user, token = register_user(env)
    payload = URLSafeTimedSerializer(SECRET).loads(token, salt=SALT)
    assert payload["user_id"] == user.id
    assert payload["expires"] > time.time()


def test_confirm_email_marks_user_verified_and_is_single_use(env):
    user, token = register_user(env)
    assert env.guard.confirm_email(token) == user.id
    assert env.db.users.find_one({"id": user.id})["verified"] is True
    # Same token cannot be used twice
    assert env.guard.confirm_email(token) is None


def test_expired_token_is_rejected(env):
    user, _ = register_user(env)
    expiring = AuthGuard(env.db, bcrypt=env.bcrypt,
                         secret_key=SECRET, salt=SALT, token_ttl=-10)
    token = expiring.issue_verification_token(user.id)
    assert env.guard.confirm_email(token) is None
    assert env.db.users.find_one({"id": user.id})["verified"] is False


def test_resend_invalidates_previous_token(env):
    user, token1 = register_user(env)
    token2 = env.guard.issue_verification_token(user.id)
    assert token2 is not None and token2 != token1
    assert env.guard.confirm_email(token1) is None
    assert env.guard.confirm_email(token2) == user.id


def test_concurrent_resend_has_exactly_one_winner(env):
    user, _ = register_user(env)
    barrier = threading.Barrier(2)

    class RacingGuard(AuthGuard):
        def _fetch_token_doc(self, user_id):
            doc = super()._fetch_token_doc(user_id)
            barrier.wait(timeout=10)  # both threads read before either writes
            return doc

    racer = RacingGuard(env.db, bcrypt=env.bcrypt, secret_key=SECRET, salt=SALT)
    results = []

    def worker():
        results.append(racer.issue_verification_token(user.id))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winners = [token for token in results if token is not None]
    assert len(winners) == 1
    stored = env.db.users.find_one({"id": user.id})["verification_token"]
    assert stored == winners[0]


# -- verified TTL cache ---------------------------------------------------------


def test_verified_cache_ttl_and_immediate_invalidation_on_resend(env):
    user, _ = register_user(env)
    calls = []
    original = env.guard._fetch_verified

    def spy(user_id):
        calls.append(user_id)
        return original(user_id)

    env.guard._fetch_verified = spy

    assert env.guard.get_verified(user.id) is False
    assert env.guard.get_verified(user.id) is False
    assert len(calls) == 1  # second call served from the 5s TTL cache

    # A successful resend invalidates the cache immediately
    assert env.guard.issue_verification_token(user.id) is not None
    env.guard.get_verified(user.id)
    assert len(calls) == 2

    # ...and the entry expires on its own after the TTL
    env.guard._verified_cache.ttl = 0.05
    time.sleep(0.06)
    env.guard.get_verified(user.id)
    assert len(calls) == 3


# -- resend route ----------------------------------------------------------------


def test_verify_route_resends_and_invalidates_old_token(env):
    user, token1 = register_user(env)
    login(env)
    resp = env.client.post("/verify")
    assert resp.get_data(as_text=True) == "Verification email sent"
    token2 = env.sent[-1][1]
    assert token2 != token1
    assert env.guard.confirm_email(token1) is None
    assert env.guard.confirm_email(token2) == user.id


def test_verify_route_when_already_verified(env):
    user, token = register_user(env)
    env.guard.confirm_email(token)
    login(env)
    resp = env.client.post("/verify")
    assert resp.get_data(as_text=True) == "Your email address is already verified"


# -- timeline ---------------------------------------------------------------------


def test_timeline_events_are_most_recent_first(env):
    user, token = register_user(env)
    env.guard.confirm_email(token)
    env.guard.record_event(user.id, "login_success")
    events = env.guard.timeline_events(user.id)
    assert [e["event"] for e in events] == [
        "login_success",
        "email_verified",
        "verification_token_issued",
        "registered",
    ]


def test_timeline_route_shows_transitions_in_reverse_order(env):
    user, _ = register_user(env)
    env.client.post("/register", data={
        "email": "tl@example.com", "title": "Ms",
        "first_name": "Time", "last_name": "Line", "pass": "pw",
    })
    token = env.sent[-1][1]
    env.client.get("/confirm/" + token)
    login(env, email="tl@example.com", password="pw")

    resp = env.client.get("/auth/timeline")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    positions = [html.index(name) for name in (
        "login_success", "email_verified",
        "verification_token_issued", "registered",
    )]
    assert positions == sorted(positions)  # newest first


def test_timeline_route_requires_login(env):
    resp = env.client.get("/auth/timeline")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
