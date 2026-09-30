import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from auth import status, timeline, tokens
from auth.guard import SESSION_USER_KEY


def register_user(client, email="bob@example.com", password="Secret123!"):
    response = client.post(
        "/register",
        data={
            "email": email,
            "title": "Mr",
            "first_name": "Bob",
            "last_name": "Jones",
            "pass": password,
        },
        follow_redirects=False,
    )
    return response


def hash_password(app, value):
    return app.bcrypt.generate_password_hash(
        value
    ).decode("utf-8")


# ---------------------------------------------------------------------------
# before_request guard
# ---------------------------------------------------------------------------

def test_protected_route_redirects_anonymous_to_login(client):
    response = client.get("/profile")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    assert "next=/profile" in response.headers["Location"]


def test_session_only_holds_user_id(client, app):
    register_user(client)
    with client.session_transaction() as flask_session:
        assert SESSION_USER_KEY in flask_session
        assert "verified" not in flask_session
        assert list(flask_session.keys()) == [SESSION_USER_KEY]


def test_stale_session_verified_flag_is_never_trusted(client, make_user):
    user = make_user(verified=False)
    with client.session_transaction() as flask_session:
        flask_session[SESSION_USER_KEY] = user["id"]
        flask_session["verified"] = True  # old marker that must be ignored

    response = client.post("/verify")
    assert response.status_code == 200
    assert response.get_data(as_text=True) == "Verification email sent"


def test_dead_session_marker_is_cleared(client):
    with client.session_transaction() as flask_session:
        flask_session[SESSION_USER_KEY] = "does-not-exist"

    response = client.get("/profile")
    assert response.status_code == 302
    with client.session_transaction() as flask_session:
        assert SESSION_USER_KEY not in flask_session


def test_authenticated_get_login_redirects_to_profile(client):
    register_user(client)
    response = client.get("/login")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/profile")


def test_public_pages_render_anonymous(client):
    assert client.get("/").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.get("/register").status_code == 200


# ---------------------------------------------------------------------------
# verified re-check cache (5s TTL, immediate invalidation)
# ---------------------------------------------------------------------------

def test_verified_recheck_cached_for_five_seconds(client, make_user, monkeypatch):
    user = make_user(verified=False)
    with client.session_transaction() as flask_session:
        flask_session[SESSION_USER_KEY] = user["id"]

    calls = {"n": 0}
    real_find_one = status.mongo.db.users.find_one

    def counting_find_one(query, *args, **kwargs):
        projection = kwargs.get("projection")
        if (query == {"id": user["id"]}
                and projection == {"verified": 1}):
            calls["n"] += 1
        return real_find_one(query, *args, **kwargs)

    monkeypatch.setattr(
        status.mongo.db.users, "find_one", counting_find_one
    )

    client.get("/auth/timeline")
    client.get("/auth/timeline")
    assert calls["n"] == 1


def test_verified_cache_expires_after_ttl(app, make_user):
    user = make_user(verified=False)
    status.cache._ttl = 0.05
    try:
        assert status.is_verified(user["id"]) is False
        status.mongo.db.users.update_one(
            {"id": user["id"]}, {"$set": {"verified": True}}
        )
        assert status.is_verified(user["id"]) is False  # still cached
        time.sleep(0.06)
        assert status.is_verified(user["id"]) is True  # fresh Mongo read
    finally:
        status.cache._ttl = status.TTL_SECONDS


def test_resend_invalidates_cache_immediately(client, make_user):
    user = make_user(verified=False)
    with client.session_transaction() as flask_session:
        flask_session[SESSION_USER_KEY] = user["id"]

    assert status.is_verified(user["id"]) is False
    # Resending must invalidate even though the TTL has not elapsed.
    client.post("/verify")
    assert user["id"] not in status.cache._store


# ---------------------------------------------------------------------------
# tokens: user_id + expires binding, atomic resend, single winner
# ---------------------------------------------------------------------------

SECRET = "secret"
SALT = "salt"


def test_token_bound_to_user_id_and_expires(make_user):
    user = make_user()
    token = tokens.issue_token(user["id"], SECRET, SALT)
    assert tokens.consume_token(token, SECRET, SALT) == user["id"]

    parsed = tokens.read_signed_token(token, SECRET, SALT, 3600)
    assert parsed is not None
    token_user_id, expires = parsed
    assert token_user_id == user["id"]
    assert expires > datetime.now(timezone.utc)

    # Tampering or wrong salt kills the token.
    assert tokens.consume_token(token[:-2] + "aa", SECRET, SALT) is None
    assert tokens.consume_token(token, SECRET, "other") is None


def test_resend_atomically_revokes_old_token(client):
    register_user(client)
    with client.session_transaction() as flask_session:
        user_id = flask_session[SESSION_USER_KEY]

    old_token = tokens.issue_token(user_id, SECRET, SALT)
    new_token = tokens.issue_token(user_id, SECRET, SALT)
    assert old_token != new_token
    assert tokens.consume_token(old_token, SECRET, SALT) is None
    assert tokens.consume_token(new_token, SECRET, SALT) == user_id
    assert tokens.mongo.db.verification_tokens.count_documents(
        {"user_id": user_id}
    ) == 1


def test_concurrent_resend_has_single_winner(make_user):
    user = make_user()
    results = []
    lock = threading.Lock()

    def issue():
        token = tokens.issue_token(user["id"], SECRET, SALT)
        with lock:
            results.append(token)

    threads = [threading.Thread(target=issue) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 20
    live = {
        token
        for token in results
        if tokens.consume_token(token, SECRET, SALT) == user["id"]
    }
    assert len(live) == 1
    assert tokens.mongo.db.verification_tokens.count_documents(
        {"user_id": user["id"]}
    ) == 1


def test_expired_token_is_rejected(make_user):
    user = make_user()
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    token = tokens.make_signed_token(user["id"], past, "expired-nonce", SECRET, SALT)
    tokens.mongo.db.verification_tokens.insert_one(
        {
            "user_id": user["id"],
            "token_hash": tokens._hash_token(token),
            "expires": past,
        }
    )
    assert tokens.consume_token(token, SECRET, SALT) is None


# ---------------------------------------------------------------------------
# legacy plaintext password migration at successful login
# ---------------------------------------------------------------------------

def test_plaintext_password_migrated_on_login(client, app, make_user):
    user = make_user(plaintext="legacy-pass-123")
    response = client.post(
        "/login", data={"email": user["email"], "pass": "legacy-pass-123"}
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/profile")

    stored = client.application
    updated = tokens.mongo.db.users.find_one({"id": user["id"]})
    assert updated["password"] != "legacy-pass-123"
    assert updated["password"].startswith("$2")
    assert app.bcrypt.check_password_hash(
        updated["password"], "legacy-pass-123"
    )

    events = timeline.events_for_user(user["id"])
    assert events[0]["event"] == timeline.EVENT_LOGIN
    assert any(
        event["event"] == timeline.EVENT_PASSWORD_MIGRATED
        for event in events
    )


def test_repeated_login_after_migration_is_unchanged(client, make_user):
    user = make_user(plaintext="legacy-pass-123")

    first = client.post(
        "/login", data={"email": user["email"], "pass": "legacy-pass-123"}
    )
    assert first.status_code == 302
    stored_after_first = tokens.mongo.db.users.find_one({"id": user["id"]})[
        "password"
    ]

    client.get("/logout")
    second = client.post(
        "/login", data={"email": user["email"], "pass": "legacy-pass-123"}
    )
    assert second.status_code == 302
    stored_after_second = tokens.mongo.db.users.find_one({"id": user["id"]})[
        "password"
    ]
    assert stored_after_first == stored_after_second


def test_wrong_password_rejected(client, make_user):
    user = make_user(plaintext="legacy-pass-123")
    response = client.post(
        "/login", data={"email": user["email"], "pass": "wrong"}
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login?error=1")
    assert tokens.mongo.db.users.find_one({"id": user["id"]})[
        "password"
    ] == "legacy-pass-123"


def test_hashed_password_login_still_works(client, app, make_user):
    user = make_user(password_hash=hash_password(app, "GoodPass1!"))
    response = client.post(
        "/login", data={"email": user["email"], "pass": "GoodPass1!"}
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/profile")


def test_login_response_structure_unchanged(client, make_user):
    user = make_user(plaintext="legacy-pass-123")

    failure = client.post(
        "/login", data={"email": user["email"], "pass": "nope"}
    )
    assert failure.status_code == 302
    assert failure.headers["Location"].endswith("/login?error=1")

    success = client.post(
        "/login", data={"email": user["email"], "pass": "legacy-pass-123"}
    )
    assert success.status_code == 302
    assert success.headers["Location"].endswith("/profile")


# ---------------------------------------------------------------------------
# confirm email flow
# ---------------------------------------------------------------------------

def test_confirm_email_marks_verified_and_invalidates_cache(client):
    register_user(client)
    with client.session_transaction() as flask_session:
        user_id = flask_session[SESSION_USER_KEY]
    confirm_url = client.application.config["CAPTURED_EMAIL_URLS"][-1]

    assert status.is_verified(user_id) is False
    response = client.get(confirm_url)
    assert response.status_code == 200
    assert b"verified successfully" in response.data

    assert status.is_verified(user_id) is True
    assert tokens.mongo.db.users.find_one({"id": user_id})["verified"] is True


def test_old_confirm_link_fails_after_resend(client):
    register_user(client)
    with client.session_transaction() as flask_session:
        user_id = flask_session[SESSION_USER_KEY]
    old_url = client.application.config["CAPTURED_EMAIL_URLS"][-1]

    client.post("/verify")
    new_url = client.application.config["CAPTURED_EMAIL_URLS"][-1]
    assert old_url != new_url

    old_response = client.get(old_url)
    assert old_response.status_code == 200
    assert b"could not be verified" in old_response.data

    new_response = client.get(new_url)
    assert new_response.status_code == 200
    assert b"verified successfully" in new_response.data


# ---------------------------------------------------------------------------
# GET /auth/timeline, newest first
# ---------------------------------------------------------------------------

def test_timeline_requires_login(client):
    response = client.get("/auth/timeline")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_timeline_is_reverse_chronological(client):
    register_user(client)
    with client.session_transaction() as flask_session:
        user_id = flask_session[SESSION_USER_KEY]
    confirm_url = client.application.config["CAPTURED_EMAIL_URLS"][-1]
    client.get(confirm_url)
    client.post("/login", data={"email": "bob@example.com",
                                "pass": "Secret123!"})

    response = client.get("/auth/timeline")
    assert response.status_code == 200
    assert b"Authentication timeline" in response.data

    page = response.get_data(as_text=True)
    ordered = [
        timeline.EVENT_REGISTERED,
        timeline.EVENT_VERIFICATION_SENT,
        timeline.EVENT_VERIFIED,
        timeline.EVENT_LOGIN,
    ]
    positions = [page.index(timeline.EVENT_LABELS[name]) for name in ordered]
    assert positions == sorted(positions, reverse=True)

    rows = timeline.events_for_user(user_id)
    seqs = [row["seq"] for row in rows]
    assert seqs == sorted(seqs, reverse=True)
    assert rows[0]["event"] == timeline.EVENT_LOGIN





