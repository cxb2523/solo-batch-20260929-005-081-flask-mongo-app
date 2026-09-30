import os
import sys

import mongomock
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import create_app
from auth import status
from user import User


@pytest.fixture
def db():
    client = mongomock.MongoClient()
    yield client["test_flask_mongo_app"]
    status.reset()


@pytest.fixture
def app(db, monkeypatch):
    application = create_app(mongo_client=db.client, testing=True)

    captured = []

    def fake_send_registration_email(user, confirm_url):
        captured.append(confirm_url)

    monkeypatch.setattr(
        "app.send_registration_email", fake_send_registration_email
    )
    application.config["CAPTURED_EMAIL_URLS"] = captured
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_user(db):
    def _make_user(email="alice@example.com", password_hash=None,
              plaintext=None, verified=False, **kwargs):
        user = User(
            kwargs.get("title", "Ms"),
            kwargs.get("first_name", "Alice"),
            kwargs.get("last_name", "Smith"),
            email,
            id=kwargs.get("id", ""),
            verified=verified,
        )
        doc = user.dict()
        if plaintext is not None:
            doc["password"] = plaintext
        else:
            doc["password"] = password_hash or "unused"
        db.users.insert_one(doc)
        return doc

    return _make_user

