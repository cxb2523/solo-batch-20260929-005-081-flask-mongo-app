"""Auth views - presentation only.  All decisions live in ``auth/guard.py``.

Route surface is unchanged for old clients: ``/login`` keeps its exact
response structure (redirect to profile on success, ``/login?error=1`` on
failure, 400 on an unsafe ``next``).
"""

from urllib.parse import urljoin, urlparse

from flask import (abort, current_app, g, redirect, render_template, request,
                   session, url_for)
from markupsafe import escape

from email_utility import send_registration_email


def guard():
    return current_app.extensions["auth_guard"]


def is_safe_url(target):
    if not target:
        return True
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and \
        ref_url.netloc == test_url.netloc


# Login
def login():
    if request.method == "GET":
        if g.user_id is not None:
            # Redirect to index if already authenticated
            return redirect(url_for("index"))
        # Render login page
        return render_template("login.html", error=request.args.get("error"))
    # Retrieve user from database
    user_data = guard().db.users.find_one(
        {"email": request.form["email"]}, {"_id": 0})
    # Check password (legacy plaintext is upgraded to a hash on success)
    if user_data and guard().check_password(user_data, request.form["pass"]):
        # Session stores nothing but the user id
        session.clear()
        session["user_id"] = user_data["id"]
        guard().invalidate_verified(user_data["id"])
        guard().record_event(user_data["id"], "login_success")

        # Check for next argument (direct user to protected page they wanted)
        next_page = request.args.get("next")
        if not is_safe_url(next_page):
            return abort(400)

        # Go to profile page after login
        return redirect(next_page or url_for("profile"))

    # Redirect to login page on error
    return redirect(url_for("login", error=1))


# Register
def register():
    if request.method == "POST":
        # Trim input data
        email = request.form["email"].strip()
        title = request.form["title"].strip()
        first_name = request.form["first_name"].strip()
        last_name = request.form["last_name"].strip()
        password = request.form["pass"].strip()

        result = guard().register_user(
            title, first_name, last_name, email, password)
        if result is not None:
            user, token = result
            session.clear()
            session["user_id"] = user.id
            send_registration_email(user, token)
            return redirect(url_for("profile"))

        # Handle duplicate email
        return redirect(url_for("register", error=1))

    # Return template for registration page if GET request
    return render_template("register.html", error=request.args.get("error"))


# Confirm email
def confirm_email(token):
    session.clear()
    success = guard().confirm_email(token) is not None
    return render_template("confirm.html", success=success)


# Verification email (resend)
def send_verification_email():
    if not g.verified:
        token = guard().issue_verification_token(g.user_id)
        if token is None:
            # Lost a concurrent resend race
            return "Could not issue verification token", 409
        send_registration_email(guard().current_user(), token)
        return "Verification email sent"
    else:
        return "Your email address is already verified"


# Logout
def logout():
    session.clear()
    return redirect(url_for("index"))


# Auth timeline (state transitions, most recent first)
def auth_timeline():
    user = guard().current_user()
    events = guard().timeline_events(g.user_id)
    rows = []
    for event in events:
        timestamp = event["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(timestamp),
                escape(event["event"]),
                escape(event.get("detail") or ""),
            )
        )
    body = "\n".join(rows) or \
        "<tr><td colspan=\"3\">No events recorded yet</td></tr>"
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="5">
  <title>Auth timeline</title>
  <style>
    body {{ font-family: sans-serif; margin: 2em; }}
    table {{ border-collapse: collapse; }}
    th, td {{ border: 1px solid #ccc; padding: 0.4em 0.8em; text-align: left; }}
    th {{ background: #f0f0f0; }}
  </style>
</head>
<body>
  <h1>Auth timeline &mdash; {name}</h1>
  <p>Most recent state transitions first. Auto-refreshes every 5 seconds.</p>
  <table>
    <thead><tr><th>Timestamp (UTC)</th><th>Event</th><th>Detail</th></tr></thead>
    <tbody>
{body}
    </tbody>
  </table>
</body>
</html>""".format(name=escape(user.display_name()), body=body)


def init_auth_routes(app):
    app.add_url_rule("/login", "login", login, methods=["GET", "POST"])
    app.add_url_rule("/register", "register", register, methods=["GET", "POST"])
    app.add_url_rule("/confirm/<token>", "confirm_email", confirm_email)
    app.add_url_rule("/verify", "send_verification_email",
                     send_verification_email, methods=["POST"])
    app.add_url_rule("/logout", "logout", logout)
    app.add_url_rule("/auth/timeline", "auth_timeline", auth_timeline)
