# Application factory and routes.
#
# Permission decisions live in auth/guard.py (mounted via before_request);
# these views only handle presentation and their own side effects.

from urllib.parse import urljoin, urlparse
import configparser
import os

from flask import (
    Flask,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

import auth
from auth import credentials, guard, status, timeline, tokens
from auth.guard import current_user, login_session, logout_session
from email_utility import (
    send_message_email,
    send_registration_email,
)
from message import Message
from note import Note
from user import User


def _load_config():
    config = configparser.ConfigParser()
    config.read('configuration.ini')
    return config['DEFAULT']


def _issue_confirm_url(user):
    token = tokens.issue_token(
        user.id,
        current_app.config['SECRET_KEY'],
        current_app.config['SECURITY_PASSWORD_SALT'],
    )
    return url_for('confirm_email', token=token, _external=True)


def create_app(mongo_client=None, testing=False):
    app = Flask(__name__)

    default = _load_config()
    app.secret_key = default['SECRET_KEY']
    app.config['SECRET_KEY'] = default['SECRET_KEY']
    app.config['SECURITY_PASSWORD_SALT'] = default['SECURITY_PASSWORD_SALT']
    app.config['PREFERRED_URL_SCHEME'] = "https"
    app.config['TESTING'] = testing
    app.config['WTF_CSRF_ENABLED'] = not testing

    if mongo_client is not None:
        db_name = os.environ.get('MONGO_DBNAME', 'test_flask_mongo_app')
        app.config['MONGO_URI'] = f'mongodb://localhost:27017/{db_name}'
        mongo = PyMongo(app)
        mongo.cx = mongo_client
        mongo.db = mongo_client[db_name]
    else:
        app.config['MONGO_DBNAME'] = os.environ.get('MONGO_DBNAME')
        app.config['MONGO_URI'] = os.environ.get('MONGODB_URI')
        mongo = PyMongo(app)

    bc = Bcrypt(app)
    app.bcrypt = bc

    Talisman(
        app,
        content_security_policy={
            'default-src': [
                '\'self\'',
                'https://stackpath.bootstrapcdn.com',
                'https://pro.fontawesome.com',
                'https://code.jquery.com',
                'https://cdnjs.cloudflare.com'
            ]
        },
        force_https=not testing,
    )

    csrf = CSRFProtect()
    csrf.init_app(app)

    auth.init_extensions(mongo, bc)
    auth.init_auth(app)
    guard.mongo = mongo

    _register_routes(app, mongo, bc)
    return app


def _register_routes(app, mongo, bc):

    # Index
    @app.route('/')
    def index():
        return render_template('index.html')

    # Login (GET presentation only; the guard redirects authenticated
    # users away. POST keeps its original response structure untouched.)
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return render_template('login.html', error=request.args.get("error"))

        user_data = mongo.db.users.find_one(
            {'email': request.form['email']}, {'_id': 0})
        if user_data:
            password_ok, migrated = credentials.verify_password(
                user_data, request.form['pass'])
            if password_ok:
                user = User.make_from_dict(user_data)
                login_session(user)
                if migrated:
                    status.invalidate(user.id)
                    timeline.record_event(
                        user.id, timeline.EVENT_PASSWORD_MIGRATED)
                timeline.record_event(user.id, timeline.EVENT_LOGIN)

                next_url = request.args.get('next')
                if not is_safe_url(next_url):
                    return abort(400)
                return redirect(next_url or url_for('profile'))

        if user_data:
            timeline.record_event(
                user_data['id'], timeline.EVENT_LOGIN_FAILED)
        return redirect(url_for('login', error=1))

    # Register
    @app.route('/register', methods=['POST', 'GET'])
    def register():
        if request.method == 'POST':
            email = request.form['email'].strip()
            title = request.form['title'].strip()
            first_name = request.form['first_name'].strip()
            last_name = request.form['last_name'].strip()
            password = request.form['pass'].strip()

            users = mongo.db.users
            existing_user = users.find_one({'email': email}, {'_id': 0})

            if existing_user is None:
                logout_session()
                hashpass = bc.generate_password_hash(password).decode('utf-8')
                new_user = User(title, first_name, last_name, email)
                user_data_to_save = new_user.dict()
                user_data_to_save['password'] = hashpass

                if users.insert_one(user_data_to_save):
                    login_session(new_user)
                    status.invalidate(new_user.id)
                    timeline.record_event(
                        new_user.id, timeline.EVENT_REGISTERED)
                    confirm_url = _issue_confirm_url(new_user)
                    timeline.record_event(
                        new_user.id, timeline.EVENT_VERIFICATION_SENT)
                    send_registration_email(new_user, confirm_url)
                    return redirect(url_for('profile'))
                return redirect(url_for('register', error=2))

            return redirect(url_for('register', error=1))

        return render_template(
            'register.html', error=request.args.get("error"))

    # Confirm email
    @app.route('/confirm/<token>', methods=['GET'])
    def confirm_email(token):
        try:
            user_id = tokens.consume_token(
                token,
                current_app.config['SECRET_KEY'],
                current_app.config['SECURITY_PASSWORD_SALT'],
            )
            if user_id:
                result = mongo.db.users.update_one(
                    {"id": user_id}, {"$set": {"verified": True}})
                if result.matched_count:
                    status.invalidate(user_id)
                    timeline.record_event(user_id, timeline.EVENT_VERIFIED)
                    return render_template('confirm.html', success=True)
        except Exception as exc:
            print(exc)
        return render_template('confirm.html', success=False)

    # Resend verification email
    @app.route('/verify', methods=['POST'])
    def send_verification_email():
        if current_user.verified is False:
            confirm_url = _issue_confirm_url(current_user)
            # The new token is live, so the verified cache must not be
            # allowed to linger until its TTL expires.
            status.invalidate(current_user.id)
            timeline.record_event(
                current_user.id, timeline.EVENT_VERIFICATION_RESENT)
            send_registration_email(current_user, confirm_url)
            return "Verification email sent"
        return "Your email address is already verified"

    # Profile
    @app.route('/profile', methods=['GET'])
    def profile():
        notes = mongo.db.notes.find(
            {"user_id": current_user.id, "deleted": False}
        ).sort("timestamp", -1)
        return render_template(
            'profile.html', notes=notes, title=current_user.title)

    # Messages
    @app.route('/messages', methods=['GET'])
    def messages():
        all_users = mongo.db.users.find(
            {"id": {"$ne": current_user.id}}, {'_id': 0})
        inbox_messages = mongo.db.messages.find(
            {"to_id": current_user.id, "deleted": False}
        ).sort("timestamp", -1)
        sent_messages = mongo.db.messages.find(
            {"from_id": current_user.id, "deleted": False,
             "hidden_for_sender": False}
        ).sort("timestamp", -1)
        return render_template(
            'messages.html', users=all_users,
            inbox_messages=inbox_messages, sent_messages=sent_messages)

    # Logout
    @app.route('/logout', methods=['GET'])
    def logout():
        logout_session()
        return redirect(url_for('index'))

    # Add note
    @app.route('/add_note', methods=['POST'])
    def add_note():
        title = request.form.get("title")
        body = request.form.get("body")
        user_id = current_user.id
        user_name = current_user.display_name()
        note = Note(title, body, user_id, user_name)
        if mongo.db.notes.insert_one(note.dict()):
            return "Success! Note added: " + title
        return "Error! Could not add note"

    # Delete note
    @app.route('/delete_note', methods=['POST'])
    def delete_note():
        note_id = request.form.get("note_id")
        if mongo.db.notes.update_one(
                {"id": note_id}, {"$set": {"deleted": True}}):
            return "Success! Note deleted"
        return "Error! Could not delete note"

    # Send message
    @app.route('/send_message', methods=['POST'])
    def send_message():
        title = request.form.get("title")
        body = request.form.get("body")
        from_id = current_user.id
        from_name = current_user.display_name()
        to_id = request.form.get("user")
        to_user_dict = mongo.db.users.find_one({"id": to_id})
        to_user = User.make_from_dict(to_user_dict)
        to_name = to_user.display_name()
        message = Message(title, body, from_id, from_name, to_id, to_name)
        if mongo.db.messages.insert_one(message.dict()):
            send_message_email(
                from_user=current_user, to_user=to_user, message=message)
            return "Success! Message sent to " + to_name + ": " + title
        return "Error! Could not send message"

    # Delete message
    @app.route('/delete_message', methods=['POST'])
    def delete_message():
        message_id = request.form.get("message_id")
        if mongo.db.messages.update_one(
                {"id": message_id}, {"$set": {"deleted": True}}):
            return "Success! Message deleted"
        return "Error! Could not delete message"

    # Hide sent message
    @app.route('/hide_sent_message', methods=['POST'])
    def hide_sent_message():
        message_id = request.form.get("message_id")
        if mongo.db.messages.update_one(
                {"id": message_id}, {"$set": {"hidden_for_sender": True}}):
            return "Success! Message hidden from sender"
        return "Error! Could not hide message"

    # Change name
    @app.route('/change_name', methods=['POST'])
    def change_name():
        title = request.form['title'].strip()
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()

        if mongo.db.users.update_one(
                {"email": current_user.email},
                {"$set": {"title": title, "first_name": first_name,
                          "last_name": last_name}}):
            return "User name updated successfully"
        return "Error! Could not update user name"

    # Delete account
    @app.route('/delete_account', methods=['POST'])
    def delete_account():
        user_id = current_user.id

        user_deleted = False
        notes_deleted = False
        messages_deleted = False

        if mongo.db.users.delete_one({"id": user_id}):
            user_deleted = True
            logout_session()
            status.invalidate(user_id)

        if mongo.db.notes.delete_many({"user_id": user_id}):
            notes_deleted = True

        if mongo.db.messages.delete_many(
                {"$or": [{"from_id": user_id}, {"to_id": user_id}]}):
            messages_deleted = True

        return {"user_deleted": user_deleted, "notes_deleted": notes_deleted,
                "messages_deleted": messages_deleted}

    # Safe URL
    def is_safe_url(target):
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        return test_url.scheme in ('http', 'https') and \
            ref_url.netloc == test_url.netloc





