# MODULE IMPORTS

# Flask modules
from flask import Flask, render_template, request, url_for, redirect, g, session
from flask_talisman import Talisman
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

# Other modules
import configparser
import os

# Local imports
from user import User
from message import Message
from note import Note
from email_utility import send_message_email
from auth.guard import AuthGuard
from auth.routes import init_auth_routes


# Create app
app = Flask(__name__)

# Configuration
config = configparser.ConfigParser()
config.read('configuration.ini')
default = config['DEFAULT']
app.secret_key = default['SECRET_KEY']
app.config['MONGO_DBNAME'] = os.environ.get('MONGO_DBNAME')
app.config['MONGO_URI'] = os.environ.get('MONGODB_URI') #default['MONGO_URI']
app.config['PREFERRED_URL_SCHEME'] = "https"

# Create Pymongo
mongo = PyMongo(app)

# Create Bcrypt
bc = Bcrypt(app)

# Create Talisman
csp = {
    'default-src': [
        '\'self\'',
        'https://stackpath.bootstrapcdn.com',
        'https://pro.fontawesome.com',
        'https://code.jquery.com',
        'https://cdnjs.cloudflare.com'
    ]
}
talisman = Talisman(app, content_security_policy=csp)

# Create CSRF protect
csrf = CSRFProtect()
csrf.init_app(app)

# Create the auth guard: every auth decision (registration, e-mail
# verification, login) is centralised in auth/guard.py and mounted here via
# before_request.  Views below only handle presentation.
guard = AuthGuard(
    lambda: mongo.db,
    bcrypt=bc,
    secret_key=app.secret_key,
    salt=default['SECURITY_PASSWORD_SALT'],
)
guard.init_app(app)
init_auth_routes(app)


# ROUTES

# Index
@app.route('/')
def index():
    return render_template('index.html')


# Profile
@app.route('/profile', methods=['GET'])
def profile():
    notes = mongo.db.notes.find(
        {"user_id": g.user_id, "deleted": False}).sort("timestamp", -1)
    return render_template('profile.html', notes=notes, title=guard.current_user().title)


# Messages
@app.route('/messages', methods=['GET'])
def messages():
    all_users = mongo.db.users.find(
        {"id": {"$ne": g.user_id}}, {'_id': 0})
    inbox_messages = mongo.db.messages.find(
        {"to_id": g.user_id, "deleted": False}).sort("timestamp", -1)
    sent_messages = mongo.db.messages.find(
        {"from_id": g.user_id, "deleted": False, "hidden_for_sender": False}).sort("timestamp", -1)
    return render_template('messages.html', users=all_users, inbox_messages=inbox_messages, sent_messages=sent_messages)


# POST REQUEST ROUTES

# Add note
@app.route('/add_note', methods=['POST'])
def add_note():
    title = request.form.get("title")
    body = request.form.get("body")
    user_id = g.user_id
    user_name = guard.current_user().display_name()
    note = Note(title, body, user_id, user_name)
    if mongo.db.notes.insert_one(note.dict()):
        return "Success! Note added: " + title
    else:
        return "Error! Could not add note"


# Delete note
@app.route('/delete_note', methods=['POST'])
def delete_note():
    note_id = request.form.get("note_id")
    if mongo.db.notes.update_one({"id": note_id}, {"$set": {"deleted": True}}):
        return "Success! Note deleted"
    else:
        return "Error! Could not delete note"


# Send message
@app.route('/send_message', methods=['POST'])
def send_message():
    title = request.form.get("title")
    body = request.form.get("body")
    from_id = g.user_id
    from_user = guard.current_user()
    from_name = from_user.display_name()
    to_id = request.form.get("user")
    to_user_dict = mongo.db.users.find_one({"id": to_id})
    to_user = User.make_from_dict(to_user_dict)
    to_name = to_user.display_name()
    message = Message(title, body, from_id, from_name, to_id, to_name)
    if mongo.db.messages.insert_one(message.dict()):
        send_message_email(from_user=from_user,
                           to_user=to_user, message=message)
        return "Success! Message sent to " + to_name + ": " + title
    else:
        return "Error! Could not send message"


# Delete message
@app.route('/delete_message', methods=['POST'])
def delete_message():
    message_id = request.form.get("message_id")
    if mongo.db.messages.update_one({"id": message_id}, {"$set": {"deleted": True}}):
        return "Success! Message deleted"
    else:
        return "Error! Could not delete message"


# Hide sent message
@app.route('/hide_sent_message', methods=['POST'])
def hide_sent_message():
    message_id = request.form.get("message_id")
    if mongo.db.messages.update_one({"id": message_id}, {"$set": {"hidden_for_sender": True}}):
        return "Success! Message hidden from sender"
    else:
        return "Error! Could not hide message"


# Change Name
@app.route('/change_name', methods=['POST'])
def change_name():
    title = request.form['title'].strip()
    first_name = request.form['first_name'].strip()
    last_name = request.form['last_name'].strip()

    if mongo.db.users.update_one({"email": guard.current_user().email}, {"$set": {"title": title, "first_name": first_name, "last_name": last_name}}):
        return "User name updated successfully"
    else:
        return "Error! Could not update user name"


# Delete Account
@app.route('/delete_account', methods=['POST'])
def delete_account():
    user_id = g.user_id

    # Deletion flags
    user_deleted = False
    notes_deleted = False
    messages_deleted = False

    # Delete user details
    if mongo.db.users.delete_one({"id": user_id}):
        user_deleted = True
        session.clear()

    # Delete notes
    if mongo.db.notes.delete_many({"user_id": user_id}):
        notes_deleted = True

    # Delete messages
    if mongo.db.messages.delete_many({"$or": [{"from_id": user_id}, {"to_id": user_id}]}):
        messages_deleted = True

    return {"user_deleted": user_deleted, "notes_deleted": notes_deleted, "messages_deleted": messages_deleted}


# Heroku environment
if __name__ == '__main__':
    if os.environ.get('APP_LOCATION') == 'heroku':
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port)
    else:
        app.run(host='localhost', port=8080, debug=True)
