from flask import url_for, render_template
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os


# Common email sending function
def send_email(receiver_email, subject, plaintext, html):

    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    PORT = os.environ.get('EMAIL_PORT')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
    PASSWORD = os.environ.get('EMAIL_PASSWORD')

    # Message setup
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = SENDER_EMAIL
    message["To"] = receiver_email

    # Turn text into plain and HTML MIMEText objects
    part1 = MIMEText(plaintext, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)

    # Create a secure SSL context
    context = ssl.create_default_context()

    # Try to log in to server and send email
    server = None
    try:
        server = smtplib.SMTP(SMTP_SERVER, PORT)
        server.ehlo()
        server.starttls(context=context)  # Secure the connection
        server.ehlo()
        server.login(SENDER_EMAIL, PASSWORD)
        server.send_message(message)
        return True
    except Exception as e:
        # Print error messages to stdout
        print(e)
        return False
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


# Convenience function - registration / verification email
# The token is issued (and stored) by the auth guard; it binds the user id
# and an expiry, and any previously sent token is already invalidated.
def send_registration_email(user, token):
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Registration successful - Please verify your email address."
    plaintext = f"Welcome {user.display_name()}.\nPlease verify your email address by following this link:\n\n{confirm_url}"
    html = render_template('verification_email.html',
                           confirm_url=confirm_url, user=user)
    send_email(user.email, subject, plaintext, html)


# Convenience function - message received notification
def send_message_email(from_user, to_user, message):
    subject = f"{from_user.display_name()} sent you a message"
    plaintext = f"{to_user.display_name()} sent you this message:\n\n{message.title}\n\n{message.body}"
    html = render_template(
        'message_email.html', from_user=from_user, to_user=to_user, message=message)
    send_email(to_user.email, subject, plaintext, html)
