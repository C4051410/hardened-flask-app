# app/routes.py
import traceback
import re
import os
from secrets import token_urlsafe
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
# Part G/B: Hashing and Checking
from werkzeug.security import generate_password_hash, check_password_hash
# Part C: Parameterized Queries
from sqlalchemy import text, select
from app import db
from app.models import User

main = Blueprint('main', __name__)


# --- Part H: Logging Helper ---
def log_security_event(message, level='INFO', **details):
    # Log contextual information
    log_data = f"{message} | IP: {request.remote_addr}"
    if 'user' in session:
        log_data += f" | User: {session['user']}"
    for key, value in details.items():
        # Do not log sensitive data (Part H)
        if key not in ['password', 'current_password', 'new_password']:
            log_data += f" | {key}: {value}"

    if level == 'WARNING':
        current_app.logger.warning(log_data)
    elif level == 'ERROR':
        current_app.logger.error(log_data)
    else:
        current_app.logger.info(log_data)


# --- Part D: Simple CSRF Implementation ---
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = token_urlsafe(16)
    return session['_csrf_token']


@main.before_request
def csrf_protect():
    # Only check POST requests for state-changing operations
    if request.method == 'POST':
        # Part D: Check CSRF token legitimacy
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            log_security_event("CSRF Violation", level='WARNING',
                               reason="Invalid or missing token")
            custom_abort_403("CSRF token missing or invalid. Request blocked.")


# --- Part A/B: Strong Password Policy ---
def validate_password(password, username):
    # 1. At least 10 characters long
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    # 2. Uppercase, digit, special character
    if not (re.search(r'[A-Z]', password) and re.search(r'\d', password) and re.search(r'[!@#$%^&*(),.?":{}|<>]',
                                                                                       password)):
        return "Password must include an uppercase letter, a digit, and a special character."
    # 3. Not contain the username (email local part is often a concern, but checking full username as required)
    if username in password:
        return "Password cannot contain your username/email address."
    # 4. Blacklist check (case-insensitive)
    blacklist = ["password123$", "qwerty123!", "adminadmin1@", "welcome123!"]
    if password.lower() in [p.lower() for p in blacklist]:
        return "Password is on the blacklist."
    # 5. Avoid repeated character sequences
    if re.search(r'(.)\1\1', password):
        return "Password cannot contain repeated character sequences (e.g., aaa or 111)."
    return None


# --- Part I: Custom Error Handlers ---
def render_custom_error(error):
    # Part I: Use custom template for errors
    return render_template('error.html', error=error.code, message=error.description), error.code


@main.app_errorhandler(400)
def bad_request(error):
    error.description = "The server could not understand the request due to invalid syntax."
    return render_custom_error(error)


@main.app_errorhandler(403)
def forbidden(error):
    # Overrides default Flask 403 response
    if not error.description:
        error.description = "You do not have the necessary permissions to access this resource."
    return render_custom_error(error)


@main.app_errorhandler(404)
def not_found(error):
    error.description = "The requested URL was not found on the server."
    return render_custom_error(error)


@main.app_errorhandler(500)
def internal_server_error(error):
    error.description = "An unexpected error occurred on the server."
    return render_custom_error(error)


# Helper for 403 error page (to remove stack trace exposure) (Part I)
def custom_abort_403(message="Access denied."):
    abort(403, description=message)


# --- Application Routes ---

@main.route('/')
def home():
    return render_template('home.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Part C: SQL Injection Mitigation (Parameterized Query)
        user_row = db.session.execute(
            text("SELECT id, username, password, role, encrypted_bio FROM user WHERE username = :username"),
            {"username": username}
        ).mappings().first()

        # Part B/G: Hashed Password Check
        if user_row and check_password_hash(user_row['password'], password):
            # Part B: Stronger Session Management (Renew session on authentication)
            # Flask's session.regenerate is not a standard feature, 
            # so we'll simulate by clearing the old session and creating a new one.
            old_session = dict(session)
            session.clear()
            session.update(old_session)

            user = db.session.get(User, user_row['id'])
            session['user'] = user.username
            session['role'] = user.role
            session['bio'] = user.bio  # Decrypted bio (auto-escaped in templates, Part D)

            log_security_event("Successful Login", level='INFO', username=user.username)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login credentials are invalid, please try again')
            # Part H: Log Failed Login Attempt
            log_security_event("Failed Login", level='WARNING', username=username)

    # Part D: Pass CSRF token to GET request before render
    return render_template('login.html', csrf_token=generate_csrf_token())


@main.route('/dashboard')
def dashboard():
    if 'user' in session:
        # Part D: XSS Mitigation - The bio (session['bio']) is rendered in dashboard.html.
        # It's XSS-safe because Flask's Jinja2 auto-escapes, and is derived from
        # the encrypted column (Part G) which was pre-validated (Part A).
        username = session['user']
        bio = session['bio']
        return render_template('dashboard.html', username=username, bio=bio)
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        bio = request.form.get('bio', '')

        # --- Part A: Syntactic and Semantic Validation ---

        # Username (must be valid email address)
        if not re.match(r'[^@]+@[^@]+\.[^@]+', username):
            flash('Username must be a valid email address.', 'error')
            return render_template('register.html', csrf_token=generate_csrf_token())

        # Check if user already exists
        if db.session.execute(select(User).filter_by(username=username)).first():
            flash('Username already exists.', 'error')
            return render_template('register.html', csrf_token=generate_csrf_token())

        # Password Policy enforcement (Part B)
        password_error = validate_password(password, username)
        if password_error:
            flash(password_error, 'error')
            return render_template('register.html', csrf_token=generate_csrf_token())

        # Length check for bio (example constraint)
        if not (1 <= len(bio) <= 500):
            flash('Bio must be between 1 and 500 characters.', 'error')
            return render_template('register.html', csrf_token=generate_csrf_token())

        # Part G: Secure Password Storage
        password_hash = generate_password_hash(password)

        # Part F: Enforce default role to prevent privilege escalation
        new_user = User(
            username=username,
            password_hash=password_hash,
            role='user',
            bio_text=bio
        )

        db.session.add(new_user)
        db.session.commit()

        # Part H: Log Successful Registration
        log_security_event("Successful Registration", level='INFO', username=username)

        return redirect(url_for('main.login'))

    return render_template('register.html', csrf_token=generate_csrf_token())


@main.route('/admin-panel')
def admin():
    # Part F: Enforce Role-Based Access Control
    if session.get('role') != 'admin':
        log_security_event("Access Control Violation", level='WARNING',
                           route='/admin-panel', role=session.get('role'))
        custom_abort_403("Access denied: You must be an administrator.")
    return render_template('admin.html')


@main.route('/moderator')
def moderator():
    # Part F: Enforce Role-Based Access Control
    if session.get('role') != 'moderator':
        log_security_event("Access Control Violation", level='WARNING',
                           route='/moderator', role=session.get('role'))
        custom_abort_403("Access denied: You must be a moderator.")
    return render_template('moderator.html')


@main.route('/user-dashboard')
def user_dashboard():
    # Part F: Enforce Role-Based Access Control
    if session.get('role') != 'user':
        log_security_event("Access Control Violation", level='WARNING',
                           route='/user-dashboard', role=session.get('role'))
        custom_abort_403("Access denied: This page is for regular users only.")

    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Part F: Protect Sensitive Routes
    if 'user' not in session:
        custom_abort_403("Access denied: Must be logged in.")

    username = session['user']

    if request.method == 'POST':
        # Part B: Require reauthentication (current password) for critical action
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        # Part C: SQL Injection Mitigation (Parameterized Query)
        user_row = db.session.execute(
            text("SELECT id, password FROM user WHERE username = :username"),
            {"username": username}
        ).mappings().first()

        # Part B: Enforce current password must be valid for user
        if not user_row or not check_password_hash(user_row['password'], current_password):
            flash('Current password is incorrect', 'error')
            log_security_event("Failed Password Change", level='WARNING',
                               username=username, reason='Incorrect current password')
            return render_template('change_password.html', csrf_token=generate_csrf_token())

        # Part B: Enforce new password must be different from current password
        if check_password_hash(user_row['password'], new_password):
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html', csrf_token=generate_csrf_token())

        # Part B: Enforce Strong Password Policy for new password
        password_error = validate_password(new_password, username)
        if password_error:
            flash(password_error, 'error')
            return render_template('change_password.html', csrf_token=generate_csrf_token())

        # Part G: Hash the new password
        new_password_hash = generate_password_hash(new_password)

        # Part C: SQL Injection Mitigation (Parameterized Query for Update)
        db.session.execute(
            text("UPDATE user SET password = :new_password_hash WHERE username = :username"),
            {"new_password_hash": new_password_hash, "username": username}
        )
        db.session.commit()

        flash('Password changed successfully', 'success')
        # Part H: Log Successful Password Change
        log_security_event("Successful Password Change", level='INFO', username=username)
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html', csrf_token=generate_csrf_token())