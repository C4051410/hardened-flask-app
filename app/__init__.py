# app/__init__.py
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman  # Part E: HTTP Security Headers
from werkzeug.security import generate_password_hash  # Part G: Hashing
from cryptography.fernet import Fernet  # Part G: Encryption
from config import config_by_name  # Part I: Configuration

db = SQLAlchemy()
talisman = Talisman()  # Initialize Talisman

# Initialize Fernet globally (Part G)
fernet = None


def create_app(config_name='development'):
    app = Flask(__name__)

    # Part I: Load config based on environment
    app.config.from_object(config_by_name[config_name])

    db.init_app(app)

    # Initialize global Fernet object after config is loaded (Part G)
    global fernet
    fernet = Fernet(app.config['FERNET_KEY'])
    from .models import fernet as model_fernet
    model_fernet = fernet  # Make sure models.py uses the initialized object

    # Part E: Apply HTTP Security Headers using Talisman
    talisman.init_app(app,
                      # Default security policy
                      force_https=app.config.get('SESSION_COOKIE_SECURE', False),
                      session_cookie_secure=app.config.get('SESSION_COOKIE_SECURE', False),
                      # Part E: X-Frame-Options (Clickjacking mitigation)
                      frame_options='DENY',
                      # Part E: Strict-Transport-Security (HSTS) - only meaningful if serving via HTTPS
                      strict_transport_security=app.config.get('SESSION_COOKIE_SECURE', False),
                      # Part E: Content Security Policy (for XSS mitigation)
                      content_security_policy={
                          'default-src': ["'self'"],
                          # Allows local CSS/JS (Part E)
                          'script-src': ["'self'", "'unsafe-inline'"],
                          'style-src': ["'self'", "'unsafe-inline'"],
                          'img-src': ["'self'"],
                      }
                      )

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User

        # --- Database Setup and Seeding ---
        # Note: In a real app, this should only run once on setup, not on every run
        db.drop_all()
        db.create_all()

        users = [
            # Part G: Store HASHED passwords for initial users
            {"username": "user1@email.com", "password": generate_password_hash("Userpass!23"), "role": "user",
             "bio": "I'm a basic user. **bold** text allowed."},
            {"username": "mod1@email.com", "password": generate_password_hash("Modpass!23"), "role": "moderator",
             "bio": "I'm a moderator."},
            {"username": "admin1@email.com", "password": generate_password_hash("Adminpass!23"), "role": "admin",
             "bio": "I'm an administrator."},
        ]

        for user_data in users:
            # Use password_hash as the password argument for the User constructor
            user = User(
                username=user_data["username"],
                password_hash=user_data["password"],
                role=user_data["role"],
                bio_text=user_data["bio"]
            )
            db.session.add(user)
        db.session.commit()

    # --- Part H: Secure Logging Setup ---
    # Only run if not in test environment
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        # File-based logging with rotation (Part H)
        file_handler = RotatingFileHandler('logs/app.log', maxBytes=1024 * 1024, backupCount=5)

        # Structured logging format (Part H) - ensure no sensitive data is logged by default
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

    return app