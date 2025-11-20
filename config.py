# config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    # Base configuration
    # Part G/I: Load secrets from environment variables, fallback to development defaults
    SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecretkey')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Part E/B: Strengthen Session Management and Cookie Security
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1', 't')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # Helps mitigate CSRF when not using tokens (though we use tokens)

    # Part G: Fernet Key for Bio Encryption
    FERNET_KEY = os.environ.get('FERNET_KEY', 'xG_Yx8m4QWlRkM7q-8I5-f3Q-b0GvYwR6tXw4z1UaAs=').encode()


class DevelopmentConfig(Config):
    # Part I: Debug mode is safe in Development
    DEBUG = True
    # Session cookies can be insecure in a local development environment (HTTP)
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    # Part I: Disable debug mode in production environment
    DEBUG = False
    # Part B: Enforce Secure cookie flag in production
    SESSION_COOKIE_SECURE = True
    # Ensure a strong SECRET_KEY is set in the environment for production
    if Config.SECRET_KEY == 'supersecretkey':
        raise ValueError("SECRET_KEY must be set to a strong value in production.")


# Dictionary to select config based on environment
config_by_name = dict(
    development=DevelopmentConfig,
    production=ProductionConfig
)