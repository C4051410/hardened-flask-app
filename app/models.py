# app/models.py
from app import db
from cryptography.fernet import Fernet

# The FERNET_KEY will be initialized in app/__init__.py for secure access.
# Placeholder for the global Fernet object
fernet = None

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Increased size for hashed password (Part G)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    # Part G: Store bio as LargeBinary (encrypted)
    encrypted_bio = db.Column(db.LargeBinary, nullable=False)

    def __init__(self, username, password_hash, role, bio_text):
        global fernet
        self.username = username
        self.password = password_hash
        self.role = role
        # Part G: Encrypt bio text before storage
        self.encrypted_bio = fernet.encrypt(bio_text.encode('utf-8'))

    # Property to automatically decrypt bio when accessed (Part G)
    @property
    def bio(self):
        global fernet
        try:
            return fernet.decrypt(self.encrypted_bio).decode('utf-8')
        except Exception:
            # Handle decryption errors gracefully (e.g., if key changes)
            return "Encrypted Content Error"

    @bio.setter
    def bio(self, bio_text):
        global fernet
        # Part G: Encrypt bio when setting the property
        self.encrypted_bio = fernet.encrypt(bio_text.encode('utf-8'))

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"





