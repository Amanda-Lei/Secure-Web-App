from cryptography.fernet import Fernet
import json
import secrets
import time
import json
import logging
from datetime import datetime
from flask import request

class EncryptedStorage:
    def __init__(self, key_file='secret.key'):
        # Load or generate encryption key
        try:
            with open(key_file, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)

        self.cipher = Fernet(self.key)

    def save_encrypted(self, filename, data):
        """Save encrypted JSON data"""
        json_data = json.dumps(data)
        encrypted = self.cipher.encrypt(json_data.encode())

        with open(filename, 'wb') as f:
            f.write(encrypted)

    def load_encrypted(self, filename):
        """Load and decrypt JSON data"""
        with open(filename, 'rb') as f:
            encrypted = f.read()

        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())

class SessionManager:
    def __init__(self, timeout=1800):  # 30 minutes
        self.timeout = timeout
        self.sessions_file = 'data/sessions.json'

    def load_sessions(self):
        try:
            with open(self.sessions_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_sessions(self, sessions):
        with open(self.sessions_file, 'w') as f:
            json.dump(sessions, f)

    def create_session(self, user_id):
        """Create new session token"""
        token = secrets.token_urlsafe(32)

        session = {
            'token': token,
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }

        sessions = self.load_sessions()
        sessions[token] = session
        self.save_sessions(sessions)

        return token

    def validate_session(self, token):
        """Check if session is valid"""
        sessions = self.load_sessions()

        if token not in sessions:
            return None

        session = sessions[token]

        # Timeout check
        if time.time() - session['last_activity'] > self.timeout:
            self.destroy_session(token)
            return None

        # Update last activity
        session['last_activity'] = time.time()
        sessions[token] = session
        self.save_sessions(sessions)

        return session

    def destroy_session(self, token):
        """Delete session"""
        sessions = self.load_sessions()

        if token in sessions:
            del sessions[token]

        self.save_sessions(sessions)

class SecurityLogger:
    def __init__(self, log_file='logs/security.log'):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)

        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def log_event(self, event_type, user_id, details, severity='INFO'):
        """Log security event"""

        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'details': details,
            'severity': severity
        }

        msg = json.dumps(log_entry)

        if severity == 'CRITICAL':
            self.logger.critical(msg)
        elif severity == 'ERROR':
            self.logger.error(msg)
        elif severity == 'WARNING':
            self.logger.warning(msg)
        else:
            self.logger.info(msg)