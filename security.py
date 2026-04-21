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
        self.storage = EncryptedStorage()

    def load_sessions(self):
        try:
            return self.storage.load_encrypted(self.sessions_file)
        except FileNotFoundError:
            return {}

    def save_sessions(self, sessions):
        self.storage.save_encrypted(self.sessions_file, sessions)

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
    def __init__(self, log_dir='logs'):
        # Security Log
        self.sec_logger = logging.getLogger('security')
        self.sec_logger.setLevel(logging.INFO)
        sec_handler = logging.FileHandler(f'{log_dir}/security.log')
        sec_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.sec_logger.addHandler(sec_handler)

        # Access Log
        self.acc_logger = logging.getLogger('access')
        self.acc_logger.setLevel(logging.INFO)
        acc_handler = logging.FileHandler(f'{log_dir}/access.log')
        acc_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.acc_logger.addHandler(acc_handler)

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

        if event_type == 'DATA_ACCESS':
            self.acc_logger.info(msg)
        else:
            if severity == 'CRITICAL':
                self.sec_logger.critical(msg)
            elif severity == 'ERROR':
                self.sec_logger.error(msg)
            elif severity == 'WARNING':
                self.sec_logger.warning(msg)
            else:
                self.sec_logger.info(msg)