from flask import Blueprint, request, render_template, redirect, url_for, make_response, g, abort
import html
import re
import bcrypt
import time
from functools import wraps

from security import EncryptedStorage, SessionManager, SecurityLogger

accounts_bp = Blueprint('accounts', __name__)

storage = EncryptedStorage()
security_log = SecurityLogger()
session_manager = SessionManager()

users_file = "data/users.json"
login_attempts = {}

def load_db(path):
    return storage.load_encrypted(path)

def save_db(path, data):
    storage.save_encrypted(path, data)

@accounts_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        username = html.escape(request.form["username"])
        password = request.form["password"]

        now = time.time()
        attempts = login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]

        if len(attempts) >= 10:
            security_log.log_event('RATE_LIMIT', user_id=username, details={'ip': ip, 'attempts': len(attempts), 'reason': 'Too many attempts'})
            return render_template("login.html", error="Too many login attempts. Try again later.")

        attempts.append(now)
        login_attempts[ip] = attempts

        users = load_db(users_file)
        user = users.get(username)
        
        if not user:
            security_log.log_event('LOGIN_FAILED', user_id=None, details={'username': username, 'reason': 'User not found'})
            return render_template("login.html", error="Invalid credentials")
        
        if user.get("locked_until") and now < user["locked_until"]:
            security_log.log_event('ACCOUNT_LOCKED', user_id=username, details={'reason': '5 failed login attempts'}, severity='ERROR')
            return render_template("login.html", error="Account locked. Try again later.")
        
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):    
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1
            if user["failed_attempts"] >= 5:
                user["locked_until"] = now + 900
                security_log.log_event('ACCOUNT_LOCKED', user_id=username, details={'reason': '5 failed login attempts'}, severity='ERROR')

            save_db(users_file, users)
            security_log.log_event('LOGIN_FAILED', user_id=None, details={'username': username, 'reason': 'Invalid password'}, severity='WARNING')
            return render_template("login.html", error="Invalid credentials")
        
        user["failed_attempts"] = 0
        user["locked_until"] = None
        save_db(users_file, users)

        token = session_manager.create_session(username)
        security_log.log_event('LOGIN_SUCCESS', user_id=username, details={'username': username})
        response = make_response(redirect('/dashboard'))
        response.set_cookie('session_token', token, httponly=True, secure=True, samesite='Strict', max_age=1800)

        return response

    return render_template("login.html")

@accounts_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        users = load_db(users_file)

        username = html.escape(request.form["username"])
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return render_template("register.html", error="Invalid username format")
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return render_template("register.html", error="Invalid email format")
        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match")
        if len(password) < 12 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password) or not re.search(r'[!@#$%^&*]', password):
            return render_template("register.html", error="Password does not meet requirements")

        if username in users:
            return render_template("register.html", error="Username already exists")
        if any(u.get('email') == email for u in users.values()):
            return render_template("register.html", error="Email already registered")

        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

        users[username] = {
            "username": username,
            "email": email,
            "password_hash": hashed.decode('utf-8'),
            "created_at": time.time(),
            "role": "user",
            "failed_attempts": 0,
            "locked_until": None
        }

        save_db(users_file, users)
        security_log.log_event('USER_REGISTERED', user_id=username, details={'username': username})
        
        return redirect(url_for("accounts.login")) 

    return render_template("register.html")