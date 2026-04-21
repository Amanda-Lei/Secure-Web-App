from flask import Flask, render_template, request, redirect, url_for, session, make_response, g, abort
import json
import re
import html
import bcrypt
import time
import secrets
from security import EncryptedStorage, SessionManager, SecurityLogger
from functools import wraps

app = Flask(__name__)

storage = EncryptedStorage()
security_log = SecurityLogger()
session_manager = SessionManager()

users_file = "data/users.json"
sess_file = "data/sessions.json"

def load_db(file_path):
    with open(file_path, 'r') as f: return json.load(f)

def save_db(file_path, data):
    with open(file_path, 'w') as f: json.dump(data, f)

login_attempts = {}  # { ip: timestamps }

@app.route("/")
def home():
    return render_template("index.html")

@app.before_request
def load_user_session():
    token = request.cookies.get('session_token')
    if token:
        session_data = session_manager.validate_session(token)
        if session_data:
            users = load_db('data/users.json')
            g.user = users.get(session_data['user_id'])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        username = html.escape(request.form["username"])
        password = request.form["password"]

        # Rate limiting: Max 10 login attempts per IP per minute
        now = time.time()
        attempts = login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]

        if len(attempts) >= 10:
            security_log.log_event('RATE_LIMIT',user_id=username,details={'ip': ip, 'attempts': len(attempts), 'reason': 'Too many attempts'})
            return render_template("login.html", error="Too many login attempts. Try again later.")

        attempts.append(now)
        login_attempts[ip] = attempts

        users = load_db(users_file)
        user = users.get(username)
        # does user exist
        if not user:
            security_log.log_event('LOGIN_FAILED',user_id=None,details={'username': username, 'reason': 'User not found'})
            return render_template("login.html", error="Invalid credentials")
        
        # is user locked out
        if user.get("locked_until") and now < user["locked_until"]:
            security_log.log_event('ACCOUNT_LOCKED',user_id=username,details={'reason': '5 failed login attempts'},severity='ERROR')
            return render_template("login.html", error="Account locked. Try again later.")
        
        # Implement account lockout after 5 failed attempts (15 minutes)
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):    
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1

            if user["failed_attempts"] >= 5:
                user["locked_until"] = now + 900
                security_log.log_event('ACCOUNT_LOCKED',user_id=username,details={'reason': '5 failed login attempts'},severity='ERROR')

            save_db(users_file, users)

            security_log.log_event('LOGIN_FAILED',user_id=None,details={'username': username, 'reason': 'Invalid password'},severity='WARNING')

            return render_template("login.html", error="Invalid credentials")
        
        # login success
        user["failed_attempts"] = 0
        user["locked_until"] = None
        save_db(users_file, users)

        token = session_manager.create_session(username)
        security_log.log_event('LOGIN_SUCCESS',user_id=username,details={'username': username})
        response = make_response(redirect('/main'))
        response.set_cookie('session_token', token, httponly=True, secure=True, samesite='Strict', max_age=1800)

        return response

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        users = load_db(users_file)

        username = html.escape(request.form["username"])
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Validate inputs
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return render_template("register.html", error="Invalid username format")
        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match")
        if len(password) < 12 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password) or not re.search(r'[!@#$%^&*]', password):
            return render_template("register.html", error="Password does not meet requirements")

        if username in users:
            return render_template("register.html", error="Username already exists")

        # Hash password
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Store user (file-based)
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

        return redirect(url_for("login"))

    return render_template("register.html")

# AUTHORIZATION CHECKS
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = g.user
            if user['role'] != role:
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/main')
@require_auth
def main():
    return render_template('main.html', user=g.user)

@app.route('/admin/dashboard')
@require_auth
@require_role('admin')
def admin_dashboard():
    return render_template('admin.html')

if __name__ == "__main__":
    app.run(debug=True)