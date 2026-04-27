from flask import Blueprint, flash, render_template, request, redirect, url_for, make_response, g, abort
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
            flash("Too many login attempts. Try again later.", "error")
            return redirect("/login")

        attempts.append(now)
        login_attempts[ip] = attempts

        users = load_db(users_file)
        user = users.get(username)
        
        if not user:
            security_log.log_event('LOGIN_FAILED', user_id=None, details={'username': username, 'reason': 'User not found'})
            flash("Invalid credentials", "error")
            return redirect('/login')
        
        if user.get("locked_until") and now < user["locked_until"]:
            security_log.log_event('ACCOUNT_LOCKED', user_id=username, details={'reason': '5 failed login attempts'}, severity='ERROR')
            flash("Account locked. Try again later.", "error")
            return redirect("/login")
        
        if not user.get("active", True):
            flash("Account is disabled.", "error")
            return redirect("/login")
        
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):    
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1
            if user["failed_attempts"] >= 5:
                user["locked_until"] = now + 900
                security_log.log_event('ACCOUNT_LOCKED', user_id=username, details={'reason': '5 failed login attempts'}, severity='ERROR')

            save_db(users_file, users)
            security_log.log_event('LOGIN_FAILED', user_id=None, details={'username': username, 'reason': 'Invalid password'}, severity='WARNING')
            flash("Invalid credentials", "error")
            return redirect("/login")
        
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
            flash("Invalid username format", "error")
            return redirect("/register")
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash("Invalid email format", "error")
            return redirect("/register")
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect("/register")
        if len(password) < 12 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password) or not re.search(r'[!@#$%^&*]', password):
            flash("Password does not meet requirements", "error")
            return redirect("/register")

        if username in users:
            flash("Username already exists", "error")
            return redirect("/register")
        if any(u.get('email') == email for u in users.values()):
            flash("Email already registered", "error")
            return redirect("/login")

        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

        users[username] = {
            "username": username,
            "email": email,
            "password_hash": hashed.decode('utf-8'),
            "created_at": time.time(),
            "role": "guest",
            "active": True,
            "failed_attempts": 0,
            "locked_until": None
        }

        save_db(users_file, users)
        security_log.log_event('USER_REGISTERED', user_id=username, details={'username': username})
        
        return redirect(url_for("accounts.login")) 

    return render_template("register.html")

@accounts_bp.route('/toggle_user/<username>', methods=['POST'])
def toggle_user(username):
    if not g.user or g.user['role'] != 'admin':
        flash("Unauthorized", "error")
        return redirect('/dashboard')

    users = load_db(users_file)

    if username not in users:
        flash("User not found", "error")
        return redirect('/dashboard')

    if username == g.user['username']:
        flash("You cannot disable yourself", "error")
        return redirect('/dashboard')

    users[username]['active'] = not users[username].get('active', True)
    save_db(users_file, users)

    status = "enabled" if users[username]['active'] else "disabled"

    security_log.log_event(
        'DATA_ACCESS',
        user_id=g.user['username'],
        details={'action': 'toggle_user', 'target': username, 'status': status}
    )

    flash(f"User {username} {status}", "info")
    return redirect('/dashboard')

@accounts_bp.route('/update_role/<username>', methods=['POST'])
def update_role(username):
    if not g.user or g.user['role'] != 'admin':
        flash("Unauthorized", "error")
        return redirect('/dashboard')

    new_role = request.form.get('role')

    if new_role not in ['guest', 'user', 'admin']:
        flash("Invalid role", "error")
        return redirect('/dashboard')

    users = load_db(users_file)

    if username not in users:
        flash("User not found", "error")
        return redirect('/dashboard')

    if username == g.user['username']:
        flash("You cannot change your own role", "error")
        return redirect('/dashboard')

    users[username]['role'] = new_role
    save_db(users_file, users)

    security_log.log_event(
        'DATA_ACCESS',
        user_id=g.user['username'],
        details={'action': 'update_role', 'target': username, 'role': new_role}
    )

    flash(f"{username} is now {new_role}", "success")
    return redirect('/dashboard')