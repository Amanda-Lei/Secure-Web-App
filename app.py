from flask import Flask, render_template, request, redirect, url_for, session
import json
import re
import html
import bcrypt
import time
import secrets

app = Flask(__name__)

users_file = "data/users.json"
sess_file = "data/sessions.json"

def load_db(file_path):
    with open(file_path, 'r') as f: return json.load(f)

def save_db(file_path, data):
    with open(file_path, 'w') as f: json.dump(data, f)

def log_event(event, username, ip, message):
    print(f"[{event}] User: {username}, IP: {ip}, Info: {message}")

login_attempts = {}  # { ip: timestamps }

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
    # Save session
    sessions = self.load_sessions()
    sessions[token] = session
    self.save_sessions(sessions)
    return token

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        username = html.escape(request.form["username"])
        password = request.form["password"]

        users = load_db(users_file)

        # Rate limiting: Max 10 login attempts per IP per minute
        now = time.time()
        attempts = login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]

        if len(attempts) >= 10:
            log_event("RATE_LIMIT", username, ip, "Too many attempts")
            return "Too many login attempts. Try again later."

        attempts.append(now)
        login_attempts[ip] = attempts

        user = users.get(username)
        # does user exist
        if not user:
            log_event("LOGIN_FAILED", username, ip, "User not found")
            return render_template("login.html", error="Invalid credentials")
        
        # is user locked out
        if user.get("locked_until") and now < user["locked_until"]:
            log_event("ACCOUNT_LOCKED", username, ip, "Account still locked")
            return render_template("login.html", error="Account locked. Try again later.")
        
        # Implement account lockout after 5 failed attempts (15 minutes)
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):    
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1

            if user["failed_attempts"] >= 5:
                user["locked_until"] = now + 900
                log_event("ACCOUNT_LOCKED", username, ip, "5 failed attempts")

            save_db(users_file, users)

            log_event("LOGIN_FAILED", username, ip, "Wrong password")

            return render_template("login.html", error="Invalid credentials")
        
        # login success

        user["failed_attempts"] = 0
        user["locked_until"] = None
        save_db(users_file, users)

        # create_session(username)

        log_event("LOGIN_SUCCESS", username, ip, "Successful login")

        return render_template("main.html")

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


if __name__ == "__main__":
    app.run(debug=True)