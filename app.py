from flask import Flask, render_template, request, redirect, url_for
import json
import re
import html
import bcrypt
import time

app = Flask(__name__)

users_file = "data/users.json"
sess_file = "data/sessions.json"

def load_db(file_path):
    with open(file_path, 'r') as f: return json.load(f)

def save_db(file_path, data):
    with open(file_path, 'w') as f: json.dump(data, f)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        return f"Logged in as {username}"

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