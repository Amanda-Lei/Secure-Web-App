import secrets
from flask import Flask, request, g, render_template, redirect, abort
from functools import wraps
from security import EncryptedStorage, SessionManager
from blueprints.accounts import accounts_bp
from blueprints.documents import documents_bp

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

storage = EncryptedStorage()
session_manager = SessionManager()

@app.before_request
def load_user_session():
    token = request.cookies.get('session_token')
    if token:
        session_data = session_manager.validate_session(token)
        if session_data:
            users = storage.load_encrypted("data/users.json")
            g.user = users.get(session_data['user_id'])
        else:
            g.user = None
    else:
        g.user = None

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
            if user['role'] != role and user['role'] != 'admin':
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# routes
app.register_blueprint(accounts_bp)
app.register_blueprint(documents_bp)

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/dashboard')
@require_auth
def dashboard():
    all_docs = storage.load_encrypted("data/documents.json")

    # admin view
    if g.user['role'] == 'admin':
        return render_template('admin.html', user=g.user, docs=all_docs)
    
    my_docs = {}
    shared_docs = {}
    
    for doc_id, doc in all_docs.items():
        if doc['owner'] == g.user['username']:
            my_docs[doc_id] = doc
        elif g.user['username'] in doc.get('shared_with', []):
            shared_docs[doc_id] = doc
            
    return render_template('dashboard.html', user=g.user, my_docs=my_docs, shared_docs=shared_docs)

@app.route('/admin/dashboard')
@require_auth
@require_role('admin')
def admin_dashboard():
    return render_template('admin.html')

if __name__ == "__main__":
    app.run(debug=True)