import os
import re
import secrets
import uuid
import io
import html
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Blueprint, flash, make_response, request, redirect, abort, g, send_file

from security import EncryptedStorage, SessionManager, SecurityLogger

documents_bp = Blueprint('documents', __name__)

storage = EncryptedStorage()
security_log = SecurityLogger()
session_manager = SessionManager()

docs_file = "data/documents.json"
users_file = "data/users.json"
UPLOAD_FOLDER = "data/files"

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}

def load_db(path):
    return storage.load_encrypted(path)

def save_db(path, data):
    storage.save_encrypted(path, data)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    # Whitelist validation for file extensions
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def safe_filename(filename):
    # Remove path traversal attempts
    filename = os.path.basename(filename)
    # Allow only alphanumeric, dash, underscore, dot
    if not re.match(r'^[\w\-\.]+$', filename):
        raise ValueError("Invalid filename")
    return filename

def safe_file_path(user_path, base_dir):
    # Secure the filename
    filename = secure_filename(user_path)
    # Construct full path
    full_path = os.path.join(base_dir, filename)
    # Verify it's within base directory
    if not os.path.abspath(full_path).startswith(os.path.abspath(base_dir)):
        raise ValueError("Path traversal detected")
    return full_path

@documents_bp.route('/upload', methods=['POST'])
@require_auth
def upload():
    # no guests, only admins and users
    if g.user['role'] not in ['admin', 'user']:
        security_log.log_event('ACCESS_DENIED', user_id=g.user['username'], details={'reason': 'Insufficient privileges'}, severity='WARNING')
        flash("Insufficient privileges.", "error")
        return redirect('/dashboard')

    if 'document' not in request.files:
        return redirect('/dashboard')
    file = request.files['document']
    
    # input validation
    if file.filename == '' or not allowed_file(file.filename):
        security_log.log_event('UPLOAD_FAILED', user_id=g.user['username'], details={'reason': 'Invalid file type or empty file'}, severity='WARNING')
        flash("Invalid file type.", "error")
        return redirect('/dashboard')

    doc_id = secrets.token_urlsafe(32)
    safe_name = secure_filename(file.filename)
    storage_filename = f"{doc_id}.enc"
    save_path = safe_file_path(storage_filename, UPLOAD_FOLDER)
    
    file_data = file.read()
    encrypted_data = storage.cipher.encrypt(file_data) 
    with open(save_path, 'wb') as f:
        f.write(encrypted_data)
        
    # save metadata to documents.json
    documents = load_db(docs_file)
    documents[doc_id] = {
        "original_filename": safe_name,
        "safe_filename": storage_filename,
        "owner": g.user['username'],
        "shared_with": [],
        "version": 1
    }
    save_db(docs_file, documents)
    
    security_log.log_event('DATA_ACCESS', user_id=g.user['username'], details={'action': 'upload', 'file': safe_name})
    return redirect('/dashboard')


@documents_bp.route('/download/<doc_id>')
@require_auth
def download(doc_id):
    documents = load_db(docs_file)
    doc = documents.get(doc_id)
    
    if not doc:
        abort(404)
        
    # access control
    has_access = doc['owner'] == g.user['username'] or g.user['username'] in doc.get('shared_with', []) or g.user['role'] == 'admin'
    
    if not (has_access):
        security_log.log_event('ACCESS_DENIED', user_id=g.user['username'], details={'action': 'download', 'file': doc_id}, severity='WARNING')
        flash("Insufficient privileges.", "error")
        return redirect('/dashboard')
        
    try:
        file_path = safe_file_path(doc['safe_filename'], UPLOAD_FOLDER)
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = storage.cipher.decrypt(encrypted_data)
        security_log.log_event('DATA_ACCESS', user_id=g.user['username'], details={'action': 'download', 'file': doc['original_filename']})
        
        return send_file(io.BytesIO(decrypted_data),download_name=doc['original_filename'],as_attachment=True)
    
    except FileNotFoundError:
        flash("File corrupted/missing.", "error")
        return redirect('/dashboard')


@documents_bp.route('/share/<doc_id>', methods=['POST'])
@require_auth
def share(doc_id):
    target_user = html.escape(request.form.get('share_username', ''))
    
    documents = load_db(docs_file)
    users = load_db(users_file)
    doc = documents.get(doc_id)
    
    # only owner can share
    if not doc or doc['owner'] != g.user['username']:
        security_log.log_event('ACCESS_DENIED', user_id=g.user['username'], details={'action': 'share', 'file': doc_id}, severity='WARNING')
        flash("Insufficient privileges", "error")
        return redirect("/dashboard")
        
    if target_user not in users:
        flash("User does not exist.", "error")
        return redirect("/dashboard")
    
    if target_user == g.user['username']:
        return redirect("/dashboard")
        
    if target_user not in doc.get('shared_with', []):
        doc.setdefault('shared_with', []).append(target_user)
        save_db(docs_file, documents)
        security_log.log_event('DATA_ACCESS', user_id=g.user['username'], details={'action': 'share', 'file': doc['original_filename'], 'target': target_user})
        
    return redirect('/dashboard')

@documents_bp.route('/delete/<doc_id>', methods=['POST'])
@require_auth
def delete(doc_id):
    documents = load_db(docs_file)
    doc = documents.get(doc_id)

    if not doc:
        abort(404)

    can_delete = doc['owner'] == g.user['username'] or g.user['role'] == 'admin'

    if not (can_delete):
        security_log.log_event('ACCESS_DENIED', user_id=g.user['username'], details={'action': 'delete', 'file': doc_id}, severity='WARNING')
        flash("Insufficient privileges", "error")
        return redirect("/dashboard")

    # delete physical file
    try:
        file_path = os.path.join(UPLOAD_FOLDER, doc['safe_filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass

    # delete metadata
    del documents[doc_id]
    save_db(docs_file, documents)

    security_log.log_event('DATA_ACCESS', user_id=g.user['username'], details={'action': 'delete', 'file': doc['original_filename']})

    return redirect('/dashboard')

@documents_bp.route('/logout')
def logout():
    token = request.cookies.get('session_token')
    if token: session_manager.destroy_session(token)
    response = make_response(redirect('/'))
    response.set_cookie('session_token', '', expires=0)
    return response