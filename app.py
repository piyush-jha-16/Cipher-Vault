from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import sqlite3
import os
import re
import csv
import io
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from utils.encryption import encrypt_password, decrypt_password, generate_salt

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key")
bcrypt = Bcrypt(app)

# Enable CORS for browser extension - allow all origins for extension to work
CORS(app, 
     resources={r"/api/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=["Content-Type", "X-Session-ID"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Google OAuth Configuration
# You'll need to set these environment variables or replace with your values
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# OAuth2 Flow configuration
# Only allow insecure transport in development (local), not in production
if os.environ.get("FLASK_ENV") == "development":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Database configuration - use persistent disk on Render, local otherwise
DB_DIR = os.environ.get("DATABASE_DIR", ".")
DB_PATH = os.path.join(DB_DIR, "database.db")

# Ensure database directory exists
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

# Database helper function
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

# Input validation helper
def validate_email(email):
    """
    Validate email format
    Returns: True if valid, False otherwise
    """
    if not email or '@' not in email:
        return False
    parts = email.split('@')
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return False
    if '.' not in parts[1] or parts[1].startswith('.') or parts[1].endswith('.'):
        return False
    return True

# Password strength checker
def check_password_strength(password):
    """
    Returns: ('weak', 'medium', 'strong')
    Criteria for strong: 
      - length >= 14 with at least 3 different character types, OR
      - length >= 12 with all 4 character types, OR
      - length >= 10 with all 4 character types including special chars
    Criteria for medium: 
      - length >= 8 with at least 3 character types
    Otherwise: weak
    """
    if not password:
        return 'weak'
    
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    criteria_met = sum([has_upper, has_lower, has_digit, has_special])
    
    # Strong password conditions
    if (length >= 14 and criteria_met >= 3) or \
       (length >= 12 and criteria_met >= 4) or \
       (length >= 10 and criteria_met >= 4 and has_special):
        return 'strong'
    # Medium password conditions
    elif length >= 8 and criteria_met >= 3:
        return 'medium'
    # Weak password
    else:
        return 'weak'

# Database Setup
def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE,
                        password TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        google_id TEXT UNIQUE,
                        display_name TEXT
                    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        website TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL,
                        strength TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )''')
    conn.commit()
    conn.close()

init_db()

# Prevent caching for protected pages
@app.after_request
def add_header(response):
    if 'username' in session:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
    return response

@app.route('/', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if form_type == 'register':
            email = request.form.get('email', '').strip()
            if not username or not email or not password:
                return render_template('auth.html', error='All fields are required')
            if len(password) < 8:
                return render_template('auth.html', error='Password must be at least 8 characters long')
            if not validate_email(email):
                return render_template('auth.html', error='Please enter a valid email address')
            
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            # Generate a unique salt for this user
            salt = generate_salt()
            
            try:
                conn = get_db_connection()
                
                # Check if email already exists
                existing_email = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
                if existing_email:
                    conn.close()
                    return render_template('auth.html', error='This email is already registered. Please use a different email or login.')
                
                # Check if username already exists
                existing_user = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
                if existing_user:
                    conn.close()
                    return render_template('auth.html', error='Username already taken. Please choose another username.')
                
                conn.execute("INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)", 
                           (username, email, hashed_pw, salt))
                conn.commit()
                conn.close()
                session['username'] = username
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError as e:
                error_msg = str(e).lower()
                if 'username' in error_msg:
                    return render_template('auth.html', error='Username already exists. Please choose another.')
                elif 'email' in error_msg:
                    return render_template('auth.html', error='This email is already registered. Please use a different email.')
                else:
                    return render_template('auth.html', error='Registration failed. Please try again.')
            except Exception as e:
                print(f"Registration error: {e}")
                return render_template('auth.html', error='An error occurred. Please try again.')
            
        elif form_type == 'login':
            if not username or not password:
                return render_template('auth.html', error='Username/Email and password are required')
            
            try:
                conn = get_db_connection()
                # Check if input is email or username
                # Try to find user by username first, then by email
                cur = conn.execute("SELECT username, password FROM users WHERE username=? OR email=?", (username, username))
                data = cur.fetchone()
                conn.close()
                
                if data and bcrypt.check_password_hash(data['password'], password):
                    # Store the actual username in session (not email)
                    session['username'] = data['username']
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('auth.html', error='Invalid username/email or password')
            except Exception as e:
                print(f"Login error: {e}")
                return render_template('auth.html', error='An error occurred. Please try again.')
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('auth.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('auth'))
    
    # Get user stats
    conn = get_db_connection()
    user = conn.execute("SELECT id, username, display_name FROM users WHERE username=?", (session['username'],)).fetchone()
    
    if not user:
        session.clear()
        return redirect(url_for('auth'))
    
    user_id = user['id']
    display_name = user['display_name'] if user['display_name'] else user['username']
    
    # Get all passwords
    passwords = conn.execute(
        "SELECT id, website, username, password, strength, created_at FROM passwords WHERE user_id=? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    
    # Calculate stats
    total_passwords = len(passwords)
    weak_passwords = sum(1 for p in passwords if p['strength'] == 'weak')
    
    # Calculate security score
    if total_passwords == 0:
        security_score = 100
    else:
        security_score = max(0, 100 - (weak_passwords * 100 // total_passwords))
    
    conn.close()
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         display_name=display_name,
                         passwords=passwords,
                         total_passwords=total_passwords,
                         weak_passwords=weak_passwords,
                         security_score=security_score)

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        website = data.get('website', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        account_password = data.get('accountPassword', '').strip()
        
        if not website or not username or not password or not account_password:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id, password, salt FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify account password
        if not bcrypt.check_password_hash(user['password'], account_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid account password'}), 401
        
        user_id = user['id']
        salt = user['salt']
        
        # Check password strength
        strength = check_password_strength(password)
        
        # Encrypt password using user's account password
        encrypted_password = encrypt_password(password, account_password, salt)
        
        conn.execute(
            "INSERT INTO passwords (user_id, website, username, password, strength) VALUES (?, ?, ?, ?, ?)",
            (user_id, website, username, encrypted_password, strength)
        )
        conn.commit()
        
        # Get updated stats
        passwords = conn.execute("SELECT strength FROM passwords WHERE user_id=?", (user_id,)).fetchall()
        total_passwords = len(passwords)
        weak_passwords = sum(1 for p in passwords if p['strength'] == 'weak')
        security_score = max(0, 100 - (weak_passwords * 100 // total_passwords)) if total_passwords > 0 else 100
        
        conn.close()
        
        return jsonify({
            'success': True,
            'strength': strength,
            'encryptedPassword': encrypted_password,
            'stats': {
                'total_passwords': total_passwords,
                'weak_passwords': weak_passwords,
                'security_score': security_score
            }
        })
    
    except Exception as e:
        print(f"Add password error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/edit_password/<int:password_id>', methods=['PUT'])
def edit_password(password_id):
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        website = data.get('website', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        account_password = data.get('accountPassword', '').strip()
        
        if not website or not username or not password or not account_password:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id, password, salt FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify account password
        if not bcrypt.check_password_hash(user['password'], account_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid account password'}), 401
        
        user_id = user['id']
        salt = user['salt']
        
        # Verify password belongs to user
        existing = conn.execute("SELECT id FROM passwords WHERE id=? AND user_id=?", 
                               (password_id, user_id)).fetchone()
        if not existing:
            conn.close()
            return jsonify({'success': False, 'error': 'Password not found'}), 404
        
        # Check password strength
        strength = check_password_strength(password)
        
        # Encrypt password
        encrypted_password = encrypt_password(password, account_password, salt)
        
        # Update password
        conn.execute(
            "UPDATE passwords SET website=?, username=?, password=?, strength=? WHERE id=? AND user_id=?",
            (website, username, encrypted_password, strength, password_id, user_id)
        )
        conn.commit()
        
        # Get updated stats
        passwords = conn.execute("SELECT strength FROM passwords WHERE user_id=?", (user_id,)).fetchall()
        total_passwords = len(passwords)
        weak_passwords = sum(1 for p in passwords if p['strength'] == 'weak')
        security_score = max(0, 100 - (weak_passwords * 100 // total_passwords)) if total_passwords > 0 else 100
        
        conn.close()
        
        return jsonify({
            'success': True,
            'strength': strength,
            'stats': {
                'total_passwords': total_passwords,
                'weak_passwords': weak_passwords,
                'security_score': security_score
            }
        })
    
    except Exception as e:
        print(f"Edit password error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/delete_password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        account_password = data.get('accountPassword', '').strip()
        
        if not account_password:
            return jsonify({'success': False, 'error': 'Account password is required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id, password FROM users WHERE username=?", (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify account password
        if not bcrypt.check_password_hash(user['password'], account_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Incorrect password'}), 401
        
        user_id = user['id']
        
        # Delete password
        conn.execute("DELETE FROM passwords WHERE id=? AND user_id=?", (password_id, user_id))
        conn.commit()
        
        # Get updated stats
        passwords = conn.execute("SELECT strength FROM passwords WHERE user_id=?", (user_id,)).fetchall()
        total_passwords = len(passwords)
        weak_passwords = sum(1 for p in passwords if p['strength'] == 'weak')
        security_score = max(0, 100 - (weak_passwords * 100 // total_passwords)) if total_passwords > 0 else 100
        
        conn.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_passwords': total_passwords,
                'weak_passwords': weak_passwords,
                'security_score': security_score
            }
        })
    
    except Exception as e:
        print(f"Delete password error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/view_password/<int:password_id>', methods=['POST'])
def view_password(password_id):
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        account_password = data.get('accountPassword', '').strip()
        
        if not account_password:
            return jsonify({'success': False, 'error': 'Account password is required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id, password, salt FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify account password
        if not bcrypt.check_password_hash(user['password'], account_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid account password'}), 401
        
        user_id = user['id']
        salt = user['salt']
        
        # Get the encrypted password
        password_data = conn.execute(
            "SELECT password FROM passwords WHERE id=? AND user_id=?", 
            (password_id, user_id)
        ).fetchone()
        
        if not password_data:
            conn.close()
            return jsonify({'success': False, 'error': 'Password not found'}), 404
        
        # Decrypt the password
        decrypted_password = decrypt_password(password_data['password'], account_password, salt)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'password': decrypted_password
        })
    
    except Exception as e:
        print(f"View password error: {e}")
        return jsonify({'success': False, 'error': 'Failed to decrypt password. Make sure you entered the correct account password.'}), 500

@app.route('/update_display_name', methods=['POST'])
def update_display_name():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        display_name = data.get('displayName', '').strip()
        
        if not display_name:
            return jsonify({'success': False, 'error': 'Display name cannot be empty'}), 400
        
        if len(display_name) > 50:
            return jsonify({'success': False, 'error': 'Display name is too long'}), 400
        
        conn = get_db_connection()
        
        # Get user ID first
        user = conn.execute("SELECT id FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Update ONLY the display_name column (NOT username)
        conn.execute("UPDATE users SET display_name=? WHERE id=?", 
                    (display_name, user['id']))
        conn.commit()
        conn.close()
        
        # Note: session['username'] stays the same (used for login)
        # Only the display_name in the database changes
        
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Update display name error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        
        if not current_password or not new_password:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id, password, salt FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify current password
        if not bcrypt.check_password_hash(user['password'], current_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
        
        user_id = user['id']
        salt = user['salt']
        
        # Get all stored passwords for this user
        stored_passwords = conn.execute(
            "SELECT id, password FROM passwords WHERE user_id=?", 
            (user_id,)
        ).fetchall()
        
        # Decrypt all passwords with old password and re-encrypt with new password
        re_encrypted_passwords = []
        for pwd in stored_passwords:
            try:
                # Decrypt with current password
                decrypted = decrypt_password(pwd['password'], current_password, salt)
                # Re-encrypt with new password
                encrypted = encrypt_password(decrypted, new_password, salt)
                re_encrypted_passwords.append((encrypted, pwd['id']))
            except Exception as e:
                print(f"Error re-encrypting password {pwd['id']}: {e}")
                conn.close()
                return jsonify({'success': False, 'error': 'Failed to re-encrypt stored passwords'}), 500
        
        # Update user's account password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        conn.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, user_id))
        
        # Update all stored passwords with re-encrypted versions
        for encrypted, pwd_id in re_encrypted_passwords:
            conn.execute("UPDATE passwords SET password=? WHERE id=?", (encrypted, pwd_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Change password error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred while changing password'}), 500

@app.route('/admin/users')
def list_users():
    """
    Admin route to list all registered users
    Note: In production, add authentication/authorization to restrict access
    """
    try:
        conn = get_db_connection()
        users = conn.execute("""
            SELECT 
                u.id,
                u.username,
                u.email,
                u.display_name,
                COUNT(p.id) as password_count,
                MIN(p.created_at) as first_password_added,
                MAX(p.created_at) as last_password_added
            FROM users u
            LEFT JOIN passwords p ON u.id = p.user_id
            GROUP BY u.id
            ORDER BY u.id DESC
        """).fetchall()
        conn.close()
        
        # Convert to list of dicts for easier display
        user_list = []
        for user in users:
            user_list.append({
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'display_name': user['display_name'] or user['username'],
                'password_count': user['password_count'],
                'first_password_added': user['first_password_added'],
                'last_password_added': user['last_password_added']
            })
        
        return jsonify({
            'success': True,
            'total_users': len(user_list),
            'users': user_list
        })
    
    except Exception as e:
        print(f"List users error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/auth/google')
def google_login():
    """Initiate Google OAuth flow"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return jsonify({'success': False, 'error': 'Google OAuth not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.'}), 500
    
    # Create flow instance to manage OAuth flow
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [url_for('google_callback', _external=True)]
            }
        },
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
    )
    
    flow.redirect_uri = url_for('google_callback', _external=True)
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='select_account'
    )
    
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            return redirect(url_for('auth', error='Google OAuth not configured'))
        
        # Verify state to prevent CSRF
        state = session.get('oauth_state')
        if not state or state != request.args.get('state'):
            return redirect(url_for('auth', error='Invalid state parameter'))
        
        # Create flow instance
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [url_for('google_callback', _external=True)]
                }
            },
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
        )
        
        flow.redirect_uri = url_for('google_callback', _external=True)
        
        # Exchange authorization code for credentials
        flow.fetch_token(authorization_response=request.url)
        
        # Get user info from Google
        credentials = flow.credentials
        request_session = google_requests.Request()
        
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            request_session,
            GOOGLE_CLIENT_ID
        )
        
        google_id = id_info.get('sub')
        email = id_info.get('email')
        name = id_info.get('name', email.split('@')[0])
        
        # Check if user exists
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE google_id=? OR email=?", (google_id, email)).fetchone()
        
        if user:
            # Update google_id if user logged in with email/password before
            if not user['google_id']:
                conn.execute("UPDATE users SET google_id=? WHERE id=?", (google_id, user['id']))
                conn.commit()
            session['username'] = user['username']
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            # Create new user with Google account - but WITHOUT a password yet
            # Generate a username from email
            base_username = email.split('@')[0]
            username = base_username
            counter = 1
            
            # Ensure unique username
            while conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                username = f"{base_username}{counter}"
                counter += 1
            
            # Store user info in session - they need to set password first
            session['pending_oauth_user'] = {
                'username': username,
                'email': email,
                'google_id': google_id,
                'display_name': name
            }
            
            conn.close()
            # Redirect to set password page
            return redirect(url_for('set_password_page'))
        
    except Exception as e:
        print(f"Google OAuth error: {e}")
        return redirect(url_for('auth', error='Failed to authenticate with Google. Please try again.'))

@app.route('/set_password', methods=['GET', 'POST'])
def set_password_page():
    """Page for new OAuth users to set their password"""
    # Check if user has pending OAuth account
    if 'pending_oauth_user' not in session:
        return redirect(url_for('auth'))
    
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Validation
        if not password or not confirm_password:
            return render_template('set_password.html', error='Both password fields are required')
        
        if password != confirm_password:
            return render_template('set_password.html', error='Passwords do not match')
        
        if len(password) < 8:
            return render_template('set_password.html', error='Password must be at least 8 characters long')
        
        # Create the user account with the password
        try:
            pending_user = session['pending_oauth_user']
            
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            salt = generate_salt()
            
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO users (username, email, password, salt, google_id, display_name) VALUES (?, ?, ?, ?, ?, ?)",
                (pending_user['username'], pending_user['email'], hashed_pw, salt, pending_user['google_id'], pending_user['display_name'])
            )
            conn.commit()
            conn.close()
            
            # Set session username and clear pending user
            session['username'] = pending_user['username']
            session.pop('pending_oauth_user', None)
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            print(f"Set password error: {e}")
            return render_template('set_password.html', error='An error occurred. Please try again.')
    
    return render_template('set_password.html')

@app.route('/import_passwords', methods=['POST'])
def import_passwords():
    """Import passwords from CSV file (e.g., exported from Google Password Manager)"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.csv'):
            return jsonify({'success': False, 'error': 'Only CSV files are supported'}), 400
        
        # Get account password for encryption
        account_password = request.form.get('accountPassword', '').strip()
        
        if not account_password:
            return jsonify({'success': False, 'error': 'Account password is required'}), 400
        
        # Get user info
        conn = get_db_connection()
        user = conn.execute("SELECT id, password, salt FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify account password
        if not bcrypt.check_password_hash(user['password'], account_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid account password'}), 401
        
        user_id = user['id']
        salt = user['salt']
        
        # Read and parse CSV file
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        
        imported_count = 0
        skipped_count = 0
        errors = []
        
        # Expected CSV format from Google Password Manager:
        # name,url,username,password
        for row in csv_reader:
            try:
                # Handle different CSV formats (Google uses 'name', 'url', 'username', 'password')
                website = row.get('name') or row.get('url') or row.get('website', '').strip()
                username = row.get('username', '').strip()
                password = row.get('password', '').strip()
                
                if not website or not username or not password:
                    skipped_count += 1
                    continue
                
                # Check if password already exists for this website
                existing = conn.execute(
                    "SELECT id FROM passwords WHERE user_id=? AND website=? AND username=?",
                    (user_id, website, username)
                ).fetchone()
                
                if existing:
                    skipped_count += 1
                    continue
                
                # Check password strength
                strength = check_password_strength(password)
                
                # Encrypt password
                encrypted_password = encrypt_password(password, account_password, salt)
                
                # Insert into database
                conn.execute(
                    "INSERT INTO passwords (user_id, website, username, password, strength) VALUES (?, ?, ?, ?, ?)",
                    (user_id, website, username, encrypted_password, strength)
                )
                
                imported_count += 1
                
            except Exception as e:
                errors.append(f"Row error: {str(e)}")
                skipped_count += 1
                continue
        
        conn.commit()
        
        # Get updated stats
        passwords = conn.execute("SELECT strength FROM passwords WHERE user_id=?", (user_id,)).fetchall()
        total_passwords = len(passwords)
        weak_passwords = sum(1 for p in passwords if p['strength'] == 'weak')
        security_score = max(0, 100 - (weak_passwords * 100 // total_passwords)) if total_passwords > 0 else 100
        
        conn.close()
        
        return jsonify({
            'success': True,
            'imported': imported_count,
            'skipped': skipped_count,
            'errors': errors[:5],  # Return first 5 errors only
            'stats': {
                'total_passwords': total_passwords,
                'weak_passwords': weak_passwords,
                'security_score': security_score
            }
        })
        
    except Exception as e:
        print(f"Import passwords error: {e}")
        return jsonify({'success': False, 'error': f'Failed to import passwords: {str(e)}'}), 500

@app.route('/delete_all_passwords', methods=['DELETE'])
def delete_all_passwords():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        account_password = data.get('accountPassword', '').strip()
        
        if not account_password:
            return jsonify({'success': False, 'error': 'Account password is required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id, password FROM users WHERE username=?", (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify account password
        if not bcrypt.check_password_hash(user['password'], account_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Incorrect password'}), 401
        
        user_id = user['id']
        
        # Get count of passwords to be deleted
        count_result = conn.execute("SELECT COUNT(*) as count FROM passwords WHERE user_id=?", (user_id,)).fetchone()
        deleted_count = count_result['count']
        
        # Delete all passwords for this user
        conn.execute("DELETE FROM passwords WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'deleted_count': deleted_count
        })
    
    except Exception as e:
        print(f"Delete all passwords error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/export_passwords', methods=['POST'])
def export_passwords():
    """Export all passwords to CSV file after authentication"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        account_password = data.get('accountPassword', '').strip()
        
        if not account_password:
            return jsonify({'success': False, 'error': 'Account password is required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id, password, salt FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify account password
        if not bcrypt.check_password_hash(user['password'], account_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Incorrect password'}), 401
        
        user_id = user['id']
        salt = user['salt']
        
        # Get all passwords for this user
        passwords = conn.execute(
            "SELECT website, username, password, strength, created_at FROM passwords WHERE user_id=? ORDER BY website",
            (user_id,)
        ).fetchall()
        
        conn.close()
        
        if not passwords:
            return jsonify({'success': False, 'error': 'No passwords to export'}), 400
        
        # Create CSV in memory
        output = io.StringIO()
        csv_writer = csv.writer(output)
        
        # Write header
        csv_writer.writerow(['Website', 'Username', 'Password', 'Strength', 'Created At'])
        
        # Write data - decrypt passwords before exporting
        for pwd in passwords:
            try:
                decrypted_password = decrypt_password(pwd['password'], account_password, salt)
                csv_writer.writerow([
                    pwd['website'],
                    pwd['username'],
                    decrypted_password,
                    pwd['strength'],
                    pwd['created_at']
                ])
            except Exception as e:
                print(f"Error decrypting password for {pwd['website']}: {e}")
                continue
        
        # Get CSV content
        csv_content = output.getvalue()
        output.close()
        
        return jsonify({
            'success': True,
            'csv_data': csv_content,
            'filename': f'cipher_vault_passwords_{session["username"]}.csv'
        })
    
    except Exception as e:
        print(f"Export passwords error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred while exporting passwords'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth'))

# ==================== Extension API Endpoints ====================

@app.route('/api/login', methods=['POST'])
def api_login():
    """API endpoint for extension login"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password are required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT username, password FROM users WHERE username=? OR email=?", 
                           (username, username)).fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            # Create a session ID
            import secrets
            session_id = secrets.token_urlsafe(32)
            
            # Store session
            session['username'] = user['username']
            session['extension_session_id'] = session_id
            
            return jsonify({
                'success': True,
                'username': user['username'],
                'sessionId': session_id
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
    
    except Exception as e:
        print(f"API login error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/api/passwords', methods=['GET'])
def api_get_passwords():
    """API endpoint to get all passwords for extension"""
    session_id = request.headers.get('X-Session-ID')
    
    if not session_id or 'extension_session_id' not in session or session.get('extension_session_id') != session_id:
        if 'username' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        user_id = user['id']
        
        # Get all passwords (without decrypting them)
        passwords = conn.execute(
            "SELECT id, website, username, strength, created_at FROM passwords WHERE user_id=? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
        
        conn.close()
        
        passwords_list = [{
            'id': pwd['id'],
            'website': pwd['website'],
            'username': pwd['username'],
            'strength': pwd['strength'],
            'created_at': pwd['created_at']
        } for pwd in passwords]
        
        return jsonify({
            'success': True,
            'passwords': passwords_list
        })
    
    except Exception as e:
        print(f"API get passwords error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/api/decrypt_password', methods=['POST'])
def api_decrypt_password():
    """API endpoint to decrypt a specific password"""
    session_id = request.headers.get('X-Session-ID')
    
    if not session_id or 'extension_session_id' not in session or session.get('extension_session_id') != session_id:
        if 'username' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        password_id = data.get('passwordId')
        account_password = data.get('accountPassword', '').strip()
        
        if not password_id or not account_password:
            return jsonify({'success': False, 'error': 'Password ID and account password are required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id, password, salt FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Verify account password
        if not bcrypt.check_password_hash(user['password'], account_password):
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid account password'}), 401
        
        user_id = user['id']
        salt = user['salt']
        
        # Get the encrypted password
        password_data = conn.execute(
            "SELECT password FROM passwords WHERE id=? AND user_id=?", 
            (password_id, user_id)
        ).fetchone()
        
        if not password_data:
            conn.close()
            return jsonify({'success': False, 'error': 'Password not found'}), 404
        
        # Decrypt the password
        decrypted_password = decrypt_password(password_data['password'], account_password, salt)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'password': decrypted_password
        })
    
    except Exception as e:
        print(f"API decrypt password error: {e}")
        return jsonify({'success': False, 'error': 'Failed to decrypt password'}), 500

@app.route('/api/delete_password', methods=['POST'])
def api_delete_password():
    """API endpoint to delete a password"""
    session_id = request.headers.get('X-Session-ID')
    
    if not session_id or 'extension_session_id' not in session or session.get('extension_session_id') != session_id:
        if 'username' not in session:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        password_id = data.get('passwordId')
        
        if not password_id:
            return jsonify({'success': False, 'error': 'Password ID is required'}), 400
        
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE username=?", 
                           (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        user_id = user['id']
        
        # Delete password
        conn.execute("DELETE FROM passwords WHERE id=? AND user_id=?", (password_id, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"API delete password error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

if __name__ == "__main__":
    app.run(debug=True)
