from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
import sqlite3
import os
import re
from utils.encryption import encrypt_password, decrypt_password, generate_salt

app = Flask(__name__)
app.secret_key = "super_secret_key"
bcrypt = Bcrypt(app)

# Database helper function
def get_db_connection():
    conn = sqlite3.connect('database.db', timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

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
                        salt TEXT NOT NULL
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
            if '@' not in email or '.' not in email.split('@')[1]:
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
                return render_template('auth.html', error='Username and password are required')
            
            try:
                conn = get_db_connection()
                cur = conn.execute("SELECT password FROM users WHERE username=?", (username,))
                data = cur.fetchone()
                conn.close()
                
                if data and bcrypt.check_password_hash(data['password'], password):
                    session['username'] = username
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('auth.html', error='Invalid username or password')
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
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE username=?", (session['username'],)).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth'))

if __name__ == "__main__":
    app.run(debug=True)
