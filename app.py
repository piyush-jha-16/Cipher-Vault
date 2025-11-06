from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = "super_secret_key"
bcrypt = Bcrypt(app)

# Database Setup
def init_db():
    conn = sqlite3.connect('database.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT NOT NULL
                    )''')
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

        if not username or not password:
            return render_template('auth.html', error='Username and password are required')

        if form_type == 'register':
            if len(password) < 8:
                return render_template('auth.html', error='Password must be at least 8 characters long')
            
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            try:
                conn = sqlite3.connect('database.db')
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
                conn.close()
                session['username'] = username
                return redirect(url_for('dashboard'))
            except:
                return render_template('auth.html', error='Username already exists. Please choose another.')
        
        elif form_type == 'login':
            conn = sqlite3.connect('database.db')
            cur = conn.execute("SELECT password FROM users WHERE username=?", (username,))
            data = cur.fetchone()
            conn.close()
            if data and bcrypt.check_password_hash(data[0], password):
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                return render_template('auth.html', error='Invalid username or password')

    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('auth.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('auth'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('auth'))

if __name__ == "__main__":
    app.run(debug=True)
