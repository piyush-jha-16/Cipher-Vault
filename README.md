# 🔐 Cipher Vault - Secure Password Manager

<div align="center">
  <img src="https://img.shields.io/badge/Security-AES--256%20Encryption-brightgreen" alt="Security Badge"/>
  <img src="https://img.shields.io/badge/Encryption-Fernet-blue" alt="Encryption Badge"/>
  <img src="https://img.shields.io/badge/Python-3.8+-yellow" alt="Python Badge"/>
  <img src="https://img.shields.io/badge/Flask-3.0.0-red" alt="Flask Badge"/>
</div>

## ✨ Features

### 🔒 Advanced Security
- **Fernet Encryption (AES-256)** - Military-grade password encryption with user-specific keys
- **Bcrypt Password Hashing** - Secure account password storage
- **User-Specific Salt** - Unique encryption salt for each user
- **Re-authentication Required** - Must enter account password to view stored passwords
- **Automatic Re-encryption** - All passwords re-encrypted when account password changes
- **Password Strength Validation** - Real-time password quality feedback with updated criteria
- **Secure Password Generator** - Cryptographically secure random passwords (8-32 characters)

### 🎨 Modern UI/UX
- **Glass Morphism Design** - Contemporary, translucent interface
- **Custom Toast Notifications** - Beautiful animated notifications (success/error/warning/info)
- **Success Modal** - Shows encrypted password after saving with security tips
- **View Password Modal** - Clean interface with re-authentication and security tips
- **Settings Modal** - Comprehensive account management
- **Dark/Light Theme** - Toggle between themes with persistent preference
- **Responsive Design** - Perfect on desktop, tablet, and mobile
- **Smooth Animations** - Delightful transitions and micro-interactions

### 💼 Dashboard Features
- **Real-time Statistics** - Total passwords, weak passwords count, security score
- **Password Management** - Add, edit, view, and delete passwords
- **Search Functionality** - Quick password lookup
- **Password Strength Indicator** - Visual strength meter with updated criteria:
  - Strong: 14+ chars with 3 char types OR 12+ chars with all 4 types
  - Medium: 10+ chars with 2+ char types
  - Weak: Everything else
- **Quick Actions** - Add password, generate password
- **Security Score** - Monitor vault security health (0-100)

### ⚙️ Settings & Account Management
- **Display Name** - Customize your display name (shown in UI)
- **Username** - Immutable login ID (shown but cannot be changed)
- **Password Change** - Change account password with automatic re-encryption of all stored passwords
- **Logout** - Secure session termination

### 🎯 Recent Enhancements

#### Encryption System
- Implemented Fernet (AES-256) encryption for stored passwords
- Each user has a unique salt stored in the database
- Encryption key derived from user's account password + salt
- Passwords encrypted before storage, decrypted only when viewed
- Re-authentication required to view passwords

#### UI Improvements
- Replaced default JavaScript alerts with custom toast notifications
- Success modal shows encrypted password after saving
- View password modal redesigned with security tips
- Settings modal with profile, security, and danger zone sections
- All modals match the application's design language

#### Bug Fixes
- Fixed password visibility toggle to work with all password fields
- Fixed password change form submission (wrapped in DOMContentLoaded)
- Separated display name from username (username for login, display name for UI)
- Fixed navbar update after display name change

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone the Repository**
```bash
git clone https://github.com/piyush-jha-16/Cipher-Vault.git
cd Cipher-Vault
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the Application**
```bash
python app.py
```

4. **Access the Application**
```
Open your browser and navigate to: http://127.0.0.1:5000
```

## 📦 Project Structure

```
Cipher-Vault/
├── app.py                          # Flask application with all routes
├── requirements.txt                # Python dependencies
├── database.db                     # SQLite database (created on first run)
├── migrate_database.py             # Migration script for salt column
├── migrate_display_name.py         # Migration script for display_name column
├── static/
│   ├── css/
│   │   └── style.css              # Custom styles and utilities
│   └── js/
│       └── script.js              # Password strength calculation
├── templates/
│   ├── auth.html                  # Login/Register page
│   ├── base.html                  # Base template (not currently used)
│   └── dashboard.html             # Main dashboard with all features
└── utils/
    └── encryption.py              # Fernet encryption/decryption utilities
```

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,        -- Login ID (immutable)
    display_name TEXT,                    -- Display name (can be changed)
    password TEXT NOT NULL,               -- Bcrypt hashed account password
    email TEXT,                           -- User email (optional)
    salt TEXT NOT NULL,                   -- Unique salt for encryption
    is_verified INTEGER DEFAULT 0,
    verification_code TEXT,
    code_expiry TEXT
);
```

### Passwords Table
```sql
CREATE TABLE passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,               -- Fernet encrypted password
    strength TEXT NOT NULL,               -- weak/medium/strong
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## 🔧 Technologies Used

### Backend
- **Flask 3.0.0** - Web framework
- **Flask-Bcrypt 1.0.1** - Password hashing for account passwords
- **cryptography 41.0.7** - Fernet encryption for stored passwords
- **SQLite** - Database

### Frontend
- **HTML5/CSS3** - Modern markup and styling
- **JavaScript (ES6+)** - Interactive features
- **Tailwind CSS** (via CDN) - Utility-first CSS framework
- **Font Awesome 6** - Icons

## 🔐 Security Architecture

### Password Encryption Flow

**When Adding/Editing Password:**
1. User enters their account password for verification
2. System verifies account password using bcrypt
3. System retrieves user's unique salt from database
4. Encryption key generated: `PBKDF2(account_password + salt, SHA256)`
5. Password encrypted using Fernet with generated key
6. Encrypted password stored in database

**When Viewing Password:**
1. User must re-enter their account password
2. System verifies account password
3. System retrieves user's salt
4. Same encryption key regenerated
5. Password decrypted using Fernet
6. Plain text password shown in modal

**When Changing Account Password:**
1. User enters current and new password
2. System verifies current password
3. System fetches ALL stored passwords for the user
4. Each password is:
   - Decrypted using current password
   - Re-encrypted using new password
5. All passwords updated in database
6. Account password hash updated
7. User logged out (must login with new password)

### Security Best Practices Implemented

✅ **No Plain Text Storage** - Passwords always encrypted before storage  
✅ **Key Derivation** - Encryption keys derived from user password (never stored)  
✅ **Unique Salts** - Each user has a unique salt for key derivation  
✅ **Re-authentication** - Account password required to view passwords  
✅ **Session Security** - Flask session management with secret key  
✅ **Password Strength Validation** - Both client and server-side  
✅ **Automatic Re-encryption** - When account password changes  
✅ **Input Validation** - XSS prevention with HTML escaping  

## 🎨 UI Components

### Toast Notifications
- **Success** - Green with checkmark icon
- **Error** - Red with X icon
- **Warning** - Yellow/orange with exclamation icon
- **Info** - Blue with info icon
- Smooth slide-in/slide-out animations (300ms)
- Auto-dismiss after 3 seconds

### Modals
- **Add/Edit Password** - Form with account password verification
- **View Password** - Shows website, username, decrypted password, security tip
- **Success Modal** - Shows encrypted password after saving
- **Password Generator** - Customizable length (8-32 characters)
- **Settings Modal** - Profile, security, and logout sections

## 📱 Responsive Design

- **Mobile (< 640px)**: Single column layout, touch-optimized
- **Tablet (640px - 1024px)**: Two column grid
- **Desktop (> 1024px)**: Three column grid with full features
- **Touch Friendly**: Large buttons and input fields

## 🎯 Future Enhancements

- [ ] Two-Factor Authentication (2FA)
- [ ] Password breach detection (Have I Been Pwned API)
- [ ] Biometric authentication
- [ ] Browser extension
- [ ] Password sharing with other users
- [ ] Password categories/folders
- [ ] Audit logs (track password access)
- [ ] Export/Import passwords (encrypted backup)
- [ ] Password history (track changes)
- [ ] Email verification on signup

## � Known Issues

- Flask-Mail is listed in requirements.txt but not currently used (planned for future email verification)

## 📄 License

This project is for educational and demonstration purposes.

## 👨‍💻 Developer

**Piyush Jha** ([@piyush-jha-16](https://github.com/piyush-jha-16))

---

<div align="center">
  <strong>Built with ❤️ for Secure Password Management</strong>
</div>
