# 🔐 Cipher Vault - Secure Password Manager

<div align="center">
  <img src="https://img.shields.io/badge/Security-AES--256%20Encryption-brightgreen" alt="Security Badge"/>
  <img src="https://img.shields.io/badge/Encryption-Fernet-blue" alt="Encryption Badge"/>
  <img src="https://img.shields.io/badge/Python-3.8+-yellow" alt="Python Badge"/>
  <img src="https://img.shields.io/badge/Flask-3.0.0-red" alt="Flask Badge"/>
</div>

A modern, secure password manager with military-grade encryption, Google OAuth integration, and a beautiful user interface. Store, manage, and organize your passwords with confidence.

---

## ✨ Features

### 🔒 Advanced Security
- **Fernet Encryption (AES-256)** - Military-grade password encryption
- **Bcrypt Password Hashing** - Secure account password storage with salt
- **User-Specific Encryption** - Unique salt for each user
- **Password Authentication** - Account password required for all sensitive operations
- **Automatic Re-encryption** - All passwords re-encrypted when account password changes
- **Password Strength Analysis** - Real-time password quality feedback
  - **Strong**: 14+ chars with 3+ types OR 12+ chars with all 4 types OR 10+ chars with all 4 types including special
  - **Medium**: 8+ chars with 3+ character types
  - **Weak**: Everything else

### 🎨 Modern UI/UX
- **Glass Morphism Design** - Contemporary, translucent interface
- **Dark/Light Theme** - Toggle between themes with localStorage persistence
- **Toast Notifications** - Beautiful animated success/error/warning/info messages
- **Responsive Design** - Perfect on desktop, tablet, and mobile devices
- **Smooth Animations** - Delightful transitions and micro-interactions
- **Search Functionality** - Real-time password filtering by website or username

### 💼 Password Management
- **Add Passwords** - Save credentials with automatic strength detection
- **Edit Passwords** - Update stored credentials anytime
- **View Passwords** - Decrypt and view passwords with authentication
- **Delete Passwords** - Remove individual passwords with confirmation
- **Delete All** - Bulk delete all passwords with authentication
- **Copy to Clipboard** - One-click password copying
- **Password Generator** - Create strong random passwords (8-32 characters)
  - Customizable character types (uppercase, lowercase, numbers, symbols)
  - Real-time strength indicator

### 📊 Dashboard Statistics
- **Total Passwords** - Track how many passwords you've stored
- **Weak Passwords** - Monitor passwords that need strengthening
- **Security Score** - Overall vault security rating (0-100)
- **Password Strength Distribution** - Visual breakdown by strength level

### 🔄 Import/Export
- **Import Passwords** - Import from CSV files (Google Password Manager format supported)
- **Export Passwords** - Download all passwords as CSV with authentication
- **Automatic Encryption** - Imported passwords encrypted immediately

### 🔐 Google OAuth Integration
- **Sign in with Google** - Quick authentication using Google account
- **OAuth Password Setup** - First-time users set account password for encryption
- **Account Linking** - Link Google account to existing email accounts

### ⚙️ Account Management
- **Display Name** - Customize your display name
- **Username** - Unique login identifier (immutable)
- **Change Password** - Update account password with automatic password re-encryption
- **Settings Modal** - Centralized account management

---

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

3. **Configure Google OAuth (Optional)**

Create a `.env` file in the root directory:
```env
SECRET_KEY=your-secret-key-here
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

To get Google OAuth credentials:
- Go to [Google Cloud Console](https://console.cloud.google.com/)
- Create a new project or select existing one
- Enable Google+ API
- Create OAuth 2.0 credentials
- Add `http://127.0.0.1:5000/auth/google/callback` as authorized redirect URI

4. **Run the Application**
```bash
python app.py
```

5. **Access the Application**
```
Open your browser and navigate to: http://127.0.0.1:5000
```

---

## 📦 Project Structure

```
Cipher-Vault/
├── app.py                          # Flask application with all routes
├── requirements.txt                # Python dependencies
├── database.db                     # SQLite database (auto-created)
├── .env                           # Environment variables (create this)
├── static/
│   ├── css/
│   │   └── style.css              # Custom styles and theme variables
│   └── js/
│       └── script.js              # Client-side utilities
├── templates/
│   ├── auth.html                  # Login/Register page with OAuth
│   ├── base.html                  # Base template
│   ├── dashboard.html             # Main dashboard with all features
│   └── set_password.html          # OAuth password setup page
└── utils/
    └── encryption.py              # Fernet encryption/decryption functions
```

---

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password TEXT NOT NULL,              -- Bcrypt hashed
    salt TEXT NOT NULL,                  -- Unique encryption salt
    google_id TEXT UNIQUE,               -- Google OAuth ID
    display_name TEXT                    -- User's display name
);
```

### Passwords Table
```sql
CREATE TABLE passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,              -- Fernet encrypted
    strength TEXT NOT NULL,              -- weak/medium/strong
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

---

## 🔧 Technologies Used

### Backend
- **Flask 3.0.0** - Web framework
- **Flask-Bcrypt 1.0.1** - Password hashing
- **cryptography 41.0.7** - Fernet (AES-256) encryption
- **SQLite** - Database
- **google-auth** - Google OAuth authentication
- **python-dotenv** - Environment variable management

### Frontend
- **HTML5/CSS3** - Modern semantic markup
- **JavaScript (ES6+)** - Interactive features
- **Tailwind CSS** (via CDN) - Utility-first styling
- **Font Awesome 6** - Icon library

---

## 🔐 Security Architecture

### Encryption Flow

**Adding/Editing Password:**
1. User enters account password for verification
2. Bcrypt verifies account password hash
3. Encryption key derived: `PBKDF2(account_password + user_salt, SHA256)`
4. Password encrypted with Fernet using derived key
5. Encrypted password stored in database

**Viewing Password:**
1. User re-authenticates with account password
2. System verifies password
3. Encryption key regenerated using same method
4. Password decrypted with Fernet
5. Plaintext displayed temporarily

**Changing Account Password:**
1. Current password verified
2. All stored passwords decrypted with old key
3. All passwords re-encrypted with new key
4. Account password hash updated
5. All passwords saved with new encryption

### Security Features

✅ **Zero-Knowledge Architecture** - Encryption keys never stored  
✅ **Per-User Encryption** - Unique salt for each user  
✅ **Re-authentication** - Password required for sensitive operations  
✅ **Session Security** - Secure Flask sessions with secret key  
✅ **Input Sanitization** - XSS protection via Jinja2 escaping  
✅ **Password Strength Validation** - Client and server-side  
✅ **Secure Password Generation** - Cryptographically random passwords  

---

## 🎨 Key Features

### Search Functionality
Real-time search filters passwords by website name or username as you type. Shows "No results found" message when no matches exist.

### Quick Actions
- **Import Passwords** - Bulk import from CSV
- **Export Data** - Download encrypted backup
- **Delete All** - Bulk delete with authentication

### Theme System
Dark and light themes with smooth transitions. Theme preference persists across sessions using localStorage.

### Toast Notifications
Custom notification system replacing browser alerts:
- Success (green), Error (red), Warning (orange), Info (blue)
- Auto-dismiss after 3 seconds
- Smooth animations

---

## 📱 Responsive Design

- **Mobile (< 640px)**: Optimized single column layout
- **Tablet (640px - 1024px)**: Two column grid
- **Desktop (> 1024px)**: Full three column layout
- **Touch Optimized**: Large tap targets and swipe-friendly

---

## 🔒 Privacy & Security

- **No Telemetry** - No tracking or analytics
- **Local Database** - All data stored locally in SQLite
- **Open Source** - Full transparency, audit the code yourself
- **No Third-Party Services** - Except optional Google OAuth

---

## 📄 License

This project is open source and available for educational purposes.

## 👨‍💻 Developer

**Piyush Jha**  
GitHub: [@piyush-jha-16](https://github.com/piyush-jha-16)
Instagram: [@_piyushjha16](https://instagram.com/_piyushjha16)

---

<div align="center">
  <strong>Built with ❤️ for Secure Password Management</strong>
  <br>
  <sub>Protecting your digital life, one password at a time</sub>
</div>
