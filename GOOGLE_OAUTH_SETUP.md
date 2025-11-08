# Google OAuth Setup Guide

This guide will help you set up Google OAuth authentication for Cipher-Vault.

## Prerequisites
- A Google account
- Python 3.7+ installed
- Cipher-Vault project set up locally

## Step 1: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a project" → "NEW PROJECT"
3. Enter project name: `Cipher-Vault` (or any name you prefer)
4. Click "CREATE"

## Step 2: Enable Google+ API

1. In the left sidebar, go to **APIs & Services** → **Library**
2. Search for "Google+ API"
3. Click on it and press **ENABLE**

## Step 3: Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Select **External** (for testing with any Google account)
3. Click **CREATE**
4. Fill in the required fields:
   - **App name**: `Cipher-Vault`
   - **User support email**: Your email
   - **Developer contact information**: Your email
5. Click **SAVE AND CONTINUE**
6. On the "Scopes" page, click **ADD OR REMOVE SCOPES**
7. Add these scopes (they should be pre-selected):
   - `openid`
   - `https://www.googleapis.com/auth/userinfo.email`
   - `https://www.googleapis.com/auth/userinfo.profile`
8. Click **UPDATE** → **SAVE AND CONTINUE**
9. On "Test users" page (optional for development):
   - Click **ADD USERS**
   - Add your Gmail address
10. Click **SAVE AND CONTINUE** → **BACK TO DASHBOARD**

## Step 4: Create OAuth 2.0 Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **+ CREATE CREDENTIALS** → **OAuth client ID**
3. Choose **Web application**
4. Configure:
   - **Name**: `Cipher-Vault Web Client`
   - **Authorized JavaScript origins**: 
     - For local development: `http://localhost:5000`
     - For production: `https://yourdomain.com`
   - **Authorized redirect URIs**:
     - For local development: `http://localhost:5000/auth/google/callback`
     - For production: `https://yourdomain.com/auth/google/callback`
5. Click **CREATE**
6. **IMPORTANT**: Copy your **Client ID** and **Client Secret**
   - You'll need these in the next step!

## Step 5: Set Environment Variables

### Windows (PowerShell)
```powershell
$env:GOOGLE_CLIENT_ID = "your-client-id-here.apps.googleusercontent.com"
$env:GOOGLE_CLIENT_SECRET = "your-client-secret-here"
$env:SECRET_KEY = "your-random-secret-key-here"
```

### Linux/Mac (Bash)
```bash
export GOOGLE_CLIENT_ID="your-client-id-here.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret-here"
export SECRET_KEY="your-random-secret-key-here"
```

### For Production (Render, Heroku, etc.)
Add these as environment variables in your hosting platform's dashboard:
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `SECRET_KEY`

## Step 6: Install Required Packages

```powershell
# Activate your virtual environment first
.\.venv\Scripts\Activate.ps1

# Install the new dependencies
pip install -r requirements.txt
```

## Step 7: Update Database Schema

Run the migration script to add the `google_id` column:

```powershell
python migrate_google_auth.py
```

## Step 8: Test Google OAuth

1. Start the Flask app:
```powershell
python app.py
```

2. Open your browser and go to `http://localhost:5000`

3. Click "Continue with Google" on the login page

4. You should be redirected to Google's login page

5. After logging in, you'll be redirected back to the dashboard

## Troubleshooting

### "redirect_uri_mismatch" Error
- Make sure the redirect URI in Google Cloud Console exactly matches:
  - `http://localhost:5000/auth/google/callback` (for local dev)
  - Make sure there's no trailing slash
  - Check the port number matches

### "Google OAuth not configured" Error
- Verify environment variables are set correctly
- Restart the Flask app after setting environment variables
- Print the values to confirm they're loaded:
  ```python
  print(f"CLIENT_ID: {os.environ.get('GOOGLE_CLIENT_ID')}")
  ```

### "invalid_client" Error
- Double-check your Client ID and Client Secret
- Make sure there are no extra spaces or quotes

### Development vs Production
- For local development: The app uses `OAUTHLIB_INSECURE_TRANSPORT=1` to allow HTTP
- **For production**: Remove this setting and use HTTPS only!

## Google Password Import Feature

Users can import their passwords from Google Password Manager:

1. Go to [passwords.google.com](https://passwords.google.com)
2. Click the gear icon (Settings)
3. Click "Export passwords"
4. Download the CSV file
5. In Cipher-Vault dashboard, click "Import" button
6. Upload the CSV file and enter your account password
7. Passwords will be imported and encrypted

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never commit credentials to Git**:
   - Add `.env` file to `.gitignore` if using one
   - Use environment variables only

2. **Production deployment**:
   - Always use HTTPS
   - Remove `OAUTHLIB_INSECURE_TRANSPORT` setting
   - Use strong, random SECRET_KEY (32+ characters)
   - Enable Google Cloud Project in production mode

3. **OAuth consent screen**:
   - For public deployment, submit app for verification
   - Until verified, show "unverified app" warning to users

4. **Password import**:
   - CSV files contain plain-text passwords
   - Advise users to delete CSV files after import
   - Imported passwords are encrypted with user's account password

## Need Help?

If you encounter issues:
1. Check the Flask app console for error messages
2. Verify all environment variables are set
3. Ensure Google Cloud Project is configured correctly
4. Check that redirect URIs match exactly
