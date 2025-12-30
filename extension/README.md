# Cipher Vault Browser Extension

A secure browser extension for managing and auto-saving passwords with the Cipher Vault password manager.

## Features

✅ **Auto-Save Passwords**: Automatically detects login forms and prompts to save credentials  
✅ **Secure Storage**: All passwords are encrypted using your master password  
✅ **Quick Access**: View and manage passwords directly from the browser  
✅ **Password Strength**: Automatically checks and displays password strength  
✅ **Search**: Quickly find saved passwords by website or username  
✅ **Copy to Clipboard**: One-click password copying  

## Installation

### 1. Set Up the Backend

The extension is configured to connect to your production server at:
`https://cipher-vault-1.onrender.com`

**For Local Development:**
If you want to test with a local backend, update `popup/popup.js` and change:
```javascript
const API_BASE_URL = 'http://localhost:5000';
```

Then start your local server:
```bash
cd d:\Projects\Cipher-Vault
python app.py
```

### 2. Generate Icons (Optional)

The extension needs icon files. You can either:

- Use the provided SVG icon and convert it to PNG formats (16x16, 48x48, 128x128), OR
- Create your own icons and save them as:
  - `icons/icon16.png`
  - `icons/icon48.png`
  - `icons/icon128.png`

To generate icons from the SVG:
1. Open `icons/generate-icons.html` in a browser
2. Right-click on the canvas and save as image for each size

### 3. Load the Extension in Chrome/Edge

1. Open your browser and go to:
   - **Chrome**: `chrome://extensions/`
   - **Edge**: `edge://extensions/`

2. Enable **Developer mode** (toggle in top right)

3. Click **Load unpacked**

4. Navigate to and select the `extension` folder:
   ```
   d:\Projects\Cipher-Vault\extension
   ```

5. The extension should now appear in your browser toolbar!

## Usage

### First Time Setup

1. Click the Cipher Vault icon in your browser toolbar
2. Login with your Cipher Vault credentials
3. You're ready to go!

### Auto-Save Passwords

1. Visit any website and login as usual
2. After submitting the login form, a popup will appear asking if you want to save the credentials
3. Click "Save" to store the password in Cipher Vault
4. Click the extension icon and enter your master password to complete the save

### Manage Passwords

1. Click the Cipher Vault icon
2. Switch to the "Passwords" tab to view all saved passwords
3. Use the search bar to find specific passwords
4. Click "View" to see a password (requires master password)
5. Click "Copy" to copy a password to clipboard
6. Click "Delete" to remove a password

### Manually Save Passwords

1. Click the Cipher Vault icon
2. Switch to the "Save New" tab
3. Fill in the website, username, and password
4. Enter your Cipher Vault master password
5. Click "Save Password"

## Security Features

- 🔒 **End-to-End Encryption**: Passwords are encrypted with your master password
- 🔐 **No Plain Text Storage**: Passwords are never stored in plain text
- 🛡️ **Secure Communication**: All API calls are made securely to your local backend
- 🔑 **Master Password Required**: View or copy operations require your master password

## Configuration

To change the backend URL, edit the `API_BASE_URL` in `popup/popup.js`:

```javascript
const API_BASE_URL = 'https://cipher-vault-1.onrender.com';  // Production
// const API_BASE_URL = 'http://localhost:5000';  // Local development
```

## Troubleshooting

### Extension not detecting logins
- Make sure you're logged into Cipher Vault in the extension
- Refresh the page after logging in
- Check browser console for any errors

### Cannot connect to server
- Verify the production server is accessible at `https://cipher-vault-1.onrender.com`
- Check that the `API_BASE_URL` in `popup.js` matches your backend URL
- For local development, ensure Flask app is running on `http://localhost:5000`

### Passwords not saving
- Verify you entered the correct master password
- Check the browser console for errors
- Ensure you're logged into the extension

## Browser Compatibility

- ✅ Chrome (version 88+)
- ✅ Microsoft Edge (version 88+)
- ✅ Brave
- ✅ Any Chromium-based browser

## Development

### File Structure

```
extension/
├── manifest.json          # Extension configuration
├── popup/
│   ├── popup.html        # Extension popup UI
│   ├── popup.css         # Popup styles
│   └── popup.js          # Popup logic
├── scripts/
│   ├── background.js     # Background service worker
│   └── content.js        # Content script for page interaction
└── icons/
    ├── icon16.png        # 16x16 icon
    ├── icon48.png        # 48x48 icon
    └── icon128.png       # 128x128 icon
```

### API Endpoints

The extension uses these backend API endpoints:

- `POST /api/login` - Login to Cipher Vault
- `GET /api/passwords` - Get list of saved passwords
- `POST /api/decrypt_password` - Decrypt a specific password
- `POST /add_password` - Save a new password
- `POST /api/delete_password` - Delete a password

## License

Same as Cipher Vault main project

## Support

For issues or questions, please open an issue in the main Cipher Vault repository.
