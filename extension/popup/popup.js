// Configuration
const API_BASE_URL = 'https://cipher-vault-1.onrender.com';

// DOM Elements
let loginView, mainView, loginForm, logoutBtn;
let passwordsList, searchInput, savePasswordForm;
let currentUser = null;
let allPasswords = [];

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
    initializeElements();
    setupEventListeners();
    await checkAuth();
});

function initializeElements() {
    loginView = document.getElementById('loginView');
    mainView = document.getElementById('mainView');
    loginForm = document.getElementById('loginForm');
    logoutBtn = document.getElementById('logoutBtn');
    passwordsList = document.getElementById('passwordsList');
    searchInput = document.getElementById('searchInput');
    savePasswordForm = document.getElementById('savePasswordForm');
}

function setupEventListeners() {
    // Login form
    loginForm.addEventListener('submit', handleLogin);
    
    // Logout
    logoutBtn.addEventListener('click', handleLogout);
    
    // Tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });
    
    // Search
    searchInput.addEventListener('input', handleSearch);
    
    // Save password form
    savePasswordForm.addEventListener('submit', handleSavePassword);
    
    // Open web app
    document.getElementById('openWebApp').addEventListener('click', (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: API_BASE_URL });
    });
    
    // Toggle password visibility
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.target;
            const input = document.getElementById(targetId);
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🙈';
            } else {
                input.type = 'password';
                btn.textContent = '👁️';
            }
        });
    });
}

async function checkAuth() {
    try {
        const result = await chrome.storage.local.get(['cipherVaultUser', 'cipherVaultSession']);
        if (result.cipherVaultUser && result.cipherVaultSession) {
            currentUser = result.cipherVaultUser;
            showMainView();
            await loadPasswords();
        } else {
            showLoginView();
        }
    } catch (error) {
        console.error('Auth check error:', error);
        showLoginView();
    }
}

function showLoginView() {
    loginView.classList.remove('hidden');
    mainView.classList.add('hidden');
}

function showMainView() {
    loginView.classList.add('hidden');
    mainView.classList.remove('hidden');
    document.getElementById('username').textContent = currentUser.username;
}

async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const errorDiv = document.getElementById('loginError');
    
    errorDiv.classList.remove('show');
    
    if (!username || !password) {
        showError(errorDiv, 'Please enter username and password');
        return;
    }
    
    try {
        // Send login request to backend
        const response = await fetch(`${API_BASE_URL}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password }),
            mode: 'cors',
            credentials: 'omit'  // Don't send cookies to avoid CORS issues
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = {
                username: data.username,
                sessionId: data.sessionId
            };
            
            // Store session
            await chrome.storage.local.set({
                cipherVaultUser: currentUser,
                cipherVaultSession: data.sessionId
            });
            
            showMainView();
            await loadPasswords();
        } else {
            showError(errorDiv, data.error || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        showError(errorDiv, 'Could not connect to server. Make sure the app is running.');
    }
}

async function handleLogout() {
    await chrome.storage.local.remove(['cipherVaultUser', 'cipherVaultSession']);
    currentUser = null;
    allPasswords = [];
    showLoginView();
    loginForm.reset();
}

async function loadPasswords() {
    passwordsList.innerHTML = '<div class="loading">Loading passwords...</div>';
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/passwords`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-ID': currentUser.sessionId
            },
            mode: 'cors',
            credentials: 'omit'
        });
        
        const data = await response.json();
        
        if (data.success) {
            allPasswords = data.passwords;
            displayPasswords(allPasswords);
        } else {
            passwordsList.innerHTML = '<div class="empty-state"><p>Failed to load passwords</p></div>';
        }
    } catch (error) {
        console.error('Load passwords error:', error);
        passwordsList.innerHTML = '<div class="empty-state"><p>Could not connect to server</p></div>';
    }
}

function displayPasswords(passwords) {
    if (passwords.length === 0) {
        passwordsList.innerHTML = `
            <div class="empty-state">
                <p>No passwords saved yet</p>
                <p style="font-size: 12px;">Click "Save New" to add your first password</p>
            </div>
        `;
        return;
    }
    
    passwordsList.innerHTML = passwords.map(pwd => `
        <div class="password-item" data-id="${pwd.id}">
            <div class="password-item-header">
                <div class="website">${escapeHtml(pwd.website)}</div>
                <span class="strength-badge strength-${pwd.strength}">${pwd.strength}</span>
            </div>
            <div class="password-item-body">
                <div><strong>Username:</strong> ${escapeHtml(pwd.username)}</div>
                <div><strong>Password:</strong> ••••••••</div>
            </div>
            <div class="password-actions">
                <button class="btn-small view-password" data-id="${pwd.id}">View</button>
                <button class="btn-small copy-password" data-id="${pwd.id}">Copy</button>
                <button class="btn-small btn-danger delete-password" data-id="${pwd.id}">Delete</button>
            </div>
        </div>
    `).join('');
    
    // Add event listeners
    document.querySelectorAll('.view-password').forEach(btn => {
        btn.addEventListener('click', () => viewPassword(btn.dataset.id));
    });
    
    document.querySelectorAll('.copy-password').forEach(btn => {
        btn.addEventListener('click', () => copyPassword(btn.dataset.id));
    });
    
    document.querySelectorAll('.delete-password').forEach(btn => {
        btn.addEventListener('click', () => deletePassword(btn.dataset.id));
    });
}

function handleSearch(e) {
    const query = e.target.value.toLowerCase().trim();
    
    if (!query) {
        displayPasswords(allPasswords);
        return;
    }
    
    const filtered = allPasswords.filter(pwd => 
        pwd.website.toLowerCase().includes(query) || 
        pwd.username.toLowerCase().includes(query)
    );
    
    displayPasswords(filtered);
}

async function viewPassword(id) {
    const password = allPasswords.find(p => p.id == id);
    if (!password) return;
    
    const accountPassword = prompt('Enter your account password to view:');
    if (!accountPassword) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/decrypt_password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-ID': currentUser.sessionId
            },
            body: JSON.stringify({
                passwordId: id,
                accountPassword: accountPassword
            }),
            mode: 'cors',
            credentials: 'omit'
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`Password: ${data.password}`);
        } else {
            alert(data.error || 'Failed to decrypt password');
        }
    } catch (error) {
        console.error('View password error:', error);
        alert('Failed to view password');
    }
}

async function copyPassword(id) {
    const password = allPasswords.find(p => p.id == id);
    if (!password) return;
    
    const accountPassword = prompt('Enter your account password to copy:');
    if (!accountPassword) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/decrypt_password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-ID': currentUser.sessionId
            },
            body: JSON.stringify({
                passwordId: id,
                accountPassword: accountPassword
            }),
            mode: 'cors',
            credentials: 'omit'
        });
        
        const data = await response.json();
        
        if (data.success) {
            await navigator.clipboard.writeText(data.password);
            alert('Password copied to clipboard!');
        } else {
            alert(data.error || 'Failed to decrypt password');
        }
    } catch (error) {
        console.error('Copy password error:', error);
        alert('Failed to copy password');
    }
}

async function deletePassword(id) {
    if (!confirm('Are you sure you want to delete this password?')) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/delete_password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-ID': currentUser.sessionId
            },
            body: JSON.stringify({ passwordId: id }),
            mode: 'cors',
            credentials: 'omit'
        });
        
        const data = await response.json();
        
        if (data.success) {
            await loadPasswords();
        } else {
            alert(data.error || 'Failed to delete password');
        }
    } catch (error) {
        console.error('Delete password error:', error);
        alert('Failed to delete password');
    }
}

async function handleSavePassword(e) {
    e.preventDefault();
    
    const website = document.getElementById('saveWebsite').value.trim();
    const username = document.getElementById('saveUsername').value.trim();
    const password = document.getElementById('savePassword').value;
    const accountPassword = document.getElementById('accountPassword').value;
    
    const errorDiv = document.getElementById('saveError');
    const successDiv = document.getElementById('saveSuccess');
    
    errorDiv.classList.remove('show');
    successDiv.classList.remove('show');
    
    if (!website || !username || !password || !accountPassword) {
        showError(errorDiv, 'All fields are required');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/add_password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-ID': currentUser.sessionId
            },
            body: JSON.stringify({
                website,
                username,
                password,
                accountPassword
            }),
            mode: 'cors',
            credentials: 'omit'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(successDiv, 'Password saved successfully!');
            savePasswordForm.reset();
            await loadPasswords();
            
            // Switch to passwords tab after 1 second
            setTimeout(() => {
                switchTab('passwords');
                successDiv.classList.remove('show');
            }, 1500);
        } else {
            showError(errorDiv, data.error || 'Failed to save password');
        }
    } catch (error) {
        console.error('Save password error:', error);
        showError(errorDiv, 'Could not connect to server');
    }
}

function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });
    
    // Update tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    if (tabName === 'passwords') {
        document.getElementById('passwordsTab').classList.add('active');
    } else if (tabName === 'save') {
        document.getElementById('saveTab').classList.add('active');
        // Auto-fill website if on a specific page
        getCurrentTabInfo();
    }
}

async function getCurrentTabInfo() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            const url = new URL(tab.url);
            const website = url.hostname;
            if (website && !document.getElementById('saveWebsite').value) {
                document.getElementById('saveWebsite').value = website;
            }
        }
    } catch (error) {
        console.error('Error getting tab info:', error);
    }
}

function showError(element, message) {
    element.textContent = message;
    element.classList.add('show');
}

function showSuccess(element, message) {
    element.textContent = message;
    element.classList.add('show');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'LOGIN_DETECTED') {
        // Auto-fill the save form when login is detected
        chrome.storage.local.get(['cipherVaultUser']).then(result => {
            if (result.cipherVaultUser) {
                chrome.storage.local.set({
                    pendingCredentials: {
                        website: message.data.website,
                        username: message.data.username,
                        password: message.data.password
                    }
                });
                
                // Notify user
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: '../icons/icon48.png',
                    title: 'Cipher Vault',
                    message: 'Login detected! Click to save credentials.'
                });
            }
        });
    }
});
