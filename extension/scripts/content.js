// Content script to detect login forms and credentials
(function() {
    let isMonitoring = false;
    let detectedCredentials = {};
    
    // Check if user is logged in to Cipher Vault
    chrome.storage.local.get(['cipherVaultUser'], (result) => {
        if (result.cipherVaultUser) {
            startMonitoring();
        }
    });
    
    // Listen for storage changes
    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (changes.cipherVaultUser) {
            if (changes.cipherVaultUser.newValue) {
                startMonitoring();
            } else {
                stopMonitoring();
            }
        }
    });
    
    function startMonitoring() {
        if (isMonitoring) return;
        isMonitoring = true;
        
        // Monitor form submissions
        document.addEventListener('submit', handleFormSubmit, true);
        
        // Monitor password field changes
        observePasswordFields();
        
        console.log('Cipher Vault: Monitoring for login forms');
    }
    
    function stopMonitoring() {
        isMonitoring = false;
        document.removeEventListener('submit', handleFormSubmit, true);
    }
    
    function handleFormSubmit(event) {
        const form = event.target;
        
        // Check if it's a login form
        if (!isLoginForm(form)) return;
        
        const credentials = extractCredentials(form);
        
        if (credentials.username && credentials.password) {
            detectedCredentials = {
                website: window.location.hostname,
                username: credentials.username,
                password: credentials.password
            };
            
            // Show save prompt
            setTimeout(() => showSavePrompt(credentials), 500);
        }
    }
    
    function isLoginForm(form) {
        // Check if form has password field
        const passwordFields = form.querySelectorAll('input[type="password"]');
        if (passwordFields.length === 0) return false;
        
        // Check if form has username/email field
        const usernameFields = form.querySelectorAll(
            'input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[id*="user"], input[id*="email"]'
        );
        
        return usernameFields.length > 0;
    }
    
    function extractCredentials(form) {
        let username = '';
        let password = '';
        
        // Find password field
        const passwordField = form.querySelector('input[type="password"]');
        if (passwordField) {
            password = passwordField.value;
        }
        
        // Find username/email field
        const usernameSelectors = [
            'input[type="email"]',
            'input[type="text"][name*="user"]',
            'input[type="text"][name*="email"]',
            'input[type="text"][id*="user"]',
            'input[type="text"][id*="email"]',
            'input[name="username"]',
            'input[name="email"]',
            'input[id="username"]',
            'input[id="email"]',
            'input[type="text"]'
        ];
        
        for (const selector of usernameSelectors) {
            const field = form.querySelector(selector);
            if (field && field.value) {
                username = field.value;
                break;
            }
        }
        
        return { username, password };
    }
    
    function showSavePrompt(credentials) {
        // Remove existing prompts
        const existingPrompt = document.getElementById('cipher-vault-save-prompt');
        if (existingPrompt) {
            existingPrompt.remove();
        }
        
        // Create save prompt
        const prompt = document.createElement('div');
        prompt.id = 'cipher-vault-save-prompt';
        prompt.innerHTML = `
            <style>
                #cipher-vault-save-prompt {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 12px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                    z-index: 999999;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    min-width: 320px;
                    animation: slideIn 0.3s ease-out;
                }
                
                @keyframes slideIn {
                    from {
                        transform: translateX(400px);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
                
                #cipher-vault-save-prompt h3 {
                    margin: 0 0 10px 0;
                    font-size: 16px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                
                #cipher-vault-save-prompt p {
                    margin: 0 0 15px 0;
                    font-size: 13px;
                    opacity: 0.9;
                }
                
                #cipher-vault-save-prompt .credentials {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 10px;
                    border-radius: 6px;
                    margin-bottom: 15px;
                    font-size: 12px;
                }
                
                #cipher-vault-save-prompt .buttons {
                    display: flex;
                    gap: 10px;
                }
                
                #cipher-vault-save-prompt button {
                    flex: 1;
                    padding: 10px;
                    border: none;
                    border-radius: 6px;
                    font-size: 13px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s;
                }
                
                #cipher-vault-save-prompt .save-btn {
                    background: white;
                    color: #667eea;
                }
                
                #cipher-vault-save-prompt .save-btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(255, 255, 255, 0.3);
                }
                
                #cipher-vault-save-prompt .dismiss-btn {
                    background: rgba(255, 255, 255, 0.2);
                    color: white;
                }
                
                #cipher-vault-save-prompt .dismiss-btn:hover {
                    background: rgba(255, 255, 255, 0.3);
                }
            </style>
            <h3>🔐 Cipher Vault</h3>
            <p>Save this password?</p>
            <div class="credentials">
                <div><strong>Website:</strong> ${escapeHtml(credentials.website)}</div>
                <div><strong>Username:</strong> ${escapeHtml(credentials.username)}</div>
            </div>
            <div class="buttons">
                <button class="save-btn" id="cipher-vault-save-btn">Save</button>
                <button class="dismiss-btn" id="cipher-vault-dismiss-btn">Not Now</button>
            </div>
        `;
        
        document.body.appendChild(prompt);
        
        // Add event listeners
        document.getElementById('cipher-vault-save-btn').addEventListener('click', () => {
            saveCredentials(credentials);
            prompt.remove();
        });
        
        document.getElementById('cipher-vault-dismiss-btn').addEventListener('click', () => {
            prompt.remove();
        });
        
        // Auto-dismiss after 15 seconds
        setTimeout(() => {
            if (document.getElementById('cipher-vault-save-prompt')) {
                prompt.remove();
            }
        }, 15000);
    }
    
    function saveCredentials(credentials) {
        // Store pending credentials
        chrome.storage.local.set({
            pendingCredentials: credentials
        });
        
        // Send message to background script
        chrome.runtime.sendMessage({
            type: 'SAVE_CREDENTIALS',
            data: credentials
        });
        
        // Show success notification
        showNotification('Click the Cipher Vault extension to complete saving', 'success');
    }
    
    function showNotification(message, type) {
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'success' ? '#28a745' : '#667eea'};
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
            z-index: 999999;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 13px;
            animation: slideIn 0.3s ease-out;
        `;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    function observePasswordFields() {
        // Monitor for dynamically added password fields
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        const passwordFields = node.querySelectorAll ? node.querySelectorAll('input[type="password"]') : [];
                        if (passwordFields.length > 0 || node.matches && node.matches('input[type="password"]')) {
                            // Password field detected
                        }
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Add CSS for animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(400px);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);
})();
