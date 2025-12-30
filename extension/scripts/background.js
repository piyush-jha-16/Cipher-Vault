// Background service worker for the extension

// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
    console.log('Cipher Vault Extension installed');
});

// Listen for messages from content script and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SAVE_CREDENTIALS') {
        handleSaveCredentials(message.data);
    } else if (message.type === 'LOGIN_DETECTED') {
        handleLoginDetected(message.data, sender);
    }
    
    return true; // Keep the message channel open for async response
});

// Handle save credentials request
async function handleSaveCredentials(credentials) {
    try {
        // Store pending credentials
        await chrome.storage.local.set({
            pendingCredentials: credentials
        });
        
        // Create notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: '../icons/icon48.png',
            title: 'Cipher Vault',
            message: 'Click the extension icon to save your credentials',
            priority: 2
        });
        
        // Open popup when notification is clicked
        chrome.notifications.onClicked.addListener(() => {
            chrome.action.openPopup();
        });
        
    } catch (error) {
        console.error('Error saving credentials:', error);
    }
}

// Handle login detection
async function handleLoginDetected(data, sender) {
    try {
        const result = await chrome.storage.local.get(['cipherVaultUser']);
        
        if (result.cipherVaultUser) {
            // Store pending credentials
            await chrome.storage.local.set({
                pendingCredentials: {
                    website: data.website,
                    username: data.username,
                    password: data.password,
                    tabId: sender.tab.id
                }
            });
            
            // Show notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: '../icons/icon48.png',
                title: 'Cipher Vault - Login Detected',
                message: `Save credentials for ${data.website}?`,
                priority: 2
            });
        }
    } catch (error) {
        console.error('Error handling login detection:', error);
    }
}

// Listen for tab updates to check if we need to autofill
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        try {
            const url = new URL(tab.url);
            const hostname = url.hostname;
            
            // Check if user is logged in
            const result = await chrome.storage.local.get(['cipherVaultUser', 'cipherVaultSession']);
            
            if (result.cipherVaultUser && result.cipherVaultSession) {
                // Could implement autofill functionality here
                // For now, we'll just detect forms
            }
        } catch (error) {
            // Invalid URL or other error
        }
    }
});

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
    // Open the extension popup
    chrome.action.openPopup();
});

// Context menu for saving passwords
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: 'savePassword',
        title: 'Save to Cipher Vault',
        contexts: ['page', 'selection']
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'savePassword') {
        // Open popup to save password
        chrome.action.openPopup();
    }
});

// Keep alive to prevent service worker from stopping
let keepAliveInterval;

function keepAlive() {
    keepAliveInterval = setInterval(() => {
        chrome.runtime.getPlatformInfo(() => {
            // Just a ping to keep alive
        });
    }, 20000); // Every 20 seconds
}

keepAlive();

// Clean up on suspension
chrome.runtime.onSuspend.addListener(() => {
    if (keepAliveInterval) {
        clearInterval(keepAliveInterval);
    }
});
