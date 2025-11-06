// CipherVault Utility Functions

// Toast Notification System
const Toast = {
  show: function(message, type = 'info', duration = 3000) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <div class="flex items-center gap-3">
        <i class="fas ${this.getIcon(type)} text-xl"></i>
        <span class="font-medium">${message}</span>
      </div>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
      toast.style.animation = 'fadeOut 0.3s ease-in-out';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },
  
  getIcon: function(type) {
    switch(type) {
      case 'success': return 'fa-check-circle';
      case 'error': return 'fa-exclamation-circle';
      case 'info': return 'fa-info-circle';
      default: return 'fa-info-circle';
    }
  },
  
  success: function(message, duration) {
    this.show(message, 'success', duration);
  },
  
  error: function(message, duration) {
    this.show(message, 'error', duration);
  },
  
  info: function(message, duration) {
    this.show(message, 'info', duration);
  }
};

// Password Strength Calculator
function calculatePasswordStrength(password) {
  let strength = 0;
  
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
  if (/\d/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;
  
  return {
    score: strength,
    label: strength <= 2 ? 'Weak' : strength <= 3 ? 'Medium' : 'Strong',
    color: strength <= 2 ? '#ef4444' : strength <= 3 ? '#f59e0b' : '#22c55e'
  };
}

// Password Generator
function generateSecurePassword(length = 16, options = {}) {
  const defaults = {
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true
  };
  
  const settings = { ...defaults, ...options };
  
  let charset = '';
  if (settings.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (settings.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (settings.numbers) charset += '0123456789';
  if (settings.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  if (!charset) return '';
  
  let password = '';
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  
  for (let i = 0; i < length; i++) {
    password += charset[array[i] % charset.length];
  }
  
  return password;
}

// Copy to Clipboard
async function copyToClipboard(text, showToast = true) {
  try {
    await navigator.clipboard.writeText(text);
    if (showToast) {
      Toast.success('Copied to clipboard!');
    }
    return true;
  } catch (err) {
    console.error('Failed to copy:', err);
    if (showToast) {
      Toast.error('Failed to copy to clipboard');
    }
    return false;
  }
}

// Format Date
function formatDate(date) {
  const d = new Date(date);
  const now = new Date();
  const diff = Math.floor((now - d) / 1000); // difference in seconds
  
  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)} days ago`;
  
  return d.toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'short', 
    day: 'numeric' 
  });
}

// Debounce Function
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Local Storage Helper
const Storage = {
  set: function(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (err) {
      console.error('Storage error:', err);
      return false;
    }
  },
  
  get: function(key, defaultValue = null) {
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : defaultValue;
    } catch (err) {
      console.error('Storage error:', err);
      return defaultValue;
    }
  },
  
  remove: function(key) {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (err) {
      console.error('Storage error:', err);
      return false;
    }
  },
  
  clear: function() {
    try {
      localStorage.clear();
      return true;
    } catch (err) {
      console.error('Storage error:', err);
      return false;
    }
  }
};

// Form Validation
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePassword(password, minLength = 8) {
  return password.length >= minLength;
}

function validateUsername(username, minLength = 3) {
  const re = /^[a-zA-Z0-9_-]+$/;
  return username.length >= minLength && re.test(username);
}

// Loading Indicator
const Loading = {
  show: function(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
      element.innerHTML = '<div class="spinner mx-auto"></div>';
      element.disabled = true;
    }
  },
  
  hide: function(elementId, originalContent) {
    const element = document.getElementById(elementId);
    if (element) {
      element.innerHTML = originalContent;
      element.disabled = false;
    }
  }
};

// Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Initialize tooltips and other UI enhancements
document.addEventListener('DOMContentLoaded', function() {
  // Add smooth scrolling
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });
  
  // Add fade-in animation to elements with data-animate attribute
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  };
  
  const observer = new IntersectionObserver(function(entries) {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('fade-in');
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);
  
  document.querySelectorAll('[data-animate]').forEach(el => {
    observer.observe(el);
  });
});

// Export for use in other scripts
window.CipherVault = {
  Toast,
  Storage,
  Loading,
  copyToClipboard,
  generateSecurePassword,
  calculatePasswordStrength,
  formatDate,
  debounce,
  validateEmail,
  validatePassword,
  validateUsername,
  escapeHtml
};
