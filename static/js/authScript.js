    // Theme Management
    function toggleTheme() {
      const body = document.body;
      const themeIcon = document.getElementById('theme-icon');
      const currentTheme = body.getAttribute('data-theme');
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      
      body.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      
      if (newTheme === 'dark') {
        themeIcon.classList.remove('fa-moon');
        themeIcon.classList.add('fa-sun');
      } else {
        themeIcon.classList.remove('fa-sun');
        themeIcon.classList.add('fa-moon');
      }
    }
    
    // Load saved theme
    document.addEventListener('DOMContentLoaded', function() {
      const savedTheme = localStorage.getItem('theme') || 'light';
      const body = document.body;
      const themeIcon = document.getElementById('theme-icon');
      
      body.setAttribute('data-theme', savedTheme);
      
      if (savedTheme === 'dark') {
        themeIcon.classList.remove('fa-moon');
        themeIcon.classList.add('fa-sun');
      }
    });
    
    // Tab switching with smooth animations
    function showTab(tab) {
      const loginTab = document.getElementById("login-tab");
      const registerTab = document.getElementById("register-tab");
      const loginContainer = document.getElementById("login-container");
      const registerContainer = document.getElementById("register-container");
      
      if (tab === "login") {
        loginTab.classList.add("active");
        registerTab.classList.remove("active");
        
        registerContainer.classList.remove("fade-enter");
        registerContainer.classList.add("fade-exit");
        
        setTimeout(() => {
          registerContainer.classList.add("hidden");
          registerContainer.classList.remove("fade-exit");
          
          loginContainer.classList.remove("hidden");
          loginContainer.classList.add("fade-enter");
        }, 300);
        
      } else {
        registerTab.classList.add("active");
        loginTab.classList.remove("active");
        
        loginContainer.classList.remove("fade-enter");
        loginContainer.classList.add("fade-exit");
        
        setTimeout(() => {
          loginContainer.classList.add("hidden");
          loginContainer.classList.remove("fade-exit");
          
          registerContainer.classList.remove("hidden");
          registerContainer.classList.add("fade-enter");
        }, 300);
      }
    }

    // Password visibility toggle
    function setupPasswordToggle(eyeId, inputId) {
      const eye = document.getElementById(eyeId);
      const input = document.getElementById(inputId);
      
      if (eye && input) {
        eye.addEventListener('click', function() {
          const icon = this.querySelector('i');
          if (input.type === 'password') {
            input.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
          } else {
            input.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
          }
        });
      }
    }
    
    setupPasswordToggle('login-eye', 'login-pass');
    setupPasswordToggle('register-eye', 'register-pass');
    
    // Password strength indicator
    const registerPass = document.getElementById('register-pass');
    if (registerPass) {
      registerPass.addEventListener('input', function() {
        const password = this.value;
        const strengthBars = document.querySelectorAll('#register-container .strength-bar');
        let strength = 0;
        
        if (password.length >= 8) strength++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
        if (/\d/.test(password)) strength++;
        if (/[^a-zA-Z0-9]/.test(password)) strength++;
        
        const colors = ['#EF4444', '#F59E0B', '#10B981', '#10B981'];
        
        strengthBars.forEach((bar, index) => {
          if (index < strength) {
            bar.style.backgroundColor = colors[strength - 1];
          } else {
            bar.style.backgroundColor = 'var(--border)';
          }
        });
      });
    }
