    // Toggle password visibility
    function togglePasswordVisibility(inputId, buttonId) {
      const input = document.getElementById(inputId);
      const button = document.getElementById(buttonId);
      const icon = button.querySelector('i');
      
      button.addEventListener('click', function() {
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
    
    togglePasswordVisibility('password', 'togglePassword');
    togglePasswordVisibility('confirmPassword', 'toggleConfirm');
    
    // Password strength checker
    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirmPassword');
    
    passwordInput.addEventListener('input', function() {
      const password = this.value;
      let strength = 0;
      
      // Check requirements
      const hasLength = password.length >= 8;
      const hasUppercase = /[A-Z]/.test(password);
      const hasLowercase = /[a-z]/.test(password);
      const hasNumber = /\d/.test(password);
      const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
      
      // Update requirement indicators
      updateRequirement('req-length', hasLength);
      updateRequirement('req-uppercase', hasUppercase);
      updateRequirement('req-lowercase', hasLowercase);
      updateRequirement('req-number', hasNumber);
      updateRequirement('req-special', hasSpecial);
      
      // Calculate strength
      if (hasLength) strength++;
      if (hasUppercase && hasLowercase) strength++;
      if (hasNumber) strength++;
      if (hasSpecial) strength++;
      
      // Update strength bars
      const colors = ['#EF4444', '#F59E0B', '#10B981', '#10B981'];
      const labels = ['Weak', 'Fair', 'Good', 'Strong'];
      
      for (let i = 1; i <= 4; i++) {
        const bar = document.getElementById(`bar${i}`);
        if (i <= strength) {
          bar.style.backgroundColor = colors[strength - 1];
        } else {
          bar.style.backgroundColor = 'var(--border)';
        }
      }
      
      const strengthLabel = document.getElementById('strengthLabel');
      if (strength > 0) {
        strengthLabel.textContent = labels[strength - 1];
        strengthLabel.style.color = colors[strength - 1];
        strengthLabel.style.fontWeight = '600';
      } else {
        strengthLabel.textContent = 'Not set';
        strengthLabel.style.color = 'var(--text-secondary)';
      }
    });
    
    function updateRequirement(id, met) {
      const element = document.getElementById(id);
      const icon = element.querySelector('i');
      const text = element.querySelector('span');
      
      if (met) {
        icon.classList.remove('fa-circle', 'text-gray-300');
        icon.classList.add('fa-check-circle', 'text-green-500');
        icon.style.fontSize = '12px';
        text.style.color = 'var(--success)';
        text.style.fontWeight = '600';
      } else {
        icon.classList.remove('fa-check-circle', 'text-green-500');
        icon.classList.add('fa-circle', 'text-gray-300');
        icon.style.fontSize = '6px';
        text.style.color = 'var(--text-secondary)';
        text.style.fontWeight = '400';
      }
    }
    
    // Form validation
    document.getElementById('setPasswordForm').addEventListener('submit', function(e) {
      const password = document.getElementById('password').value;
      const confirm = document.getElementById('confirmPassword').value;
      
      if (password !== confirm) {
        e.preventDefault();
        alert('Passwords do not match!');
        return;
      }
      
      if (password.length < 8) {
        e.preventDefault();
        alert('Password must be at least 8 characters long!');
        return;
      }
    });
