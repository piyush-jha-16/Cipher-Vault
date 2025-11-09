    // Toast Notification System
    function showToast(title, message, type = 'info', duration = 4000) {
      const toastContainer = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = `toast ${type}`;
      
      const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
      };
      
      toast.innerHTML = `
        <div class="toast-icon">
          <i class="fas ${icons[type]}"></i>
        </div>
        <div class="toast-content">
          <div class="toast-title">${title}</div>
          <div class="toast-message">${message}</div>
        </div>
        <div class="toast-close" onclick="removeToast(this)">
          <i class="fas fa-times"></i>
        </div>
      `;
      
      toastContainer.appendChild(toast);
      
      setTimeout(() => {
        removeToast(toast);
      }, duration);
    }
    
    function removeToast(element) {
      const toast = element.classList?.contains('toast') ? element : element.closest('.toast');
      if (toast) {
        toast.classList.add('removing');
        setTimeout(() => {
          toast.remove();
        }, 300);
      }
    }
    
    // Success Modal Functions
    function openSuccessModal(data) {
      document.getElementById('successWebsite').textContent = data.website;
      document.getElementById('successUsername').textContent = data.username;
      document.getElementById('successEncryptedPassword').textContent = data.encryptedPassword;
      
      // Set strength indicator
      const strengthIcon = document.getElementById('successStrengthIcon');
      const strengthText = document.getElementById('successStrength');
      const strengthBadge = document.getElementById('successStrengthBadge');
      
      if (data.strength === 'weak') {
        strengthIcon.style.background = 'rgba(239, 68, 68, 0.1)';
        strengthIcon.querySelector('i').style.color = '#EF4444';
        strengthText.textContent = 'Weak Password';
        strengthText.style.color = '#EF4444';
        strengthBadge.textContent = '⚠️ Weak';
        strengthBadge.style.background = 'rgba(239, 68, 68, 0.1)';
        strengthBadge.style.color = '#EF4444';
      } else if (data.strength === 'medium') {
        strengthIcon.style.background = 'rgba(245, 158, 11, 0.1)';
        strengthIcon.querySelector('i').style.color = '#F59E0B';
        strengthText.textContent = 'Medium Strength';
        strengthText.style.color = '#F59E0B';
        strengthBadge.textContent = '⚡ Medium';
        strengthBadge.style.background = 'rgba(245, 158, 11, 0.1)';
        strengthBadge.style.color = '#F59E0B';
      } else {
        strengthIcon.style.background = 'rgba(16, 185, 129, 0.1)';
        strengthIcon.querySelector('i').style.color = '#10B981';
        strengthText.textContent = 'Strong Password';
        strengthText.style.color = '#10B981';
        strengthBadge.textContent = '✓ Strong';
        strengthBadge.style.background = 'rgba(16, 185, 129, 0.1)';
        strengthBadge.style.color = '#10B981';
      }
      
      document.getElementById('successModal').classList.remove('hidden');
    }
    
    function closeSuccessModal() {
      document.getElementById('successModal').classList.add('hidden');
      // Reload page to show new password in list
      window.location.reload();
    }
    
    // Modal functions
    function openAddPasswordModal() {
      document.getElementById('addPasswordModal').classList.remove('hidden');
      document.getElementById('addPasswordForm').reset();
    }
    
    function closeAddPasswordModal() {
      document.getElementById('addPasswordModal').classList.add('hidden');
    }
    
    // Import Modal functions
    function openImportModal() {
      document.getElementById('importModal').classList.remove('hidden');
      document.getElementById('importForm').reset();
      document.getElementById('importProgress').classList.add('hidden');
    }
    
    function closeImportModal() {
      document.getElementById('importModal').classList.add('hidden');
    }
    
    // Confirm Password Modal functions
    function openConfirmPasswordModal() {
      document.getElementById('confirmPasswordModal').classList.remove('hidden');
      document.getElementById('confirmPasswordForm').reset();
    }
    
    function closeConfirmPasswordModal() {
      document.getElementById('confirmPasswordModal').classList.add('hidden');
      document.getElementById('confirmPasswordForm').reset();
      pendingDeletePasswordId = null;
    }
    
    function toggleConfirmPassword() {
      const input = document.getElementById('confirmAccountPassword');
      const icon = document.getElementById('confirmPasswordToggleIcon');
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    }
    
    // Delete All Modal functions
    function openDeleteAllModal() {
      const totalPasswords = parseInt(document.getElementById('total-passwords').textContent);
      if (totalPasswords === 0) {
        showToast('No Passwords', 'There are no passwords to delete.', 'error');
        return;
      }
      document.getElementById('deleteAllModal').classList.remove('hidden');
      document.getElementById('deleteAllForm').reset();
    }
    
    function closeDeleteAllModal() {
      document.getElementById('deleteAllModal').classList.add('hidden');
      document.getElementById('deleteAllForm').reset();
    }
    
    function toggleDeleteAllPassword() {
      const input = document.getElementById('deleteAllPassword');
      const icon = document.getElementById('deleteAllPasswordToggleIcon');
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    }
    
    async function deleteAllPasswords(event) {
      event.preventDefault();
      
      const accountPassword = document.getElementById('deleteAllPassword').value.trim();
      
      if (!accountPassword) {
        showToast('Password Required', 'Please enter your account password.', 'error');
        return;
      }
      
      try {
        const response = await fetch('/delete_all_passwords', {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ accountPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
          closeDeleteAllModal();
          showToast('All Passwords Deleted', `Successfully deleted ${data.deleted_count} passwords.`, 'success');
          
          // Reload page after a short delay
          setTimeout(() => window.location.reload(), 1500);
        } else {
          showToast('Delete Failed', data.error, 'error');
        }
      } catch (error) {
        console.error('Error:', error);
        showToast('Delete Failed', 'Failed to delete passwords. Please try again.', 'error');
      }
    }
    
    // Export Modal functions
    function openExportModal() {
      const totalPasswords = parseInt(document.getElementById('total-passwords').textContent);
      if (totalPasswords === 0) {
        showToast('No Passwords', 'There are no passwords to export.', 'error');
        return;
      }
      document.getElementById('exportModal').classList.remove('hidden');
      document.getElementById('exportForm').reset();
    }
    
    function closeExportModal() {
      document.getElementById('exportModal').classList.add('hidden');
      document.getElementById('exportForm').reset();
    }
    
    function toggleExportPassword() {
      const input = document.getElementById('exportPassword');
      const icon = document.getElementById('exportPasswordToggleIcon');
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    }
    
    async function exportPasswords(event) {
      event.preventDefault();
      
      const accountPassword = document.getElementById('exportPassword').value.trim();
      
      if (!accountPassword) {
        showToast('Password Required', 'Please enter your account password.', 'error');
        return;
      }
      
      try {
        const response = await fetch('/export_passwords', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ accountPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
          // Create a blob from the CSV data
          const blob = new Blob([data.csv_data], { type: 'text/csv' });
          const url = window.URL.createObjectURL(blob);
          
          // Create a temporary download link
          const a = document.createElement('a');
          a.href = url;
          a.download = data.filename;
          document.body.appendChild(a);
          a.click();
          
          // Cleanup
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
          
          closeExportModal();
          showToast('Export Successful', 'Your passwords have been exported to CSV.', 'success');
        } else {
          showToast('Export Failed', data.error, 'error');
        }
      } catch (error) {
        console.error('Error:', error);
        showToast('Export Failed', 'Failed to export passwords. Please try again.', 'error');
      }
    }

    // Edit Password Modal functions
    function openEditPasswordModal(passwordId) {
      const passwordElement = document.querySelector(`[data-password-id="${passwordId}"]`);
      const website = passwordElement.getAttribute('data-website');
      const username = passwordElement.getAttribute('data-username');
      
      document.getElementById('editPasswordId').value = passwordId;
      document.getElementById('editWebsite').value = website;
      document.getElementById('editUsername').value = username;
      document.getElementById('editPassword').value = '';
      
      document.getElementById('editPasswordModal').classList.remove('hidden');
    }
    
    function closeEditPasswordModal() {
      document.getElementById('editPasswordModal').classList.add('hidden');
      document.getElementById('editPasswordForm').reset();
    }
    
    // Edit password function
    async function editPassword(event) {
      event.preventDefault();
      
      const passwordId = document.getElementById('editPasswordId').value;
      const website = document.getElementById('editWebsite').value.trim();
      const username = document.getElementById('editUsername').value.trim();
      const password = document.getElementById('editPassword').value.trim();
      const accountPassword = document.getElementById('editAccountPassword').value.trim();
      
      if (!website || !username || !password || !accountPassword) {
        showToast('Missing Fields', 'All fields are required to update the password.', 'error');
        return;
      }
      
      try {
        const response = await fetch(`/edit_password/${passwordId}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ website, username, password, accountPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
          // Update stats
          updateStats(data.stats);
          
          // Close edit modal
          closeEditPasswordModal();
          
          // Show success toast based on strength
          if (data.strength === 'weak') {
            showToast('Password Updated', '⚠️ Your password was updated but it\'s weak. Consider using a stronger password.', 'warning', 5000);
          } else if (data.strength === 'medium') {
            showToast('Password Updated', '✓ Your password was updated with medium strength.', 'success');
          } else {
            showToast('Password Updated', '✓ Your password was updated with strong security!', 'success');
          }
          
          // Reload page after a short delay
          setTimeout(() => window.location.reload(), 2000);
        } else {
          showToast('Update Failed', data.error, 'error');
        }
      } catch (error) {
        console.error('Error:', error);
        showToast('Update Failed', 'Failed to update password. Please try again.', 'error');
      }
    }
    
    // Toggle edit password visibility
    function toggleEditPasswordVisibility() {
      const input = document.getElementById('editPassword');
      const icon = event.target;
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    }
    
    // Generate password for edit modal
    function generateEditPassword() {
      const length = 16;
      const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
      let password = "";
      for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
      }
      document.getElementById('editPassword').value = password;
    }
    
    // Add password function
    async function addPassword(event) {
      event.preventDefault();
      
      const website = document.getElementById('website').value.trim();
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value.trim();
      const accountPassword = document.getElementById('accountPassword').value.trim();
      
      if (!website || !username || !password || !accountPassword) {
        showToast('Missing Fields', 'All fields are required to save the password.', 'error');
        return;
      }
      
      try {
        const response = await fetch('/add_password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ website, username, password, accountPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
          // Update stats
          updateStats(data.stats);
          
          // Close add modal
          closeAddPasswordModal();
          
          // Show success modal with encrypted password
          openSuccessModal({
            website: website,
            username: username,
            encryptedPassword: data.encryptedPassword,
            strength: data.strength
          });
        } else {
          showToast('Save Failed', data.error, 'error');
        }
      } catch (error) {
        console.error('Error:', error);
        showToast('Save Failed', 'Failed to save password. Please try again.', 'error');
      }
    }
    
    // Delete password function with authentication
    let pendingDeletePasswordId = null;
    
    function deletePassword(passwordId) {
      pendingDeletePasswordId = passwordId;
      openConfirmPasswordModal();
    }
    
    async function confirmDeletePassword() {
      const accountPassword = document.getElementById('confirmAccountPassword').value.trim();
      
      if (!accountPassword) {
        showToast('Password Required', 'Please enter your account password.', 'error');
        return;
      }
      
      if (!pendingDeletePasswordId) {
        showToast('Error', 'No password selected for deletion.', 'error');
        return;
      }
      
      try {
        const response = await fetch(`/delete_password/${pendingDeletePasswordId}`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ accountPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
          // Close confirmation modal
          closeConfirmPasswordModal();
          
          // Update stats
          updateStats(data.stats);
          
          // Show success toast
          showToast('Password Deleted', 'The password has been permanently removed.', 'success');
          
          // Remove the password element with animation
          const passwordElement = document.querySelector(`[data-password-id="${pendingDeletePasswordId}"]`);
          if (passwordElement) {
            passwordElement.style.animation = 'slideOutRight 0.3s ease-in forwards';
            setTimeout(() => passwordElement.remove(), 300);
          }
          
          pendingDeletePasswordId = null;
          
          // Check if list is now empty
          setTimeout(() => {
            const passwordList = document.getElementById('password-list');
            if (passwordList.children.length === 0) {
              window.location.reload();
            }
          }, 400);
        } else {
          showToast('Delete Failed', data.error, 'error');
        }
      } catch (error) {
        console.error('Error:', error);
        showToast('Delete Failed', 'Failed to delete password. Please try again.', 'error');
      }
    }
    
    // Update stats function
    function updateStats(stats) {
      document.getElementById('total-passwords').textContent = stats.total_passwords;
      document.getElementById('weak-passwords').textContent = stats.weak_passwords;
      document.getElementById('security-score').textContent = stats.security_score + '%';
      updateSecurityScoreColor(stats.security_score);
    }
    
    // View Password Modal functions
    function openViewPasswordModal(passwordId) {
      const passwordElement = document.querySelector(`[data-password-id="${passwordId}"]`);
      const website = passwordElement.getAttribute('data-website');
      const username = passwordElement.getAttribute('data-username');
      
      document.getElementById('viewPasswordId').value = passwordId;
      document.getElementById('viewPasswordWebsite').value = website;
      document.getElementById('viewPasswordUsername').value = username;
      document.getElementById('viewAccountPassword').value = '';
      document.getElementById('authSection').classList.remove('hidden');
      document.getElementById('passwordDisplaySection').classList.add('hidden');
      document.getElementById('viewPasswordModal').classList.remove('hidden');
    }
    
    function closeViewPasswordModal() {
      document.getElementById('viewPasswordModal').classList.add('hidden');
      document.getElementById('viewAccountPassword').value = '';
      document.getElementById('decryptedPassword').textContent = '';
      document.getElementById('displayWebsite').textContent = '';
      document.getElementById('displayUsername').textContent = '';
    }
    
    // Authenticate and view password
    async function authenticateAndViewPassword() {
      const passwordId = document.getElementById('viewPasswordId').value;
      const website = document.getElementById('viewPasswordWebsite').value;
      const username = document.getElementById('viewPasswordUsername').value;
      const accountPassword = document.getElementById('viewAccountPassword').value.trim();
      
      if (!accountPassword) {
        showToast('Password Required', 'Please enter your account password to view this password.', 'warning');
        return;
      }
      
      try {
        const response = await fetch(`/view_password/${passwordId}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ accountPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
          // Populate the display fields
          document.getElementById('displayWebsite').textContent = website;
          document.getElementById('displayUsername').textContent = username;
          document.getElementById('decryptedPassword').textContent = data.password;
          
          // Switch views
          document.getElementById('authSection').classList.add('hidden');
          document.getElementById('passwordDisplaySection').classList.remove('hidden');
          
          showToast('Password Decrypted', 'Your password has been decrypted successfully.', 'success', 3000);
        } else {
          showToast('Authentication Failed', data.error, 'error');
        }
      } catch (error) {
        console.error('Error:', error);
        showToast('View Failed', 'Failed to decrypt password. Please try again.', 'error');
      }
    }
    
    // Copy decrypted password
    function copyDecryptedPassword() {
      const password = document.getElementById('decryptedPassword').textContent;
      navigator.clipboard.writeText(password).then(() => {
        showToast('Copied!', 'Password copied to clipboard.', 'success', 2000);
        const btn = event.target.closest('button');
        const icon = btn.querySelector('i');
        icon.classList.remove('fa-copy');
        icon.classList.add('fa-check');
        setTimeout(() => {
          icon.classList.remove('fa-check');
          icon.classList.add('fa-copy');
        }, 2000);
      }).catch(() => {
        showToast('Copy Failed', 'Failed to copy password to clipboard.', 'error');
      });
    }
    
    // Copy password (removed - users must view password first)
    function copyPassword(encryptedPassword) {
      showToast('Security Notice', 'Please use the "View Password" button to decrypt and copy your password securely.', 'info', 4000);
    }
    
    // Attach form submit handler
    document.addEventListener('DOMContentLoaded', function() {
      const addForm = document.getElementById('addPasswordForm');
      if (addForm) {
        addForm.addEventListener('submit', addPassword);
      }
      
      const editForm = document.getElementById('editPasswordForm');
      if (editForm) {
        editForm.addEventListener('submit', editPassword);
      }
      
      const confirmPasswordForm = document.getElementById('confirmPasswordForm');
      if (confirmPasswordForm) {
        confirmPasswordForm.addEventListener('submit', function(e) {
          e.preventDefault();
          confirmDeletePassword();
        });
      }
      
      const deleteAllForm = document.getElementById('deleteAllForm');
      if (deleteAllForm) {
        deleteAllForm.addEventListener('submit', deleteAllPasswords);
      }
      
      const exportForm = document.getElementById('exportForm');
      if (exportForm) {
        exportForm.addEventListener('submit', exportPasswords);
      }
      
      const importForm = document.getElementById('importForm');
      if (importForm) {
        importForm.addEventListener('submit', async function(e) {
          e.preventDefault();
          
          const fileInput = document.getElementById('importFile');
          const passwordInput = document.getElementById('importAccountPassword');
          const progressDiv = document.getElementById('importProgress');
          
          if (!fileInput.files[0]) {
            showToast('Please select a CSV file', 'error');
            return;
          }
          
          const formData = new FormData();
          formData.append('file', fileInput.files[0]);
          formData.append('accountPassword', passwordInput.value);
          
          try {
            progressDiv.classList.remove('hidden');
            
            const response = await fetch('/import_passwords', {
              method: 'POST',
              body: formData
            });
            
            const data = await response.json();
            
            progressDiv.classList.add('hidden');
            
            if (data.success) {
              showToast(`Successfully imported ${data.imported} passwords! (${data.skipped} skipped)`, 'success');
              closeImportModal();
              
              // Update stats if provided
              if (data.stats) {
                document.getElementById('totalPasswords').textContent = data.stats.total_passwords;
                document.getElementById('weakPasswords').textContent = data.stats.weak_passwords;
                document.getElementById('securityScore').textContent = data.stats.security_score + '%';
                updateSecurityCircle(data.stats.security_score);
              }
              
              // Reload page to show imported passwords without delay
              location.reload();
            } else {
              showToast(data.error || 'Failed to import passwords', 'error');
            }
          } catch (error) {
            progressDiv.classList.add('hidden');
            console.error('Import error:', error);
            showToast('An error occurred while importing passwords', 'error');
          }
        });
      }
    });
    
    function openGeneratePasswordModal() {
      document.getElementById('generatePasswordModal').classList.remove('hidden');
      regeneratePassword();
    }
    
    function closeGeneratePasswordModal() {
      document.getElementById('generatePasswordModal').classList.add('hidden');
    }
    
    // Password visibility toggle
    function togglePasswordVisibility(inputId) {
      // If no inputId provided, default to 'password' for backward compatibility
      const input = document.getElementById(inputId || 'password');
      const icon = event.target.closest('button').querySelector('i');
      
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    }
    
    // Generate password
    function generatePassword() {
      const length = 16;
      const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
      let password = "";
      for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
      }
      document.getElementById('password').value = password;
    }
    
    // Generate password for modal with options
    function regeneratePassword() {
      const length = parseInt(document.getElementById('passwordLength').value);
      const includeLetters = document.getElementById('includeLetters').checked;
      const includeNumbers = document.getElementById('includeNumbers').checked;
      const includeSymbols = document.getElementById('includeSymbols').checked;
      
      let charset = "";
      if (includeLetters) charset += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
      if (includeNumbers) charset += "0123456789";
      if (includeSymbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";
      
      if (charset === "") {
        showToast('Please select at least one character type', 'warning');
        return;
      }
      
      let password = "";
      for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
      }
      
      document.getElementById('generatedPassword').textContent = password;
    }
    
    // Copy generated password
    function copyGeneratedPassword() {
      const password = document.getElementById('generatedPassword').textContent;
      navigator.clipboard.writeText(password).then(() => {
        const btn = event.target.closest('button');
        const icon = btn.querySelector('i');
        const originalClass = icon.className;
        icon.className = 'fas fa-check';
        showToast('Password copied to clipboard!', 'success');
        setTimeout(() => {
          icon.className = originalClass;
        }, 2000);
      });
    }
    
    // Use generated password in add password form
    function useGeneratedPassword() {
      const password = document.getElementById('generatedPassword').textContent;
      document.getElementById('password').value = password;
      closeGeneratePasswordModal();
      showToast('Password inserted into form', 'success');
    }
    
    // Update length value and slider background
    document.getElementById('passwordLength')?.addEventListener('input', function() {
      document.getElementById('lengthValue').textContent = this.value;
      const percentage = ((this.value - this.min) / (this.max - this.min)) * 100;
      this.style.background = `linear-gradient(to right, var(--accent) 0%, var(--accent) ${percentage}%, var(--border) ${percentage}%, var(--border) 100%)`;
      regeneratePassword();
    });
    
    // Regenerate on checkbox change
    document.getElementById('includeLetters')?.addEventListener('change', regeneratePassword);
    document.getElementById('includeNumbers')?.addEventListener('change', regeneratePassword);
    document.getElementById('includeSymbols')?.addEventListener('change', regeneratePassword);
    
    // Update security score card color
    function updateSecurityScoreColor(score) {
      const card = document.getElementById('securityScoreCard');
      const text = document.getElementById('securityScoreText');
      const icon = document.getElementById('securityScoreIcon');
      
      if (score >= 80) {
        card.style.background = 'linear-gradient(135deg, #10B981 0%, #059669 100%)';
        text.textContent = 'Excellent protection';
        icon.className = 'fas fa-shield-alt text-3xl';
      } else if (score >= 60) {
        card.style.background = 'linear-gradient(135deg, #3B82F6 0%, #2563EB 100%)';
        text.textContent = 'Good security';
        icon.className = 'fas fa-shield-alt text-3xl';
      } else if (score >= 40) {
        card.style.background = 'linear-gradient(135deg, #F59E0B 0%, #D97706 100%)';
        text.textContent = 'Fair protection';
        icon.className = 'fas fa-exclamation-triangle text-3xl';
      } else if (score >= 20) {
        card.style.background = 'linear-gradient(135deg, #EF4444 0%, #DC2626 100%)';
        text.textContent = 'Weak security';
        icon.className = 'fas fa-exclamation-circle text-3xl';
      } else {
        card.style.background = 'linear-gradient(135deg, #DC2626 0%, #991B1B 100%)';
        text.textContent = 'Critical - Action needed';
        icon.className = 'fas fa-skull-crossbones text-3xl';
      }
    }
    
    // Initialize security score color on page load
    document.addEventListener('DOMContentLoaded', function() {
      const score = parseInt(document.getElementById('security-score').textContent);
      updateSecurityScoreColor(score);
      
      // Initialize generator
      regeneratePassword();
    });

    // Settings Modal Functions
    function openSettingsModal() {
      document.getElementById('settingsModal').classList.remove('hidden');
      // Pre-fill display name with current display name from navbar
      const currentDisplayName = document.getElementById('displayName').textContent;
      document.getElementById('settingsDisplayName').value = currentDisplayName;
    }

    function closeSettingsModal() {
      document.getElementById('settingsModal').classList.add('hidden');
      // Clear password change fields
      document.getElementById('currentPassword').value = '';
      document.getElementById('newPassword').value = '';
      document.getElementById('confirmPassword').value = '';
    }

    // Update Display Name
    async function updateDisplayName() {
      const displayName = document.getElementById('settingsDisplayName').value.trim();
      
      if (!displayName) {
        showToast('Display name cannot be empty', 'error');
        return;
      }

      try {
        const response = await fetch('/update_display_name', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ displayName })
        });

        const data = await response.json();

        if (data.success) {
          // Update the navbar with new display name
          document.getElementById('displayName').textContent = displayName;
          showToast('Display name updated successfully', 'success');
        } else {
          showToast(data.error || 'Failed to update display name', 'error');
        }
      } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred', 'error');
      }
    }

    // Handle Password Change Form
    window.addEventListener('DOMContentLoaded', function() {
      const changePasswordForm = document.getElementById('changePasswordForm');
      if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', async function(e) {
          e.preventDefault();
          
          const currentPassword = document.getElementById('currentPassword').value;
          const newPassword = document.getElementById('newPassword').value;
          const confirmNewPassword = document.getElementById('confirmPassword').value;

          // Validation
          if (!currentPassword || !newPassword || !confirmNewPassword) {
            showToast('All password fields are required', 'error');
            return;
          }

          if (newPassword !== confirmNewPassword) {
            showToast('New passwords do not match', 'error');
            return;
          }

          if (newPassword === currentPassword) {
            showToast('New password must be different from current password', 'error');
            return;
          }

          // Check password strength
          const strength = calculatePasswordStrength(newPassword);
          if (strength.score < 2) {
            showToast('New password is too weak. Please use a stronger password.', 'warning');
            return;
          }

          try {
            showToast('Changing password and re-encrypting stored passwords...', 'info');
            
            const response = await fetch('/change_password', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                currentPassword,
                newPassword
              })
            });

            const data = await response.json();

            if (data.success) {
              showToast('Password changed successfully! Please log in again.', 'success');
              // Clear form
              changePasswordForm.reset();
              closeSettingsModal();
              // Redirect to login after 2 seconds
              setTimeout(() => {
                window.location.href = '/logout';
              }, 2000);
            } else {
              showToast(data.error || 'Failed to change password', 'error');
            }
          } catch (error) {
            console.error('Error:', error);
            showToast('An error occurred while changing password', 'error');
          }
        });
      }
    });
    
    // Close modals on backdrop click
    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
      backdrop.addEventListener('click', function(e) {
        if (e.target === this) {
          this.classList.add('hidden');
        }
      });
    });
    
    // Search functionality
    document.getElementById('search-input')?.addEventListener('input', function() {
      const searchTerm = this.value.toLowerCase().trim();
      const passwordCards = document.querySelectorAll('[data-password-id]');
      
      let visibleCount = 0;
      
      passwordCards.forEach(card => {
        const website = card.getAttribute('data-website').toLowerCase();
        const username = card.getAttribute('data-username').toLowerCase();
        
        // Check if search term matches website or username
        if (website.includes(searchTerm) || username.includes(searchTerm)) {
          card.style.display = '';
          card.style.animation = 'fadeIn 0.3s ease-in';
          visibleCount++;
        } else {
          card.style.display = 'none';
        }
      });
      
      // Show/hide empty state message
      const passwordList = document.getElementById('password-list');
      let noResultsMsg = document.getElementById('no-search-results');
      
      if (visibleCount === 0 && searchTerm !== '') {
        if (!noResultsMsg) {
          noResultsMsg = document.createElement('div');
          noResultsMsg.id = 'no-search-results';
          noResultsMsg.className = 'text-center py-16';
          noResultsMsg.innerHTML = `
            <div class="w-24 h-24 mx-auto mb-6 rounded-full flex items-center justify-center" style="background: rgba(239, 68, 68, 0.1);">
              <i class="fas fa-search text-4xl" style="color: #EF4444;"></i>
            </div>
            <h3 class="text-xl font-semibold text-primary mb-2">No results found</h3>
            <p class="text-sm text-secondary mb-6">No passwords match "${searchTerm}"</p>
          `;
          passwordList.appendChild(noResultsMsg);
        } else {
          noResultsMsg.querySelector('p').textContent = `No passwords match "${searchTerm}"`;
          noResultsMsg.style.display = '';
        }
      } else if (noResultsMsg) {
        noResultsMsg.style.display = 'none';
      }
    });
    
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
