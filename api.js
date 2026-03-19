// API Configuration
const API_BASE_URL = 'http://localhost:3009/api';

// Store token
let authToken = localStorage.getItem('authToken');

// ==================== AUTHENTICATION ====================

// Register user
async function apiRegister(name, email, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, email, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Registration failed');
        }

        // Save token
        authToken = data.token;
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));

        return data;
    } catch (error) {
        console.error('Registration error:', error);
        throw error;
    }
}

// Login user
async function apiLogin(email, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }

        // Save token
        authToken = data.token;
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));

        return data;
    } catch (error) {
        console.error('Login error:', error);
        throw error;
    }
}

// Logout user
async function apiLogout() {
    try {
        if (authToken) {
            await fetch(`${API_BASE_URL}/auth/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
        }
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        // Clear local storage
        authToken = null;
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
    }
}

// Get current user
async function apiGetCurrentUser() {
    try {
        const response = await fetch(`${API_BASE_URL}/auth/me`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get user');
        }

        return data.user;
    } catch (error) {
        console.error('Get user error:', error);
        throw error;
    }
}

// ==================== USER PROFILE ====================

// Update profile
async function apiUpdateProfile(name, email) {
    try {
        const response = await fetch(`${API_BASE_URL}/users/profile`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ name, email })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to update profile');
        }

        return data;
    } catch (error) {
        console.error('Update profile error:', error);
        throw error;
    }
}

// Change password
async function apiChangePassword(currentPassword, newPassword) {
    try {
        const response = await fetch(`${API_BASE_URL}/users/change-password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ currentPassword, newPassword })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to change password');
        }

        return data;
    } catch (error) {
        console.error('Change password error:', error);
        throw error;
    }
}

// Get user settings
async function apiGetSettings() {
    try {
        const response = await fetch(`${API_BASE_URL}/users/settings`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get settings');
        }

        return data.settings;
    } catch (error) {
        console.error('Get settings error:', error);
        throw error;
    }
}

// Update user settings
async function apiUpdateSettings(settings) {
    try {
        const response = await fetch(`${API_BASE_URL}/users/settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(settings)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to update settings');
        }

        return data;
    } catch (error) {
        console.error('Update settings error:', error);
        throw error;
    }
}

// ==================== FILE MANAGEMENT ====================

// Upload file
async function apiUploadFile(file) {
    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch(`${API_BASE_URL}/files/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            },
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to upload file');
        }

        return data.file;
    } catch (error) {
        console.error('Upload file error:', error);
        throw error;
    }
}

// Get user files
async function apiGetFiles() {
    try {
        const response = await fetch(`${API_BASE_URL}/files`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get files');
        }

        return data.files;
    } catch (error) {
        console.error('Get files error:', error);
        throw error;
    }
}

// Delete file
async function apiDeleteFile(fileId) {
    try {
        const response = await fetch(`${API_BASE_URL}/files/${fileId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to delete file');
        }

        return data;
    } catch (error) {
        console.error('Delete file error:', error);
        throw error;
    }
}

// ==================== ACTIVITY ====================

// Get user activity
async function apiGetActivity(limit = 20, offset = 0) {
    try {
        const response = await fetch(`${API_BASE_URL}/activity?limit=${limit}&offset=${offset}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get activity');
        }

        return data;
    } catch (error) {
        console.error('Get activity error:', error);
        throw error;
    }
}

// Log tool usage
async function apiLogToolUsage(tool, fileName = null, fileSize = null, details = null) {
    try {
        await fetch(`${API_BASE_URL}/activity/tool`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ tool, fileName, fileSize, details })
        });
    } catch (error) {
        console.error('Log tool usage error:', error);
    }
}

// ==================== STATISTICS ====================

// Get user statistics
async function apiGetStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/stats`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get stats');
        }

        return data.stats;
    } catch (error) {
        console.error('Get stats error:', error);
        throw error;
    }
}

// Get usage by tool
async function apiGetToolStats() {
    try {
        const response = await fetch(`${API_BASE_URL}/stats/tools`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get tool stats');
        }

        return data.tools;
    } catch (error) {
        console.error('Get tool stats error:', error);
        throw error;
    }
}

// ==================== HELPER FUNCTIONS ====================

// Check if user is logged in
function isLoggedIn() {
    return !!authToken && !!localStorage.getItem('user');
}

// Get current user from local storage
function getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

// Update your existing login function
async function handleLogin() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!email || !password) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    try {
        const result = await apiLogin(email, password);
        
        isLoggedIn = true;
        currentUser = result.user;
        
        showToast(`Welcome back, ${currentUser.name}!`, 'success');
        closeAuthModal();
        updateAuthUI();
        
        // Log login activity
        apiLogToolUsage('login');
    } catch (error) {
        showToast(error.message, 'error');
    }
}

// Update your existing signup function
async function handleSignup() {
    const name = document.getElementById('signupName').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirm = document.getElementById('signupConfirmPassword').value;
    
    if (!name || !email || !password || !confirm) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    if (password !== confirm) {
        showToast('Passwords do not match', 'error');
        return;
    }
    
    try {
        const result = await apiRegister(name, email, password);
        
        isLoggedIn = true;
        currentUser = result.user;
        
        showToast(`Welcome, ${name}!`, 'success');
        closeAuthModal();
        updateAuthUI();
    } catch (error) {
        showToast(error.message, 'error');
    }
}

// Update logout function
async function handleLogout() {
    await apiLogout();
    isLoggedIn = false;
    currentUser = null;
    processedResult = null;
    showToast('You have been logged out successfully', 'info');
    updateAuthUI();
}

// Update auth UI function
function updateAuthUI() {
    const authButtons = document.getElementById('authButtons');
    const userMenu = document.getElementById('userMenu');
    
    if (isLoggedIn && currentUser) {
        authButtons.style.display = 'none';
        userMenu.style.display = 'block';
        document.getElementById('userAvatar').textContent = currentUser.name.substring(0, 2).toUpperCase();
        document.getElementById('userName').textContent = currentUser.name;
        document.getElementById('userEmail').textContent = currentUser.email;
    } else {
        authButtons.style.display = 'flex';
        userMenu.style.display = 'none';
    }
}

// Check login status on page load
document.addEventListener('DOMContentLoaded', function() {
    if (isLoggedIn()) {
        currentUser = getCurrentUser();
        isLoggedIn = true;
        updateAuthUI();
    }
});