const API_BASE_URL = 'http://localhost:3000/api/v1';

// Base function for making API requests
const makeRequest = async (url, options = {}) => {
    const config = {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
        credentials: 'include', // Important for cookies
        ...options,
    };

    // Handle FormData (for file uploads)
    if (options.body instanceof FormData) {
        delete config.headers['Content-Type']; // Let browser set boundary
    }

    try {
        const response = await fetch(`${API_BASE_URL}${url}`, config);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Something went wrong');
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
};

// Authentication API functions
export const authAPI = {
    // Register user
    register: async (userData) => {
        console.log(userData)
        return makeRequest('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData),
        });
    },

    // Login user
    login: async (credentials) => {
        return makeRequest('/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials),
        });
    },

    // Logout user
    logout: async () => {
        return makeRequest('/auth/logout', {
            method: 'POST',
        });
    },

    // Get current user
    getCurrentUser: async () => {
        return makeRequest('/auth/current-user');
    },

    // Refresh token
    refreshToken: async () => {
        return makeRequest('/auth/refresh-token', {
            method: 'POST',
        });
    },

    // Change password
    changePassword: async (passwordData) => {
        return makeRequest('/auth/change-password', {
            method: 'POST',
            body: JSON.stringify(passwordData),
        });
    },

    // Update profile
    updateProfile: async (profileData) => {
        return makeRequest('/auth/update-profile', {
            method: 'PATCH',
            body: JSON.stringify(profileData),
        });
    },

    // Update avatar
    updateAvatar: async (avatarFile) => {
        const formData = new FormData();
        formData.append('avatar', avatarFile);
        
        return makeRequest('/auth/update-avatar', {
            method: 'PATCH',
            body: formData,
        });
    },
};

export default makeRequest;
