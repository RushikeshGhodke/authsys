import React, { createContext, useContext, useState, useEffect } from 'react';
import { authAPI } from '../utils/api';

const AuthContext = createContext();

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [isAuthenticated, setIsAuthenticated] = useState(false);

    // Check if user is logged in on app start
    useEffect(() => {
        checkAuth();
    }, []);

    const checkAuth = async () => {
        try {
            setLoading(true);
            const response = await authAPI.getCurrentUser();
            if (response.success) {
                setUser(response.data);
                setIsAuthenticated(true);
            }
        } catch (error) {
            console.log('User not authenticated');
            setUser(null);
            setIsAuthenticated(false);
        } finally {
            setLoading(false);
        }
    };

    const register = async (userData) => {
        try {
            const response = await authAPI.register(userData);
            if (response.success) {
                return response;
            }
            throw new Error(response.message);
        } catch (error) {
            throw error;
        }
    };

    const login = async (credentials) => {
        try {
            const response = await authAPI.login(credentials);
            if (response.success) {
                setUser(response.data.user);
                setIsAuthenticated(true);
                return response;
            }
            throw new Error(response.message);
        } catch (error) {
            throw error;
        }
    };

    const logout = async () => {
        try {
            await authAPI.logout();
            setUser(null);
            setIsAuthenticated(false);
        } catch (error) {
            // Even if API call fails, clear local state
            setUser(null);
            setIsAuthenticated(false);
            console.error('Logout error:', error);
        }
    };

    const updateUser = (userData) => {
        setUser(userData);
    };

    const value = {
        user,
        loading,
        isAuthenticated,
        register,
        login,
        logout,
        updateUser,
        checkAuth,
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};
