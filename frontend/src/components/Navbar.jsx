import React from 'react'
import { Lock, User, LogOut } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const Navbar = () => {
    const { user, logout, isAuthenticated } = useAuth();
    const navigate = useNavigate();

    const handleLogout = async () => {
        try {
            await logout();
            navigate('/');
        } catch (error) {
            console.error('Logout error:', error);
        }
    };

    return (
        <>
            <header className="fixed top-0 left-0 right-0 bg-white shadow-sm border-b border-[#F0F0F0] z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between h-16">
                        {/* Logo */}
                        <div className="flex items-center">
                            <Lock size={18} className="text-[#0061A1]" />
                            <span className="ml-2 text-xl font-bold text-[#0061A1] poppins-semibold">authsys</span>
                        </div>

                        {/* Navigation */}
                        <div className="flex items-center space-x-4">
                            {isAuthenticated ? (
                                <>
                                    <span className="text-sm text-[#7D7D7D] hidden md:block">
                                        Welcome, {user?.name || user?.username}
                                    </span>
                                    <Link to="/profile" className="hidden md:flex items-center space-x-1 text-[#7D7D7D] hover:text-[#0061A1] transition-colors">
                                        <User size={16} />
                                        <span className="text-md poppins-semibold">Profile</span>
                                    </Link>
                                    <button 
                                        onClick={handleLogout}
                                        className="flex items-center space-x-1 text-[#7D7D7D] hover:text-red-600 transition-colors"
                                    >
                                        <LogOut size={16} />
                                        <span className="text-md poppins-semibold">Logout</span>
                                    </button>
                                </>
                            ) : (
                                <div className="flex items-center space-x-4">
                                    <Link to="/login" className="text-[#7D7D7D] hover:text-[#0061A1] transition-colors text-sm poppins-semibold">
                                        Login
                                    </Link>
                                    <Link to="/register" className="bg-[#0061A1] text-white px-4 py-2 rounded-md text-sm poppins-semibold hover:bg-[#004a7c] transition-colors">
                                        Sign Up
                                    </Link>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </header>

        </>
    )
}

export default Navbar