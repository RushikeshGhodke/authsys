import React from 'react';
import { Link } from 'react-router-dom';
import { Lock, User, UserPlus, ArrowRight } from 'lucide-react';

const LandingPage = () => {
    return (
        <div className="min-h-screen bg-gradient-to-br from-[#F9F9F9] to-[#E8F4FD]">
            {/* Navigation */}
            <nav className="bg-white shadow-sm border-b border-[#F0F0F0]">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between h-16">
                        <div className="flex items-center">
                            <Lock size={18} className="text-[#0061A1]" />
                            <span className="ml-2 text-xl font-bold text-[#0061A1] poppins-semibold">authsys</span>
                        </div>
                        
                        <div className="flex items-center space-x-4">
                            <Link to="/login" className="text-[#7D7D7D] hover:text-[#0061A1] transition-colors text-sm poppins-semibold">
                                Login
                            </Link>
                            <Link to="/register" className="bg-[#0061A1] text-white px-4 py-2 rounded-md text-sm poppins-semibold hover:bg-[#004a7c] transition-colors">
                                Sign Up
                            </Link>
                        </div>
                    </div>
                </div>
            </nav>

            {/* Hero Section */}
            <div className="flex items-center justify-center min-h-[calc(100vh-4rem)]">
                <div className="text-center max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="mb-6">
                        <Lock size={64} className="text-[#0061A1] mx-auto mb-6" />
                        <h1 className="text-2xl md:text-4xl font-bold text-[#0061A1] mb-4 poppins-bold">
                            Welcome to AuthSys
                        </h1>
                        <p className="text-lg md:text-xl text-[#7D7D7D] mb-8 poppins-regular">
                            Secure authentication system with modern design
                        </p>
                        <p className="text-md text-[#656565] mb-12 poppins-regular max-w-2xl mx-auto">
                            Experience seamless login and registration with our secure authentication platform. 
                            Built with modern technologies and best security practices.
                        </p>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-12">
                        <Link 
                            to="/register" 
                            className="bg-[#0061A1] text-white px-6 py-4 rounded-lg text-md font-semibold hover:bg-[#004a7c] transition-colors flex items-center gap-2 poppins-semibold min-w-[200px] justify-center"
                        >
                            <UserPlus size={20} />
                            Get Started
                            <ArrowRight size={20} />
                        </Link>
                        
                        <Link 
                            to="/login" 
                            className="bg-white text-[#0061A1] border border-[#0061A1] px-6 py-4 rounded-lg text-md font-semibold hover:bg-[#0061A1] hover:text-white transition-colors flex items-center gap-2 poppins-semibold min-w-[200px] justify-center"
                        >
                            <User size={20} />
                            Sign In
                        </Link>
                    </div>

                    {/* Features */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-3xl mx-auto">
                        <div className="bg-white p-6 rounded-xl shadow-md">
                            <Lock size={32} className="text-[#0061A1] mx-auto mb-3" />
                            <h3 className="text-lg font-semibold text-[#0061A1] mb-2 poppins-semibold">Secure</h3>
                            <p className="text-[#7D7D7D] text-sm poppins-regular">Advanced security with JWT tokens and encrypted passwords</p>
                        </div>
                        
                        <div className="bg-white p-6 rounded-xl shadow-md">
                            <User size={32} className="text-[#0061A1] mx-auto mb-3" />
                            <h3 className="text-lg font-semibold text-[#0061A1] mb-2 poppins-semibold">User Friendly</h3>
                            <p className="text-[#7D7D7D] text-sm poppins-regular">Clean and intuitive interface for the best user experience</p>
                        </div>
                        
                        <div className="bg-white p-6 rounded-xl shadow-md">
                            <ArrowRight size={32} className="text-[#0061A1] mx-auto mb-3" />
                            <h3 className="text-lg font-semibold text-[#0061A1] mb-2 poppins-semibold">Fast</h3>
                            <p className="text-[#7D7D7D] text-sm poppins-regular">Quick registration and login process with instant access</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LandingPage;