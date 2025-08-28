import React, { useState } from 'react';
import { User, Mail, Lock, Eye, EyeOff, ArrowRight } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const RegisterPage = () => {
    const navigate = useNavigate();
    const { register } = useAuth();

    const [showPassword, setShowPassword] = useState(false);
    const [formData, setFormData] = useState({
        username: '',
        name: '',
        email: '',
        password: ''
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    const togglePasswordVisibility = () => {
        setShowPassword((prev) => !prev);
    };

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
        setError(''); // Clear error when user types
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess('');

        try {
            await register(formData);
            setSuccess('Registration successful! You can now login.');
            setTimeout(() => {
                navigate('/login');
            }, 2000);
        } catch (error) {
            setError(error.message || 'Registration failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className='min-h-screen max-h-screen flex items-center justify-center bg-[#F9F9F9]'>
            <div className='w-full max-w-sm md:max-w-md bg-white p-6 md:p-8 lg:p-10 rounded-xl border border-[#F0F0F0] shadow-lg flex flex-col items-center justify-center gap-5'>
                <p className='text-2xl md:text-3xl poppins-semibold text-[#0061A1]'>Register</p>
                <div className='w-full border border-[#E1E1E1]'></div>

                {error && (
                    <div className='w-full p-3 bg-red-100 border border-red-300 rounded-md'>
                        <p className='text-red-600 text-sm'>{error}</p>
                    </div>
                )}

                {success && (
                    <div className='w-full p-3 bg-green-100 border border-green-300 rounded-md'>
                        <p className='text-green-600 text-sm'>{success}</p>
                    </div>
                )}

                <form onSubmit={handleSubmit} className='w-full space-y-5'>
                    <div className='flex flex-col gap-2 w-full'>
                        <div className='text-[#7D7D7D] flex items-center gap-2'>
                            <User size={16} />
                            <p className='text-md'>Username</p>
                        </div>
                        <input 
                            type="text" 
                            name="username"
                            placeholder='Username' 
                            value={formData.username}
                            onChange={handleChange}
                            required
                            className='w-full border-2 border-[#D1CDCD] rounded-md p-2 text-sm poppins-regular text-[#656565]' 
                        />
                    </div>

                    <div className='flex flex-col gap-2 w-full'>
                        <div className='text-[#7D7D7D] flex items-center gap-2'>
                            <User size={16} />
                            <p className='text-md'>Full Name</p>
                        </div>
                        <input 
                            type="text" 
                            name="name"
                            placeholder='Full Name' 
                            value={formData.name}
                            onChange={handleChange}
                            required
                            className='w-full border-2 border-[#D1CDCD] rounded-md p-2 text-sm poppins-regular text-[#656565]' 
                        />
                    </div>

                    <div className='flex flex-col gap-2 w-full'>
                        <div className='text-[#7D7D7D] flex items-center gap-2'>
                            <Mail size={16} />
                            <p className='text-md'>Email</p>
                        </div>
                        <input 
                            type="email" 
                            name="email"
                            placeholder='Email Address' 
                            value={formData.email}
                            onChange={handleChange}
                            required
                            className='w-full border-2 border-[#D1CDCD] rounded-md p-2 text-sm poppins-regular text-[#656565]' 
                        />
                    </div>

                    <div className='flex flex-col gap-2 w-full'>
                        <div className='text-[#7D7D7D] flex items-center gap-2'>
                            <Lock size={16} />
                            <p className='text-md'>Password</p>
                        </div>
                        <div className='relative'>
                            <input
                                type={showPassword ? 'text' : 'password'}
                                name="password"
                                placeholder='Password'
                                value={formData.password}
                                onChange={handleChange}
                                required
                                className='w-full border-2 border-[#D1CDCD] rounded-md p-2 text-sm poppins-regular text-[#656565] pr-10'
                            />
                            <button
                                type='button'
                                onClick={togglePasswordVisibility}
                                className='absolute right-2 top-1/2 -translate-y-1/2 text-[#7D7D7D] hover:cursor-pointer'
                                tabIndex={-1}
                            >
                                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                            </button>
                        </div>
                    </div>

                    <button 
                        type='submit'
                        disabled={loading}
                        className='bg-[#0061A1] text-[#FFFFFF] w-full min-h-10 rounded-md mt-2 hover:cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed'
                    >
                        {loading ? 'Creating Account...' : 'Register'}
                    </button>
                </form>

                <Link to={'/login'} className='text-xs underline text-[#0061A1] flex items-center gap-1'>Already have one? Just Login <ArrowRight size={15} /></Link>
            </div>
        </div>
    )
}

export default RegisterPage;
