import React, { useState } from 'react';
import { User, Lock, Eye, EyeOff, ArrowRight } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const LoginPage = () => {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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

    try {
      // Use either username or email for login
      const credentials = {
        username: formData.username,
        email: formData.username, // Backend accepts both
        password: formData.password
      };

      await login(credentials);
      navigate('/home');
    } catch (error) {
      setError(error.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className='poppins-regular min-h-screen max-h-screen flex items-center justify-center bg-[#F9F9F9]'>
      <div className='w-full max-w-sm md:max-w-md bg-white p-6 md:p-8 lg:p-10 rounded-xl border border-[#F0F0F0] shadow-lg flex flex-col items-center justify-center gap-5'>
        <p className='text-2xl md:text-3xl poppins-semibold text-[#0061A1]'>Login</p>
        <div className='w-full border border-[#E1E1E1]'></div>

        {error && (
          <div className='w-full p-3 bg-red-100 border border-red-300 rounded-md'>
            <p className='text-red-600 text-sm'>{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className='w-full space-y-5'>
          <div className='flex flex-col gap-2 w-full'>
            <div className='text-[#7D7D7D] flex items-center gap-2'>
              <User size={16} />
              <p className='text-md'>Username or Email</p>
            </div>
            <input 
              type="text" 
              name="username"
              placeholder='Username or Email' 
              value={formData.username}
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
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>

        <Link to={'/register'} className='text-xs underline text-[#0061A1] flex items-center gap-1'>Don't have? Create a new one <ArrowRight size={15}/></Link>
      </div>
    </div>
  )
}

export default LoginPage;