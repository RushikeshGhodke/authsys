import React, { useState } from 'react';
import Navbar from '../components/Navbar';
import { useAuth } from '../context/AuthContext';
import { authAPI } from '../utils/api';
import {
    User,
    Mail,
    Lock,
    Camera,
    Edit3,
    Save,
    X,
    Eye,
    EyeOff,
    Calendar,
    Shield,
    Activity,
    Settings,
    SaveIcon
} from 'lucide-react';

const Profile = () => {
    const { user, updateUser, isAuthenticated } = useAuth();
    const [isEditing, setIsEditing] = useState(false);
    const [isChangingPassword, setIsChangingPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [showOldPassword, setShowOldPassword] = useState(false);
    const [showNewPassword, setShowNewPassword] = useState(false);

    const [profileData, setProfileData] = useState({
        name: user?.name || '',
        email: user?.email || ''
    });

    const [passwordData, setPasswordData] = useState({
        oldPassword: '',
        newPassword: ''
    });

    const [selectedAvatar, setSelectedAvatar] = useState(null);
    const [avatarPreview, setAvatarPreview] = useState(null);

    if (!isAuthenticated || !user) {
        return (
            <>
                <Navbar />
                <div className="min-h-screen flex items-center justify-center bg-[#F9F9F9] pt-16">
                    <div className="text-center">
                        <h2 className="text-2xl font-bold text-[#0061A1] mb-4">Please log in to access your profile</h2>
                        <p className="text-[#7D7D7D]">You need to be authenticated to view this content.</p>
                    </div>
                </div>
            </>
        );
    }

    const handleProfileChange = (e) => {
        setProfileData({
            ...profileData,
            [e.target.name]: e.target.value
        });
        setError('');
    };

    const handlePasswordChange = (e) => {
        setPasswordData({
            ...passwordData,
            [e.target.name]: e.target.value
        });
        setError('');
    };

    const handleAvatarChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setSelectedAvatar(file);
            const reader = new FileReader();
            reader.onloadend = () => {
                setAvatarPreview(reader.result);
            };
            reader.readAsDataURL(file);
        }
    };

    const handleUpdateProfile = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess('');

        try {
            const response = await authAPI.updateProfile(profileData);
            if (response.success) {
                updateUser(response.data);
                setSuccess('Profile updated successfully!');
                setIsEditing(false);
            }
        } catch (error) {
            setError(error.message || 'Failed to update profile');
        } finally {
            setLoading(false);
        }
    };

    const handleUpdateAvatar = async () => {
        if (!selectedAvatar) return;

        setLoading(true);
        setError('');
        setSuccess('');

        try {
            const response = await authAPI.updateAvatar(selectedAvatar);
            if (response.success) {
                updateUser(response.data.user);
                setSuccess('Avatar updated successfully!');
                setSelectedAvatar(null);
                setAvatarPreview(null);
            }
        } catch (error) {
            setError(error.message || 'Failed to update avatar');
        } finally {
            setLoading(false);
        }
    };

    const handleChangePassword = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess('');

        try {
            const response = await authAPI.changePassword(passwordData);
            if (response.success) {
                setSuccess('Password changed successfully!');
                setPasswordData({ oldPassword: '', newPassword: '' });
                setIsChangingPassword(false);
            }
        } catch (error) {
            setError(error.message || 'Failed to change password');
        } finally {
            setLoading(false);
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    };

    return (
        <>
            <Navbar />
            <div className="min-h-screen bg-[#F9F9F9] py-6 pt-18">
                <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
                    {/* Profile Header */}
                    <div className="bg-white rounded-xl shadow-lg p-8 mb-8">
                        <div className="flex flex-col md:flex-row items-center md:items-start space-y-6 md:space-y-0 md:space-x-8">
                            {/* Avatar Section */}
                            <div className="relative">
                                <div className="w-32 h-32 bg-gray-200 rounded-full flex items-center justify-center overflow-hidden">
                                    {avatarPreview ? (
                                        <img src={avatarPreview} alt="Avatar Preview" className="w-full h-full object-cover" />
                                    ) : user.avatar_url ? (
                                        <img src={user.avatar_url} alt="User Avatar" className="w-full h-full object-cover" />
                                    ) : (
                                        <User size={48} className="text-gray-400" />
                                    )}
                                </div>
                                <label className="absolute bottom-0 right-0 bg-[#0061A1] text-white p-2 rounded-full cursor-pointer hover:bg-[#004a7c] transition-colors">
                                    <Camera size={16} />
                                    <input
                                        type="file"
                                        accept="image/*"
                                        onChange={handleAvatarChange}
                                        className="hidden"
                                    />
                                </label>
                                {selectedAvatar && (
                                    <button
                                        onClick={handleUpdateAvatar}
                                        disabled={loading}
                                        className="absolute -bottom-8 left-1/2 transform -translate-x-1/2 bg-green-600 text-white px-4 py-1 rounded-md text-sm hover:bg-green-700 transition-colors disabled:opacity-50"
                                    >
                                        {loading ? 'Uploading...' : <SaveIcon />}
                                    </button>
                                )}
                            </div>

                            {/* User Info */}
                            <div className="flex-1 text-center md:text-left">
                                <h1 className="text-3xl font-bold text-gray-800 mb-2 poppins-bold">
                                    {user.name || user.username}
                                </h1>
                                <p className="text-[#7D7D7D] mb-4 poppins-regular">@{user.username}</p>
                                <div className="flex flex-col md:flex-row md:items-center space-y-2 md:space-y-0 md:space-x-6 text-sm text-gray-600">
                                    <div className="flex items-center justify-center md:justify-start">
                                        <Mail size={16} className="mr-2" />
                                        <span className="poppins-regular">{user.email}</span>
                                    </div>
                                    <div className="flex items-center justify-center md:justify-start">
                                        <Calendar size={16} className="mr-2" />
                                        <span className="poppins-regular">Joined {formatDate(user.created_at)}</span>
                                    </div>
                                </div>
                            </div>

                            {/* Edit Button */}
                            <button
                                onClick={() => setIsEditing(!isEditing)}
                                className="bg-[#0061A1] text-white px-6 py-2 rounded-lg hover:bg-[#004a7c] transition-colors flex items-center gap-2 poppins-semibold"
                            >
                                {isEditing ? <X size={16} /> : <Edit3 size={16} />}
                                {isEditing ? 'Cancel' : 'Edit Profile'}
                            </button>
                        </div>
                    </div>

                    {/* Messages */}
                    {error && (
                        <div className="bg-red-100 border border-red-300 text-red-600 p-4 rounded-lg mb-6">
                            {error}
                        </div>
                    )}

                    {success && (
                        <div className="bg-green-100 border border-green-300 text-green-600 p-4 rounded-lg mb-6">
                            {success}
                        </div>
                    )}

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        {/* Profile Information */}
                        <div className="bg-white rounded-xl shadow-lg p-8">
                            <div className="flex items-center justify-between mb-6">
                                <h2 className="text-2xl font-bold text-gray-800 poppins-bold">Profile Information</h2>
                                <User className="text-[#0061A1]" size={24} />
                            </div>

                            {isEditing ? (
                                <form onSubmit={handleUpdateProfile} className="space-y-6">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">Full Name</label>
                                        <input
                                            type="text"
                                            name="name"
                                            value={profileData.name}
                                            onChange={handleProfileChange}
                                            className="w-full border-2 border-gray-300 rounded-lg p-3 focus:border-[#0061A1] focus:outline-none poppins-regular"
                                            required
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">Email Address</label>
                                        <input
                                            type="email"
                                            name="email"
                                            value={profileData.email}
                                            onChange={handleProfileChange}
                                            className="w-full border-2 border-gray-300 rounded-lg p-3 focus:border-[#0061A1] focus:outline-none poppins-regular"
                                            required
                                        />
                                    </div>
                                    <button
                                        type="submit"
                                        disabled={loading}
                                        className="w-full bg-[#0061A1] text-white py-3 rounded-lg hover:bg-[#004a7c] transition-colors disabled:opacity-50 flex items-center justify-center gap-2 poppins-semibold"
                                    >
                                        <Save size={16} />
                                        {loading ? 'Saving...' : 'Save Changes'}
                                    </button>
                                </form>
                            ) : (
                                <div className="space-y-6">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">Full Name</label>
                                        <p className="text-gray-800 poppins-regular">{user.name || 'Not provided'}</p>
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">Username</label>
                                        <p className="text-gray-800 poppins-regular">{user.username}</p>
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">Email Address</label>
                                        <p className="text-gray-800 poppins-regular">{user.email}</p>
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">Member Since</label>
                                        <p className="text-gray-800 poppins-regular">{formatDate(user.created_at)}</p>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Security Settings */}
                        <div className="bg-white rounded-xl shadow-lg p-8">
                            <div className="flex items-center justify-between mb-6">
                                <h2 className="text-2xl font-bold text-gray-800 poppins-bold">Security Settings</h2>
                                <Shield className="text-[#0061A1]" size={24} />
                            </div>

                            {isChangingPassword ? (
                                <form onSubmit={handleChangePassword} className="space-y-6">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">Current Password</label>
                                        <div className="relative">
                                            <input
                                                type={showOldPassword ? 'text' : 'password'}
                                                name="oldPassword"
                                                value={passwordData.oldPassword}
                                                onChange={handlePasswordChange}
                                                className='w-full border-2 border-[#D1CDCD] rounded-md p-2 text-sm poppins-regular text-[#656565] pr-10'
                                                required
                                            />
                                            <button
                                                type="button"
                                                onClick={() => setShowOldPassword(!showOldPassword)}
                                                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400"
                                            >
                                                {showOldPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                                            </button>
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">New Password</label>
                                        <div className="relative">
                                            <input
                                                type={showNewPassword ? 'text' : 'password'}
                                                name="newPassword"
                                                value={passwordData.newPassword}
                                                onChange={handlePasswordChange}
                                                className='w-full border-2 border-[#D1CDCD] rounded-md p-2 text-sm poppins-regular text-[#656565] pr-10'
                                                required
                                            />
                                            <button
                                                type="button"
                                                onClick={() => setShowNewPassword(!showNewPassword)}
                                                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400"
                                            >
                                                {showNewPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                                            </button>
                                        </div>
                                    </div>
                                    <div className="flex space-x-4">
                                        <button
                                            type="submit"
                                            disabled={loading}
                                            className="flex-row p-2 bg-[#0061A1] text-white py-2 rounded-lg hover:bg-[#004a7c] transition-colors disabled:opacity-50 flex items-center justify-center gap-2 poppins-semibold"
                                        >
                                            <Lock size={16} />
                                            {loading ? 'Changing...' : 'Change Password'}
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => {
                                                setIsChangingPassword(false);
                                                setPasswordData({ oldPassword: '', newPassword: '' });
                                            }}
                                            className="flex-1 bg-gray-500 text-white py-3 rounded-lg hover:bg-gray-600 transition-colors poppins-semibold"
                                        >
                                            Cancel
                                        </button>
                                    </div>
                                </form>
                            ) : (
                                <div className="space-y-6">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-2 poppins-semibold">Password</label>
                                        <p className="text-gray-800 poppins-regular">••••••••••••</p>
                                    </div>
                                    <button
                                        onClick={() => setIsChangingPassword(true)}
                                        className="w-full bg-[#0061A1] text-white py-2 rounded-lg hover:bg-[#004a7c] transition-colors flex items-center justify-center gap-2 poppins-semibold"
                                    >
                                        <Lock size={16} />
                                        Change Password
                                    </button>
                                </div>
                            )}

                            <div className="mt-8 pt-6 border-t border-gray-200">
                                <h3 className="text-lg font-semibold text-gray-800 mb-4 poppins-semibold">Account Security</h3>
                                <div className="space-y-3 text-sm text-gray-600">
                                    <div className="flex items-center justify-between">
                                        <span className="poppins-regular">Two-Factor Authentication</span>
                                        <span className="text-red-600 poppins-semibold">Disabled</span>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="poppins-regular">Login Notifications</span>
                                        <span className="text-green-600 poppins-semibold">Enabled</span>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="poppins-regular">Session Timeout</span>
                                        <span className="text-gray-800 poppins-semibold">24 hours</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
};

export default Profile