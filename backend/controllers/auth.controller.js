import asyncHandler from "../utils/asyncHandler.js";
import ApiError from "../utils/ApiError.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import ApiResponse from "../utils/ApiResponse.js";
import connection from "../db/index.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";

// Helper function to generate JWT tokens
const generateTokens = (userId) => {
    const accessToken = jwt.sign(
        { id: userId },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
    );

    const refreshToken = jwt.sign(
        { id: userId },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    );

    return { accessToken, refreshToken };
};

// Helper function to hash password
const hashPassword = async (password) => {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
};

// Helper function to compare password
const comparePassword = async (password, hashedPassword) => {
    return await bcrypt.compare(password, hashedPassword);
};

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const { accessToken, refreshToken } = generateTokens(userId);

        // Update user's refresh token in database
        await connection.execute(
            'UPDATE users SET refresh_token = ? WHERE id = ?',
            [refreshToken, userId]
        );

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong while creating tokens.", error);
    }
};

const registerUser = asyncHandler(async (req, res) => {
    const { username, name, email, password } = req.body;
    console.log(username, name, email, password)
    // Validate required fields
    if ([username, name, email, password].some((field) => field?.trim() === "")) {
        throw new ApiError(400, "All fields (username, name, email, password) are required");
    }

    try {
        // Check if user already exists
        const [existingUsers] = await connection.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        console.log("existingUsers: ", existingUsers)

        if (existingUsers.length > 0) {
            throw new ApiError(409, "User with username or email already exists");
        }

        // Handle optional avatar upload
        let avatarUrl = null;
        if (req.file) {
            const cloudinaryResponse = await uploadOnCloudinary(req.file.path);
            if (cloudinaryResponse) {
                avatarUrl = cloudinaryResponse.secure_url;
            }
        }

        // Hash password
        const hashedPassword = await hashPassword(password);
        console.log("hashedPassword:", hashedPassword)

        // Create user
        const [result] = await connection.execute(
            `INSERT INTO users (username, name, email, password) 
             VALUES (?, ?, ?, ?)`,
            [username.toLowerCase(), name, email.toLowerCase(), hashedPassword]
        );

        console.log("result:", result)

        // Get created user without password
        const [newUser] = await connection.execute(
            'SELECT id, username, name, email, avatar_url, created_at FROM users WHERE id = ?',
            [result.insertId]
        );

        if (!newUser[0]) {
            throw new ApiError(500, "Something went wrong while creating user");
        }

        return res.status(201).json(new ApiResponse(201, newUser[0], "User registered successfully"));
    } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(500, "Database error during registration", error);
    }
});

const loginUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    if (!(username || email)) {
        throw new ApiError(400, "Username or Email is required");
    }

    if (!password) {
        throw new ApiError(400, "Password is required");
    }

    try {
        // Find user by username or email
        const [users] = await connection.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            [username?.toLowerCase() || '', email?.toLowerCase() || '']
        );

        if (users.length === 0) {
            throw new ApiError(404, "User does not exist");
        }

        const user = users[0];

        // Verify password
        const isPasswordValid = await comparePassword(password, user.password);

        if (!isPasswordValid) {
            throw new ApiError(401, "Invalid password");
        }

        // Generate tokens
        const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user.id);

        // Get user without sensitive data
        const [loggedInUser] = await connection.execute(
            'SELECT id, username, name, email, avatar_url, created_at FROM users WHERE id = ?',
            [user.id]
        );

        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            maxAge: 24 * 60 * 60 * 1000, // 1 day for access token
            path: '/'
        };

        const refreshOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days for refresh token
            path: '/'
        };

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, refreshOptions)
            .json(new ApiResponse(200, {
                user: loggedInUser[0],
                accessToken,
                refreshToken
            }, "User logged in successfully"));
    } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(500, "Database error during login", error);
    }
});

const logoutUser = asyncHandler(async (req, res) => {
    try {
        // Clear refresh token from database
        await connection.execute(
            'UPDATE users SET refresh_token = NULL WHERE id = ?',
            [req.user.id]
        );

        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            path: '/'
        };

        return res
            .status(200)
            .clearCookie("accessToken", options)
            .clearCookie("refreshToken", options)
            .json(new ApiResponse(200, {}, "User logged out successfully"));
    } catch (error) {
        throw new ApiError(500, "Database error during logout", error);
    }
});

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Refresh token not found");
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.JWT_SECRET);

        // Find user and verify refresh token
        const [users] = await connection.execute(
            'SELECT * FROM users WHERE id = ? AND refresh_token = ?',
            [decodedToken.id, incomingRefreshToken]
        );

        if (users.length === 0) {
            throw new ApiError(401, "Invalid or expired refresh token");
        }

        const user = users[0];

        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            maxAge: 24 * 60 * 60 * 1000, // 1 day for access token
            path: '/'
        };

        const refreshOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days for refresh token
            path: '/'
        };

        const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshToken(user.id);

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, refreshOptions)
            .json(new ApiResponse(200, {
                accessToken,
                refreshToken: newRefreshToken
            }, "Access Token refreshed successfully"));
    } catch (error) {
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            throw new ApiError(401, "Invalid or expired refresh token");
        }
        throw new ApiError(500, "Error refreshing token", error);
    }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        throw new ApiError(400, "Old password and new password are required");
    }

    try {
        // Get user's current password
        const [users] = await connection.execute(
            'SELECT password FROM users WHERE id = ?',
            [req.user.id]
        );

        if (users.length === 0) {
            throw new ApiError(404, "User not found");
        }

        const user = users[0];
        const isPasswordCorrect = await comparePassword(oldPassword, user.password);

        if (!isPasswordCorrect) {
            throw new ApiError(400, "Invalid old password");
        }

        // Hash new password and update
        const hashedNewPassword = await hashPassword(newPassword);
        await connection.execute(
            'UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?',
            [hashedNewPassword, req.user.id]
        );

        // Get updated user without sensitive data
        const [updatedUser] = await connection.execute(
            'SELECT id, username, name, email, avatar_url FROM users WHERE id = ?',
            [req.user.id]
        );

        return res.status(200).json(new ApiResponse(200, { user: updatedUser[0] }, "Password changed successfully"));
    } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(500, "Database error during password change", error);
    }
});

const getCurrentUser = asyncHandler(async (req, res) => {
    try {
        // Get current user without sensitive data
        const [users] = await connection.execute(
            'SELECT id, username, name, email, avatar_url, created_at FROM users WHERE id = ?',
            [req.user.id]
        );

        if (users.length === 0) {
            throw new ApiError(404, "User not found");
        }

        return res.status(200).json(new ApiResponse(200, users[0], "Current user fetched successfully"));
    } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(500, "Database error fetching user", error);
    }
});

const updateUserProfile = asyncHandler(async (req, res) => {
    const { name, email } = req.body;

    if (!name || !email) {
        throw new ApiError(400, "Name and email are required");
    }

    try {
        // Check if email is already taken by another user
        const [existingUsers] = await connection.execute(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            [email.toLowerCase(), req.user.id]
        );

        if (existingUsers.length > 0) {
            throw new ApiError(409, "Email is already taken by another user");
        }

        // Handle avatar upload if provided
        let avatarUrl = null;
        if (req.files?.avatar?.[0]?.path) {
            // You can implement cloudinary upload here
            avatarUrl = req.files.avatar[0].path;
        }

        // Update user profile
        if (avatarUrl) {
            await connection.execute(
                'UPDATE users SET name = ?, email = ?, avatar_url = ?, updated_at = NOW() WHERE id = ?',
                [name, email.toLowerCase(), avatarUrl, req.user.id]
            );
        } else {
            await connection.execute(
                'UPDATE users SET name = ?, email = ?, updated_at = NOW() WHERE id = ?',
                [name, email.toLowerCase(), req.user.id]
            );
        }

        // Get updated user
        const [updatedUser] = await connection.execute(
            'SELECT id, username, name, email, avatar_url, created_at FROM users WHERE id = ?',
            [req.user.id]
        );

        return res.status(200).json(new ApiResponse(200, updatedUser[0], "Profile updated successfully"));
    } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(500, "Database error during profile update", error);
    }
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    // Check if file was uploaded
    if (!req.file) {
        throw new ApiError(400, "Avatar image file is required");
    }

    try {
        // Upload file to Cloudinary
        const cloudinaryResponse = await uploadOnCloudinary(req.file.path);

        if (!cloudinaryResponse) {
            throw new ApiError(500, "Failed to upload avatar to Cloudinary");
        }

        // Update avatar URL in database
        await connection.execute(
            'UPDATE users SET avatar_url = ?, updated_at = NOW() WHERE id = ?',
            [cloudinaryResponse.secure_url, req.user.id]
        );

        // Get updated user
        const [updatedUser] = await connection.execute(
            'SELECT id, username, name, email, avatar_url, created_at FROM users WHERE id = ?',
            [req.user.id]
        );

        if (updatedUser.length === 0) {
            throw new ApiError(404, "User not found");
        }

        return res.status(200).json(
            new ApiResponse(
                200, 
                {
                    user: updatedUser[0],
                    cloudinaryUrl: cloudinaryResponse.secure_url,
                    publicId: cloudinaryResponse.public_id
                }, 
                "Avatar updated successfully"
            )
        );
    } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new ApiError(500, "Database error during avatar update", error);
    }
});

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateUserProfile,
    updateUserAvatar
};
