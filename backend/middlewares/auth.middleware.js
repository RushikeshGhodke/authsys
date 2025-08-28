import ApiError from "../utils/ApiError.js";
import asyncHandler from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import connection from "../db/index.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            throw new ApiError(401, "Unauthorized request - No token provided");
        }

        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        // Get user from database
        const [users] = await connection.execute(
            'SELECT id, username, name, email, avatar_url FROM users WHERE id = ?',
            [decodedToken.id]
        );

        if (users.length === 0) {
            throw new ApiError(401, "Invalid access token - User not found");
        }

        req.user = users[0];
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            throw new ApiError(401, "Invalid access token");
        }
        if (error.name === 'TokenExpiredError') {
            throw new ApiError(401, "Access token expired");
        }
        throw error instanceof ApiError ? error : new ApiError(401, "Invalid access token");
    }
});
