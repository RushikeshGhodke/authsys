import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import ApiError from './utils/ApiError.js';
import ApiResponse from './utils/ApiResponse.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:5173",
    credentials: true
}));

app.use(express.json({}));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

// Health check route
app.get('/health', (req, res) => {
    res.status(200).json(
        new ApiResponse(200, {
            status: "Server is running",
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development'
        }, "Server health check successful")
    );
});

// Import routes
import authRoutes from './routes/auth.routes.js';

// Routes declaration
app.use("/api/v1/auth", authRoutes);

// API routes
app.get('/api/v1', (req, res) => {
    res.status(200).json(
        new ApiResponse(200, {
            message: "API is working",
            version: "1.0.0",
            endpoints: {
                health: "/health",
                auth: "/api/v1/auth",
                users: "/api/v1/users"
            }
        }, "Welcome to ShopHub API")
    );
});

// Global error handling middleware
app.use((err, req, res, next) => {
    if (err instanceof ApiError) {
        return res.status(err.statusCode).json({
            success: false,
            message: err.message,
            errors: err.errors,
            stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
        });
    }

    // Handle other errors
    console.error('Unhandled Error:', err);
    return res.status(500).json({
        success: false,
        message: "Internal Server Error",
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

// 404 handler - must be the last middleware
app.use((req, res) => {
    res.status(404).json(
        new ApiResponse(404, null, `Route ${req.originalUrl} not found`)
    );
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Frontend URL: http://localhost:5173`);
    console.log(`Backend URL: http://localhost:${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`API Base: http://localhost:${PORT}/api/v1`);
});

export default app;