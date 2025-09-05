import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

let connection;

// Create the connection to database
console.log(process.env.DB_HOST);

try {
    connection = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'auth_sys',
        ssl: false
    });

    console.log('MySQL Database connected successfully');

    // Test the connection
    await connection.ping();
    console.log('Database connection is active');

} catch (error) {
    console.error("MySQL connection error:", error.message);
    process.exit(1);
}

export default connection;