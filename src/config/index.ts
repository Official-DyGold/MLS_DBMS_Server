import dotenv from 'dotenv';

dotenv.config();

export const config = {
    env: process.env.NODE_ENV || 'development',
    port: process.env.PORT || 5000,
    jwtSecret: process.env.JWT_SECRET || 'default_jwt_secret',
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'default_jwt_refresh_secret',
    emailUser: process.env.EMAIL_USER || 'default_email_user',
    emailPassword: process.env.EMAIL_PASS || 'default_email_password',
    emailService: process.env.SERVICE_NAME || 'gmail', // e.g., 'gmail', 'yahoo', etc.
    db: {
        host: process.env.DB_HOST || 'localhost',
        port: Number(process.env.DB_PORT) || 5432,
        user: process.env.DB_USER || 'default_db_user',
        password: process.env.DB_PASS || 'default_db_password',
        database: process.env.DB_NAME || 'default_db_name',
        dialect: 'postgres', // or 'mysql', 'sqlite', etc.
    }
};
