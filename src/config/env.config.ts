import dotenv from "dotenv";

dotenv.config();

interface EnvConfig {
    NODE_ENV: string;
    PORT: number;
    MAIL_TRAP_USER: string;
    MAIL_TRAP_PASSWORD: string;
    MAIL_TRAP_PORT: number;
    MONGO_URI: string;
    DB_NAME: string;
    APP_EMAIL: string;
    ACCESS_TOKEN_SECRET: string;
    REFRESH_TOKEN_SECRET: string;
    APP_URL: string;
}

export const envConfig = {
    NODE_ENV: String(process.env.NODE_ENV),
    PORT: Number(process.env.PORT || 3000),
    MAIL_TRAP_USER: String(process.env.MAIL_TRAP_USER),
    MAIL_TRAP_PASSWORD: String(process.env.MAIL_TRAP_PASSWORD),
    MAIL_TRAP_PORT: Number(process.env.MAIL_TRAP_PORT),
    MONGO_URI: String(process.env.MONGO_URI),
    DB_NAME: String(process.env.DB_NAME),
    APP_EMAIL: String(process.env.APP_EMAIL),
    ACCESS_TOKEN_SECRET: String(process.env.ACCESS_TOKEN_SECRET),
    REFRESH_TOKEN_SECRET: String(process.env.REFRESH_TOKEN_SECRET),
    APP_URL: String(process.env.APP_URL),
} satisfies EnvConfig;
