import dotenv from "dotenv";

dotenv.config();

interface EnvConfig {
    NODE_ENV: string;
    PORT: number;
}

export const envConfig = {
    NODE_ENV: String(process.env.NODE_ENV),
    PORT: Number(process.env.PORT || 3000),
} satisfies EnvConfig;
