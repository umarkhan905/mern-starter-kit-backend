import mongoose from "mongoose";
import { envConfig } from "../config/env.config.js";
import { logger } from "../lib/winston.js";

export const connectDB = async () => {
    try {
        const conn = await mongoose.connect(envConfig.MONGO_URI, {
            dbName: envConfig.DB_NAME,
        });

        logger.info(`MongoDB connected successfully: ${conn.connection.host}`);
    } catch (error) {
        logger.error("MongoDB connection error:", error);
        process.exit(1); // Exit the process with failure
    }
};
