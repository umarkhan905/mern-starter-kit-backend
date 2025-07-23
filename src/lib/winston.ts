import * as winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import { envConfig } from "../config/env.config.js";

const transport = new DailyRotateFile({
    level: envConfig.NODE_ENV === "production" ? "info" : "debug",
    filename: "./src/logs/debug/starter-kit-%DATE%-combined.log",
    datePattern: "YYYY-MM-DD",
    zippedArchive: true,
    maxSize: "20m",
    maxFiles: "14d",
}) satisfies DailyRotateFile;

const errorTransport = new DailyRotateFile({
    level: "error",
    filename: "./src/logs/error/starter-kit-%DATE%-error.log",
    datePattern: "YYYY-MM-DD",
    zippedArchive: true,
    maxSize: "20m",
    maxFiles: "14d",
}) satisfies DailyRotateFile;

export const logger = winston.createLogger({
    level: envConfig.NODE_ENV === "production" ? "info" : "debug",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        winston.format.json()
    ),
    transports: [transport, errorTransport],
});

// Add console transport for development environment
if (envConfig.NODE_ENV !== "production") {
    logger.add(
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            ),
        })
    );
}
