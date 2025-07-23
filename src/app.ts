import express from "express";

const app = express();

// logger middleware to log requests
import loggerMiddleware from "./middlewares/logger.middleware.js";
app.use(loggerMiddleware);

// cookie parser middleware to handle cookies
import cookieParser from "cookie-parser";
app.use(cookieParser());

// Middleware to serve static files from the 'public' directory
app.use(express.static("public"));

// Middleware to parse JSON bodies
app.use(express.json());

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

// API Response Time Middleware
import apiResponseTime from "./middlewares/api-time.middleware.js";
app.use(apiResponseTime);

/* ==================== Start Import Routes ==================== */
import healthCheckRoute from "./routes/healthCheck.route.js";
app.use("/api/health-check", healthCheckRoute);

import authRoute from "./routes/auth.route.js";
app.use("/api/auth", authRoute);

/* ==================== End Import Routes ==================== */

// error handling middleware
import errorMiddleware from "./middlewares/error.middleware.js";
app.use(errorMiddleware);

export { app };
