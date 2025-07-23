import express from "express";

const app = express();

// logger middleware to log requests
import loggerMiddleware from "./middlewares/logger.middleware.js";
app.use(loggerMiddleware);

// Middleware to serve static files from the 'public' directory
app.use(express.static("public"));

// Middleware to parse JSON bodies
app.use(express.json());

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

/* ==================== Start Import Routes ==================== */

/* ==================== End Import Routes ==================== */

// error handling middleware
import errorMiddleware from "./middlewares/error.middleware.js";
app.use(errorMiddleware);
