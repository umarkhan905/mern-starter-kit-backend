import rateLimit from "express-rate-limit";
import { asyncHandler } from "../utils/asyncHandler";
import createHttpError from "http-errors";

// 🚨 Prevent abuse on sensitive routes (auth, email)
export const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    handler: asyncHandler(async (req, res) => {
        throw createHttpError(
            429,
            "Too many attempts. Please try again later."
        );
    }),
});

// 🔁 For token refresh, allow a bit more
export const refreshRateLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 30,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    handler: asyncHandler(async (req, res) => {
        throw createHttpError(
            429,
            "Too many attempts. Please try again later."
        );
    }),
});

// 📩 Email-related routes (verify, resend, forgot)
export const emailRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 3,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    handler: asyncHandler(async (req, res) => {
        throw createHttpError(
            429,
            "Too many attempts. Please try again later."
        );
    }),
});

// 👤 General API usage
export const generalApiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    handler: asyncHandler(async (req, res) => {
        throw createHttpError(
            429,
            "Too many attempts. Please try again later."
        );
    }),
});
