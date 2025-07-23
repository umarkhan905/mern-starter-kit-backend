import { Router } from "express";
import { authController } from "../controllers/auth.controller.js";
import auth from "../middlewares/auth.middleware.js";
import {
    authRateLimiter,
    emailRateLimiter,
    refreshRateLimiter,
    generalApiLimiter,
} from "../middlewares/rate-limiter.middleware.js";

const router = Router();

// 🔒 Auth-sensitive routes
router.post("/signup", authRateLimiter, authController.signup);
router.post("/login", authRateLimiter, authController.login);

// 📩 Email verification, forgot password, resend
router.post("/verify-email", emailRateLimiter, authController.verifyEmail);
router.post(
    "/resend-verification-email",
    emailRateLimiter,
    authController.resendVerificationEmail
);
router.post(
    "/forgot-password",
    emailRateLimiter,
    authController.forgotPassword
);
router.post("/reset-password", emailRateLimiter, authController.resetPassword);

// 🔁 Refresh token (a bit looser)
router.post(
    "/refresh-access-token",
    refreshRateLimiter,
    authController.refreshAccessToken
);

// 👤 Get current user (auth protected)
router.get(
    "/current-user",
    auth,
    generalApiLimiter,
    authController.getCurrentUser
);

export default router;
