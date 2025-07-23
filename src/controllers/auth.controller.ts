import { Request, Response } from "express";
import createHttpError from "http-errors";

import { asyncHandler } from "../utils/asyncHandler.js";
import { logger } from "../lib/winston.js";
import {
    validateForgotPassword,
    validateLogin,
    validateResetPassword,
    validateSignup,
    validateVerifyEmail,
} from "../validators/handlers/auth.handler.js";
import { createHttpSuccessResponse } from "../utils/http-success-response.js";
import { authService } from "../services/auth.service.js";
import { COOKIE_OPTIONS } from "../constants/index.js";
import { Types } from "mongoose";
import { AuthRequest } from "../types/index.js";
import { userService } from "../services/user.service.js";

const signup = asyncHandler(async (req: Request, res: Response) => {
    logger.info("Initiating signup request");
    logger.info("Validating request body");

    const { error, value } = validateSignup(req.body);
    if (error) {
        logger.warn(`Validation error during signup: ${error.message}`);
        throw createHttpError(400, error.message);
    }

    logger.info("Request body validated successfully");
    logger.info("Attempting for Signup");

    const user = await authService.signup(value);

    logger.info("Signup attempt successfully completed");
    logger.info(
        `User signed up successfully: ${user.email} and ID: ${user._id}`
    );
    logger.info("Closing signup request");

    createHttpSuccessResponse(
        res,
        201,
        "User signed up successfully! Please check your inbox to verify your email address",
        { user }
    );
});

const verifyEmail = asyncHandler(async (req: Request, res: Response) => {
    logger.info("Initiating verify email request");
    logger.info("Validating request body");

    const { error, value } = validateVerifyEmail(req.body);
    if (error) {
        logger.warn(`Validation error during verify email: ${error.message}`);
        throw createHttpError(400, error.message);
    }

    logger.info("Request body validated successfully");
    logger.info("Attempting for verify email");

    const user = await authService.verifyEmail(value);

    logger.info("Verify email attempt successfully completed");
    logger.info(
        `User verified successfully: ${user.email} and ID: ${user._id}`
    );
    logger.info("Closing verify email request");

    createHttpSuccessResponse(
        res,
        200,
        "Email verified successfully! You can now login",
        { user }
    );
});

const login = asyncHandler(async (req: Request, res: Response) => {
    logger.info("Initiating login request");
    logger.info("Validating request body");

    const { error, value } = validateLogin(req.body);
    if (error) {
        logger.warn(`Validation error during login email: ${error.message}`);
        throw createHttpError(400, error.message);
    }

    logger.info("Request body validated successfully");
    logger.info("Attempting for login");
    const { user, accessToken, refreshToken } = await authService.login({
        ...value,
        userAgent: req.headers["user-agent"],
        ipAddress: req.ip,
    });

    logger.info("Login attempt successfully completed");
    logger.info(
        `User logged in successfully: ${user.email} and ID: ${user._id}`
    );
    logger.info("Closing login request");

    res.cookie("refreshToken", refreshToken, COOKIE_OPTIONS);
    createHttpSuccessResponse(res, 200, "User logged in successfully", {
        user,
        accessToken,
    });
});

const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
    logger.info("Initiating forgot password request");
    logger.info("Validating request body");

    const { error, value } = validateForgotPassword(req.body);
    if (error) {
        logger.warn(
            `Validation error during forgot password: ${error.message}`
        );
        throw createHttpError(400, error.message);
    }

    logger.info("Request body validated successfully");
    logger.info("Attempting for forgot password");

    const user = await authService.forgotPassword(value.email);

    logger.info("Forgot password attempt successfully completed");
    logger.info(
        `Forgot password email sent successfully: ${user.email} and ID: ${user._id}`
    );
    logger.info("Closing forgot password request");

    createHttpSuccessResponse(
        res,
        200,
        "Forgot password email sent successfully! Please check your inbox to reset your password",
        { user }
    );
});

const resetPassword = asyncHandler(async (req: Request, res: Response) => {
    logger.info("Initiating reset password request");
    logger.info("Validating request body");

    const { error, value } = validateResetPassword(req.body);
    if (error) {
        logger.warn(`Validation error during reset password: ${error.message}`);
        throw createHttpError(400, error.message);
    }

    logger.info("Request body validated successfully");
    logger.info("Attempting for reset password");

    const user = await authService.resetPassword(value);

    logger.info("Reset password attempt successfully completed");
    logger.info(
        `Password reset successfully: ${user.email} and ID: ${user._id}`
    );
    logger.info("Closing reset password request");

    createHttpSuccessResponse(
        res,
        200,
        "Password reset successfully! You can now login",
        { user }
    );
});

const resendVerificationEmail = asyncHandler(
    async (req: Request, res: Response) => {
        logger.info("Initiating resend verification email request");
        logger.info("Validating request body");

        const { userId } = req.body;
        if (!userId) {
            logger.warn(
                `Validation error during resend verification email: userId is required`
            );
            throw createHttpError(400, "userId is required");
        }

        const isValid = Types.ObjectId.isValid(userId);
        if (!isValid) {
            logger.warn(
                `Validation error during resend verification email: userId is invalid`
            );
            throw createHttpError(400, "Invalid userId");
        }

        logger.info("Request body validated successfully");
        logger.info("Attempting for resend verification email");

        const user = await authService.resendVerificationEmail(userId);

        logger.info("Resend verification email attempt successfully completed");
        logger.info(
            `Verification email resent successfully: ${user.email} and ID: ${user._id}`
        );
        logger.info("Closing resend verification email request");

        createHttpSuccessResponse(
            res,
            200,
            "Verification email resent successfully! Please check your inbox to verify your email address",
            { user }
        );
    }
);

const refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {
    logger.info("Initiating refresh access token request");
    logger.info("Validating request body or cookie");
    const refreshToken = req.cookies["refreshToken"] || req?.body?.refreshToken;

    if (!refreshToken) {
        logger.warn(`Refresh token not found`);
        throw createHttpError(400, "Refresh token not found");
    }

    logger.info("Request body or cookie validated successfully");
    logger.info("Attempting for refresh access token");

    const { accessToken } = await authService.refreshAccessToken(refreshToken);

    logger.info("Refresh access token attempt successfully completed");
    logger.info("Access token refreshed successfully");
    logger.info("Closing refresh access token request");

    createHttpSuccessResponse(res, 200, "Access token refreshed successfully", {
        accessToken,
    });
});

const getCurrentUser = asyncHandler(async (req: AuthRequest, res: Response) => {
    logger.info("Initiating get current user request");
    logger.info("Attempting for get current user");

    const user = await userService.getUserById(req.user.userId);

    const userWithoutPassword = await userService.excludeUserPassword(user);
    if (!user) {
        logger.warn("User not found");
        throw createHttpError(404, "User not found");
    }

    logger.info("Get current user attempt successfully completed");
    logger.info(`User found successfully: ${user.email} and ID: ${user._id}`);
    logger.info("Closing get current user request");

    createHttpSuccessResponse(res, 200, "User found successfully", {
        user: userWithoutPassword,
    });
});

export const authController = {
    signup,
    verifyEmail,
    login,
    forgotPassword,
    resetPassword,
    resendVerificationEmail,
    getCurrentUser,
    refreshAccessToken,
};
