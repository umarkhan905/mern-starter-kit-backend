import createHttpError from "http-errors";
import jwt, { JwtPayload } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { Types } from "mongoose";
import { Login, ResetPassword, Signup, VerifyEmail } from "../types/validators";
import { AccessToken, NewSession, RefreshToken } from "../types";

import { logger } from "../lib/winston.js";
import { userService } from "./user.service.js";
import { emailsService } from "./emails.service.js";
import { verificationService } from "./verification.service.js";
import {
    ACCESS_TOKEN_EXPIRES_IN,
    REFRESH_TOKEN_EXPIRES_IN,
    SESSION_EXPIRES_IN,
} from "../constants/index.js";
import { envConfig } from "../config/env.config.js";
import { sessionService } from "./session.service.js";

const signup = async (data: Signup) => {
    // Check if user already exists
    const existingUser = await userService.getUserByEmail(data.email);
    if (existingUser) {
        logger.warn(`User with email ${data.email} already exists`);
        throw createHttpError(409, "User already exists with this email");
    }

    // Create user
    const user = await userService.createUser(data);
    if (!user) {
        logger.warn(`Failed to create user with email ${data.email}`);
        throw createHttpError(
            500,
            "Something went wrong while signing up! Please try again."
        );
    }

    // Send verification email
    await emailsService.sendVerificationEmail({
        userId: user._id as Types.ObjectId,
        email: data.email,
    });

    return userService.excludeUserPassword(user);
};

const verifyEmail = async (data: VerifyEmail) => {
    // Check if verification token is valid
    const verification =
        await verificationService.getVerificationByUserIdAndToken(data);
    if (!verification) {
        logger.warn(`Verification token not found for user ${data.userId}`);
        throw createHttpError(400, "Invalid verification code");
    }

    // Check if verification token is expired
    if (verification.expiresAt < new Date()) {
        logger.warn(`Verification token expired for user ${data.userId}`);
        throw createHttpError(400, "Verification code has expired");
    }

    // Update user as verified
    const user = await userService.updateUser(data.userId, {
        isVerified: true,
    });
    if (!user) {
        logger.warn(`User not found with ID: ${data.userId}`);
        throw createHttpError(404, "User not found with the provided ID");
    }

    // Delete verification token
    await verificationService.deleteVerification(
        verification._id as Types.ObjectId
    );

    return userService.excludeUserPassword(user);
};

const login = async (
    data: Login & { userAgent: string; ipAddress: string }
) => {
    const user = await userService.getUserByEmail(data.email);
    if (!user) {
        logger.warn(`User not found with email: ${data.email}`);
        throw createHttpError(400, "Invalid email or password");
    }

    const isPasswordCorrect = await user.comparePassword(data.password);
    if (!isPasswordCorrect) {
        logger.warn(
            `Incorrect password for user with email: ${data.email} and ID: ${user._id}`
        );
        throw createHttpError(400, "Invalid email or password");
    }

    if (!user.isVerified) {
        logger.warn(
            `User with email: ${data.email} and ID: ${user._id} is not verified`
        );
        throw createHttpError(403, "Please verify your email before login");
    }

    const { accessToken, refreshToken } = await createNewSession({
        role: user.role,
        userId: user._id as Types.ObjectId,
        userAgent: data.userAgent,
        ipAddress: data.ipAddress,
    });

    return {
        accessToken,
        refreshToken,
        user: userService.excludeUserPassword(user),
    };
};

const generateAccessToken = (data: AccessToken) => {
    return jwt.sign(data, envConfig.ACCESS_TOKEN_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRES_IN,
    });
};

const generateRefreshToken = (data: RefreshToken) => {
    return jwt.sign(data, envConfig.REFRESH_TOKEN_SECRET, {
        expiresIn: REFRESH_TOKEN_EXPIRES_IN,
    });
};

const createNewSession = async (data: NewSession) => {
    // Generate access and refresh tokens
    const accessToken = generateAccessToken({
        role: data.role,
        userId: data.userId,
    });
    const refreshToken = generateRefreshToken({
        userId: data.userId,
    });

    // Create session
    const session = await sessionService.createSession({
        userId: data.userId,
        sessionToken: refreshToken,
        expiresAt: new Date(Date.now() + SESSION_EXPIRES_IN),
        userAgent: data.userAgent,
        ipAddress: data.ipAddress,
    });
    if (!session) {
        logger.warn(`Failed to create session for user ${data.userId}`);
        throw createHttpError(
            500,
            "Something went wrong while logging in! Please try again."
        );
    }

    // Return access and refresh tokens
    return { accessToken, refreshToken };
};

const resendVerificationEmail = async (userId: Types.ObjectId) => {
    const user = await userService.getUserById(userId);
    if (!user) {
        logger.warn(`User not found with ID: ${userId}`);
        throw createHttpError(404, "User not found with the provided ID");
    }

    await emailsService.sendVerificationEmail({
        userId,
        email: user.email,
    });

    return userService.excludeUserPassword(user);
};

const forgotPassword = async (email: string) => {
    // Check if user exists
    const user = await userService.getUserByEmail(email);
    if (!user) {
        logger.warn(`User not found with email: ${email}`);
        throw createHttpError(404, "User not found with the provided email");
    }

    // Send forgot password email
    await emailsService.sendForgotPasswordEmail({
        userId: user._id as Types.ObjectId,
        email,
    });

    // Return user
    return userService.excludeUserPassword(user);
};

const resetPassword = async (data: ResetPassword) => {
    // Check if user verification token exists
    const verification = await verificationService.getVerificationByToken(
        data.token
    );
    if (!verification) {
        logger.warn(`Verification token not found for user ${data.token}`);
        throw createHttpError(400, "Invalid verification code");
    }

    // Check if verification token is expired
    if (verification.expiresAt < new Date()) {
        logger.warn(`Verification token expired for user ${data.token}`);
        throw createHttpError(400, "Verification code has expired");
    }

    // Update user password
    const hashedPassword = await hashPassword(data.password);
    const user = await userService.updateUser(verification.userId, {
        password: hashedPassword,
    });
    if (!user) {
        logger.warn(`User not found with ID: ${verification.userId}`);
        throw createHttpError(404, "User not found with the provided ID");
    }

    // Delete verification token
    await verificationService.deleteVerification(
        verification._id as Types.ObjectId
    );

    // Return user
    return userService.excludeUserPassword(user);
};

const hashPassword = async (password: string) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};

const refreshAccessToken = async (refreshToken: string) => {
    // Verify refresh token
    const decoded = verifyJWT(refreshToken, "refresh");

    if (!decoded?.userId) {
        logger.warn(`Decoded token missing userId`);
        throw createHttpError(400, "Invalid token payload");
    }

    const session = await sessionService.getSessionByUserId(decoded.userId);
    if (!session) {
        logger.warn(`No session found for userId: ${decoded.userId}`);
        throw createHttpError(401, "Invalid session or user not logged in");
    }

    // Check token match (optional security layer)
    if (session.sessionToken !== refreshToken) {
        logger.warn(`Refresh token mismatch for userId: ${decoded.userId}`);
        throw createHttpError(401, "Invalid refresh token");
    }

    // Check session expiration
    if (session.expiresAt < new Date() || !session.valid) {
        logger.warn(`Session expired for userId: ${decoded.userId}`);
        throw createHttpError(403, "Session expired");
    }

    // get user by id
    const user = await userService.getUserById(session.userId);
    if (!user) {
        logger.warn(`User not found for userId: ${session.userId}`);
        throw createHttpError(404, "User not found");
    }

    // Generate new access token
    const accessToken = generateAccessToken({
        userId: session.userId,
        role: user.role,
    });

    return { accessToken };
};

const verifyJWT = (token: string, type: "access" | "refresh"): JwtPayload => {
    const tokenSecret =
        type === "access"
            ? envConfig.ACCESS_TOKEN_SECRET
            : envConfig.REFRESH_TOKEN_SECRET;

    try {
        const decoded = jwt.verify(token, tokenSecret);
        return decoded as JwtPayload;
    } catch (error) {
        logger.warn(`Invalid ${type} token: ${(error as Error).message}`);
        throw createHttpError(401, "Invalid or expired token");
    }
};

export const authService = {
    signup,
    verifyEmail,
    login,
    resendVerificationEmail,
    forgotPassword,
    resetPassword,
    refreshAccessToken,
    verifyJWT,
};
