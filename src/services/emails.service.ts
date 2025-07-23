import createHttpError from "http-errors";
import { v4 as uuid } from "uuid";
import { Subject, VerificationEmailData } from "../types/index.js";

import { envConfig } from "../config/env.config.js";
import { VERIFICATION_TOKEN_EXPIRES_IN } from "../constants/index.js";
import { transport } from "../lib/nodemailer.js";
import { logger } from "../lib/winston.js";
import { verificationService } from "./verification.service.js";
import { parseMJML } from "../lib/parse-mjml.js";

const sendVerificationEmail = async (data: VerificationEmailData) => {
    // Generate verification token
    const { token, expiresAt } = generateVerificationToken();

    // Create verification token
    const verification = await verificationService.createVerification({
        userId: data.userId,
        token,
        expiresAt,
    });
    if (!verification) {
        logger.warn(
            `Failed to create verification token for user ${data.userId}`
        );
        throw createHttpError(
            500,
            "Something went wrong while sending verification email! Please try again."
        );
    }

    // Parse MJML
    const html = parseMJML("verify-email").replace(
        "{{ VERIFICATION_CODE }}",
        token
    );

    // Send email
    const isEmailSent = await sendEmail(data.email, "verify-email", html);
    if (!isEmailSent) {
        logger.warn(`Failed to send verification email to user ${data.userId}`);
        throw createHttpError(
            500,
            "Something went wrong while sending verification email! Please try again."
        );
    }

    // Return verification
    return verification;
};
const sendForgotPasswordEmail = async (data: VerificationEmailData) => {
    // Generate verification token
    const { token, expiresAt } = generateResetToken();

    // Create verification token
    const verification = await verificationService.createVerification({
        userId: data.userId,
        token,
        expiresAt,
    });
    if (!verification) {
        logger.warn(
            `Failed to create verification token for user ${data.userId}`
        );
        throw createHttpError(
            500,
            "Something went wrong while sending verification email! Please try again."
        );
    }

    // Parse MJML
    const html = parseMJML("reset-password").replace(
        "{{ RESET_PASSWORD_LINK }}",
        `${envConfig.APP_URL}/reset-password/${token}`
    );

    // Send email
    const isEmailSent = await sendEmail(data.email, "forgot-password", html);
    if (!isEmailSent) {
        logger.warn(`Failed to send verification email to user ${data.userId}`);
        throw createHttpError(
            500,
            "Something went wrong while sending verification email! Please try again."
        );
    }

    // Return verification
    return verification;
};

const sendEmail = async (to: string, subject: Subject, html: string) => {
    const info = await transport.sendMail({
        from: envConfig.APP_EMAIL,
        to,
        subject: getEmailSubject(subject),
        html,
    });

    return info.accepted.length > 0;
};

const generateVerificationToken = () => {
    const token = Math.floor(Math.random() * 1000000).toString();
    const expiresAt = new Date(Date.now() + VERIFICATION_TOKEN_EXPIRES_IN);

    return { token, expiresAt };
};

const generateResetToken = () => {
    const token = uuid();
    const expiresAt = new Date(Date.now() + VERIFICATION_TOKEN_EXPIRES_IN);

    return { token, expiresAt };
};

const getEmailSubject = (subject: Subject) => {
    switch (subject) {
        case "verify-email":
            return "Verify your email address";
        case "forgot-password":
            return "Reset your password";
        case "welcome":
            return "Welcome to our platform";
        default:
            return "Email Verification";
    }
};

export const emailsService = { sendVerificationEmail, sendForgotPasswordEmail };
