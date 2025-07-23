import { CookieOptions } from "express";

export const VERIFICATION_TOKEN_EXPIRES_IN = 10 * 60 * 1000; // 10 minutes
export const ACCESS_TOKEN_EXPIRES_IN = "15m"; // 15 minutes
export const REFRESH_TOKEN_EXPIRES_IN = "7d"; // 7 days
export const SESSION_EXPIRES_IN = 7 * 24 * 60 * 60 * 1000; // 7 days
export const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: SESSION_EXPIRES_IN, // 7 days
} satisfies CookieOptions;
