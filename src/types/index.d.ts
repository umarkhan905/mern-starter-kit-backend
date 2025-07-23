import { Types } from "mongoose";
import { Role } from "./models";
import { Request } from "express";

export type Subject = "verify-email" | "forgot-password" | "welcome";

export interface VerificationData {
    userId: Types.ObjectId;
    token: string;
    expiresAt: Date;
}

export interface VerificationEmailData {
    userId: Types.ObjectId;
    email: string;
}

interface SessionData {
    userId: Types.ObjectId;
    userAgent: string;
    ipAddress: string;
}

export type CreateSession = SessionData & {
    sessionToken: string;
    expiresAt: Date;
};

export type AccessToken = Pick<SessionData, "userId"> & {
    role: Role;
};

export type RefreshToken = Pick<SessionData, "userId">;

export type NewSession = SessionData & {
    role: Role;
};

export interface AuthRequest extends Request {
    user: AccessToken;
}
