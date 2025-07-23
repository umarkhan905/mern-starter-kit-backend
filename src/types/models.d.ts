import { Document, Types } from "mongoose";

export enum Role {
    USER = "user",
    ADMIN = "admin",
}

export interface IUser extends Document {
    name: string;
    email: string;
    password: string;
    isVerified: boolean;
    role: Role;
    image: string;
    createdAt: Date;
    updatedAt: Date;
    comparePassword: (password: string) => Promise<boolean>;
}

export interface ISession extends Document {
    userId: Types.ObjectId;
    sessionToken: string;
    expiresAt: Date;
    valid: boolean;
    userAgent: string;
    ipAddress: string;
    createdAt: Date;
    updatedAt: Date;
}

export interface IVerification extends Document {
    userId: Types.ObjectId;
    token: string;
    expiresAt: Date;
    createdAt: Date;
    updatedAt: Date;
}
