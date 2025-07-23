import { Types } from "mongoose";

export interface Signup {
    name: string;
    email: string;
    password: string;
}

export interface Login {
    email: string;
    password: string;
}

export interface VerifyEmail {
    token: string;
    userId: Types.ObjectId;
}

export interface ResetPassword {
    token: string;
    password: string;
}
