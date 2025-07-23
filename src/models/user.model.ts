import mongoose, { Schema } from "mongoose";
import bcrypt from "bcryptjs";

import { IUser } from "../types/models";

enum Role {
    USER = "user",
    ADMIN = "admin",
}

const userSchema = new Schema<IUser>(
    {
        name: {
            type: String,
            required: true,
            trim: true,
            minlength: 3,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
        },
        password: {
            type: String,
            required: true,
            minlength: 6,
        },
        isVerified: {
            type: Boolean,
            default: false,
        },
        role: {
            type: String,
            enum: Object.values(Role),
            default: Role.USER,
        },
        image: {
            type: String,
        },
    },
    { timestamps: true }
);

// pre save hook
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// compare password
userSchema.methods.comparePassword = async function (
    password: string
): Promise<boolean> {
    return await bcrypt.compare(password, this.password);
};

export const User = mongoose.model<IUser>("User", userSchema);
