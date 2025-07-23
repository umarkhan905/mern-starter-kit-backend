import mongoose, { Schema } from "mongoose";

import { IVerification } from "../types/models";

const verificationSchema = new Schema<IVerification>(
    {
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },
        token: {
            type: String,
            required: true,
        },
        expiresAt: {
            type: Date,
            required: true,
        },
    },
    { timestamps: true }
);

// Indexes
verificationSchema.index({ userId: 1, token: 1 }, { unique: true });
verificationSchema.index({ token: 1 }, { unique: true });

export const Verification = mongoose.model<IVerification>(
    "Verification",
    verificationSchema
);
