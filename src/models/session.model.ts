import mongoose, { Schema } from "mongoose";

import { ISession } from "../types/models";

const sessionSchema = new Schema<ISession>(
    {
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },
        sessionToken: {
            type: String,
            required: true,
        },
        expiresAt: {
            type: Date,
            required: true,
        },
        valid: {
            type: Boolean,
            default: true,
        },
        userAgent: {
            type: String,
            required: true,
        },
        ipAddress: {
            type: String,
            required: true,
        },
    },
    { timestamps: true }
);

// Indexes
sessionSchema.index({ userId: 1 });
sessionSchema.index({ userId: 1, sessionToken: 1 }, { unique: true });

export const Session = mongoose.model<ISession>("Session", sessionSchema);
