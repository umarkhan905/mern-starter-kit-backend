import { Types } from "mongoose";
import { VerificationData } from "../types";
import { VerifyEmail } from "../types/validators";

import { Verification } from "../models/verification.model.js";

const createVerification = async (data: VerificationData) => {
    const verification = await Verification.create(data);
    return verification;
};

const getVerificationByUserIdAndToken = async (data: VerifyEmail) => {
    const verification = await Verification.findOne({
        userId: data.userId,
        token: data.token,
    });
    return verification;
};

const deleteVerification = async (verificationId: Types.ObjectId) => {
    const verification = await Verification.findByIdAndDelete(verificationId);
    return verification;
};

const getVerificationByToken = async (token: string) => {
    const verification = await Verification.findOne({ token });
    return verification;
};

export const verificationService = {
    createVerification,
    getVerificationByUserIdAndToken,
    deleteVerification,
    getVerificationByToken,
};
