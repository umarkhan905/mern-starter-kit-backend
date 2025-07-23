import { CreateSession } from "../types";
import { Types } from "mongoose";

import { Session } from "../models/session.model.js";

const createSession = async (data: CreateSession) => {
    const session = await Session.create(data);
    return session;
};

const getSessionByUserId = async (userId: Types.ObjectId) => {
    const session = await Session.findOne({ userId }).exec();
    return session;
};

export const sessionService = { createSession, getSessionByUserId };
