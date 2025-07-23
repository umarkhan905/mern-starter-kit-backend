import { Types } from "mongoose";
import { IUser } from "../types/models";
import { Signup } from "../types/validators";

import { User } from "../models/user.model.js";

const getUserByEmail = async (email: string) => {
    const user = await User.findOne({ email });
    return user;
};

const createUser = async (data: Signup) => {
    const user = await User.create(data);
    return user;
};

const updateUser = async (userId: Types.ObjectId, data: Partial<IUser>) => {
    const user = await User.findByIdAndUpdate(userId, data, { new: true });
    return user;
};

const excludeUserPassword = (user: IUser) => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = user.toObject();
    return userWithoutPassword;
};

const getUserById = async (userId: Types.ObjectId) => {
    const user = await User.findById(userId);
    return user;
};

export const userService = {
    getUserByEmail,
    createUser,
    updateUser,
    excludeUserPassword,
    getUserById,
};
