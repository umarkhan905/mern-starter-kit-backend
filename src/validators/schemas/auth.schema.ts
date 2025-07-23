import Joi from "joi";
import {
    Signup,
    Login,
    VerifyEmail,
    ResetPassword,
} from "../../types/validators";

const signupSchema = Joi.object<Signup>({
    name: Joi.string().min(3).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object<Login>({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
});

const verifyEmailSchema = Joi.object<VerifyEmail>({
    token: Joi.string().required(),
    userId: Joi.string().required(),
});

const forgotPasswordSchema = Joi.object<{ email: string }>({
    email: Joi.string().email().required(),
});

const resetPasswordSchema = Joi.object<ResetPassword>({
    token: Joi.string().required(),
    password: Joi.string().min(6).required(),
});

export {
    signupSchema,
    loginSchema,
    verifyEmailSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
};
