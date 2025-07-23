import {
    Signup,
    Login,
    VerifyEmail,
    ResetPassword,
} from "../../types/validators";
import {
    signupSchema,
    loginSchema,
    verifyEmailSchema,
    forgotPasswordSchema,
    resetPasswordSchema,
} from "../schemas/auth.schema.js";

const validateSignup = (data: Signup) => signupSchema.validate(data);
const validateLogin = (data: Login) => loginSchema.validate(data);
const validateVerifyEmail = (data: VerifyEmail) =>
    verifyEmailSchema.validate(data);
const validateForgotPassword = (data: { email: string }) =>
    forgotPasswordSchema.validate(data);
const validateResetPassword = (data: ResetPassword) =>
    resetPasswordSchema.validate(data);

export {
    validateSignup,
    validateLogin,
    validateVerifyEmail,
    validateForgotPassword,
    validateResetPassword,
};
