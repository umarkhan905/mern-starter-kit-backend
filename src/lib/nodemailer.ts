import nodemailer from "nodemailer";
import { envConfig } from "../config/env.config.js";

export const transport = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: envConfig.MAIL_TRAP_PORT,
    auth: {
        user: envConfig.MAIL_TRAP_USER,
        pass: envConfig.MAIL_TRAP_PASSWORD,
    },
});
