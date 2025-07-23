import { Response, NextFunction } from "express";
import createHttpError from "http-errors";
import { AuthRequest } from "../types/index";

import { asyncHandler } from "../utils/asyncHandler.js";
import { authService } from "../services/auth.service.js";
import { logger } from "../lib/winston.js";

const auth = asyncHandler(
    async (req: AuthRequest, _: Response, next: NextFunction) => {
        // Step 1: Check Access Token
        const token =
            req.cookies?.accessToken ||
            req.header("Authorization")?.replace("Bearer ", "");
        if (!token) {
            throw createHttpError(401, "Unauthorized: Access token is missing");
        }

        // Step 2: Verify Access Token
        const decoded = authService.verifyJWT(token, "access");
        if (!decoded?.userId || !decoded?.role) {
            logger.warn(`Decoded token missing userId or role`);
            throw createHttpError(400, "Invalid token payload");
        }

        req.user = {
            userId: decoded.userId,
            role: decoded.role,
        };
        next();
    }
);

export default auth;
