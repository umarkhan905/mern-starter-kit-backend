import { Response } from "express";
import { successResponse } from "./http.js";

export const createHttpSuccessResponse = (
    res: Response,
    status: number,
    message: string,
    data: Record<string, unknown> | null
) => res.status(status).json(successResponse(status, message, data));
