import { Request, Response } from "express";
import createHttpError from "http-errors";
import { asyncHandler } from "../utils/asyncHandler.js";
import { createHttpSuccessResponse } from "../utils/http-success-response.js";

const healthCheck = asyncHandler(async (req: Request, res: Response) => {
    createHttpSuccessResponse(res, 200, "Service is running smoothly", null);
});

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const badRequest = asyncHandler(async (req: Request, res: Response) => {
    throw createHttpError(400, "This is a bad request");
});

export { healthCheck, badRequest };
