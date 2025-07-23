import { Request, Response, NextFunction } from "express";
import { isHttpError } from "http-errors";
import { logger } from "../lib/winston.js";
import { envConfig } from "../config/env.config.js";
import { HttpException } from "../utils/httpException.js";
import { errorResponse } from "../utils/http.js";

const errorMiddleware = (
    err: unknown,
    req: Request,
    res: Response,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    next: NextFunction
) => {
    logger.error("Error Middleware Triggered");
    let errorMessage = "An unexpected error occurred";
    let errorStatus = 500;

    // Check if the error is http error
    if (isHttpError(err)) {
        errorMessage = err.message;
        errorStatus = err.status;
    }

    // Check if the error is an instance of HttpException
    if (err instanceof Error) {
        const httpException = err as HttpException;
        errorMessage = httpException.message;
        errorStatus = httpException.status || 500;
    }

    // Log the error details
    if (envConfig.NODE_ENV !== "production") {
        logger.error(`Error Stack: ${err instanceof Error ? err.stack : err}`);
    }

    logger.error(
        `[${req.method}] ${req.path} >> StatusCode:: ${errorStatus}, Message:: ${errorMessage}`
    );

    res.status(errorStatus).json(errorResponse(errorStatus, errorMessage));
};

export default errorMiddleware;
