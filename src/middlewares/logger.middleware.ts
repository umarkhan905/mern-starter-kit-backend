import { Request, Response, NextFunction } from "express";
import { logger } from "../lib/winston.js";

const loggerMiddleware = (req: Request, res: Response, next: NextFunction) => {
    logger.info(`Request ${req.method} to ${req.url}`);
    logger.info(`Request Body: ${JSON.stringify(req.body)}`);
    logger.info(`Request Query: ${JSON.stringify(req.query)}`);
    logger.info(`Request Params: ${JSON.stringify(req.params)}`);
    next();
};

export default loggerMiddleware;
