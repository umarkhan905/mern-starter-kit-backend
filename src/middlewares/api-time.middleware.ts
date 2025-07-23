import { Request, Response, NextFunction } from "express";
import { logger } from "../lib/winston.js";

const apiResponseTime = (req: Request, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    res.on("finish", () => {
        const endTime = Date.now();
        const responseTime = endTime - startTime;
        logger.info(`Response Time: ${responseTime}ms`);
    });
    next();
};

export default apiResponseTime;
