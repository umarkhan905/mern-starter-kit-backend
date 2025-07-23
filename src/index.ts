import { app } from "./app.js";
import { envConfig } from "./config/env.config.js";
import { logger } from "./lib/winston.js";
import { connectDB } from "./config/db.config.js";

connectDB().then(() => {
    app.listen(envConfig.PORT, () => {
        logger.info(`======= ENV: ${envConfig.NODE_ENV} =======`);
        logger.info(`Server running on http://localhost:${envConfig.PORT}`);
        logger.info(`=================================`);
    });
});
