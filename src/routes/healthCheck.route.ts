import { Router } from "express";
import {
    healthCheck,
    badRequest,
} from "../controllers/healthCheck.controller.js";

const router = Router();

router.get("/", healthCheck);
router.get("/bad", badRequest);

export default router;
