import { defaults, test } from "./config";
import webcat from "./webcat";
import { logger } from "./webcat/logger";

logger.info("Starting up background");
webcat.start(import.meta.env.VITE_TESTING ? test : defaults);
