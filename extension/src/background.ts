import { defaults, test } from "./config";
import webcat from "./webcat";

console.log("[webcat] Starting up background");
webcat.start(import.meta.env.VITE_TESTING ? test : defaults);
