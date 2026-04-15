export const enrollment_name = "/.well-known/webcat/enrollment.json";
export const manifest_name = "/.well-known/webcat/manifest.json";
export const bundle_name = "/.well-known/webcat/bundle.json";
export const bundle_prev_name = "/.well-known/webcat/bundle-prev.json";
// Here it's full metadata, potentially with 100kb of manifests each
export const lru_cache_size = 32;
// Items here are just the size in bytes for a domain
export const lru_set_size = 8192;
export const endpoint = "https://webcat.freedom.press/";
// During alpha, update every hour. Wall-clock based so that sleep/suspend
// doesn't silently postpone updates.
export const UPDATE_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
export const CHECK_INTERVAL_MS = 5 * 60 * 1000; // poll every 5 minutes
export const FETCH_TIMEOUT_MS = 3000; // 3 second timeout for fetches
