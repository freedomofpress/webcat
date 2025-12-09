export const version = 0.2;
// TODO: decide when to fetch what! We could obtain enrollment info earlier
// eg. via headers, or we might have enrollment info cached but wanted to fetch
// a new manifest
export const enrollment_name = "/.well-known/webcat/enrollment.json";
export const manifest_name = "/.well-known/webcat/manifest.json";
export const bundle_name = "/.well-known/webcat/bundle.json";
export const bundle_prev_name = "/.well-known/webcat/bundle-prev.json";
// Here it's full metadata, potentially with 100kb of manifests each
export const lru_cache_size = 32;
// Items here are just the size in bytes for a domain
export const lru_set_size = 8192;
//export const endpoint = "https://webcat.freedom.press";
export const endpoint =
  "https://raw.githubusercontent.com/freedomofpress/webcat-infra-chain/refs/heads/main/test_data/";
