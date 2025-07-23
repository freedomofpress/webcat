export const version = 0.1;
// We changed it once, so why not again :)
export const manifest_name = "webcat.json";
export const tuf_sigstore_url = "https://tuf-repo-cdn.sigstore.dev";
export const tuf_sigstore_root = "assets/1.root.json";
export const tuf_sigstore_namespace = "sigstore";
// Here it's full metadata, potentially with 100kb of manifests each
export const lru_cache_size = 32;
// Items here are just the size in bytes for a domain
export const lru_set_size = 8192;
// Sigsum config used for list updates
export const update_server_key =
  "b6e50fd2d90c561ac88eb3bd837dfabc6b8158e095689ba5410a7879eb632258";
export const update_url = "https://transparency.cat/update/";
