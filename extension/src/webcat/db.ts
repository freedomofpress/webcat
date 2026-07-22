import { lru_cache_size, lru_set_size } from "../config";
import { CacheKey, LRUCache, LRUSet } from "./cache";
import { BlockMeta, Database } from "./interfaces/database";
import { CachePartition } from "./interfaces/originstate";
import { OriginStateHolder } from "./originstate";
import { extractHostname, extractRawHash } from "./parsers";

const META_KEY = "block_meta";

export class WebcatDatabase implements Database {
  readonly origins = new LRUCache<CacheKey<CachePartition>, OriginStateHolder>(
    lru_cache_size,
  );
  readonly nonOrigins = new LRUSet<CacheKey<CachePartition>>(lru_set_size);

  async updateList(
    leaves: readonly (readonly [string, string])[],
    meta: BlockMeta,
  ): Promise<void> {
    await browser.storage.local.clear();

    const batch: Record<string, unknown> = {};
    for (const [reverseKey, hexHash] of leaves) {
      const hostname = extractHostname(reverseKey);
      const rawHash = extractRawHash(hexHash);
      batch[hostname] = Array.from(rawHash);
    }
    batch[META_KEY] = meta;

    await browser.storage.local.set(batch);

    this.origins.clear();
    this.nonOrigins.clear();

    console.log(`[webcat] Replaced list with ${leaves.length} entries`);
  }

  async getBlockMeta(): Promise<BlockMeta | null> {
    const result = await browser.storage.local.get(META_KEY);
    return (result[META_KEY] as BlockMeta) ?? null;
  }

  async listAllFQDNs(): Promise<string[]> {
    const all = await browser.storage.local.get(null);
    return Object.keys(all).filter((k) => k !== META_KEY);
  }

  async getFQDNEnrollment(
    fqdn: string,
    cachePartition: CachePartition,
  ): Promise<Uint8Array> {
    // 1. Positive-cache hit
    const originState = this.origins.get(CacheKey(fqdn, cachePartition));
    if (originState) {
      const cached = originState.current.enrollment_hash;
      if (!cached) {
        throw new Error(
          "FATAL: cached origin exists without an enrollment_hash",
        );
      }
      return cached;
    }

    // 2. Negative-cache hit
    if (this.nonOrigins.has(CacheKey(fqdn, cachePartition))) {
      return new Uint8Array();
    }

    // 3. Storage lookup
    const result = await browser.storage.local.get(fqdn);
    const stored = result[fqdn];
    if (stored) {
      return new Uint8Array(stored);
    } else {
      this.nonOrigins.add(CacheKey(fqdn, cachePartition));
      return new Uint8Array();
    }
  }

  async setLastChecked(): Promise<void> {
    await browser.storage.session.set({ lastChecked: Date.now() });
  }

  async getLastChecked(): Promise<number | null> {
    const result = await browser.storage.session.get("lastChecked");
    return result.lastChecked ?? null;
  }

  async setLastUpdated(): Promise<void> {
    await browser.storage.session.set({ lastUpdated: Date.now() });
  }

  async getLastUpdated(): Promise<number | null> {
    const result = await browser.storage.session.get("lastUpdated");
    return result.lastUpdated ?? null;
  }
}
