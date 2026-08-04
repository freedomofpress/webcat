import { NamespacedKVStore } from "../browser/kvstore";
import { CacheKey, LRUSet, PersistentLRUCache } from "./cache";
import { BlockMeta, Database } from "./interfaces/database";
import { CachePartition } from "./interfaces/originstate";
import { OriginState } from "./originstate";
import { extractHostname, extractRawHash } from "./parsers";

const META_KEY = "block_meta";

export type WebcatDatabaseConfig = {
  namespace: string;
  originCacheSize: number;
  nonOriginCacheSize: number;
};

export class WebcatDatabase extends NamespacedKVStore implements Database {
  readonly origins: PersistentLRUCache<CacheKey<CachePartition>, OriginState>;
  readonly nonOrigins: LRUSet<CacheKey<CachePartition>>;
  readonly enrollments = this.namespace("enrollments");

  constructor(config: WebcatDatabaseConfig) {
    super(config.namespace);
    this.origins = new PersistentLRUCache(
      config.originCacheSize,
      this.namespace("origins"),
      "session",
      OriginState,
    );
    this.nonOrigins = new LRUSet(config.nonOriginCacheSize);
  }

  async updateList(
    leaves: readonly (readonly [string, string])[],
    meta: BlockMeta,
  ): Promise<void> {
    const batch: Record<string, unknown> = {};
    for (const [reverseKey, hexHash] of leaves) {
      const hostname = extractHostname(reverseKey);
      const rawHash = extractRawHash(hexHash);
      batch[hostname] = Array.from(rawHash);
    }

    await this.enrollments.clear();
    await this.enrollments.set(batch);
    await this.set({ [META_KEY]: meta });

    await this.origins.clear();
    await this.nonOrigins.clear();

    console.log(`[webcat] Replaced list with ${leaves.length} entries`);
  }

  async getBlockMeta(): Promise<BlockMeta | null> {
    return (await this.get(META_KEY)) ?? null;
  }

  async listAllFQDNs(): Promise<string[]> {
    return await this.enrollments.getKeys();
  }

  async getFQDNEnrollment(
    fqdn: string,
    cachePartition: CachePartition,
  ): Promise<Uint8Array> {
    // 1. Positive-cache hit
    const originState = await this.origins.get(CacheKey(fqdn, cachePartition));
    if (originState) {
      const cached = originState.enrollment_hash;
      if (!cached) {
        throw new Error(
          "FATAL: cached origin exists without an enrollment_hash",
        );
      }
      return cached;
    }

    // 2. Negative-cache hit
    if (await this.nonOrigins.has(CacheKey(fqdn, cachePartition))) {
      return new Uint8Array();
    }

    // 3. Storage lookup
    const stored = await this.enrollments.get(fqdn);
    if (stored) {
      return new Uint8Array(stored);
    } else {
      await this.nonOrigins.add(CacheKey(fqdn, cachePartition));
      return new Uint8Array();
    }
  }

  async setLastChecked(): Promise<void> {
    await this.set({ lastChecked: Date.now() }, "session");
  }

  async getLastChecked(): Promise<number | null> {
    return (await this.get("lastChecked", "session")) ?? null;
  }

  async setLastUpdated(): Promise<void> {
    await this.set({ lastUpdated: Date.now() }, "session");
  }

  async getLastUpdated(): Promise<number | null> {
    return (await this.get("lastUpdated", "session")) ?? null;
  }
}
