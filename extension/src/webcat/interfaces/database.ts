import { CacheKey, LRUCache, LRUSet } from "../cache";
import { CachePartition, OriginState } from "./originstate";

export interface BlockMeta {
  blockTime: number;
  rootHash: string;
}

/**
 * A persistence interface for enrollment information and origin states.
 */
export interface Database {
  /**
   * A partitioned LRU cache of origin states.
   */
  readonly origins: LRUCache<CacheKey<CachePartition>, OriginState>;
  /**
   * A partitioned LRU set of fully-qualified domain names not enrolled in
   * WEBCAT.
   */
  readonly nonOrigins: LRUSet<CacheKey<CachePartition>>;
  /**
   * Updates the list of enrolled fully-qualified domain names.
   */
  updateList(
    leaves: readonly (readonly [string, string])[],
    meta: BlockMeta,
  ): Promise<void>;
  /**
   * Reads block metadata from the database.
   *
   * @returns A Promise that resolves the metadata for the most recently
   *   applied block.
   */
  getBlockMeta(): Promise<BlockMeta | null>;
  /**
   * Reads fully-qualified domain names of enrolled origins from the database.
   *
   * @returns A Promise that resolves to an array of the FQDNs whose enrollment
   *   is persisted locally.
   */
  listAllFQDNs(): Promise<string[]>;
  /**
   * Reads an enrollment hash from the database.
   *
   * @param fqdn The fully-qualified domain name whose enrollment hash to read.
   * @param cachePartition The cache partition to use for cache lookups.
   * @returns A Promise that resolves to the locally persisted enrollment hash
   *   corresponding to fqdn.
   */
  getFQDNEnrollment(
    fqdn: string,
    cachePartition: CachePartition,
  ): Promise<Uint8Array>;

  /**
   * Persists current time as the time of the latest enrollment update attempt.
   */
  setLastChecked(): Promise<void>;

  /**
   * Reads the timestamp of the most recent enrollment update attempt.
   *
   * @returns A Promise that resolves to a time in milliseconds.
   */
  getLastChecked(): Promise<number | null>;

  /**
   * Persists the current time as the time of the latest successful enrollment
   * update.
   */
  setLastUpdated(): Promise<void>;

  /**
   * Reads the timestamp of the most recent successful enrollment update.
   *
   * @returns A Promise that resolves to a time in milliseconds.
   */
  getLastUpdated(): Promise<number | null>;
}
