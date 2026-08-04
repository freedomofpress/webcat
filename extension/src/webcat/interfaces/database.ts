import { CacheKey, LRUCache, LRUSet } from "../cache";
import { CachePartition, OriginState } from "./originstate";

export interface BlockMeta {
  blockTime: number;
  rootHash: string;
}

export interface Database {
  readonly origins: LRUCache<CacheKey<CachePartition>, OriginState>;
  readonly nonOrigins: LRUSet<CacheKey<CachePartition>>;
  updateList(
    leaves: readonly (readonly [string, string])[],
    meta: BlockMeta,
  ): Promise<void>;
  getBlockMeta(): Promise<BlockMeta | null>;
  listAllFQDNs(): Promise<string[]>;
  getFQDNEnrollment(
    fqdn: string,
    cachePartition: CachePartition,
  ): Promise<Uint8Array>;
  setLastChecked(): Promise<void>;
  getLastChecked(): Promise<number | null>;
  setLastUpdated(): Promise<void>;
  getLastUpdated(): Promise<number | null>;
}
