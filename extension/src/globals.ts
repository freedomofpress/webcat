import { lru_cache_size, lru_set_size } from "./config";
import { CacheKey, LRUCache, LRUSet } from "./webcat/cache";
import { OriginStateHolder } from "./webcat/interfaces/originstate";
import { CachePartition } from "./webcat/interfaces/requeststate";

export const origins = new LRUCache<
  CacheKey<CachePartition>,
  OriginStateHolder
>(lru_cache_size);
export const nonOrigins = new LRUSet<CacheKey<CachePartition>>(lru_set_size);

declare const __IS_TESTING__: boolean;
if (__IS_TESTING__) {
  Object.defineProperty(globalThis, "state", {
    value: {
      origins,
      nonOrigins,
    },
  });
}
