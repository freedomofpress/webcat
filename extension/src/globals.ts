import { lru_cache_size, lru_set_size } from "./config";
import { CacheKey, LRUCache, LRUSet } from "./webcat/cache";
import { WebcatDatabase } from "./webcat/db";
import { stringToUint8Array, Uint8ArrayToBase64Url } from "./webcat/encoding";
import { OriginStateHolder } from "./webcat/interfaces/originstate";

export type CachePartition = { firstParty: string; incognito: boolean };

export const origins = new LRUCache<
  CacheKey<CachePartition>,
  OriginStateHolder
>(lru_cache_size);
export const pendingOrigins: Map<string, OriginStateHolder> = new Map();
export const nonOrigins = new LRUSet<CacheKey<CachePartition>>(lru_set_size);
export const tabs: Map<number, CachePartition> = new Map();
export const db = new WebcatDatabase();
export const hookMarker = stringToUint8Array(
  `__WEBCAT_HOOK__{${Uint8ArrayToBase64Url(crypto.getRandomValues(new Uint8Array(32)))}}\n`,
);
export const endMarker = stringToUint8Array(
  `__WEBCAT_END__{${Uint8ArrayToBase64Url(crypto.getRandomValues(new Uint8Array(32)))}}\n`,
);

declare const __IS_TESTING__: boolean;
if (__IS_TESTING__) {
  Object.defineProperty(globalThis, "state", {
    value: {
      origins,
      pendingOrigins,
      nonOrigins,
      tabs,
      db,
      hookMarker,
      endMarker,
    },
  });
}
