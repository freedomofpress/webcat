import { lru_cache_size, lru_set_size } from "./config";
import { LRUCache, LRUSet } from "./webcat/cache";
import { WebcatDatabase } from "./webcat/db";
import { stringToUint8Array, Uint8ArrayToBase64Url } from "./webcat/encoding";
import { OriginStateHolder } from "./webcat/interfaces/originstate";

export const origins = new LRUCache<string, OriginStateHolder>(lru_set_size);
export const nonOrigins = new LRUSet<string>(lru_cache_size);
export const tabs: Map<number, string> = new Map();
export const db = new WebcatDatabase();
export const hookMarker = stringToUint8Array(
  `__WEBCAT_HOOK__{${Uint8ArrayToBase64Url(crypto.getRandomValues(new Uint8Array(32)))}}\n`,
);
export const endMarker = stringToUint8Array(
  `__WEBCAT_END__{${Uint8ArrayToBase64Url(crypto.getRandomValues(new Uint8Array(32)))}}\n`,
);
