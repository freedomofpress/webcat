import { lru_cache_size, lru_set_size } from "./config";
import { LRUCache, LRUSet } from "./webcat/cache";
import { OriginStateHolder } from "./webcat/interfaces/originstate";

export const origins = new LRUCache<string, OriginStateHolder>(lru_set_size);
export const nonOrigins = new LRUSet<string>(lru_cache_size);
export const tabs: Map<number, string> = new Map();
