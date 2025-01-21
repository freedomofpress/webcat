import { lru_cache_size, lru_set_size } from "./config";
import { LRUCache, LRUSet } from "./webcat/cache";
import { OriginState, PopupState } from "./webcat/interfaces";

export const origins = new LRUCache<string, OriginState>(lru_set_size);
export const nonOrigins = new LRUSet<string>(lru_cache_size);
export const tabs: Map<number, string> = new Map();
export const popups: Map<number, PopupState> = new Map();
