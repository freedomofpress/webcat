import { KVStore } from "../browser/kvstore";
import { Lock, Mutex } from "../browser/sync";

declare const CacheKeySymbol: unique symbol;
/** @internal */
export type CacheKey<T> = string & { [CacheKeySymbol]: T | undefined };

/**
 * Constructs a cache key from a primary string key and a set of attributes,
 * enabling arbitrary cache partitioning.
 *
 * @typeParam T - A string-indexed object type for cache attributes.
 */
export function CacheKey<T extends { [index: string]: { toString(): string } }>(
  key: string,
  attrs: T,
): CacheKey<T> {
  return (encodeURIComponent(key) +
    (attrs
      ? "?" +
        Object.keys(attrs)
          .sort()
          .map(
            (name) =>
              `${encodeURIComponent(name)}=${encodeURIComponent(attrs[name].toString())}`,
          )
      : "")) as CacheKey<T>;
}

/**
 * Checks whether a given {@link CacheKey} is in the specified partition.
 *
 * @typeParam P The type of the partition attribute object to check against.
 * @typeParam T The type of the cache partition attributes of the key.
 * @param key The key to check.
 * @param partition The cache partition attributes.
 * @returns true if the key has the specified attributes, i.e. is in the
 * partition; false otherwise.
 */
export function isInPartition<
  P extends { [index: string]: { toString(): string } },
  T extends P,
>(key: CacheKey<T>, partition: P) {
  const [_, q] = key.split("?");
  if (q) {
    const attrs = {} as Record<string, string>;
    q.split(",").forEach((attr) => {
      const [name, value] = attr.split("=");
      attrs[name] = value;
    });
    return Object.keys(partition).every(
      (name) => partition[name].toString() === attrs[name],
    );
  }
  return Object.keys(partition).length === 0;
}

/**
 * A fixed-size in-memory cache that automatically evicts the least recently
 * used entry first when it reaches its size limit.
 *
 * @typeParam K The type of cache keys.
 * @typeParam V The type of values store in this cache.
 */
export class LRUCache<K, V> {
  /** @internal */
  protected readonly mutex: Mutex;
  readonly #cache: Map<K, V>;
  readonly #limit: number;

  /**
   * @param limit The maximum number of entries held by the cache.
   */
  constructor(limit: number);
  /** @internal */
  constructor(limit: number, mutex: Mutex);
  constructor(limit: number, mutex?: Mutex) {
    this.mutex = mutex || new Mutex();
    this.#limit = limit;
    this.#cache = new Map<K, V>();
  }

  /**
   * Reads a cached value.
   *
   * @param key The key to read.
   * @returns A Promise that resolves with the value read.
   */
  async get(key: K): Promise<V | undefined>;
  /** @internal */
  async get(key: K, l?: Lock): Promise<V | undefined>;
  async get(key: K, l?: Lock): Promise<V | undefined> {
    using lock = await this.mutex.acquire(l);
    if (!this.#cache.has(key)) return undefined;

    const value = this.#cache.get(key) as V;
    await this.set(key, value, lock);
    return value;
  }

  /**
   * Caches a value.
   *
   * @param key The key to use.
   * @param value The value to cache.
   */
  async set(key: K, value: V): Promise<void>;
  /** @internal */
  async set(key: K, value: V, l?: Lock): Promise<void>;
  async set(key: K, value: V, l?: Lock): Promise<void> {
    using lock = await this.mutex.acquire(l);
    if (this.#cache.has(key)) {
      // Remove the old value to update its position
      await this.delete(key, lock);
    } else if (this.#cache.size >= this.#limit) {
      // Remove the least recently used key (first key in the Map)
      const oldestKey = this.#cache.keys().next().value;
      if (oldestKey !== undefined) {
        await this.delete(oldestKey, lock);
      }
    }
    this.#cache.set(key, value);
  }

  /**
   * @returns A Promise that resolves to true if the given key exists in the cache.
   */
  async has(key: K): Promise<boolean>;
  /** @internal */
  async has(key: K, l?: Lock): Promise<boolean>;
  async has(key: K, l?: Lock): Promise<boolean> {
    using _lock = await this.mutex.acquire(l);
    return this.#cache.has(key);
  }

  /**
   * @returns A Promise that resolves to an array of the keys in the cache.
   */
  async keys(): Promise<K[]>;
  /** @internal */
  async keys(l?: Lock): Promise<K[]>;
  async keys(l?: Lock): Promise<K[]> {
    using _lock = await this.mutex.acquire(l);
    return Array.from(this.#cache.keys());
  }

  /**
   * Clears a single value from the cache.
   *
   * @param key The key to clear.
   */
  async delete(key: K): Promise<void>;
  /** @internal */
  async delete(key: K, l?: Lock): Promise<void>;
  async delete(key: K, l?: Lock): Promise<void> {
    using _lock = await this.mutex.acquire(l);
    this.#cache.delete(key);
  }

  /**
   * Clears all values from the cache.
   */
  async clear(): Promise<void>;
  /** @internal */
  async clear(l?: Lock): Promise<void>;
  async clear(l?: Lock): Promise<void> {
    using _lock = await this.mutex.acquire(l);
    this.#cache.clear();
  }
}

/**
 * An object that can be converted to a {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object | Plain Old JavaScript Object}
 * compatible with persistence APIs.
 */
export type Pojoifiable = {
  /**
   * @returns A POJO representation of the object.
   */
  toPOJO(): object;
};

/**
 * Complementary interface to {@link Pojoifiable}.
 */
export interface Depojoifier<V> {
  /**
   * @param pojo An object created via {@link Pojoifiable.toPOJO}.
   * @returns A corresponding {@link Pojoifiable} object.
   */
  fromPOJO(pojo: object): V;
}

/**
 * Arguments for the {@link PersistentLRUCache} constructor:
 *  1. limit: the maximum number of entries held by the cache
 *  2. store: a {@link KVStore} instance to use for persistence
 *  3. area: the name of the {@link browser.storage.StorageArea | storage area}
 *    to use
 *  4. (optional) depojoifier: a {@link Depojoifier} for converting presisted
 *    POJOs to V; required if and only if V extends {@link Pojoifiable}.
 *
 * @typeParam V The type of values stored in the cache.
 * @expand
 */
export type PersistentLRUCacheArgs<V> = V extends Pojoifiable
  ? [number, KVStore, "session" | "local", Depojoifier<V>]
  : [number, KVStore, "session" | "local"];

/**
 * A persistent {@link LRUCache}. Supported value types are limited by the
 * storage API. In addition to JSON-ifiable values, i.e. Plain Old JavaScript
 * Objects (POJOs), accepted by the storage API, arbitrary objects that
 * implement the {@link Pojoifiable} interface can be cached. The conversion
 * from {@link Pojoifiable} (and back via the {@link Depojoifier} interface) is
 * handled automatically.
 *
 * @typeParam K The type of cache keys.
 * @typeParam V The type of values store in this cache.
 */
export class PersistentLRUCache<
  K extends string,
  V extends Pojoifiable | unknown,
> extends LRUCache<K, V> {
  readonly #store: KVStore;
  readonly #area: "session" | "local";
  readonly #depojoifier: PersistentLRUCacheArgs<V>[3];
  readonly #ready: Promise<void>;

  /** @param args */
  constructor(...[limit, store, area, depojoifier]: PersistentLRUCacheArgs<V>) {
    super(limit);
    this.#store = store;
    this.#area = area;
    this.#depojoifier = depojoifier;
    this.#ready = this.#load();
  }

  async #load() {
    const keys = (await this.#store.getKeys("", this.#area)) as K[];
    for (const key of keys) {
      const pojo = await this.#store.get(key, this.#area);
      const v = this.#depojoifier?.fromPOJO(pojo) ?? pojo;
      await super.set(key, v);
    }
  }

  override async get(key: K): Promise<V | undefined>;
  /** @internal */
  override async get(key: K, l?: Lock): Promise<V | undefined>;
  override async get(key: K, l?: Lock): Promise<V | undefined> {
    await this.#ready;
    return super.get(key, l);
  }

  override async set(key: K, value: V): Promise<void>;
  /** @internal */
  override async set(key: K, value: V, l?: Lock): Promise<void>;
  override async set(key: K, value: V, l?: Lock): Promise<void> {
    await this.#ready;
    using lock = await this.mutex.acquire(l);
    const pojo = (value as Pojoifiable)?.toPOJO?.() ?? value;
    await super.set(key, value, lock);
    await this.#store.set({ [key]: pojo }, this.#area);
  }

  override async has(key: K): Promise<boolean>;
  /** @internal */
  override async has(key: K, l?: Lock): Promise<boolean>;
  override async has(key: K, l?: Lock): Promise<boolean> {
    await this.#ready;
    return super.has(key, l);
  }

  override async keys(): Promise<K[]>;
  /** @internal */
  override async keys(l?: Lock): Promise<K[]>;
  override async keys(l?: Lock): Promise<K[]> {
    await this.#ready;
    return super.keys(l);
  }

  override async delete(key: K): Promise<void>;
  /** @internal */
  override async delete(key: K, l?: Lock): Promise<void>;
  override async delete(key: K, l?: Lock): Promise<void> {
    await this.#ready;
    using lock = await this.mutex.acquire(l);
    await this.#store.remove(key, this.#area);
    return super.delete(key, lock);
  }

  override async clear(): Promise<void>;
  /** @internal */
  override async clear(l?: Lock): Promise<void>;
  override async clear(l?: Lock): Promise<void> {
    await this.#ready;
    using lock = await this.mutex.acquire(l);
    await this.#store.clear("", this.#area);
    return super.clear(lock);
  }
}

/**
 * An unkeyed fixed-size in-memory cache that automatically evicts the least
 * recently used entry first when it reaches its size limit.
 *
 * @typeParam T The type of values to store in this cache.
 */
export class LRUSet<T> {
  #cache: Set<T>;
  #limit: number;

  /**
   * @param limit The maximum number of entries held by the cache.
   */
  constructor(limit: number) {
    this.#limit = limit;
    this.#cache = new Set<T>();
  }

  /**
   * @returns A Promise that resolves to true if the given value exists in the cache.
   */
  async has(value: T): Promise<boolean> {
    if (!this.#cache.has(value)) return false;
    // Move the accessed value to the end to mark it as recently used
    this.#cache.delete(value);
    this.#cache.add(value);
    return true;
  }

  /**
   * Caches a value.
   *
   * @param value The value to cache.
   */
  async add(value: T): Promise<void> {
    if (this.#cache.has(value)) {
      // Remove the old value to update its position
      this.#cache.delete(value);
    } else if (this.#cache.size >= this.#limit) {
      // Remove the least recently used value (first item in the Set)
      const oldestValue = this.#cache.values().next().value;
      if (oldestValue !== undefined) {
        this.#cache.delete(oldestValue);
      }
    }
    this.#cache.add(value);
  }

  /**
   * @returns A Promise that resolves to an array of the values in the cache.
   */
  async values(): Promise<T[]> {
    return Array.from(this.#cache.values());
  }

  /**
   * Clears a single value from the cache.
   *
   * @param value The value to clear.
   */
  async delete(value: T): Promise<void> {
    this.#cache.delete(value);
  }

  /**
   * Clears all values from the cache.
   */
  async clear(): Promise<void> {
    this.#cache.clear();
  }
}
