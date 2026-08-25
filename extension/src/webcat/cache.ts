import { KVStore } from "../browser/kvstore";
import { Lock, Mutex } from "../browser/sync";

declare const CacheKeySymbol: unique symbol;
export type CacheKey<T> = string & { [CacheKeySymbol]: T | undefined };
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

export class LRUCache<K, V> {
  /** @internal */
  protected readonly mutex: Mutex;
  readonly #cache: Map<K, V>;
  readonly #limit: number;

  constructor(limit: number);
  /** @internal */
  constructor(limit: number, mutex: Mutex);
  constructor(limit: number, mutex?: Mutex) {
    this.mutex = mutex || new Mutex();
    this.#limit = limit;
    this.#cache = new Map<K, V>();
  }

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

  async has(key: K): Promise<boolean>;
  /** @internal */
  async has(key: K, l?: Lock): Promise<boolean>;
  async has(key: K, l?: Lock): Promise<boolean> {
    using _lock = await this.mutex.acquire(l);
    return this.#cache.has(key);
  }

  async keys(): Promise<K[]>;
  /** @internal */
  async keys(l?: Lock): Promise<K[]>;
  async keys(l?: Lock): Promise<K[]> {
    using _lock = await this.mutex.acquire(l);
    return Array.from(this.#cache.keys());
  }

  async delete(key: K): Promise<void>
  /** @internal */
  async delete(key: K, l?: Lock): Promise<void>;
  async delete(key: K, l?: Lock): Promise<void> {
    using _lock = await this.mutex.acquire(l);
    this.#cache.delete(key);
  }

  async clear(): Promise<void>;
  /** @internal */
  async clear(l?: Lock): Promise<void>;
  async clear(l?: Lock): Promise<void> {
    using _lock = await this.mutex.acquire(l);
    this.#cache.clear();
  }
}

export type Pojoifiable = { toPOJO(): object };
export type PersistentLRUCacheArgs<V> = V extends Pojoifiable
  ? [number, KVStore, "session" | "local", { fromPOJO(pojo: object): V }]
  : [number, KVStore, "session" | "local"];
export class PersistentLRUCache<
  K extends string,
  V extends Pojoifiable | unknown,
> extends LRUCache<K, V> {
  readonly #store: KVStore;
  readonly #area: "session" | "local";
  readonly #depojoifier: PersistentLRUCacheArgs<V>[3];
  readonly #ready: Promise<void>;

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

  override async keys(): Promise<K[]>
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

export class LRUSet<T> {
  #cache: Set<T>;
  #limit: number;

  constructor(limit: number) {
    this.#limit = limit;
    this.#cache = new Set<T>();
  }

  async has(value: T): Promise<boolean> {
    if (!this.#cache.has(value)) return false;
    // Move the accessed value to the end to mark it as recently used
    this.#cache.delete(value);
    this.#cache.add(value);
    return true;
  }

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

  async values(): Promise<T[]> {
    return Array.from(this.#cache.values());
  }

  async delete(value: T): Promise<void> {
    this.#cache.delete(value);
  }

  async clear(): Promise<void> {
    this.#cache.clear();
  }
}
