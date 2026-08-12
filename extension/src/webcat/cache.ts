import { KVStore } from "../browser/kvstore";

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
  #cache: Map<K, V>;
  #limit: number;

  constructor(limit: number) {
    this.#limit = limit;
    this.#cache = new Map<K, V>();
  }

  async get(key: K): Promise<V | undefined> {
    if (!this.#cache.has(key)) return undefined;

    const value = this.#cache.get(key) as V;
    await this.set(key, value);
    return value;
  }

  async set(key: K, value: V): Promise<void> {
    if (this.#cache.has(key)) {
      // Remove the old value to update its position
      await this.delete(key);
    } else if (this.#cache.size >= this.#limit) {
      // Remove the least recently used key (first key in the Map)
      const oldestKey = this.#cache.keys().next().value;
      if (oldestKey !== undefined) {
        await this.delete(oldestKey);
      }
    }
    this.#cache.set(key, value);
  }

  async has(key: K): Promise<boolean> {
    return this.#cache.has(key);
  }

  async keys(): Promise<K[]> {
    return Array.from(this.#cache.keys());
  }

  async delete(key: K): Promise<void> {
    this.#cache.delete(key);
  }

  async clear(): Promise<void> {
    this.#cache.clear();
  }
}

type pojoifiable = { toPOJO(): object };
type PersistentLRUCacheArgs<V> = V extends pojoifiable
  ? [number, KVStore, "session" | "local", { fromPOJO(pojo: object): V }]
  : [number, KVStore, "session" | "local"];
export class PersistentLRUCache<
  K extends string,
  V extends pojoifiable | unknown,
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

  override async get(key: K): Promise<V | undefined> {
    await this.#ready;
    return super.get(key);
  }

  override async set(key: K, value: V): Promise<void> {
    await this.#ready;
    const pojo = (value as pojoifiable)?.toPOJO?.() ?? value;
    await super.set(key, value);
    await this.#store.set({ [key]: pojo }, this.#area);
  }

  override async has(key: K): Promise<boolean> {
    await this.#ready;
    return super.has(key);
  }

  override async keys(): Promise<K[]> {
    await this.#ready;
    return super.keys();
  }

  override async delete(key: K): Promise<void> {
    await this.#ready;
    await this.#store.remove(key, this.#area);
    return super.delete(key);
  }

  override async clear(): Promise<void> {
    await this.#ready;
    await this.#store.clear("", this.#area);
    return super.clear();
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
