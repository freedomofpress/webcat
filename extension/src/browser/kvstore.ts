import { Mutex } from "./sync";

/**
 * Persistent key-value storage backed by the {@link browser.storage} API.
 */
export class KVStore {
  /**
   * Reads a persisted value.
   *
   * @param key The key to read.
   * @param area The name of the {@link browser.storage.StorageArea | storage area} to read from.
   * @returns A Promise that resolves to the value read.
   */
  async get(key: string, area: "local" | "session" = "local") {
    const item = await browser.storage[area].get(key);
    return item[key];
  }

  /**
   * Stores values.
   *
   * @param items An object consisting of one or more key/value pairs to store.
   * @param area The name of the {@link browser.storage.StorageArea | storage area} to use.
   */
  async set(
    items: { [key: string]: unknown },
    area: "local" | "session" = "local",
  ) {
    return browser.storage[area].set(items);
  }

  /**
   * Clears all values whose key matches the specified prefix.
   *
   * @param prefix The prefix to match against.
   * @param area The name of the {@link browser.storage.StorageArea | storage area} to use.
   */
  async clear(prefix: string = "", area: "local" | "session" = "local") {
    const keys = await this.getKeys(prefix, area);
    return browser.storage[area].remove(keys);
  }

  /**
   * Retrieves a list of stored keys matching the specified prefix.
   *
   * @param prefix The prefix to match against.
   * @param area The name of the {@link browser.storage.StorageArea | storage area} to read from.
   * @returns A Promise that resolves to an array of matching keys.
   */
  async getKeys(prefix: string = "", area: "local" | "session" = "local") {
    let keys: string[];
    if (browser.storage[area]["getKeys"]) {
      keys = await browser.storage[area].getKeys();
    } else {
      keys = Object.keys(await browser.storage[area].get(null));
    }
    return keys.filter((key) => key.startsWith(`${prefix}`));
  }

  /**
   * Clears a single persisted value.
   *
   * @param key The key to clear.
   * @param area The name of the {@link browser.storage.StorageArea | storage area} to use.
   */
  async remove(key: string, area: "local" | "session" = "local") {
    return browser.storage[area].remove(key);
  }
}

/**
 * Namespaced key-value storage. Operations are atomic within
 * an instance; distinct instances of the same namespace may
 * access the same data in an unsafe manner.
 */
export class NamespacedKVStore implements KVStore {
  readonly #mutex = new Mutex();
  readonly #namespace: string;
  readonly #store: KVStore;

  /**
   * @param namespace The namespace prefix to use for this store.
   * @param store A backing {@link KVStore} instance to use for persistence.
   */
  constructor(namespace: string, store: KVStore = new KVStore()) {
    this.#namespace = namespace;
    this.#store = store;
  }

  async get(key: string, area: "local" | "session" = "local") {
    using _lock = await this.#mutex.acquire();
    const namespacedKey = `${this.#namespace}:${key}`;
    return await this.#store.get(namespacedKey, area);
  }

  async set(
    items: { [key: string]: unknown },
    area: "local" | "session" = "local",
  ) {
    using _lock = await this.#mutex.acquire();
    const namespacedItems = {} as { [key: string]: unknown };
    for (const key in items) {
      namespacedItems[`${this.#namespace}:${key}`] = items[key];
    }
    return await this.#store.set(namespacedItems, area);
  }

  async clear(prefix: string = "", area: "local" | "session" = "local") {
    using _lock = await this.#mutex.acquire();
    return await this.#store.clear(`${this.#namespace}:${prefix}`, area);
  }

  async getKeys(prefix: string = "", area: "local" | "session" = "local") {
    using _lock = await this.#mutex.acquire();
    const namespacedKeys = await this.#store.getKeys(
      `${this.#namespace}:${prefix}`,
      area,
    );
    return namespacedKeys.map((key) =>
      key.substring(this.#namespace.length + 1),
    );
  }

  async remove(key: string, area?: "local" | "session"): Promise<void> {
    using _lock = await this.#mutex.acquire();
    const namespacedKey = `${this.#namespace}:${key}`;
    return await this.#store.remove(namespacedKey, area);
  }

  /**
   * Creates a new subnamespace within this namespace.
   *
   * @param namespace A new namespace prefix to append to the existing prefix.
   */
  namespace(namespace: string) {
    return new NamespacedKVStore(namespace, this);
  }
}
