/**
 * Persistent key-value storage.
 */
export class KVStore {
  async get(key: string, area: "local" | "session" = "local") {
    const item = await browser.storage[area].get(key);
    return item[key];
  }

  async set(
    items: { [key: string]: unknown },
    area: "local" | "session" = "local",
  ) {
    return browser.storage[area].set(items);
  }

  async clear(prefix: string = "", area: "local" | "session" = "local") {
    const keys = await this.getKeys(prefix, area);
    return browser.storage[area].remove(keys);
  }

  async getKeys(prefix: string = "", area: "local" | "session" = "local") {
    let keys: string[];
    if (browser.storage[area]["getKeys"]) {
      keys = await browser.storage[area].getKeys();
    } else {
      keys = Object.keys(await browser.storage[area].get(null));
    }
    return keys.filter((key) => key.startsWith(`${prefix}`));
  }

  async remove(key: string, area: "local" | "session" = "local") {
    return browser.storage[area].remove(key);
  }
}

/**
 * Namespaced key-value storage.
 */
export class NamespacedKVStore implements KVStore {
  readonly #namespace: string;
  readonly #store: KVStore;

  constructor(namespace: string, store: KVStore = new KVStore()) {
    this.#namespace = namespace;
    this.#store = store;
  }

  async get(key: string, area: "local" | "session" = "local") {
    const namespacedKey = `${this.#namespace}:${key}`;
    return this.#store.get(namespacedKey, area);
  }

  async set(
    items: { [key: string]: unknown },
    area: "local" | "session" = "local",
  ) {
    const namespacedItems = {} as { [key: string]: unknown };
    for (const key in items) {
      namespacedItems[`${this.#namespace}:${key}`] = items[key];
    }
    return this.#store.set(namespacedItems, area);
  }

  async clear(prefix: string = "", area: "local" | "session" = "local") {
    return this.#store.clear(`${this.#namespace}:${prefix}`, area);
  }

  async getKeys(prefix: string = "", area: "local" | "session" = "local") {
    const namespacedKeys = await this.#store.getKeys(
      `${this.#namespace}:${prefix}`,
      area,
    );
    return namespacedKeys.map((key) =>
      key.substring(this.#namespace.length + 1),
    );
  }

  async remove(key: string, area?: "local" | "session"): Promise<void> {
    const namespacedKey = `${this.#namespace}:${key}`;
    return this.#store.remove(namespacedKey, area);
  }

  namespace(namespace: string) {
    return new NamespacedKVStore(namespace, this);
  }
}
