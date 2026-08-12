import { beforeEach, describe, expect, it, vi } from "vitest";

import { LRUCache, LRUSet, PersistentLRUCache } from "./../../src/webcat/cache";

class MockKVStore {
  data = new Map<string, unknown>();

  get = vi.fn().mockImplementation(async (key: string) => {
    return this.data.get(key);
  });
  set = vi
    .fn()
    .mockImplementation(async (items: { [key: string]: unknown }) => {
      for (const key in items) {
        this.data.set(key, items[key]);
      }
    });
  clear = vi.fn().mockImplementation(async () => {
    this.data.clear();
  });
  getKeys = vi.fn().mockImplementation(async () => {
    return Array.from(this.data.keys());
  });
  remove = vi.fn().mockImplementation(async (key: string) => {
    this.data.delete(key);
  });
}

describe.each([
  ["LRUCache", (n: number) => new LRUCache<string, number>(n)],
  [
    "PersistentLRUCache",
    (n: number) =>
      new PersistentLRUCache<string, number>(n, new MockKVStore(), "session"),
  ],
])("%s", (_, createLRUCache) => {
  it("should return undefined for missing keys", async () => {
    const cache = createLRUCache(3);
    await expect(cache.get("missing")).resolves.toBeUndefined();
  });

  it("should store and retrieve values", async () => {
    const cache = createLRUCache(3);
    await cache.set("a", 1);
    await expect(cache.get("a")).resolves.toBe(1);
  });

  it("should evict the least recently used item when limit is exceeded", async () => {
    const cache = createLRUCache(3);
    await cache.set("a", 1);
    await cache.set("b", 2);
    await cache.set("c", 3);
    await cache.set("d", 4); // "a" should be evicted
    await expect(cache.get("a")).resolves.toBeUndefined();
    await expect(cache.get("b")).resolves.toBe(2);
    await expect(cache.get("c")).resolves.toBe(3);
    await expect(cache.get("d")).resolves.toBe(4);
  });

  it("should update the recently used order when a key is accessed", async () => {
    const cache = createLRUCache(3);
    await cache.set("a", 1);
    await cache.set("b", 2);
    await cache.set("c", 3);
    await cache.get("a"); // Access "a", making it recently used
    await cache.set("d", 4); // "b" should be evicted
    await expect(cache.get("b")).resolves.toBeUndefined();
    await expect(cache.get("a")).resolves.toBe(1);
  });

  it("should overwrite existing keys without changing the size", async () => {
    const cache = createLRUCache(3);
    await cache.set("a", 1);
    await cache.set("a", 2); // Overwrite "a"
    await expect(cache.get("a")).resolves.toBe(2);
    await expect(cache.keys()).resolves.toStrictEqual(
      expect.objectContaining({ length: 1 }),
    );
  });
});

describe("LRUCache", () => {
  it("should set atomically", async () => {
    const cache = new (class extends LRUCache<string, number> {
      constructor() {
        super(1);
      }
      // LRUCache.set calls delete when evicting
      async delete(...args: [string]) {
        await super.delete(...args);
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    })();
    // Set twice to trigger eviction and the timeout
    // Do not await; the operations should still be atomic
    cache.set("a", 1);
    cache.set("a", 2);
    await expect(cache.get("a")).resolves.toBe(2);
  });

  it("should get atomically", async () => {
    const cache = new (class extends LRUCache<string, number> {
      constructor() {
        super(3);
      }
      // LRUCache.get calls set to update key order
      async set(...args: [string, number]) {
        await super.set(...args);
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    })();
    await cache.set("a", 1);
    await cache.set("b", 2);
    // Get without awaiting; the order of the keys should change
    cache.get("a");
    await expect(cache.keys()).resolves.toStrictEqual(["b", "a"]);
  });
});

describe("PersistentLRUCache", () => {
  it("should set atomically", async () => {
    const store = new MockKVStore();
    store.set.mockImplementation(async function (
      this: MockKVStore,
      items: Record<string, unknown>,
    ) {
      if (items.a) {
        // Introduce an artificial delay to the first set call
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      for (const key in items) {
        this.data.set(key, items[key]);
      }
    });
    const cache = new PersistentLRUCache(3, store, "session");
    cache.set("a", 1);
    cache.set("b", 2);
    await expect(cache.keys()).resolves.toStrictEqual(["a", "b"]);
    await expect(store.getKeys()).resolves.toStrictEqual(["a", "b"]);
  });
});

describe("PersistentLRUCache", () => {
  let store: MockKVStore;
  let cache: PersistentLRUCache<string, unknown>;

  beforeEach(async () => {
    store = new MockKVStore();
    store.data.set("one", 1);
    store.data.set("two", 2);
    store.data.set("three", 3);
    cache = new PersistentLRUCache(5, store, "session");
  });

  it("should load persisted entries", async () => {
    await expect(cache.keys()).resolves.toStrictEqual(["one", "two", "three"]);
    await expect(cache.get("one")).resolves.toBe(1);
    await expect(cache.get("two")).resolves.toBe(2);
    await expect(cache.get("three")).resolves.toBe(3);
    await expect(cache.get("four")).resolves.toBe(undefined);
  });

  it("should persist new entries", async () => {
    await cache.set("four", 4);
    await cache.set("object", { x: NaN });
    await cache.set("string", "gnirts");
    expect(store.set).toHaveBeenCalledWith({ four: 4 }, "session");
    expect(store.set).toHaveBeenCalledWith({ object: { x: NaN } }, "session");
    expect(store.set).toHaveBeenCalledWith({ string: "gnirts" }, "session");
  });

  it("should persist and load pojoifiable values", async () => {
    class P {
      toPOJO() {
        return { pojo: true };
      }
      static fromPOJO(p: object) {
        return p && new P();
      }
    }
    const p = new P();
    await cache.set("thing", p);
    cache = new PersistentLRUCache<string, P>(5, store, "session", P);
    await expect(cache.get("thing")).resolves.toBeInstanceOf(P);
    await expect(cache.get("four")).resolves.toBeUndefined();
  });

  it("should evict a persisted value", async () => {
    await cache.set("one", "ONE!!1");
    await cache.set("four", 4);
    await cache.set("object", { x: NaN });
    await cache.set("string", "gnirts");
    await expect(store.get("one")).resolves.toBe("ONE!!1");
    await expect(store.get("two")).resolves.toBeUndefined();
  });

  it("should retain key order after reload", async () => {
    await cache.set("one", "ONE!!1");
    await cache.get("two");
    await expect(cache.keys()).resolves.toStrictEqual(["three", "one", "two"]);
    cache = new PersistentLRUCache<string, unknown>(5, store, "session");
    await expect(cache.keys()).resolves.toStrictEqual(["three", "one", "two"]);
  });
});

describe("LRUSet", () => {
  it("should check for existence of values", async () => {
    const cache = new LRUSet<number>(3);
    cache.add(1);
    await expect(cache.has(1)).resolves.toBe(true);
    await expect(cache.has(2)).resolves.toBe(false);
  });

  it("should maintain the LRU order", async () => {
    const cache = new LRUSet<number>(3);
    cache.add(1);
    cache.add(2);
    cache.add(3);
    cache.has(1); // Access "1", making it recently used
    cache.add(4); // "2" should be evicted
    await expect(cache.has(2)).resolves.toBe(false);
    await expect(cache.has(1)).resolves.toBe(true);
    await expect(cache.has(3)).resolves.toBe(true);
    await expect(cache.has(4)).resolves.toBe(true);
  });

  it("should not exceed the size limit", async () => {
    const cache = new LRUSet<number>(3);
    cache.add(1);
    cache.add(2);
    cache.add(3);
    cache.add(4);
    await expect(cache.values()).resolves.toStrictEqual(
      expect.objectContaining({ length: 3 }),
    );
  });

  it("should remove the least recently used item", async () => {
    const cache = new LRUSet<number>(2);
    cache.add(1);
    cache.add(2);
    cache.add(3); // "1" should be evicted
    await expect(cache.has(1)).resolves.toBe(false);
    await expect(cache.has(2)).resolves.toBe(true);
    await expect(cache.has(3)).resolves.toBe(true);
  });

  it("should move accessed items to the end", async () => {
    const cache = new LRUSet<number>(3);
    cache.add(1);
    cache.add(2);
    cache.add(3);
    cache.has(1); // Access "1", making it recently used
    cache.add(4); // "2" should be evicted
    await expect(cache.has(2)).resolves.toBe(false);
    await expect(cache.values()).resolves.toEqual([3, 1, 4]);
  });
});
