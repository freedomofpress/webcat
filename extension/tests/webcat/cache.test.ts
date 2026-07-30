import { describe, expect, it } from "vitest";

import { LRUCache, LRUSet } from "./../../src/webcat/cache";

describe("LRUCache", () => {
  it("should return undefined for missing keys", async () => {
    const cache = new LRUCache<string, number>(3);
    await expect(cache.get("missing")).resolves.toBeUndefined();
  });

  it("should store and retrieve values", async () => {
    const cache = new LRUCache<string, number>(3);
    cache.set("a", 1);
    await expect(cache.get("a")).resolves.toBe(1);
  });

  it("should evict the least recently used item when limit is exceeded", async () => {
    const cache = new LRUCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    cache.set("d", 4); // "a" should be evicted
    await expect(cache.get("a")).resolves.toBeUndefined();
    await expect(cache.get("b")).resolves.toBe(2);
    await expect(cache.get("c")).resolves.toBe(3);
    await expect(cache.get("d")).resolves.toBe(4);
  });

  it("should update the recently used order when a key is accessed", async () => {
    const cache = new LRUCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    cache.get("a"); // Access "a", making it recently used
    cache.set("d", 4); // "b" should be evicted
    await expect(cache.get("b")).resolves.toBeUndefined();
    await expect(cache.get("a")).resolves.toBe(1);
  });

  it("should overwrite existing keys without changing the size", async () => {
    const cache = new LRUCache<string, number>(3);
    cache.set("a", 1);
    cache.set("a", 2); // Overwrite "a"
    await expect(cache.get("a")).resolves.toBe(2);
    await expect(cache.keys()).resolves.toStrictEqual(
      expect.objectContaining({ length: 1 }),
    );
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
