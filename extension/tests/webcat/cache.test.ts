import { describe, expect, it } from "vitest";

import { LRUCache, LRUSet } from "./../../src/webcat/cache";

describe("LRUCache", () => {
  it("should return undefined for missing keys", () => {
    const cache = new LRUCache<string, number>(3);
    expect(cache.get("missing")).toBeUndefined();
  });

  it("should store and retrieve values", () => {
    const cache = new LRUCache<string, number>(3);
    cache.set("a", 1);
    expect(cache.get("a")).toBe(1);
  });

  it("should evict the least recently used item when limit is exceeded", () => {
    const cache = new LRUCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    cache.set("d", 4); // "a" should be evicted
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBe(2);
    expect(cache.get("c")).toBe(3);
    expect(cache.get("d")).toBe(4);
  });

  it("should update the recently used order when a key is accessed", () => {
    const cache = new LRUCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    cache.get("a"); // Access "a", making it recently used
    cache.set("d", 4); // "b" should be evicted
    expect(cache.get("b")).toBeUndefined();
    expect(cache.get("a")).toBe(1);
  });

  it("should overwrite existing keys without changing the size", () => {
    const cache = new LRUCache<string, number>(3);
    cache.set("a", 1);
    cache.set("a", 2); // Overwrite "a"
    expect(cache.get("a")).toBe(2);
    expect(cache.keys().length).toBe(1);
  });
});

describe("LRUSet", () => {
  it("should check for existence of values", () => {
    const cache = new LRUSet<number>(3);
    cache.add(1);
    expect(cache.has(1)).toBe(true);
    expect(cache.has(2)).toBe(false);
  });

  it("should maintain the LRU order", () => {
    const cache = new LRUSet<number>(3);
    cache.add(1);
    cache.add(2);
    cache.add(3);
    cache.has(1); // Access "1", making it recently used
    cache.add(4); // "2" should be evicted
    expect(cache.has(2)).toBe(false);
    expect(cache.has(1)).toBe(true);
    expect(cache.has(3)).toBe(true);
    expect(cache.has(4)).toBe(true);
  });

  it("should not exceed the size limit", () => {
    const cache = new LRUSet<number>(3);
    cache.add(1);
    cache.add(2);
    cache.add(3);
    cache.add(4);
    expect(cache.values().length).toBe(3);
  });

  it("should remove the least recently used item", () => {
    const cache = new LRUSet<number>(2);
    cache.add(1);
    cache.add(2);
    cache.add(3); // "1" should be evicted
    expect(cache.has(1)).toBe(false);
    expect(cache.has(2)).toBe(true);
    expect(cache.has(3)).toBe(true);
  });

  it("should move accessed items to the end", () => {
    const cache = new LRUSet<number>(3);
    cache.add(1);
    cache.add(2);
    cache.add(3);
    cache.has(1); // Access "1", making it recently used
    cache.add(4); // "2" should be evicted
    expect(cache.has(2)).toBe(false);
    expect(cache.values()).toEqual([3, 1, 4]);
  });
});
