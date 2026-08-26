import { setImmediate } from "node:timers";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { NamespacedKVStore } from "../../src/browser/kvstore";

const mockGet = vi.fn().mockImplementation(async (key) => {
  return { [key]: "value" };
});
const mockSet = vi.fn();
const mockRemove = vi.fn();
const mockGetKeys = vi.fn().mockImplementation(async () => {
  return ["foo", "bar", "baz"];
});

vi.stubGlobal("browser", {
  storage: {
    local: {
      get: mockGet,
      set: mockSet,
      remove: mockRemove,
      getKeys: mockGetKeys,
    },
  },
});

describe("NamespacedKVStore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("executes get atomically", async () => {
    mockGet.mockImplementationOnce((key) => {
      const { promise, resolve } = Promise.withResolvers();
      setImmediate(() => resolve({ [key]: "value" }));
      return promise;
    });

    const store = new NamespacedKVStore("ns");
    store.get("foo");
    await store.set({ foo: "bar" });
    expect(mockGet).toHaveBeenCalledOnce();
    expect(mockSet).toHaveBeenCalledOnce();
    expect(mockGet.mock.settledResults[0].value).toStrictEqual({
      "ns:foo": "value",
    });
  });

  it("executes set atomically", async () => {
    mockSet.mockImplementationOnce(() => {
      const { promise, resolve } = Promise.withResolvers<void>();
      setImmediate(() => resolve());
      return promise;
    });

    const store = new NamespacedKVStore("ns");
    store.set({ foo: "bar" });
    await store.get("foo");
    expect(mockSet).toHaveBeenCalledOnce();
    expect(mockGet).toHaveBeenCalledOnce();
    expect(mockSet.mock.settledResults[0].type).toBe("fulfilled");
  });

  it("executes clear atomically", async () => {
    mockRemove.mockImplementationOnce(() => {
      const { promise, resolve } = Promise.withResolvers<void>();
      setImmediate(() => resolve());
      return promise;
    });

    const store = new NamespacedKVStore("ns");
    store.clear();
    await store.get("foo");
    expect(mockRemove).toHaveBeenCalledOnce();
    expect(mockGet).toHaveBeenCalledOnce();
    expect(mockRemove.mock.settledResults[0].type).toBe("fulfilled");
  });

  it("executes getKeys atomically", async () => {
    mockGetKeys.mockImplementationOnce(() => {
      const { promise, resolve } = Promise.withResolvers();
      setImmediate(() => resolve(["foo", "bar", "baz"]));
      return promise;
    });

    const store = new NamespacedKVStore("ns");
    store.getKeys();
    await store.get("foo");
    expect(mockGetKeys).toHaveBeenCalledOnce();
    expect(mockGet).toHaveBeenCalledOnce();
    expect(mockGetKeys.mock.settledResults[0].value).toStrictEqual([
      "foo",
      "bar",
      "baz",
    ]);
  });

  it("executes remove atomically", async () => {
    mockRemove.mockImplementationOnce(() => {
      const { promise, resolve } = Promise.withResolvers<void>();
      setImmediate(() => resolve());
      return promise;
    });

    const store = new NamespacedKVStore("ns");
    store.remove("foo");
    await store.get("foo");
    expect(mockRemove).toHaveBeenCalledOnce();
    expect(mockGet).toHaveBeenCalledOnce();
    expect(mockRemove.mock.settledResults[0].type).toBe("fulfilled");
  });
});
