import { describe, expect, it } from "vitest";

import { KVStore } from "../../src/browser/kvstore";
import { WorkerRegistry } from "../../src/webcat/workers";

class MemoryStore {
  data = new Map<string, unknown>();
  async get(key: string) {
    return this.data.get(key);
  }
  async set(items: Record<string, unknown>) {
    for (const key in items) this.data.set(key, items[key]);
  }
  async remove(key: string) {
    this.data.delete(key);
  }
}

const registry = () => {
  const store = new MemoryStore();
  return [new WorkerRegistry(store as unknown as KVStore), store] as const;
};
const W = "https://enrolled.example/w.js";

describe("WorkerRegistry", () => {
  it("knows nothing about a script it was not told about", async () => {
    const [workers] = registry();
    await expect(workers.lookup(7, W)).resolves.toBeUndefined();
  });

  it("replays a recorded first party while the tab stays", async () => {
    const [workers] = registry();
    await workers.record(7, W, "https://embedder.example");
    await expect(workers.lookup(7, W)).resolves.toEqual({
      firstParty: "https://embedder.example",
      stale: false,
    });
  });

  it("keeps tabs apart", async () => {
    const [workers] = registry();
    await workers.record(7, W, "https://embedder.example");
    await expect(workers.lookup(8, W)).resolves.toBeUndefined();
  });

  it("marks a script stale after the tab navigates, and forgets it after the next", async () => {
    const [workers, store] = registry();
    await workers.record(7, W, "https://embedder.example");
    await workers.navigated(7);
    await expect(workers.lookup(7, W)).resolves.toEqual({
      firstParty: "https://embedder.example",
      stale: true,
    });
    await workers.navigated(7);
    await expect(workers.lookup(7, W)).resolves.toBeUndefined();
    expect(store.data.size).toBe(0);
  });

  it("records the new document's script under the new count", async () => {
    const [workers] = registry();
    await workers.record(7, W, "https://embedder.example");
    await workers.navigated(7);
    await workers.record(7, W, "https://enrolled.example");
    await expect(workers.lookup(7, W)).resolves.toEqual({
      firstParty: "https://enrolled.example",
      stale: false,
    });
  });

  it("does not create a record for a tab without workers", async () => {
    const [workers, store] = registry();
    await workers.navigated(7);
    expect(store.data.size).toBe(0);
  });

  it("forgets a closed tab", async () => {
    const [workers, store] = registry();
    await workers.record(7, W, "https://embedder.example");
    await workers.forget(7);
    expect(store.data.size).toBe(0);
  });
});
