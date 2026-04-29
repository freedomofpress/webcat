/* eslint-disable  @typescript-eslint/no-explicit-any */
import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock globals
vi.mock("../../src/globals", () => ({
  origins: new Map(),
  nonOrigins: { has: () => false, add: () => {}, clear: () => {} },
}));

vi.mock("../../src/webcat/logger", () => ({
  logger: { addLog: vi.fn() },
}));

import { WebcatDatabase } from "../../src/webcat/db";

// ---------------------------------------------------------------------------
// Helpers – build a fake leaf that extractHostname / extractRawHash accept.
// extractHostname expects "canonical/.tld.domain" (reversed labels).
// extractRawHash expects a hex string starting with 0a <len> <payload…>.
// ---------------------------------------------------------------------------
function fakeLeaf(fqdn: string, payload: number[]): [string, string] {
  const labels = fqdn.split(".").reverse();
  const reverseKey = `canonical/.${labels.join(".")}`;
  const raw = [0x0a, payload.length, ...payload];
  const hex = raw.map((b) => b.toString(16).padStart(2, "0")).join("");
  return [reverseKey, hex];
}

// ---------------------------------------------------------------------------
// Fake browser.storage.local + session backed by plain objects
// ---------------------------------------------------------------------------
function makeFakeStore() {
  let storage: Record<string, any> = {};
  return {
    get: vi.fn(async (keyOrNull: string | null) => {
      if (keyOrNull === null) return { ...storage };
      if (typeof keyOrNull === "string") {
        return keyOrNull in storage ? { [keyOrNull]: storage[keyOrNull] } : {};
      }
      const result: Record<string, any> = {};
      for (const k of keyOrNull as unknown as string[]) {
        if (k in storage) result[k] = storage[k];
      }
      return result;
    }),
    set: vi.fn(async (items: Record<string, any>) => {
      Object.assign(storage, items);
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      const arr = Array.isArray(keys) ? keys : [keys];
      for (const k of arr) delete storage[k];
    }),
    clear: vi.fn(async () => {
      storage = {};
    }),
  };
}

function fakeBrowserStorage() {
  globalThis.browser = {
    storage: {
      local: makeFakeStore(),
      session: makeFakeStore(),
    },
  };
}

describe("WebcatDatabase", () => {
  let db: InstanceType<typeof WebcatDatabase>;

  beforeEach(() => {
    fakeBrowserStorage();
    db = new WebcatDatabase();
  });

  it("updateList stores and retrieves enrollment by fqdn", async () => {
    const leaf = fakeLeaf("example.com", [0xca, 0xfe]);
    await db.updateList([leaf], { blockTime: 100 });

    const enrollment = await db.getFQDNEnrollment("example.com");
    expect(enrollment).toBeInstanceOf(Uint8Array);
    expect(Array.from(enrollment)).toEqual([0xca, 0xfe]);
  });

  it("updateList clears old entries before writing new ones", async () => {
    await db.updateList([fakeLeaf("old.com", [1])], { blockTime: 100 });
    await db.updateList([fakeLeaf("new.com", [2])], { blockTime: 200 });

    const oldEnrollment = await db.getFQDNEnrollment("old.com");
    expect(oldEnrollment.length).toBe(0);

    const newEnrollment = await db.getFQDNEnrollment("new.com");
    expect(Array.from(newEnrollment)).toEqual([2]);
  });

  it("stores and retrieves block meta", async () => {
    await db.updateList([fakeLeaf("example.com", [1])], { blockTime: 42 });

    const meta = await db.getBlockMeta();
    expect(meta).toEqual({ blockTime: 42 });
  });

  it("getBlockMeta returns null when storage is empty", async () => {
    const meta = await db.getBlockMeta();
    expect(meta).toBeNull();
  });

  it("getFQDNEnrollment returns empty Uint8Array for unknown fqdn", async () => {
    const result = await db.getFQDNEnrollment("nope.org");
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(0);
  });
});
