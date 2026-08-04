import { beforeEach, describe, expect, it, vi } from "vitest";

import { HookBuilder } from "../../src/webcat/hookbuilder";

vi.mock("../../dist/hooks/content.js?raw", () => ({
  default: `content {{ "__DATA_PLACEHOLDER__" }}`,
}));
vi.mock("../../dist/hooks/page.js?raw", () => ({
  default: `page {{ "__DATA_PLACEHOLDER__" }}`,
}));

const jwk = {
  alg: "A256GCM",
  ext: true,
  k: "wao3Q7TQ5qNH0NrtGT1eoNPiBJOwcGC3AJUfaQORigg",
  key_ops: ["encrypt", "decrypt"],
  kty: "oct",
};

vi.spyOn(crypto.subtle, "generateKey").mockImplementation(
  (
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: Iterable<KeyUsage>,
  ) => {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      algorithm,
      extractable,
      Array.from(keyUsages),
    );
  },
);

vi.spyOn(crypto, "getRandomValues").mockImplementation(
  (array: ArrayBufferView<ArrayBuffer>) => {
    new Uint8Array(array.buffer).fill(0);
    return array;
  },
);

class MockKVStore {
  get = vi.fn().mockImplementation(async () => {});
  set = vi.fn();
  clear = vi.fn();
  getKeys = vi.fn();
  remove = vi.fn();
}

describe("HookBuilder", () => {
  let store = new MockKVStore();
  let hb: HookBuilder;

  beforeEach(() => {
    store = new MockKVStore();
    hb = new HookBuilder(store);
  });

  it("should embed inputs into page hooks", async () => {
    await expect(
      hb.getPageHooks([], "https://example.com", false),
    ).resolves.toBe(
      `page {{ {"hashes":[],"firstParty":"egOLMfeVlE8w__HOJT410NMGCCxj67csTwNTCATLSv5O_a3Ff1Lb7Dk-MWpWzPM=","sameOriginWithFirstParty":false} }}`,
    );
    expect(store.set).toHaveBeenCalledWith(
      { firstPartySalt: new Uint8Array(256 / 8).fill(0) },
      "session",
    );
    expect(store.set).toHaveBeenCalledWith(
      { firstPartyKey: Uint8Array.fromBase64(jwk.k).buffer },
      "session",
    );
  });

  it("should embed inputs into content script hooks", async () => {
    await expect(
      hb.getContentScriptHooks([], "https://example.com", false),
    ).resolves.toStrictEqual([
      expect.any(Function),
      [
        '{"hashes":[],"firstParty":"egOLMfeVlE8w__HOJT410NMGCCxj67csTwNTCATLSv5O_a3Ff1Lb7Dk-MWpWzPM=","sameOriginWithFirstParty":false}',
      ],
    ]);
    expect(store.set).toHaveBeenCalledWith(
      { firstPartySalt: new Uint8Array(256 / 8).fill(0) },
      "session",
    );
    expect(store.set).toHaveBeenCalledWith(
      { firstPartyKey: Uint8Array.fromBase64(jwk.k).buffer },
      "session",
    );
  });

  it("should correctly decrypt a fragment", async () => {
    await expect(
      hb.decryptFragment(
        "https://webcat.tech/worker.js#egOLMfeVlE8w__HOJT410NMGCCxj67csTwNTCATLSv5O_a3Ff1Lb7Dk-MWpWzPM=",
      ),
    ).resolves.toBe("https://example.com");
    expect(store.set).toHaveBeenCalledWith(
      { firstPartySalt: new Uint8Array(256 / 8).fill(0) },
      "session",
    );
    expect(store.set).toHaveBeenCalledWith(
      { firstPartyKey: Uint8Array.fromBase64(jwk.k).buffer },
      "session",
    );
  });

  it("should use a stored key and salt", async () => {
    const store = new MockKVStore();
    store.get.mockImplementation(async (key: string) => {
      if (key === "firstPartyKey") {
        const value = new ArrayBuffer(256 / 8);
        new Uint8Array(value).fill(0);
        return value;
      } else if (key === "firstPartySalt") {
        const value = new ArrayBuffer(256 / 8);
        new Uint8Array(value).fill(1);
        return value;
      }
    });
    const hb = new HookBuilder(store);
    await expect(
      hb.getPageHooks([], "https://example.com", false),
    ).resolves.toBe(
      `page {{ {"hashes":[],"firstParty":"iUVA3nR8tTZvSXRqV_fxC0266M2ZQFFQkrup04pLjVLLm3WdeuUeCXmJXIv3uVc=","sameOriginWithFirstParty":false} }}`,
    );
    expect(store.set).not.toHaveBeenCalled();
  });
});
