import { beforeEach, describe, expect, it, vi } from "vitest";

import { HookBuilder } from "../../src/webcat/hookbuilder";

vi.mock("../../dist/hooks/content.js?raw", () => ({
  default: `content {{ "__DATA_PLACEHOLDER__" }}`,
}));
vi.mock("../../dist/hooks/page.js?raw", () => ({
  default: `page {{ "__DATA_PLACEHOLDER__" }}`,
}));

vi.spyOn(crypto.subtle, "generateKey").mockImplementation(
  (
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: Iterable<KeyUsage>,
  ) => {
    return crypto.subtle.importKey(
      "jwk",
      {
        alg: "A256GCM",
        ext: true,
        k: "wao3Q7TQ5qNH0NrtGT1eoNPiBJOwcGC3AJUfaQORigg",
        key_ops: ["encrypt", "decrypt"],
        kty: "oct",
      },
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

describe("HookBuilder", () => {
  let hb: HookBuilder;

  beforeEach(() => {
    hb = new HookBuilder();
  });

  it("should embed inputs into page hooks", async () => {
    await expect(
      hb.getPageHooks([], "https://example.com", false),
    ).resolves.toBe(
      `page {{ {"hashes":[],"firstParty":"egOLMfeVlE8w__HOJT410NMGCCxj67csTwNTCATLSv5O_a3Ff1Lb7Dk-MWpWzPM=","sameOriginWithFirstParty":false} }}`,
    );
  });

  it("should embed inputs into content script hooks", async () => {
    await expect(
      hb.getContentScriptHooks([], "https://example.com", false),
    ).resolves.toBe(
      `content {{ {"hashes":[],"firstParty":"egOLMfeVlE8w__HOJT410NMGCCxj67csTwNTCATLSv5O_a3Ff1Lb7Dk-MWpWzPM=","sameOriginWithFirstParty":false} }}`,
    );
  });

  it("should correctly decrypt a fragment", async () => {
    await expect(
      hb.decryptFragment(
        "https://webcat.tech/worker.js#egOLMfeVlE8w__HOJT410NMGCCxj67csTwNTCATLSv5O_a3Ff1Lb7Dk-MWpWzPM=",
      ),
    ).resolves.toBe("https://example.com");
  });
});
