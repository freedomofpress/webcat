import { describe, expect, it } from "vitest";

import { canonicalize } from "../../src/webcat/canonicalize";
import { stringToUint8Array, Uint8ArrayToHex } from "../../src/webcat/encoding";
// Vectors from webcat-spec/vectors/canonical-json.json (server.md §1.0),
// generated with the olpc-cjson crate the enrollment chain hashes with.
import fixture from "./fixtures/canonical-json.json";

type Vector = {
  name: string;
  input: unknown;
  canonical_hex?: string;
  sha256?: string;
  error?: boolean;
};

describe("canonicalize matches the spec vectors", () => {
  for (const v of fixture.vectors as Vector[]) {
    it(v.name, async () => {
      const out = canonicalize(v.input);
      if (v.error) {
        expect(out).toBeNull();
        return;
      }
      expect(out).not.toBeNull();
      const bytes = stringToUint8Array(out as string);
      expect(Uint8ArrayToHex(bytes)).toBe(v.canonical_hex);
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      expect(Uint8ArrayToHex(new Uint8Array(digest))).toBe(v.sha256);
    });
  }
});
