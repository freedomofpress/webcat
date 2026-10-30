import {
  canonicalizeJCS,
  canonicalizeOLPC,
} from "@freedomofpress/crypto-browser";
import { describe, expect, it } from "vitest";

import { canonicalForm, hasSchema } from "../../src/webcat/canonicalize";

describe("canonicalForm", () => {
  // A Sigsum tree head carries raw newlines, where OLPC and JCS differ.
  const legacy = { timestamp: "tree_size 1\nroot_hash aa", files: {} };

  it("uses OLPC for a manifest without a schema field", () => {
    expect(hasSchema(legacy)).toBe(false);
    expect(canonicalForm(legacy)).toBe(canonicalizeOLPC(legacy));
    expect(canonicalForm(legacy)).not.toBe(canonicalizeJCS(legacy));
  });

  it("uses JCS for a manifest with manifest_schema, whatever other fields it carries", () => {
    const versioned = { ...legacy, manifest_schema: 1 };
    expect(hasSchema(versioned)).toBe(true);
    expect(canonicalForm(versioned)).toBe(canonicalizeJCS(versioned));
    // Only the manifest's own field counts.
    const stray = { ...legacy, enrollment_schema: 1 };
    expect(hasSchema(stray)).toBe(false);
    expect(canonicalForm(stray)).toBe(canonicalizeOLPC(stray));
  });

  it("throws for a document the chosen dialect cannot encode", () => {
    // OLPC has no floats; a versioned document with one encodes under JCS.
    expect(() => canonicalForm({ n: 1.5 })).toThrow();
    expect(canonicalForm({ manifest_schema: 1, n: 1.5 })).toBe(
      '{"manifest_schema":1,"n":1.5}',
    );
  });
});
