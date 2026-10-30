import { describe, expect, it } from "vitest";

import {
  EnrollmentTypes,
  Manifest,
  SigstoreEnrollment,
  SigsumEnrollment,
} from "../../src/webcat/interfaces/bundle";
import { WebcatErrorCode } from "../../src/webcat/interfaces/errors";
import { Schema, validate } from "../../src/webcat/schema";
import {
  validateManifest,
  validateSigstoreEnrollment,
  validateSigsumEnrollment,
} from "../../src/webcat/validators";

const HASH = "oUTcA3p3Jmt-YJG7Ium44fhAOOTHs-WMiJwWQH4_D8g";

const manifest: Manifest = {
  version: "1.0.0",
  default_csp: "default-src 'self'",
  extra_csp: {},
  files: { "/": HASH, "/index.html": HASH },
  wasm: [],
};

const sigsum: SigsumEnrollment = {
  type: EnrollmentTypes.Sigsum,
  signers: ["c2lnbmVyMQ"],
  threshold: 1,
  policy: "c29tZS1zaWdzdW0tcG9saWN5",
  max_age: 3600,
  logs: { log: "https://log.example" },
};

const sigstore: SigstoreEnrollment = {
  type: EnrollmentTypes.Sigstore,
  trusted_root: {} as SigstoreEnrollment["trusted_root"],
  claims: { "2.5.29.17": "alice@example.com" },
  max_age: 3600,
};

describe("manifest schema", () => {
  it("accepts a legacy manifest with the deprecated fields and ignores version 1 fields on it", () => {
    expect(
      validateManifest({
        ...manifest,
        app: "https://app",
        default_index: "index.html",
        default_fallback: "/index.html",
      }),
    ).toBeNull();
    for (const field of ["fallback_hashes", "source", "artifact"]) {
      expect(validateManifest({ ...manifest, [field]: 5 })).toBeNull();
    }
  });

  it("rejects a legacy fallback that is not one of the files", () => {
    for (const legacy of [
      { ...manifest, app: "https://app", default_fallback: "/missing.html" },
      { ...manifest, app: "https://app", default_fallback: 5 },
      { ...manifest, app: "https://app", default_index: 5 },
    ] as unknown as Manifest[]) {
      expect(validateManifest(legacy)?.code).toBe(
        WebcatErrorCode.Manifest.FALLBACK_HASHES_MALFORMED,
      );
    }
  });

  it("accepts a version 1 manifest", () => {
    expect(
      validateManifest({
        ...manifest,
        manifest_schema: 1,
        source: "https://git",
        artifact: "https://x/${version}.tgz",
      }),
    ).toBeNull();
  });

  it("ignores the deprecated fields on a version 1 manifest, even malformed", () => {
    for (const field of ["app", "default_index", "default_fallback"]) {
      expect(
        validateManifest({ ...manifest, manifest_schema: 1, [field]: 5 }),
      ).toBeNull();
    }
  });

  it("tells a malformed schema version from one newer than supported", () => {
    const withSchema = (manifest_schema: unknown) =>
      validateManifest({ ...manifest, manifest_schema } as unknown as Manifest)
        ?.code;
    for (const v of [0, -1, 1.5, "1", null]) {
      expect(withSchema(v)).toBe(WebcatErrorCode.Manifest.SCHEMA_INVALID);
    }
    for (const v of [2, 3, 100]) {
      expect(withSchema(v)).toBe(WebcatErrorCode.Manifest.SCHEMA_UNSUPPORTED);
    }
  });

  it("rejects a manifest older than the configured minimum, after its own checks", () => {
    const error = validateManifest(manifest, 1);
    expect(error?.code).toBe(WebcatErrorCode.Manifest.SCHEMA_DEPRECATED);
    expect(error?.details).toEqual(["0", "1"]);
    expect(validateManifest({ ...manifest, manifest_schema: 1 }, 1)).toBeNull();
    // Malformed fields and versions are reported before the minimum.
    expect(validateManifest({ ...manifest, files: {} }, 1)?.code).toBe(
      WebcatErrorCode.Manifest.FILES_MISSING,
    );
    expect(
      validateManifest(
        { ...manifest, manifest_schema: 0 } as unknown as Manifest,
        1,
      )?.code,
    ).toBe(WebcatErrorCode.Manifest.SCHEMA_INVALID);
  });

  it("rejects provenance fields that are not strings", () => {
    expect(
      validateManifest({
        ...manifest,
        manifest_schema: 1,
        source: 1,
      } as unknown as Manifest)?.code,
    ).toBe(WebcatErrorCode.Manifest.PROVENANCE_MALFORMED);
  });

  it("keeps the check order: files before default_csp before wasm", () => {
    const empty = {
      ...manifest,
      files: {},
      default_csp: "",
      wasm: undefined,
    } as unknown as Manifest;
    expect(validateManifest(empty)?.code).toBe(
      WebcatErrorCode.Manifest.FILES_MISSING,
    );
    expect(validateManifest({ ...empty, files: manifest.files })?.code).toBe(
      WebcatErrorCode.Manifest.DEFAULT_CSP_MISSING,
    );
    expect(
      validateManifest({ ...empty, files: manifest.files, default_csp: "x" })
        ?.code,
    ).toBe(WebcatErrorCode.Manifest.WASM_MISSING);
  });
});

describe("enrollment schemas", () => {
  it("accepts legacy and version 1 Sigsum enrollments", () => {
    expect(
      validateSigsumEnrollment({ ...sigsum, cas_url: "https://cas" }),
    ).toBeNull();
    expect(
      validateSigsumEnrollment({ ...sigsum, enrollment_schema: 1 }),
    ).toBeNull();
  });

  it("ignores cas_url on a version 1 Sigsum enrollment", () => {
    expect(
      validateSigsumEnrollment({
        ...sigsum,
        enrollment_schema: 1,
        cas_url: "https://cas",
      }),
    ).toBeNull();
  });

  it("tells a malformed enrollment schema from one newer than supported", () => {
    const withSchema = (enrollment_schema: unknown) =>
      validateSigstoreEnrollment({
        ...sigstore,
        enrollment_schema,
      } as unknown as SigstoreEnrollment)?.code;
    expect(withSchema("1")).toBe(WebcatErrorCode.Enrollment.SCHEMA_INVALID);
    expect(withSchema(2)).toBe(WebcatErrorCode.Enrollment.SCHEMA_UNSUPPORTED);
  });

  it("rejects an enrollment older than the configured minimum", () => {
    expect(validateSigsumEnrollment(sigsum, 1)?.code).toBe(
      WebcatErrorCode.Enrollment.SCHEMA_DEPRECATED,
    );
    expect(validateSigstoreEnrollment(sigstore, 1)?.code).toBe(
      WebcatErrorCode.Enrollment.SCHEMA_DEPRECATED,
    );
    expect(
      validateSigsumEnrollment({ ...sigsum, enrollment_schema: 1 }, 1),
    ).toBeNull();
  });

  it("names the first malformed signer and claim", () => {
    expect(
      validateSigsumEnrollment({
        ...sigsum,
        signers: ["ok", 5],
      } as unknown as SigsumEnrollment)?.details,
    ).toEqual(["5"]);
    expect(
      validateSigstoreEnrollment({ ...sigstore, claims: { a: "x", b: "" } })
        ?.details,
    ).toEqual(["b"]);
  });
});

describe("validate", () => {
  type Doc = { s?: number; a?: string; b?: string };
  const schema: Schema<Doc> = {
    field: "s",
    deprecated: WebcatErrorCode.Manifest.SCHEMA_DEPRECATED,
    rules: [
      {
        field: "s",
        test: (v) => v === undefined || v === 1,
        error: WebcatErrorCode.Manifest.SCHEMA_INVALID,
      },
      {
        field: "a",
        schema: [1],
        test: (v) => typeof v === "string",
        error: WebcatErrorCode.Manifest.FILES_MISSING,
      },
      {
        field: "b",
        schema: [0],
        test: () => true,
        error: WebcatErrorCode.Manifest.FILES_MISSING,
      },
    ],
  };

  it("applies a rule only to the versions it names and ignores the field elsewhere", () => {
    expect(validate({ a: "x" }, schema)).toBeNull();
    expect(validate({ s: 1 }, schema)?.code).toBe(
      WebcatErrorCode.Manifest.FILES_MISSING,
    );
    expect(validate({ s: 1, a: "x" }, schema)).toBeNull();
    expect(validate({ s: 1, a: "x", b: "y" }, schema)).toBeNull();
    expect(validate({ b: "y" }, schema)).toBeNull();
  });
});

// A synthetic document with three schema versions.
describe("validate across schema versions", () => {
  type Doc = {
    s?: number;
    kept?: string;
    added?: string;
    retired?: string;
    old_name?: string;
    new_name?: string;
    required?: string;
    gone?: string;
    pair_a?: number;
    pair_b?: number;
  };
  const { Manifest: M } = WebcatErrorCode;
  const schema: Schema<Doc> = {
    field: "s",
    deprecated: M.SCHEMA_DEPRECATED,
    rules: [
      // First, so nothing else runs on a bad version; then the version ceiling.
      {
        field: "s",
        test: (v) =>
          v === undefined || (Number.isInteger(v) && (v as number) >= 1),
        error: M.SCHEMA_INVALID,
      },
      {
        field: "s",
        test: (v) => v === undefined || (v as number) <= 2,
        error: M.SCHEMA_UNSUPPORTED,
      },
      // No `schema`: the field exists in every version.
      {
        field: "kept",
        test: (v) => v === undefined || typeof v === "string",
        error: M.FILES_MALFORMED,
      },
      // Introduced in version 2.
      {
        field: "added",
        schema: [2],
        test: (v) => v === undefined || typeof v === "string",
        error: M.FILES_MALFORMED,
      },
      // Retired after version 1.
      {
        field: "retired",
        schema: [0, 1],
        test: () => true,
        error: M.FILES_MALFORMED,
      },
      // Renamed in version 2: both names are rows, each in its versions.
      {
        field: "old_name",
        schema: [0, 1],
        test: () => true,
        error: M.FILES_MALFORMED,
      },
      {
        field: "new_name",
        schema: [2],
        test: () => true,
        error: M.FILES_MALFORMED,
      },
      // Required from version 1.
      {
        field: "required",
        schema: [1, 2],
        test: (v) => typeof v === "string",
        error: M.DEFAULT_CSP_MISSING,
      },
      // Validated in no version: whatever it holds is ignored.
      {
        field: "gone",
        schema: [],
        test: () => false,
        error: M.FILES_MALFORMED,
      },
      // A cross-field invariant reads the whole document.
      {
        test: (_, d) => d.pair_a === undefined || d.pair_b !== undefined,
        error: M.WASM_MISSING,
        detail: (_, d) => [String(d.pair_a)],
      },
    ],
  };
  const v0: Doc = {};
  const v1: Doc = { s: 1, required: "x" };
  const v2: Doc = { s: 2, required: "x" };

  it("accepts each version's own field set", () => {
    expect(
      validate({ ...v0, kept: "k", retired: "r", old_name: "o" }, schema),
    ).toBeNull();
    expect(
      validate({ ...v1, kept: "k", retired: "r", old_name: "o" }, schema),
    ).toBeNull();
    expect(
      validate({ ...v2, kept: "k", added: "a", new_name: "n" }, schema),
    ).toBeNull();
  });

  it("ignores a field that belongs to another version, even malformed", () => {
    expect(
      validate({ ...v0, added: 5 as unknown as string }, schema),
    ).toBeNull();
    expect(validate({ ...v1, new_name: "n" }, schema)).toBeNull();
    expect(validate({ ...v2, retired: "r", old_name: "o" }, schema)).toBeNull();
    for (const doc of [v0, v1, v2]) {
      expect(validate({ ...doc, gone: "g" }, schema)).toBeNull();
    }
  });

  it("treats a required field as absent when missing, and null as present", () => {
    expect(validate({ s: 1 }, schema)?.code).toBe(M.DEFAULT_CSP_MISSING);
    expect(
      validate({ ...v2, kept: null as unknown as string }, schema)?.code,
    ).toBe(M.FILES_MALFORMED);
    // JSON cannot carry undefined; an explicit one counts as absent.
    expect(validate({ ...v2, kept: undefined }, schema)).toBeNull();
  });

  it("rejects a malformed version, and a newer one distinctly, before any gated row runs", () => {
    for (const s of [0, "1", null, 1.5]) {
      expect(
        validate({ s: s as number, added: 5 as unknown as string }, schema)
          ?.code,
      ).toBe(M.SCHEMA_INVALID);
    }
    expect(
      validate({ s: 3, added: 5 as unknown as string }, schema)?.code,
    ).toBe(M.SCHEMA_UNSUPPORTED);
  });

  it("deprecates a valid document below the minimum version", () => {
    expect(validate(v1, schema, 2)?.code).toBe(M.SCHEMA_DEPRECATED);
    expect(validate(v1, schema, 2)?.details).toEqual(["1", "2"]);
    expect(validate(v0, schema, 1)?.details).toEqual(["0", "1"]);
    expect(validate(v2, schema, 2)).toBeNull();
    expect(validate(v1, schema, 1)).toBeNull();
  });

  it("ignores fields no row mentions", () => {
    for (const doc of [v0, v1, v2]) {
      expect(validate({ ...doc, future: true } as Doc, schema)).toBeNull();
    }
  });

  it("reports the first failing row in table order with its details", () => {
    // kept fails before the invariant.
    expect(
      validate({ ...v2, kept: 5 as unknown as string, pair_a: 1 }, schema)
        ?.code,
    ).toBe(M.FILES_MALFORMED);
    const error = validate({ ...v2, pair_a: 7 }, schema);
    expect(error?.code).toBe(M.WASM_MISSING);
    expect(error?.details).toEqual(["7"]);
    expect(validate({ ...v2, pair_a: 7, pair_b: 8 }, schema)).toBeNull();
  });
});
