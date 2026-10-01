// validateCSP.test.ts
import { describe, expect, it, vi } from "vitest";

// No browser/permissions mock: validators must load without a `browser`
// global so tooling (e.g. webcat-cli) can import them.
import { Manifest } from "../../src/webcat/interfaces/bundle";
import { WebcatErrorCode } from "../../src/webcat/interfaces/errors";
import { validateCSP, validateManifest } from "../../src/webcat/validators";

// Mocks (unchanged)
vi.mock("../../src/webcat/logger", () => ({
  logger: {
    addLog: vi.fn(),
  },
}));

describe("validateCSP", () => {
  // Test 1: Pass when default-src is 'none' (other directives are not required)
  it("should pass when default-src is 'none' even if no other directives are provided", () => {
    const csp = "default-src 'none'";
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 2: Pass with default-src 'self' and all required directives valid
  it("should pass with default-src 'self' and valid script-src, style-src, object-src, child-src/frame-src, and worker-src", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self' 'sha256-def'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 3: Missing object-src when default-src is not 'none'
  it("should throw an error if object-src is missing when default-src is not 'none'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      // object-src missing
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and object-src is not defined.",
    );
  });

  // Test 4: object-src is defined but not 'none'
  it("should throw an error if object-src is not 'none'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'sha256-abc'",
      "style-src 'self'",
      "object-src 'self'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "Non-allowed object-src directive 'self'",
    );
  });

  // Test 5: Missing script-src when default-src is not 'none'
  it("should throw an error if script-src is missing", () => {
    const csp = [
      "default-src 'self'",
      // script-src missing
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and script-src is not defined.",
    );
  });

  // Test 6: Missing style-src when default-src is not 'none'
  it("should throw an error if style-src is missing", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      // style-src missing
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and style-src is not defined.",
    );
  });

  // Test 7: Missing worker-src when default-src is not 'none'
  it("should throw an error if worker-src is missing", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      // worker-src missing
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and worker-src is not defined.",
    );
  });

  // Test 8: frame-src and child-src are not restricted
  it("does not restrict frame-src or child-src", () => {
    const base = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "worker-src 'self'",
    ];
    for (const frames of [
      [],
      ["frame-src evil.com"],
      ["child-src http://evil.com", "frame-src 'self'"],
      ["child-src 'self'", "frame-src *"],
    ]) {
      const csp = [...base, ...frames].join("; ");
      expect(validateCSP(csp)).toBeUndefined();
    }
  });

  // Test 11: style-src never allows host sources, enrolled or not
  it("should throw for any style-src host source", () => {
    for (const host of ["evil.com", "https://trusted.com"]) {
      const csp = [
        "default-src 'self'",
        "script-src 'self'",
        `style-src ${host}`,
        "object-src 'none'",
        "worker-src 'self'",
      ].join("; ");
      expect(() => validateCSP(csp)).toThrow(
        `style-src cannot contain ${host} which is unsupported`,
      );
    }
  });

  // Test 14: Valid child-src with a blob: source
  it("should pass for child-src with a blob: source", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src blob:myblob",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 16: Invalid script-src containing 'unsafe-inline'
  it("should throw an error for script-src containing 'unsafe-inline'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "script-src cannot contain 'unsafe-inline' which is unsupported.",
    );
  });

  // Test 17: Valid style-src containing 'unsafe-inline'
  it("should pass for style-src containing 'unsafe-inline'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 18: Valid script-src containing 'wasm-unsafe-eval'
  it("should pass for script-src containing 'wasm-unsafe-eval'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 19: Valid style-src with a valid hash source
  it("should pass for style-src containing a valid hash", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'sha256-validhash'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 21: Blob in script-src
  it("should throw an error for a blob: in script-src", () => {
    const csp = [
      "default-src 'self'",
      "script-src blob:",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "script-src cannot contain blob: which is unsupported.",
    );
  });

  // See https://github.com/freedomofpress/webcat/issues/99
  it("should throw when default-src contains 'none' and 'self' and object-src is missing", () => {
    const csp = [
      "default-src 'none' 'self'",
      "script-src 'self'",
      "style-src 'self'",
      // object-src missing
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");

    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and object-src is not defined.",
    );
  });

  // See https://github.com/freedomofpress/webcat/issues/101
  it("should throw when CSP contains a comma (multiple policies)", () => {
    const csp = "script-src 'unsafe-eval', script-src 'self'";

    expect(() => validateCSP(csp)).toThrow("CSP contains a comma");
  });

  it("should throw when a valid CSP is followed by a comma and garbage", () => {
    const csp =
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "object-src 'none'",
        "worker-src 'self'",
      ].join("; ") + ", @invalid-policy";

    expect(() => validateCSP(csp)).toThrow("CSP contains a comma");
  });
});

describe("validateManifest", () => {
  const manifest: Manifest = {
    name: "app",
    version: "1.0.0",
    default_csp: "default-src 'self'",
    extra_csp: {},
    default_index: "index.html",
    default_fallback: "/index.html",
    files: { "/index.html": "oUTcA3p3Jmt-YJG7Ium44fhAOOTHs-WMiJwWQH4_D8g" },
    wasm: [],
  };

  it("accepts base64url SHA-256 file hashes", () => {
    expect(validateManifest(manifest)).toBeNull();
  });

  it("rejects file hashes that are not base64url SHA-256 digests", () => {
    for (const hash of [
      "",
      "not base64url!",
      "a".repeat(64),
      "YQ==",
      // Non-canonical: the same digest with non-zero padding bits
      "oUTcA3p3Jmt-YJG7Ium44fhAOOTHs-WMiJwWQH4_D8h",
    ]) {
      const files = { ...manifest.files, "/x.js": hash };
      expect(validateManifest({ ...manifest, files })?.code).toBe(
        WebcatErrorCode.Manifest.FILES_MALFORMED,
      );
    }
  });
});
