// validateCSP.test.ts
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  enforceHTTPS,
  isSafeRelativeLocation,
  validateCSP,
  validateProtocolAndPort,
} from "../../src/webcat/validators";

// Mocks (unchanged)
vi.mock("../../src/webcat/logger", () => ({
  logger: {
    addLog: vi.fn(),
  },
}));

vi.mock("../../src/webcat/db", () => {
  return {
    WebcatDatabase: vi.fn().mockImplementation(() => ({
      getFQDNEnrollment: vi.fn(async (fqdn: string) => {
        if (fqdn === "trusted.com") {
          return new Uint8Array([0, 1, 2, 3]);
        }
        return new Uint8Array();
      }),

      getListCount: vi.fn(async () => 42),

      // Include other methods your test may call
      setLastChecked: vi.fn(),
      getLastChecked: vi.fn(async () => Date.now()),

      updateList: vi.fn(),
      setRootHash: vi.fn(),
      getRootHash: vi.fn(async () => "deadbeef"),
      setLastBlockHeight: vi.fn(),
      getLastBlockHeight: vi.fn(async () => 1337),
    })),
  };
});

describe("validateCSP", () => {
  let valid_sources: Set<string>;
  const trustedFQDN = "trusted.com";

  beforeEach(() => {
    valid_sources = new Set();
  });

  // Test 1: Pass when default-src is 'none' (other directives are not required)
  it("should pass when default-src is 'none' even if no other directives are provided", async () => {
    const csp = "default-src 'none'";
    await expect(
      validateCSP(csp, trustedFQDN, valid_sources),
    ).resolves.toBeUndefined();
  });

  // Test 2: Pass with default-src 'self' and all required directives valid
  it("should pass with default-src 'self' and valid script-src, style-src, object-src, child-src/frame-src, and worker-src", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self' 'sha256-def'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(
      validateCSP(csp, trustedFQDN, valid_sources),
    ).resolves.toBeUndefined();
  });

  // Test 3: Missing object-src when default-src is not 'none'
  it("should throw an error if object-src is missing when default-src is not 'none'", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      // object-src missing
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "default-src is not none, and object-src is not defined.",
    );
  });

  // Test 4: object-src is defined but not 'none'
  it("should throw an error if object-src is not 'none'", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'sha256-abc'",
      "style-src 'self'",
      "object-src 'self'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "Non-allowed object-src directive 'self'",
    );
  });

  // Test 5: Missing script-src when default-src is not 'none'
  it("should throw an error if script-src is missing", async () => {
    const csp = [
      "default-src 'self'",
      // script-src missing
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "default-src is not none, and script-src is not defined.",
    );
  });

  // Test 6: Missing style-src when default-src is not 'none'
  it("should throw an error if style-src is missing", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      // style-src missing
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "default-src is not none, and style-src is not defined.",
    );
  });

  // Test 7: Missing worker-src when default-src is not 'none'
  it("should throw an error if worker-src is missing", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      // worker-src missing
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "default-src is not none, and worker-src is not defined.",
    );
  });

  // Test 8: Missing both child-src and frame-src when default-src is not 'none'
  it("should throw an error if both child-src and frame-src are missing", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "object-src 'none'",
      "worker-src 'self'",
      // child-src and frame-src missing
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "default-src is not none, and neither frame-src or child-src are defined.",
    );
  });

  // Test 9: Invalid frame-src source (unallowed host without enrollment)
  it("should throw an error for an invalid frame-src source", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src evil.com",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "frame-src value evil.com, parsed as FQDN: evil.com is not enrolled and thus not allowed.",
    );
  });

  // Test 11: Invalid style-src source (non-enrolled and not a valid keyword/hash)
  /*
  it("should throw an error for an invalid style-src source", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src evil.com",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "style-src value evil.com, parsed as FQDN: evil.com is not enrolled and thus not allowed"
    );
  });
  */

  // Test 12: Valid style-src with an enrolled origin (commented out if enrollment is not required)
  /*
  it("should pass for style-src with an enrolled origin", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src trusted.com",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).resolves.toBeUndefined();
  });
  */

  // Test 13: Invalid child-src with an http: scheme
  it("should throw an error for child-src containing an http: source", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self' 'sha256-abc'",
      "object-src 'none'",
      "child-src http://evil.com",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "child-src value http://evil.com, parsed as FQDN: evil.com is not enrolled and thus not allowed.",
    );
  });

  // Test 14: Valid child-src with a blob: source
  it("should pass for child-src with a blob: source", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src blob:myblob",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(
      validateCSP(csp, trustedFQDN, valid_sources),
    ).resolves.toBeUndefined();
  });

  // Test 15: Invalid frame-src with a wildcard "*"
  it("should throw an error for frame-src containing a wildcard", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src *",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "frame-src cannot contain * which is unsupported.",
    );
  });

  // Test 16: Invalid script-src containing 'unsafe-inline'
  it("should throw an error for script-src containing 'unsafe-inline'", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "script-src cannot contain 'unsafe-inline' which is unsupported.",
    );
  });

  // Test 17: Valid style-src containing 'unsafe-inline'
  it("should pass for style-src containing 'unsafe-inline'", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(
      validateCSP(csp, trustedFQDN, valid_sources),
    ).resolves.toBeUndefined();
  });

  // Test 18: Valid script-src containing 'wasm-unsafe-eval'
  it("should pass for script-src containing 'wasm-unsafe-eval'", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(
      validateCSP(csp, trustedFQDN, valid_sources),
    ).resolves.toBeUndefined();
  });

  // Test 19: Valid style-src with a valid hash source
  it("should pass for style-src containing a valid hash", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'sha256-validhash'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(
      validateCSP(csp, trustedFQDN, valid_sources),
    ).resolves.toBeUndefined();
  });

  // Test 20: Non-enrolled child-src should throw (simulate non-enrollment)
  it("should throw an error for child-src with a non-enrolled origin", async () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src evil.com",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "child-src value evil.com, parsed as FQDN: evil.com is not enrolled and thus not allowed.",
    );
  });

  // Test 21: Blob in script-src
  it("should throw an error for a blob: in script-src", async () => {
    const csp = [
      "default-src 'self'",
      "script-src blob:",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    await expect(validateCSP(csp, trustedFQDN, valid_sources)).rejects.toThrow(
      "script-src cannot contain blob: which is unsupported.",
    );
  });
});

describe("validateProtocolAndPort", () => {
  it("allows https with default port", () => {
    const url = new URL("https://example.com");
    expect(validateProtocolAndPort(url)).toBe(true);
  });

  it("allows https with explicit port 443", () => {
    const url = new URL("https://example.com:443");
    expect(validateProtocolAndPort(url)).toBe(true);
  });

  it("allows http with default port", () => {
    const url = new URL("http://example.com");
    expect(validateProtocolAndPort(url)).toBe(true);
  });

  it("allows http with explicit port 80", () => {
    const url = new URL("http://example.com:80");
    expect(validateProtocolAndPort(url)).toBe(true);
  });

  it("rejects https with a non-standard port", () => {
    const url = new URL("https://example.com:8443");
    expect(validateProtocolAndPort(url)).toBe(false);
  });

  it("rejects http with a non-standard port", () => {
    const url = new URL("http://example.com:8080");
    expect(validateProtocolAndPort(url)).toBe(false);
  });

  it("rejects unsupported protocol (ftp)", () => {
    const url = new URL("ftp://example.com");
    expect(validateProtocolAndPort(url)).toBe(false);
  });

  it("rejects unsupported protocol (file)", () => {
    const url = new URL("file:///etc/passwd");
    expect(validateProtocolAndPort(url)).toBe(false);
  });

  it("rejects data: URLs", () => {
    const url = new URL("data:text/plain,hello");
    expect(validateProtocolAndPort(url)).toBe(false);
  });
});

describe("enforceHTTPS", () => {
  it("redirects http to https for normal domains", () => {
    const url = new URL("http://example.com/path");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBe("https://example.com/path");
    expect(url.protocol).toBe("https:");
  });

  it("does nothing for already-https URLs", () => {
    const url = new URL("https://example.com/path");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBeUndefined();
    expect(url.protocol).toBe("https:");
  });

  it("does not redirect .onion domains", () => {
    const url = new URL("http://example.onion/path");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBeUndefined();
    expect(url.protocol).toBe("http:");
  });

  it("handles localhost correctly (redirects to https)", () => {
    const url = new URL("http://localhost:8080/path");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBe("https://localhost:8080/path");
    expect(url.protocol).toBe("https:");
  });

  it("handles subdomains correctly", () => {
    const url = new URL("http://a.b.c.example.com/");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBe("https://a.b.c.example.com/");
  });

  it("is idempotent when called twice", () => {
    const url = new URL("http://example.com/");
    const first = enforceHTTPS(url);
    const second = enforceHTTPS(url);

    expect(first).toBe("https://example.com/");
    expect(second).toBeUndefined();
    expect(url.protocol).toBe("https:");
  });
});

describe("isSafeRelativeLocation", () => {
  it("allows absolute-path relative locations", () => {
    expect(isSafeRelativeLocation("/")).toBe(true);
    expect(isSafeRelativeLocation("/login")).toBe(true);
    expect(isSafeRelativeLocation("/a/b/c")).toBe(true);
  });

  it("allows parent-relative paths", () => {
    expect(isSafeRelativeLocation("../login")).toBe(true);
    expect(isSafeRelativeLocation("../a/b")).toBe(true);
  });

  it("allows same-relative paths", () => {
    expect(isSafeRelativeLocation("./login")).toBe(true);
  });

  it("trims whitespace before validation", () => {
    expect(isSafeRelativeLocation(" /login ")).toBe(true);
    expect(isSafeRelativeLocation("  ../login")).toBe(true);
  });

  it("rejects protocol-relative URLs", () => {
    expect(isSafeRelativeLocation("//evil.com")).toBe(false);
    expect(isSafeRelativeLocation("///evil.com")).toBe(false);
  });

  it("rejects absolute URLs with schemes", () => {
    expect(isSafeRelativeLocation("https://evil.com")).toBe(false);
    expect(isSafeRelativeLocation("http://evil.com")).toBe(false);
    expect(isSafeRelativeLocation("ftp://evil.com")).toBe(false);
    expect(isSafeRelativeLocation("javascript:alert(1)")).toBe(false);
    expect(isSafeRelativeLocation("blob:abcd")).toBe(false);
    expect(isSafeRelativeLocation("data:text/plain,hi")).toBe(false);
  });

  it("rejects backslash-based paths", () => {
    expect(isSafeRelativeLocation("\\evil.com")).toBe(false);
    expect(isSafeRelativeLocation("/\\evil.com")).toBe(false);
    expect(isSafeRelativeLocation("\\\\evil.com")).toBe(false);
  });

  it("rejects bare relative paths", () => {
    expect(isSafeRelativeLocation("login")).toBe(false);
  });

  it("allows encoded slashes (no decoding is performed)", () => {
    expect(isSafeRelativeLocation("/%2f%2fevil.com")).toBe(true);
    expect(isSafeRelativeLocation("%2f%2fevil.com")).toBe(false);
  });

  it("allows control characters (current behavior)", () => {
    expect(isSafeRelativeLocation("/foo\nbar")).toBe(true);
    expect(isSafeRelativeLocation("/foo\rbar")).toBe(true);
    expect(isSafeRelativeLocation("/foo\tbar")).toBe(true);
  });
});
