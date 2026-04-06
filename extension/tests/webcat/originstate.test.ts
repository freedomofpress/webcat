/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { beforeEach, describe, expect, it, vi } from "vitest";

import { canonicalize } from "../../src/webcat/canonicalize";
import { stringToUint8Array } from "../../src/webcat/encoding";
import type {
  Bundle,
  Enrollment,
  Manifest,
  SigsumSignatures,
} from "../../src/webcat/interfaces/bundle";
import { EnrollmentTypes } from "../../src/webcat/interfaces/bundle";
import {
  WebcatError,
  WebcatErrorCode,
} from "../../src/webcat/interfaces/errors";
import {
  BundleFetcher,
  OriginStateFailed,
  OriginStateInitial,
  OriginStateVerifiedEnrollment,
  OriginStateVerifiedManifest,
} from "../../src/webcat/interfaces/originstate";
import { SHA256 } from "../../src/webcat/utils";

// --- Mocks ---
// Prevent real fetch calls from BundleFetcher constructor
vi.stubGlobal(
  "fetch",
  vi.fn(() => Promise.resolve({ ok: false, status: 0 })),
);

vi.stubGlobal("browser", {
  browsingData: {
    remove: vi.fn().mockResolvedValue(undefined),
  },
  webRequest: {
    onBeforeRequest: { removeListener: vi.fn() },
    onHeadersReceived: { removeListener: vi.fn() },
  },
});

vi.mock("../../src/webcat/db", () => ({
  WebcatDatabase: vi.fn().mockImplementation(() => ({
    getFQDNEnrollment: vi.fn(async (fqdn: string) => {
      if (fqdn === "trusted.com") return new Uint8Array([0, 1, 2, 3]);
      if (fqdn === "delegated.com") return new Uint8Array([0, 1, 2, 3]);
      return new Uint8Array();
    }),
    getListCount: vi.fn(async () => 42),
    setLastChecked: vi.fn(),
    getLastChecked: vi.fn(async () => Date.now()),
    updateList: vi.fn(),
    setRootHash: vi.fn(),
    getRootHash: vi.fn(async () => "deadbeef"),
    setLastBlockHeight: vi.fn(),
    getLastBlockHeight: vi.fn(async () => 1337),
  })),
}));

vi.mock("../../src/webcat/validators", async () => {
  const actual = await vi.importActual<
    typeof import("../../src/webcat/validators")
  >("../../src/webcat/validators");
  const defaultNow = Math.floor(Date.now() / 1000);
  return {
    ...actual,
    validateCSP: vi.fn(async () => {}),
    witnessTimestampsFromCosignedTreeHead: vi.fn(async () => [
      defaultNow - 5000,
      defaultNow - 100000,
      defaultNow - 200000,
    ]),
    verifySigsumManifest: vi.fn(async () => null),
    verifySigstoreManifest: vi.fn(async () => null),
  };
});

async function computeEnrollmentHash(
  enrollment: Enrollment,
): Promise<Uint8Array> {
  const canonical = canonicalize(enrollment);
  const bytes = stringToUint8Array(canonical);
  const digest = await SHA256(bytes);
  return digest instanceof Uint8Array ? digest : new Uint8Array(digest);
}

const SIGNER1 = "c2lnbmVyMQ";
const SIGNER2 = "c2lnbmVyMg";
const TEST_POLICY = "c29tZS1zaWdzdW0tcG9saWN5";

function makeEnrollment(overrides = {}): Enrollment {
  return {
    type: EnrollmentTypes.Sigsum,
    policy: TEST_POLICY,
    signers: [SIGNER1, SIGNER2],
    threshold: 1,
    max_age: 360000,
    cas_url: "https://cas.example.com",
    logs: { log1: "https://log.example.com" },
    ...overrides,
  } as Enrollment;
}

function makeManifest(overrides = {}): Manifest {
  return {
    name: "test-app",
    version: "1.0.0",
    default_csp:
      "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'",
    extra_csp: {},
    default_index: "index.html",
    default_fallback: "/index.html",
    timestamp: new Date().toISOString(),
    files: { "/index.html": "hash1" },
    wasm: [],
    ...overrides,
  };
}

// ─────────────────────────────────────────────
//  BundleFetcher
// ─────────────────────────────────────────────
describe("BundleFetcher", () => {
  it("is iterable and yields current then previous", () => {
    const fetcher = new BundleFetcher("https://example.com");
    const items = [...fetcher];
    expect(items.length).toBe(2);
    expect(items[0]).toBe(fetcher.current);
    expect(items[1]).toBe(fetcher.previous);
  });

  it("sets FETCH_ERROR when fetch rejects", async () => {
    const fetcher = new BundleFetcher("https://example.com");
    // Override promises with rejections
    (fetcher as any).current.promise = Promise.reject(new Error("network"));
    (fetcher as any).previous.promise = Promise.reject(new Error("network"));

    await fetcher.awaitAll();

    expect(fetcher.current.error).toBeDefined();
    expect(fetcher.current.error!.code).toBe(WebcatErrorCode.Fetch.FETCH_ERROR);
    expect(fetcher.previous.error).toBeDefined();
  });

  it("sets FETCH_ERROR when response is not ok", async () => {
    const fetcher = new BundleFetcher("https://example.com");
    (fetcher as any).current.promise = Promise.resolve({
      ok: false,
      status: 404,
    });
    (fetcher as any).previous.promise = Promise.resolve({
      ok: false,
      status: 500,
    });

    await fetcher.awaitAll();

    expect(fetcher.current.error!.code).toBe(WebcatErrorCode.Fetch.FETCH_ERROR);
  });

  it("sets MALFORMED when response JSON is invalid", async () => {
    const fetcher = new BundleFetcher("https://example.com");
    (fetcher as any).current.promise = Promise.resolve({
      ok: true,
      json: () => Promise.reject(new SyntaxError("bad json")),
    });
    (fetcher as any).previous.promise = Promise.resolve({
      ok: true,
      json: () => Promise.reject(new SyntaxError("bad json")),
    });

    await fetcher.awaitAll();

    expect(fetcher.current.error!.code).toBe(WebcatErrorCode.Bundle.MALFORMED);
  });

  it("sets ENROLLMENT_MISSING when bundle lacks enrollment", async () => {
    const fetcher = new BundleFetcher("https://example.com");
    (fetcher as any).current.promise = Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ manifest: {}, signatures: {} }),
    });
    (fetcher as any).previous.promise = Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ manifest: {}, signatures: {} }),
    });

    await fetcher.awaitAll();

    expect(fetcher.current.error!.code).toBe(
      WebcatErrorCode.Bundle.ENROLLMENT_MISSING,
    );
  });

  it("sets MANIFEST_MISSING when bundle lacks manifest", async () => {
    const fetcher = new BundleFetcher("https://example.com");
    (fetcher as any).current.promise = Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ enrollment: {}, signatures: {} }),
    });
    (fetcher as any).previous.promise = Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ enrollment: {} }),
    });

    await fetcher.awaitAll();

    expect(fetcher.current.error!.code).toBe(
      WebcatErrorCode.Bundle.MANIFEST_MISSING,
    );
  });

  it("sets SIGNATURES_MISSING when bundle lacks signatures", async () => {
    const fetcher = new BundleFetcher("https://example.com");
    (fetcher as any).current.promise = Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ enrollment: {}, manifest: {} }),
    });
    (fetcher as any).previous.promise = Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ enrollment: {}, manifest: {} }),
    });

    await fetcher.awaitAll();

    expect(fetcher.current.error!.code).toBe(
      WebcatErrorCode.Bundle.SIGNATURES_MISSING,
    );
  });

  it("populates value when bundle is well-formed", async () => {
    const bundle: Bundle = {
      enrollment: makeEnrollment(),
      manifest: makeManifest(),
      signatures: { [SIGNER1]: "sig1" },
    };
    const fetcher = new BundleFetcher("https://example.com");
    (fetcher as any).current.promise = Promise.resolve({
      ok: true,
      json: () => Promise.resolve(bundle),
    });
    (fetcher as any).previous.promise = Promise.resolve({
      ok: true,
      json: () => Promise.resolve(bundle),
    });

    await fetcher.awaitAll();

    expect(fetcher.current.value).toEqual(bundle);
    expect(fetcher.current.error).toBeUndefined();
  });

  it("skips slots that already have value or error", async () => {
    const fetcher = new BundleFetcher("https://example.com");
    fetcher.current.value = {
      enrollment: makeEnrollment(),
      manifest: makeManifest(),
      signatures: {},
    };
    fetcher.previous.error = new WebcatError(WebcatErrorCode.Fetch.FETCH_ERROR);

    // Suppress the original fetch promises to avoid unhandled rejections
    (fetcher as any).current.promise.catch(() => {});
    (fetcher as any).previous.promise.catch(() => {});

    await fetcher.awaitAll();

    // Should remain unchanged
    expect(fetcher.current.value).toBeDefined();
    expect(fetcher.previous.error!.code).toBe(
      WebcatErrorCode.Fetch.FETCH_ERROR,
    );
  });
});

// ─────────────────────────────────────────────
//  Enrollment fallback to previous bundle
// ─────────────────────────────────────────────
describe("OriginStateInitial – enrollment fallback", () => {
  it("falls back to previous bundle when current hash mismatches", async () => {
    const enrollment = makeEnrollment();
    const differentEnrollment = makeEnrollment({ threshold: 2 });
    const enrollmentHash = await computeEnrollmentHash(enrollment);

    const fetcher = new BundleFetcher("https://example.com");
    // Current has different enrollment
    fetcher.current.value = {
      enrollment: differentEnrollment,
      manifest: makeManifest(),
      signatures: { [SIGNER1]: "sig" },
    };
    // Previous has matching enrollment
    fetcher.previous.value = {
      enrollment,
      manifest: makeManifest(),
      signatures: { [SIGNER1]: "sig" },
    };

    const state = new OriginStateInitial(
      fetcher,
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const result = await state.verifyEnrollment();
    expect(result).toBeInstanceOf(OriginStateVerifiedEnrollment);
  });

  it("fails with MISMATCH when both current and previous hash mismatch", async () => {
    const enrollment = makeEnrollment();
    const enrollmentHash = await computeEnrollmentHash(enrollment);

    const different1 = makeEnrollment({ threshold: 2 });
    const different2 = makeEnrollment({ max_age: 1 });

    const fetcher = new BundleFetcher("https://example.com");
    fetcher.current.value = {
      enrollment: different1,
      manifest: makeManifest(),
      signatures: { [SIGNER1]: "sig" },
    };
    fetcher.previous.value = {
      enrollment: different2,
      manifest: makeManifest(),
      signatures: { [SIGNER1]: "sig" },
    };

    const state = new OriginStateInitial(
      fetcher,
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const result = await state.verifyEnrollment();
    expect(result).toBeInstanceOf(OriginStateFailed);
    expect((result as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Enrollment.MISMATCH,
    );
  });

  it("fails with MISMATCH when current mismatches and previous fetch failed", async () => {
    const enrollment = makeEnrollment();
    const enrollmentHash = await computeEnrollmentHash(enrollment);

    const different = makeEnrollment({ threshold: 2 });

    const fetcher = new BundleFetcher("https://example.com");
    fetcher.current.value = {
      enrollment: different,
      manifest: makeManifest(),
      signatures: { [SIGNER1]: "sig" },
    };
    fetcher.previous.error = new WebcatError(WebcatErrorCode.Fetch.FETCH_ERROR);

    const state = new OriginStateInitial(
      fetcher,
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const result = await state.verifyEnrollment();
    expect(result).toBeInstanceOf(OriginStateFailed);
    expect((result as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Enrollment.MISMATCH,
    );
  });

  it("propagates current fetch error when no enrollment is passed", async () => {
    const enrollment = makeEnrollment();
    const enrollmentHash = await computeEnrollmentHash(enrollment);

    const fetcher = new BundleFetcher("https://example.com");
    fetcher.current.error = new WebcatError(WebcatErrorCode.Fetch.FETCH_ERROR);

    const state = new OriginStateInitial(
      fetcher,
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    // No enrollment passed → falls back to fetcher.current.value which is undefined
    const result = await state.verifyEnrollment();
    expect(result).toBeInstanceOf(OriginStateFailed);
    expect((result as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Fetch.FETCH_ERROR,
    );
  });
});

// ─────────────────────────────────────────────
//  Invalid enrollment type
// ─────────────────────────────────────────────
describe("OriginStateInitial – invalid enrollment type", () => {
  it("fails with TYPE_INVALID for unknown enrollment type", async () => {
    const badEnrollment = {
      type: "unknown_type" as any,
      max_age: 3600,
      policy: "something",
      signers: ["key1"],
      threshold: 1,
      cas_url: "https://example.com",
      logs: { log1: "https://log.example.com" },
    } as Enrollment;

    const enrollmentHash = await computeEnrollmentHash(badEnrollment);

    const fetcher = new BundleFetcher("https://example.com");
    const state = new OriginStateInitial(
      fetcher,
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const result = await state.verifyEnrollment(badEnrollment);
    expect(result).toBeInstanceOf(OriginStateFailed);
    expect((result as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Enrollment.TYPE_INVALID,
    );
  });
});

// ─────────────────────────────────────────────
//  OriginStateFailed
// ─────────────────────────────────────────────
describe("OriginStateFailed", () => {
  it("copies properties from previous state and sets status to failed", async () => {
    const enrollment = makeEnrollment();
    const enrollmentHash = await computeEnrollmentHash(enrollment);

    const fetcher = new BundleFetcher("https://example.com");
    const initial = new OriginStateInitial(
      fetcher,
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const error = new WebcatError(WebcatErrorCode.Enrollment.MISMATCH);
    const failed = new OriginStateFailed(initial, error);

    expect(failed.status).toBe("failed");
    expect(failed.error).toBe(error);
    expect(failed.fqdn).toBe("example.com");
    expect(failed.scheme).toBe("https:");
    expect(failed.port).toBe("443");
  });
});

// ─────────────────────────────────────────────
//  verifyCSP –  path matching
// ─────────────────────────────────────────────
describe("OriginStateVerifiedManifest.verifyCSP – advanced", () => {
  const defaultCSP = "default-src 'none'";
  const adminCSP = "script-src 'self' admin";
  const adminSettingsCSP = "script-src 'self' admin-settings";
  const apiCSP = "script-src 'self' api";

  let verifiedManifest: OriginStateVerifiedManifest;

  beforeEach(async () => {
    const enrollment = makeEnrollment();
    const enrollmentHash = await computeEnrollmentHash(enrollment);

    const fetcher = new BundleFetcher("https://example.com");
    const initial = new OriginStateInitial(
      fetcher,
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const res = await initial.verifyEnrollment(enrollment);
    const verifiedEnrollment = res as OriginStateVerifiedEnrollment;

    const manifest = makeManifest({
      default_csp: defaultCSP,
      extra_csp: {
        "/admin": adminCSP,
        "/admin/settings": adminSettingsCSP,
        "/api": apiCSP,
      },
    });

    verifiedManifest = new OriginStateVerifiedManifest(
      verifiedEnrollment,
      manifest,
      new Set(["example.com"]),
    );
  });

  it("selects longest prefix match for nested paths", () => {
    // /admin/settings/page should match /admin/settings (longer prefix)
    expect(
      verifiedManifest.verifyCSP(adminSettingsCSP, "/admin/settings/page"),
    ).toBe(true);

    // Should NOT match shorter /admin prefix
    expect(verifiedManifest.verifyCSP(adminCSP, "/admin/settings/page")).toBe(
      false,
    );
  });

  it("selects /admin prefix for /admin/users", () => {
    expect(verifiedManifest.verifyCSP(adminCSP, "/admin/users")).toBe(true);
  });

  it("selects /api prefix for /api/v1/data", () => {
    expect(verifiedManifest.verifyCSP(apiCSP, "/api/v1/data")).toBe(true);
  });

  it("falls back to default CSP for unmatched path", () => {
    expect(verifiedManifest.verifyCSP(defaultCSP, "/about")).toBe(true);
  });

  it("resolves / to default_index path", () => {
    // "/" becomes "index.html" per the code, which doesn't match any extra_csp prefix
    expect(verifiedManifest.verifyCSP(defaultCSP, "/")).toBe(true);
  });

  it("uses exact match when available (higher priority than prefix)", () => {
    // /admin is an exact match
    expect(verifiedManifest.verifyCSP(adminCSP, "/admin")).toBe(true);
  });

  it("returns false when CSP string doesn't match the selected policy", () => {
    expect(verifiedManifest.verifyCSP("wrong-csp", "/admin")).toBe(false);
    expect(verifiedManifest.verifyCSP("wrong-csp", "/about")).toBe(false);
  });
});

// ─────────────────────────────────────────────
//  verifyManifest – extra_csp validation failure
// ─────────────────────────────────────────────
describe("OriginStateVerifiedEnrollment.verifyManifest – extra_csp", () => {
  it("fails when extra_csp validation throws", async () => {
    const { validateCSP } = await import("../../src/webcat/validators");
    const mock = validateCSP as unknown as vi.Mock;

    // First call (default_csp) succeeds, second call (extra_csp) throws
    let callCount = 0;
    mock.mockImplementation(async () => {
      callCount++;
      if (callCount === 2) {
        throw new Error("Invalid extra CSP");
      }
    });

    const enrollment = makeEnrollment();
    const enrollmentHash = await computeEnrollmentHash(enrollment);
    const fetcher = new BundleFetcher("https://example.com");
    const initial = new OriginStateInitial(
      fetcher,
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );
    const res = await initial.verifyEnrollment(enrollment);
    const verifiedEnrollment = res as OriginStateVerifiedEnrollment;

    const manifest = makeManifest({
      extra_csp: { "/admin": "invalid-csp-value" },
    });
    const signatures: SigsumSignatures = { [SIGNER1]: "sig" };

    const result = await verifiedEnrollment.verifyManifest(
      manifest,
      signatures,
    );
    expect(result).toBeInstanceOf(OriginStateFailed);
    expect((result as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.EXTRA_CSP_INVALID,
    );

    // Reset mock
    mock.mockImplementation(async () => {});
  });
});
