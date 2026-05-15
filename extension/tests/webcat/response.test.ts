import { beforeEach, describe, expect, it, vi } from "vitest";

import { canonicalize } from "../../src/webcat/canonicalize";
import { stringToUint8Array } from "../../src/webcat/encoding";
import type {
  Enrollment,
  Manifest,
  SigstoreEnrollment,
  SigstoreSignatures,
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
  OriginStateHolder,
  OriginStateInitial,
  OriginStateVerifiedEnrollment,
  OriginStateVerifiedManifest,
} from "../../src/webcat/interfaces/originstate";
import { validateResponseContent } from "../../src/webcat/response";
import { SHA256 } from "../../src/webcat/utils";

function makeDummyFetcher(): BundleFetcher {
  // base URL is irrelevant, fetch will never be awaited in these tests
  return new BundleFetcher("https://example.com");
}

// --- Mocks ---
vi.stubGlobal("browser", {
  browsingData: {
    remove: vi.fn().mockResolvedValue(undefined),
  },
  webRequest: {
    onBeforeRequest: { removeListener: vi.fn() },
    onHeadersReceived: { removeListener: vi.fn() },
    filterResponseData: vi.fn(),
  },
});

// errorpage / setOKIcon touch many browser APIs we haven't stubbed; keep the
// fail-closed path under test in isolation.
vi.mock("../../src/webcat/ui", () => ({
  errorpage: vi.fn(),
  setOKIcon: vi.fn(),
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

      // Include other methods your test may call
      setLastChecked: vi.fn(),
      getLastChecked: vi.fn(async () => Date.now()),

      updateList: vi.fn(),
      getBlockMeta: vi.fn(async () => ({
        blockTime: 1337,
        rootHash: "deadbeef",
      })),
    })),
  };
});

vi.mock("@freedomofpress/sigsum/dist/verify", () => ({
  verifyMessageWithCompiledPolicy: vi.fn(async () => true),
}));

vi.mock("../../src/webcat/validators", async () => {
  const actual = await vi.importActual<
    typeof import("../../src/webcat/validators")
  >("../../src/webcat/validators");
  const defaultNow = Math.floor(Date.now() / 1000);
  const witnessTimestampsFromCosignedTreeHead = vi.fn(async () => {
    return [defaultNow - 5000, defaultNow - 100000, defaultNow - 200000];
  });

  return {
    ...actual,
    validateCSP: vi.fn(async () => {}),
    witnessTimestampsFromCosignedTreeHead,
    verifySigsumManifest: vi.fn(
      async (
        enrollment: {
          signers: string[];
          threshold: number;
          max_age: number;
        },
        manifest: { timestamp?: string },
        signatures: Record<string, string>,
      ) => {
        let validCount = 0;
        for (const pubKey of Object.keys(signatures)) {
          if (enrollment.signers.includes(pubKey)) {
            validCount++;
          }
        }

        if (validCount < enrollment.threshold) {
          return new WebcatError(
            WebcatErrorCode.Manifest.THRESHOLD_UNSATISFIED,
            [String(validCount), String(enrollment.threshold)],
          );
        }

        if (!manifest.timestamp) {
          return new WebcatError(WebcatErrorCode.Manifest.TIMESTAMP_MISSING);
        }

        const timestamps = await witnessTimestampsFromCosignedTreeHead(
          new Uint8Array(),
          manifest.timestamp,
        );

        const timestamp = timestamps.sort((a, b) => a - b)[
          Math.floor(timestamps.length / 2)
        ];
        const now = Math.floor(Date.now() / 1000);

        if (now - timestamp > enrollment.max_age) {
          return new WebcatError(WebcatErrorCode.Manifest.EXPIRED, [
            String(enrollment.max_age),
            String(timestamp),
          ]);
        }

        return null;
      },
    ),
    verifySigstoreManifest: vi.fn(async () => null),
  };
});

// Helper: compute hash exactly as production does
async function computeEnrollmentHash(
  enrollment: Enrollment,
): Promise<Uint8Array> {
  const canonical = canonicalize(enrollment);
  const bytes = stringToUint8Array(canonical);
  const digest = await SHA256(bytes);
  return digest instanceof Uint8Array ? digest : new Uint8Array(digest);
}

// Dummy policy & signers
const TEST_POLICY_B64URL = "c29tZS1zaWdzdW0tcG9saWN5";
const SIGNER1 = "c2lnbmVyMQ";
const SIGNER2 = "c2lnbmVyMg";
const SIGNER3 = "c2lnbmVyMw";

//
// ─────────────────────────────────────────────
//   OriginStateInitial.verifyEnrollment
// ─────────────────────────────────────────────
//
describe("OriginStateInitial.verifyEnrollment", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginStateInitial;

  beforeEach(async () => {
    enrollment = {
      type: EnrollmentTypes.Sigsum,
      policy: TEST_POLICY_B64URL,
      signers: [SIGNER1, SIGNER2, SIGNER3],
      threshold: 2,
      max_age: 360000,
      cas_url: "https://cas.example.com",
      logs: {
        log1: "https://log.example.com",
      },
    };

    enrollmentHash = await computeEnrollmentHash(enrollment);
    state = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );
  });

  it("accepts a valid enrollment that matches hash", async () => {
    const res = await state.verifyEnrollment(enrollment);

    expect(res).toBeInstanceOf(OriginStateVerifiedEnrollment);
    expect((res as OriginStateVerifiedEnrollment).enrollment).toEqual(
      enrollment,
    );
  });

  it("fails when enrollment hash mismatches", async () => {
    const different: Enrollment = { ...enrollment, threshold: 3 };

    const res = await state.verifyEnrollment(different);

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;

    expect(failed.error.code).toBe(WebcatErrorCode.Enrollment.MISMATCH);
  });

  it("fails when signers is not an array", async () => {
    // eslint-disable-next-line
    const mutated = { ...enrollment, signers: null as any };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      mutatedHash,
    );

    const res = await mutatedState.verifyEnrollment(mutated);

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;

    expect(failed.error.code).toBe(
      WebcatErrorCode.Enrollment.SIGNERS_MALFORMED,
    );
  });

  it("fails when signers is empty", async () => {
    const mutated = { ...enrollment, signers: [] };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      mutatedHash,
    );

    const res = await mutatedState.verifyEnrollment(mutated);

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;

    expect(failed.error.code).toBe(WebcatErrorCode.Enrollment.SIGNERS_EMPTY);
  });

  it("fails when threshold <= 0", async () => {
    const mutated = { ...enrollment, threshold: 0 };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      mutatedHash,
    );

    const res = await mutatedState.verifyEnrollment(mutated);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Enrollment.THRESHOLD_MALFORMED,
    );
  });

  it("fails when threshold > signers length", async () => {
    const mutated = { ...enrollment, threshold: 10 };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      mutatedHash,
    );

    const res = await mutatedState.verifyEnrollment(mutated);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Enrollment.THRESHOLD_IMPOSSIBLE,
    );
  });
});

//
// ─────────────────────────────────────────────
//   OriginStateInitial.verifyEnrollment (sigstore)
// ─────────────────────────────────────────────
//
describe("OriginStateInitial.verifyEnrollment (sigstore)", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginStateInitial;
  const trustedRoot = {} as unknown as SigstoreEnrollment["trusted_root"];

  beforeEach(async () => {
    enrollment = {
      type: EnrollmentTypes.Sigstore,
      trusted_root: trustedRoot,
      claims: {
        "2.5.29.17": "https://github.com/example/repo",
      },
      max_age: 3600,
    };

    enrollmentHash = await computeEnrollmentHash(enrollment);
    state = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );
  });

  it("accepts a valid sigstore enrollment that matches hash", async () => {
    const res = await state.verifyEnrollment(enrollment);

    expect(res).toBeInstanceOf(OriginStateVerifiedEnrollment);
    expect((res as OriginStateVerifiedEnrollment).enrollment).toEqual(
      enrollment,
    );
  });

  it("fails when trusted_root is missing", async () => {
    // eslint-disable-next-line
    const mutated: Enrollment = { ...enrollment, trusted_root: null as any };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      mutatedHash,
    );

    const res = await mutatedState.verifyEnrollment(mutated);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Enrollment.TRUSTED_ROOT_MISSING,
    );
  });

  it("fails when claims is empty", async () => {
    const mutated: Enrollment = {
      type: EnrollmentTypes.Sigstore,
      trusted_root: trustedRoot,
      claims: {},
      max_age: 3600,
    };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      mutatedHash,
    );

    const res = await mutatedState.verifyEnrollment(mutated);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Enrollment.CLAIMS_EMPTY,
    );
  });
});

//
// ─────────────────────────────────────────────
//   OriginStateVerifiedEnrollment.verifyManifest
// ─────────────────────────────────────────────
//
describe("OriginStateVerifiedEnrollment.verifyManifest", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let initial: OriginStateInitial;
  let verifiedEnrollment: OriginStateVerifiedEnrollment;

  const defaultCSP =
    "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'";

  let manifest: Manifest;
  let signatures: SigsumSignatures;

  beforeEach(async () => {
    enrollment = {
      type: EnrollmentTypes.Sigsum,
      policy: TEST_POLICY_B64URL,
      signers: [SIGNER1, SIGNER2, SIGNER3],
      threshold: 2,
      max_age: 360000,
      cas_url: "https://cas.example.com",
      logs: {
        log1: "https://log.example.com",
      },
    };

    enrollmentHash = await computeEnrollmentHash(enrollment);
    initial = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const res = await initial.verifyEnrollment(enrollment);
    verifiedEnrollment = res as OriginStateVerifiedEnrollment;

    manifest = {
      name: "test-app",
      version: "1.0.0",
      default_csp: defaultCSP,
      extra_csp: {},
      default_index: "index.html",
      default_fallback: "/index.html",
      timestamp: new Date().toISOString(),
      files: {
        "/index.html": "hash1",
      },
      wasm: [],
    };

    signatures = {
      [SIGNER1]: "signature1",
      [SIGNER2]: "signature2",
    };
  });

  it("accepts a valid manifest", async () => {
    const res = await verifiedEnrollment.verifyManifest(manifest, signatures);

    expect(res).toBeInstanceOf(OriginStateVerifiedManifest);
    expect((res as OriginStateVerifiedManifest).manifest).toEqual(manifest);
  });

  it("fails when not enough signatures", async () => {
    const tooFew: SigsumSignatures = { [SIGNER1]: "signature1" };

    const res = await verifiedEnrollment.verifyManifest(manifest, tooFew);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.THRESHOLD_UNSATISFIED,
    );
  });

  it("fails when files list empty", async () => {
    const emptyFiles = { ...manifest, files: {} };

    const res = await verifiedEnrollment.verifyManifest(emptyFiles, signatures);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.FILES_MISSING,
    );
  });

  it("fails when default_csp missing", async () => {
    const badManifest = { ...manifest, default_csp: "" };

    const res = await verifiedEnrollment.verifyManifest(
      badManifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.DEFAULT_CSP_MISSING,
    );
  });

  it("fails when default_index file is missing", async () => {
    const badManifest = { ...manifest, default_index: "/missing.html" };

    const res = await verifiedEnrollment.verifyManifest(
      badManifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.DEFAULT_INDEX_MISSING_FILE,
    );
  });

  it("fails when wasm missing", async () => {
    const badManifest = { ...manifest };
    // @ts-expect-error simulate missing wasm
    delete badManifest.wasm;

    const res = await verifiedEnrollment.verifyManifest(
      badManifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.WASM_MISSING,
    );
  });

  it("fails when expired", async () => {
    const validators = await import("../../src/webcat/validators");
    const mock =
      validators.witnessTimestampsFromCosignedTreeHead as unknown as vi.Mock;

    // Force timestamps extremely old
    mock.mockResolvedValue([10, 20, 30]);

    const res = await verifiedEnrollment.verifyManifest(manifest, signatures);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.EXPIRED,
    );
  });
});

//
// ─────────────────────────────────────────────
//   OriginStateVerifiedEnrollment.verifyManifest (sigstore)
// ─────────────────────────────────────────────
//
describe("OriginStateVerifiedEnrollment.verifyManifest (sigstore)", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let initial: OriginStateInitial;
  let verifiedEnrollment: OriginStateVerifiedEnrollment;
  let manifest: Manifest;
  let signatures: SigstoreSignatures;
  const trustedRoot = {} as unknown as SigstoreEnrollment["trusted_root"];

  const defaultCSP =
    "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'";

  beforeEach(async () => {
    enrollment = {
      type: EnrollmentTypes.Sigstore,
      trusted_root: trustedRoot,
      claims: {
        "2.5.29.17": "https://github.com/example/repo",
      },
      max_age: 3600,
    };

    enrollmentHash = await computeEnrollmentHash(enrollment);
    initial = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const res = await initial.verifyEnrollment(enrollment);
    verifiedEnrollment = res as OriginStateVerifiedEnrollment;

    manifest = {
      name: "test-app",
      version: "1.0.0",
      default_csp: defaultCSP,
      extra_csp: {},
      default_index: "index.html",
      default_fallback: "/index.html",
      files: {
        "/index.html": "hash1",
        "/index.html.br": "hash2",
        "/index.html.gz": "hash3",
        "/index.html.zst": "hash4",
        "/index.html.xz": "hash5",
        "/index.html.bz2": "hash6",
        "/index.html.lz4": "hash7",
      },
      wasm: [],
    };

    signatures = [{} as SigstoreSignatures[number]];
  });

  it("accepts a valid sigstore manifest", async () => {
    const res = await verifiedEnrollment.verifyManifest(manifest, signatures);

    expect(res).toBeInstanceOf(OriginStateVerifiedManifest);
    expect((res as OriginStateVerifiedManifest).manifest).toEqual(manifest);
  });

  it("fails when sigstore verification fails", async () => {
    const validators = await import("../../src/webcat/validators");
    const mock = validators.verifySigstoreManifest as unknown as vi.Mock<
      [Enrollment, Manifest, SigstoreSignatures],
      Promise<WebcatError | null>
    >;

    mock.mockResolvedValueOnce(
      new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED),
    );

    const res = await verifiedEnrollment.verifyManifest(manifest, signatures);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.VERIFY_FAILED,
    );
  });
});

//
// ─────────────────────────────────────────────
//   OriginStateVerifiedManifest.verifyCSP
// ─────────────────────────────────────────────
//
describe("OriginStateVerifiedManifest.verifyCSP", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let initial: OriginStateInitial;
  let verifiedEnrollment: OriginStateVerifiedEnrollment;
  let verifiedManifestState: OriginStateVerifiedManifest;

  const defaultCSP =
    "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'";

  beforeEach(async () => {
    enrollment = {
      type: EnrollmentTypes.Sigsum,
      policy: TEST_POLICY_B64URL,
      signers: [SIGNER1, SIGNER2],
      threshold: 1,
      max_age: 360000,
      cas_url: "https://cas.example.com",
      logs: {
        log1: "https://log.example.com",
      },
    };

    enrollmentHash = await computeEnrollmentHash(enrollment);
    initial = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const res = await initial.verifyEnrollment(enrollment);
    verifiedEnrollment = res as OriginStateVerifiedEnrollment;

    const manifest: Manifest = {
      name: "test-app",
      version: "1.0.0",
      default_csp: defaultCSP,
      extra_csp: {
        "/admin": "default-src 'none'; script-src 'self' 'unsafe-inline';",
      },
      default_index: "index.html",
      default_fallback: "/index.html",
      timestamp: new Date().toISOString(),
      files: {
        "/index.html": "hash1",
        "/admin/index.html": "hash2",
      },
      wasm: [],
    };

    verifiedManifestState = new OriginStateVerifiedManifest(
      verifiedEnrollment,
      manifest,
      new Set(["example.com"]),
    );
  });

  it("matches default CSP for /", () => {
    expect(verifiedManifestState.verifyCSP(defaultCSP, "/")).toBe(true);
  });

  it("matches extra CSP for exact path", () => {
    const csp = "default-src 'none'; script-src 'self' 'unsafe-inline';";
    expect(verifiedManifestState.verifyCSP(csp, "/admin")).toBe(true);
  });

  it("falls back to default CSP", () => {
    expect(verifiedManifestState.verifyCSP(defaultCSP, "/other")).toBe(true);
  });

  it("returns false for incorrect CSP", () => {
    const badCsp = "default-src 'self'; script-src 'self';";
    expect(verifiedManifestState.verifyCSP(badCsp, "/")).toBe(false);
  });
});

//
// ─────────────────────────────────────────────
//   validateResponseContent fail-closed behavior
// ─────────────────────────────────────────────
//
describe("validateResponseContent fail-closed", () => {
  function makeFilter() {
    const noop = () => {};
    return {
      // Pre-populate handlers with no-ops so the test types stay non-nullable;
      // validateResponseContent overwrites these during setup.
      onstart: noop as (event: Event) => void,
      ondata: noop as (event: { data: ArrayBuffer }) => void,
      onstop: noop as (event: Event) => void,
      onerror: noop as (event: Event) => void,
      status: "uninitialized",
      error: "",
      write: vi.fn(),
      close: vi.fn(),
      disconnect: vi.fn(),
      suspend: vi.fn(),
      resume: vi.fn(),
    };
  }

  const DENIED = new Uint8Array([68, 69, 78, 73, 69, 68]);

  it("blocks content when onstart throws (manifest not verified)", async () => {
    const filter = makeFilter();
    (
      browser.webRequest.filterResponseData as unknown as vi.Mock
    ).mockReturnValue(filter);

    // Holder whose status is NOT "verified_manifest" → assertVerifiedManifest
    // throws inside onstart, simulating a programmer error or bad state.
    const holder = {
      current: { status: "verified_enrollment", manifest: undefined },
      stale: false,
    } as unknown as OriginStateHolder;

    const details = {
      requestId: "req-1",
      url: "https://example.com/index.html",
      type: "main_frame",
      tabId: 0,
    } as unknown as browser.webRequest._OnBeforeRequestDetails;

    await validateResponseContent(details, holder);

    // The browser would invoke onstart once the response begins streaming.
    await filter.onstart({} as Event);

    expect(filter.write).toHaveBeenCalledTimes(1);
    expect(new Uint8Array(filter.write.mock.calls[0][0])).toEqual(DENIED);
    expect(filter.close).toHaveBeenCalledTimes(1);
  });

  it("blocks content when ondata throws (e.g. undefined manifest access)", async () => {
    const filter = makeFilter();
    (
      browser.webRequest.filterResponseData as unknown as vi.Mock
    ).mockReturnValue(filter);

    // Pretend onstart succeeded but the manifest closure is still uninitialized
    // (simulates any unexpected runtime error reaching into manifest fields).
    const holder = {
      current: { status: "verified_enrollment", manifest: undefined },
      stale: false,
    } as unknown as OriginStateHolder;

    const details = {
      requestId: "req-2",
      url: "https://example.com/app.js",
      type: "script",
      tabId: 0,
    } as unknown as browser.webRequest._OnBeforeRequestDetails;

    await validateResponseContent(details, holder);

    // Skip onstart and feed data directly — manifest is undefined inside the
    // closure, so any access throws TypeError.
    await filter.ondata({ data: new Uint8Array([1, 2, 3]).buffer });

    // ondata's body only touches `manifest` on the hookMarker branch; non-marker
    // bytes are just buffered. So force the throw path by sending the hook marker.
    const { hookMarker } = await import("../../src/globals");
    await filter.ondata({ data: hookMarker.buffer });

    expect(filter.write).toHaveBeenCalledTimes(1);
    expect(new Uint8Array(filter.write.mock.calls[0][0])).toEqual(DENIED);
    expect(filter.close).toHaveBeenCalledTimes(1);
  });

  it("blocks content on filter.onerror", async () => {
    const filter = makeFilter();
    (
      browser.webRequest.filterResponseData as unknown as vi.Mock
    ).mockReturnValue(filter);

    const holder = {
      current: { status: "verified_enrollment", manifest: undefined },
      stale: false,
    } as unknown as OriginStateHolder;

    const details = {
      requestId: "req-3",
      url: "https://example.com/style.css",
      type: "stylesheet",
      tabId: 0,
    } as unknown as browser.webRequest._OnBeforeRequestDetails;

    await validateResponseContent(details, holder);

    filter.error = "underlying stream error";
    filter.onerror({} as Event);

    expect(filter.write).toHaveBeenCalledTimes(1);
    expect(new Uint8Array(filter.write.mock.calls[0][0])).toEqual(DENIED);
    expect(filter.close).toHaveBeenCalledTimes(1);
  });
});
