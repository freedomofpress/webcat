import { TrustedRoot } from "@freedomofpress/sigstore-browser";
import { beforeEach, describe, expect, it, Mock, vi } from "vitest";

import { HeadersReceivedDetails } from "../../src/browser/requests";
import { canonicalize } from "../../src/webcat/canonicalize";
import { WebcatDatabase } from "../../src/webcat/db";
import { stringToUint8Array } from "../../src/webcat/encoding";
import { HookBuilder } from "../../src/webcat/hookbuilder";
import type {
  Enrollment,
  Manifest,
  SigstoreEnrollment,
  SigstoreSignatures,
  SigsumEnrollment,
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
import { Stateful } from "../../src/webcat/interfaces/requeststate";
import {
  isSafeRelativeLocation,
  ResponseValidator,
} from "../../src/webcat/response";
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
  },
});

vi.mock("../../src/webcat/db", () => {
  return {
    WebcatDatabase: vi.fn().mockImplementation(function () {
      return {
        getFQDNEnrollment: vi.fn(async (fqdn: string) => {
          if (fqdn === "trusted.com") {
            return new Uint8Array([0, 1, 2, 3]);
          }
          return new Uint8Array();
        }),

        setLastChecked: vi.fn(),
        getLastChecked: vi.fn(async () => Date.now()),

        updateList: vi.fn(),
        getBlockMeta: vi.fn(async () => ({
          blockTime: 1337,
          rootHash: "deadbeef",
        })),
      };
    }),
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
  const witnessTimestampsFromCosignedTreeHead = vi.fn(
    async (_policy, _head) => {
      return [defaultNow - 5000, defaultNow - 100000, defaultNow - 200000];
    },
  );

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
  let enrollment: SigsumEnrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginStateInitial;
  let db: WebcatDatabase;
  const cachePartition = {
    firstParty: "https://example.com",
    incognito: false,
  };

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
      cachePartition,
    );
    db = new WebcatDatabase();
  });

  it("accepts a valid enrollment that matches hash", async () => {
    const res = await state.verifyEnrollment(db, enrollment);

    expect(res).toBeInstanceOf(OriginStateVerifiedEnrollment);
    expect((res as OriginStateVerifiedEnrollment).enrollment).toEqual(
      enrollment,
    );
  });

  it("fails when enrollment hash mismatches", async () => {
    const different: SigsumEnrollment = { ...enrollment, threshold: 3 };

    const res = await state.verifyEnrollment(db, different);

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
      cachePartition,
    );

    const res = await mutatedState.verifyEnrollment(db, mutated);

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
      cachePartition,
    );

    const res = await mutatedState.verifyEnrollment(db, mutated);

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
      cachePartition,
    );

    const res = await mutatedState.verifyEnrollment(db, mutated);

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
      cachePartition,
    );

    const res = await mutatedState.verifyEnrollment(db, mutated);

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
  let enrollment: SigstoreEnrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginStateInitial;
  let db: WebcatDatabase;
  const trustedRoot = {} as unknown as SigstoreEnrollment["trusted_root"];
  const cachePartition = {
    firstParty: "https://example.com",
    incognito: false,
  };

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
      cachePartition,
    );
    db = new WebcatDatabase();
  });

  it("accepts a valid sigstore enrollment that matches hash", async () => {
    const res = await state.verifyEnrollment(db, enrollment);

    expect(res).toBeInstanceOf(OriginStateVerifiedEnrollment);
    expect((res as OriginStateVerifiedEnrollment).enrollment).toEqual(
      enrollment,
    );
  });

  it("fails when trusted_root is missing", async () => {
    const mutated: SigstoreEnrollment = {
      ...enrollment,
      trusted_root: null as unknown as TrustedRoot,
    };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginStateInitial(
      makeDummyFetcher(),
      "https:",
      "443",
      "example.com",
      mutatedHash,
      cachePartition,
    );

    const res = await mutatedState.verifyEnrollment(db, mutated);

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
      cachePartition,
    );

    const res = await mutatedState.verifyEnrollment(db, mutated);

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
  let db: WebcatDatabase;
  const cachePartition = {
    firstParty: "https://example.com",
    incognito: false,
  };

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
      cachePartition,
    );
    db = new WebcatDatabase();

    const res = await initial.verifyEnrollment(db, enrollment);
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
    const res = await verifiedEnrollment.verifyManifest(
      db,
      manifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateVerifiedManifest);
    expect((res as OriginStateVerifiedManifest).manifest).toEqual(manifest);
  });

  it("fails when not enough signatures", async () => {
    const tooFew: SigsumSignatures = { [SIGNER1]: "signature1" };

    const res = await verifiedEnrollment.verifyManifest(db, manifest, tooFew);

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.THRESHOLD_UNSATISFIED,
    );
  });

  it("fails when files list empty", async () => {
    const emptyFiles = { ...manifest, files: {} };

    const res = await verifiedEnrollment.verifyManifest(
      db,
      emptyFiles,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    expect((res as OriginStateFailed).error.code).toBe(
      WebcatErrorCode.Manifest.FILES_MISSING,
    );
  });

  it("fails when default_csp missing", async () => {
    const badManifest = { ...manifest, default_csp: "" };

    const res = await verifiedEnrollment.verifyManifest(
      db,
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
      db,
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
      db,
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
    const mock = validators.witnessTimestampsFromCosignedTreeHead as Mock;

    // Force timestamps extremely old
    mock.mockResolvedValue([10, 20, 30]);

    const res = await verifiedEnrollment.verifyManifest(
      db,
      manifest,
      signatures,
    );

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
  let db: WebcatDatabase;
  const trustedRoot = {} as unknown as SigstoreEnrollment["trusted_root"];
  const cachePartition = {
    firstParty: "https://example.com",
    incognito: false,
  };

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
      cachePartition,
    );
    db = new WebcatDatabase();

    const res = await initial.verifyEnrollment(db, enrollment);
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
    const res = await verifiedEnrollment.verifyManifest(
      db,
      manifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateVerifiedManifest);
    expect((res as OriginStateVerifiedManifest).manifest).toEqual(manifest);
  });

  it("fails when sigstore verification fails", async () => {
    const validators = await import("../../src/webcat/validators");
    const mock = validators.verifySigstoreManifest as Mock;

    mock.mockResolvedValueOnce(
      new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED),
    );

    const res = await verifiedEnrollment.verifyManifest(
      db,
      manifest,
      signatures,
    );

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
  let db: WebcatDatabase;

  const cachePartition = {
    firstParty: "https://example.com",
    incognito: false,
  };
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
      cachePartition,
    );
    db = new WebcatDatabase();

    const res = await initial.verifyEnrollment(db, enrollment);
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

describe("ResponseValidator.extractAndValidateHeaders", () => {
  let rv: ResponseValidator;

  beforeEach(() => {
    rv = new ResponseValidator(new WebcatDatabase(), {} as HookBuilder);
  });

  it("requires CSP for non-cached responses", () => {
    const details = {
      responseHeaders: [{ name: "x-webcat-version", value: "1.2.3" }],
      fromCache: false,
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.MISSING_CRITICAL,
    );
  });

  it("allows missing CSP for fully cached responses", () => {
    const details = {
      responseHeaders: [{ name: "x-webcat-version", value: "1.2.3" }],
      fromCache: true,
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Map);
    expect((result as Map<string, string>).has("content-security-policy")).toBe(
      false,
    );
  });

  it("allows missing CSP for 304 responses", () => {
    const details = {
      responseHeaders: [{ name: "x-webcat-version", value: "1.2.3" }],
      fromCache: false,
      statusCode: 304,
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Map);
    expect((result as Map<string, string>).has("content-security-policy")).toBe(
      false,
    );
  });

  it("blocks Location header on sub-resource requests (script)", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "/other.js" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "script",
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.LOCATION_SUBRESOURCE,
    );
  });

  it("blocks Location header on sub-resource requests (stylesheet)", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "/other.css" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "stylesheet",
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.LOCATION_SUBRESOURCE,
    );
  });

  it("blocks Location header on sub-resource requests (xmlhttprequest)", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "/api/other" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "xmlhttprequest",
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.LOCATION_SUBRESOURCE,
    );
  });

  it("allows safe relative Location header on main_frame", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "/login" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "main_frame",
      state: { isFrame: true },
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Map);
  });

  it("allows safe relative Location header on sub_frame", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "/embed" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "sub_frame",
      state: { isFrame: true },
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Map);
  });

  it("blocks external Location header even on main_frame", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "https://evil.com" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "main_frame",
      state: { isFrame: true },
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.LOCATION_EXTERNAL,
    );
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
