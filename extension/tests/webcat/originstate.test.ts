import { beforeEach, describe, expect, it, Mock, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

import {
  canonicalizeJCS,
  canonicalizeOLPC,
  sha256,
} from "@freedomofpress/crypto-browser";
import { stringToUint8Array } from "@freedomofpress/crypto-browser";
import { TrustedRoot } from "@freedomofpress/sigstore-browser";

import { defaults } from "../../src/config";
import { WebcatDatabase } from "../../src/webcat/db";
import {
  Enrollment,
  EnrollmentTypes,
  Manifest,
  SigstoreEnrollment,
  SigstoreSignatures,
  SigsumEnrollment,
  SigsumSignatures,
} from "../../src/webcat/interfaces/bundle";
import {
  WebcatError,
  WebcatErrorCode,
} from "../../src/webcat/interfaces/errors";
import { BundleFetcher, OriginState } from "../../src/webcat/originstate";

// --- Mocks ---
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
          Math.floor((timestamps.length - 1) / 2)
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

function makeDummyFetcher(): BundleFetcher {
  // base URL is irrelevant, fetch will never be awaited in these tests
  return new BundleFetcher("https://example.com", defaults);
}

// Helper: compute hash exactly as production does
async function computeEnrollmentHash(
  enrollment: Enrollment,
): Promise<Uint8Array> {
  const bytes = stringToUint8Array(canonicalizeJCS(enrollment));
  return sha256(bytes);
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
describe("OriginState.verifyEnrollment", () => {
  let enrollment: SigsumEnrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginState;
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
    db = {} as WebcatDatabase;
    state = new OriginState(
      db,
      makeDummyFetcher(),
      enrollmentHash,
      cachePartition,
    );
  });

  it("accepts a valid enrollment that matches hash", async () => {
    await state.verifyEnrollment(enrollment);

    expect(state.isEnrollmentVerified()).toBe(true);
    expect(state.enrollment).toEqual(enrollment);
  });

  it("fails when enrollment hash mismatches", async () => {
    const different: SigsumEnrollment = { ...enrollment, threshold: 3 };

    await state.verifyEnrollment(different);

    expect(state.isFailed()).toBe(true);
    expect(state.error?.code).toBe(WebcatErrorCode.Enrollment.MISMATCH);
  });

  // Enrollments hash under RFC 8785 with or without enrollment_schema.
  const hashWith = async (
    encode: (e: object) => string,
    e: SigsumEnrollment,
  ): Promise<Uint8Array> => sha256(stringToUint8Array(encode(e)));

  it("accepts a legacy enrollment committed under RFC 8785", async () => {
    const legacy = {
      ...enrollment,
      logs: { log1: "https://log.example.com\n" },
    };
    const legacyState = new OriginState(
      db,
      makeDummyFetcher(),
      await hashWith(canonicalizeJCS, legacy),
      cachePartition,
    );

    await legacyState.verifyEnrollment(legacy);

    expect(legacyState.isEnrollmentVerified()).toBe(true);
  });

  it("rejects an enrollment older than the configured minimum schema", async () => {
    const fetcher = new BundleFetcher("https://example.com", {
      ...defaults,
      minEnrollmentSchema: 1,
    });
    const minState = new OriginState(
      db,
      fetcher,
      await hashWith(canonicalizeJCS, enrollment),
      cachePartition,
    );

    await minState.verifyEnrollment(enrollment);

    expect(minState.error?.code).toBe(
      WebcatErrorCode.Enrollment.SCHEMA_DEPRECATED,
    );
  });

  it("rejects an enrollment committed under OLPC canonical JSON", async () => {
    const { cas_url: _, ...rest } = enrollment;
    const versioned: SigsumEnrollment = {
      ...rest,
      enrollment_schema: 1,
      logs: { log1: "https://log.example.com\n" },
    };
    const versionedState = new OriginState(
      db,
      makeDummyFetcher(),
      await hashWith(canonicalizeOLPC, versioned),
      cachePartition,
    );

    await versionedState.verifyEnrollment(versioned);

    expect(versionedState.error?.code).toBe(
      WebcatErrorCode.Enrollment.MISMATCH,
    );
  });

  it("fails when signers is not an array", async () => {
    // eslint-disable-next-line
    const mutated = { ...enrollment, signers: null as any };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginState(
      db,
      makeDummyFetcher(),
      mutatedHash,
      cachePartition,
    );

    await mutatedState.verifyEnrollment(mutated);

    expect(mutatedState.isFailed()).toBe(true);
    expect(mutatedState.error?.code).toBe(
      WebcatErrorCode.Enrollment.SIGNERS_MALFORMED,
    );
  });

  it("fails when signers is empty", async () => {
    const mutated = { ...enrollment, signers: [] };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginState(
      db,
      makeDummyFetcher(),
      mutatedHash,
      cachePartition,
    );

    await mutatedState.verifyEnrollment(mutated);

    expect(mutatedState.isFailed()).toBe(true);
    expect(mutatedState.error?.code).toBe(
      WebcatErrorCode.Enrollment.SIGNERS_EMPTY,
    );
  });

  it("fails when threshold <= 0", async () => {
    const mutated = { ...enrollment, threshold: 0 };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginState(
      db,
      makeDummyFetcher(),
      mutatedHash,
      cachePartition,
    );

    await mutatedState.verifyEnrollment(mutated);

    expect(mutatedState.isFailed()).toBe(true);
    expect(mutatedState.error?.code).toBe(
      WebcatErrorCode.Enrollment.THRESHOLD_MALFORMED,
    );
  });

  it("fails when threshold > signers length", async () => {
    const mutated = { ...enrollment, threshold: 10 };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginState(
      db,
      makeDummyFetcher(),
      mutatedHash,
      cachePartition,
    );

    await mutatedState.verifyEnrollment(mutated);

    expect(mutatedState.isFailed()).toBe(true);
    expect(mutatedState.error?.code).toBe(
      WebcatErrorCode.Enrollment.THRESHOLD_IMPOSSIBLE,
    );
  });
});

//
// ─────────────────────────────────────────────
//   OriginState.verifyEnrollment (sigstore)
// ─────────────────────────────────────────────
//
describe("OriginState.verifyEnrollment (sigstore)", () => {
  let enrollment: SigstoreEnrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginState;
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
    db = {} as WebcatDatabase;
    state = new OriginState(
      db,
      makeDummyFetcher(),
      enrollmentHash,
      cachePartition,
    );
  });

  it("accepts a valid sigstore enrollment that matches hash", async () => {
    await state.verifyEnrollment(enrollment);

    expect(state.isEnrollmentVerified()).toBe(true);
    expect(state.enrollment).toEqual(enrollment);
  });

  it("fails when trusted_root is missing", async () => {
    const mutated: SigstoreEnrollment = {
      ...enrollment,
      trusted_root: null as unknown as TrustedRoot,
    };

    const mutatedHash = await computeEnrollmentHash(mutated);
    const mutatedState = new OriginState(
      db,
      makeDummyFetcher(),
      mutatedHash,
      cachePartition,
    );

    await mutatedState.verifyEnrollment(mutated);

    expect(mutatedState.isFailed()).toBe(true);
    expect(mutatedState.error?.code).toBe(
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
    const mutatedState = new OriginState(
      db,
      makeDummyFetcher(),
      mutatedHash,
      cachePartition,
    );

    await mutatedState.verifyEnrollment(mutated);

    expect(mutatedState.isFailed()).toBe(true);
    expect(mutatedState.error?.code).toBe(
      WebcatErrorCode.Enrollment.CLAIMS_EMPTY,
    );
  });
});

//
// ─────────────────────────────────────────────
//   OriginState.verifyManifest
// ─────────────────────────────────────────────
//
describe("OriginState.verifyManifest", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginState;
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
    db = {} as WebcatDatabase;
    state = new OriginState(
      db,
      makeDummyFetcher(),
      enrollmentHash,
      cachePartition,
    );

    await state.verifyEnrollment(enrollment);

    manifest = {
      app: "test-app",
      version: "1.0.0",
      default_csp: defaultCSP,
      extra_csp: {},
      default_index: "index.html",
      default_fallback: "/index.html",
      timestamp: new Date().toISOString(),
      files: {
        "/index.html": "hash1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
      wasm: [],
    };

    signatures = {
      [SIGNER1]: "signature1",
      [SIGNER2]: "signature2",
    };
  });

  it("accepts a valid manifest", async () => {
    await state.verifyManifest(manifest, signatures);

    expect(state.isManifestVerified()).toBe(true);
    expect(state.manifest).toEqual(manifest);
  });

  it("fails when not enough signatures", async () => {
    const tooFew: SigsumSignatures = { [SIGNER1]: "signature1" };

    await state.verifyManifest(manifest, tooFew);

    expect(state.isFailed()).toBe(true);
    expect(state.error?.code).toBe(
      WebcatErrorCode.Manifest.THRESHOLD_UNSATISFIED,
    );
  });

  it("fails when files list empty", async () => {
    const emptyFiles = { ...manifest, files: {} };

    await state.verifyManifest(emptyFiles, signatures);

    expect(state.isFailed()).toBe(true);
    expect(state.error?.code).toBe(WebcatErrorCode.Manifest.FILES_MISSING);
  });

  it("fails when default_csp missing", async () => {
    const badManifest = { ...manifest, default_csp: "" };

    await state.verifyManifest(badManifest, signatures);

    expect(state.isFailed()).toBe(true);
    expect(state.error?.code).toBe(
      WebcatErrorCode.Manifest.DEFAULT_CSP_MISSING,
    );
  });

  it("fails when fallback_hashes is malformed", async () => {
    // fallback_hashes exists from manifest_schema 1 on, without the legacy fields.
    const {
      app: _app,
      default_index: _i,
      default_fallback: _f,
      ...rest
    } = manifest;
    const badManifest = {
      ...rest,
      manifest_schema: 1 as const,
      fallback_hashes: ["/missing.html"],
    };

    await state.verifyManifest(badManifest, signatures);

    expect(state.isFailed()).toBe(true);
    expect(state.error?.code).toBe(
      WebcatErrorCode.Manifest.FALLBACK_HASHES_MALFORMED,
    );
  });

  it("rewrites legacy default_index and default_fallback", async () => {
    const legacy = {
      ...manifest,
      fallback_hashes: undefined,
      default_index: "index.html",
      default_fallback: "/404.html",
      files: {
        "/index.html": "hash1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/docs/index.html": "hash2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/404.html": "hash3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    };

    await state.verifyManifest(legacy, signatures);

    expect(state.isManifestVerified()).toBe(true);
    expect(state.manifest?.files["/"]).toBe(legacy.files["/index.html"]);
    expect(state.manifest?.files["/docs/"]).toBe(
      legacy.files["/docs/index.html"],
    );
    expect(state.manifest?.fallback_hashes).toEqual([
      legacy.files["/404.html"],
    ]);
  });

  it("fails when wasm missing", async () => {
    const badManifest = { ...manifest };
    // @ts-expect-error simulate missing wasm
    delete badManifest.wasm;

    await state.verifyManifest(badManifest, signatures);

    expect(state.isFailed()).toBe(true);
    expect(state.error?.code).toBe(WebcatErrorCode.Manifest.WASM_MISSING);
  });

  it("fails when expired", async () => {
    const validators = await import("../../src/webcat/validators");
    const mock = validators.witnessTimestampsFromCosignedTreeHead as Mock;

    // Force timestamps extremely old
    mock.mockResolvedValue([10, 20, 30]);

    await state.verifyManifest(manifest, signatures);

    expect(state.isFailed()).toBe(true);
    expect(state.error?.code).toBe(WebcatErrorCode.Manifest.EXPIRED);
  });
});

//
// ─────────────────────────────────────────────
//   OriginState.verifyManifest (sigstore)
// ─────────────────────────────────────────────
//
describe("OriginState.verifyManifest (sigstore)", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginState;
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
    db = {} as WebcatDatabase;
    state = new OriginState(
      db,
      makeDummyFetcher(),
      enrollmentHash,
      cachePartition,
    );

    await state.verifyEnrollment(enrollment);

    manifest = {
      app: "test-app",
      version: "1.0.0",
      default_csp: defaultCSP,
      extra_csp: {},
      files: {
        "/index.html": "hash1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/index.html.br": "hash2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/index.html.gz": "hash3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/index.html.zst": "hash4_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/index.html.xz": "hash5_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/index.html.bz2": "hash6_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/index.html.lz4": "hash7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
      wasm: [],
    };

    signatures = [{} as SigstoreSignatures[number]];
  });

  it("accepts a valid sigstore manifest", async () => {
    await state.verifyManifest(manifest, signatures);

    expect(state.isManifestVerified()).toBe(true);
    expect(state.manifest).toEqual(manifest);
  });

  it("fails when sigstore verification fails", async () => {
    const validators = await import("../../src/webcat/validators");
    const mock = validators.verifySigstoreManifest as Mock;

    mock.mockResolvedValueOnce(
      new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED),
    );

    await state.verifyManifest(manifest, signatures);

    expect(state.isFailed()).toBe(true);
    expect(state.error?.code).toBe(WebcatErrorCode.Manifest.VERIFY_FAILED);
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
  let state: OriginState;
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
    db = {} as WebcatDatabase;
    state = new OriginState(
      db,
      makeDummyFetcher(),
      enrollmentHash,
      cachePartition,
    );

    await state.verifyEnrollment(enrollment);

    const manifest: Manifest = {
      manifest_schema: 1,
      version: "1.0.0",
      default_csp: defaultCSP,
      extra_csp: {
        "/admin": "default-src 'none'; script-src 'self' 'unsafe-inline';",
      },
      fallback_hashes: ["hash1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      timestamp: new Date().toISOString(),
      files: {
        "/index.html": "hash1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/admin/index.html": "hash2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
      wasm: [],
    };

    state.status = "verified_manifest";
    state.manifest = manifest;
    state.validUntil = 0;
  });

  it("matches default CSP for /", () => {
    expect(state.verifyCSP(defaultCSP, "/")).toBe(true);
  });

  it("matches extra CSP for exact path", () => {
    const csp = "default-src 'none'; script-src 'self' 'unsafe-inline';";
    expect(state.verifyCSP(csp, "/admin")).toBe(true);
  });

  it("falls back to default CSP", () => {
    expect(state.verifyCSP(defaultCSP, "/other")).toBe(true);
  });

  it("returns false for incorrect CSP", () => {
    const badCsp = "default-src 'self'; script-src 'self';";
    expect(state.verifyCSP(badCsp, "/")).toBe(false);
  });
});
