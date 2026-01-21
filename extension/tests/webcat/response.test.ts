import { beforeEach, describe, expect, it, vi } from "vitest";

import { canonicalize } from "../../src/webcat/canonicalize";
import { stringToUint8Array } from "../../src/webcat/encoding";
import { EnrollmentTypes } from "../../src/webcat/interfaces/bundle";
import type {
  Enrollment,
  Manifest,
  SigsumSignatures,
} from "../../src/webcat/interfaces/bundle";
import { WebcatError, WebcatErrorCode } from "../../src/webcat/interfaces/errors";
import {
  OriginStateFailed,
  OriginStateInitial,
  OriginStateVerifiedEnrollment,
  OriginStateVerifiedManifest,
} from "../../src/webcat/interfaces/originstate";
import { SHA256 } from "../../src/webcat/utils";

// --- Mocks ---
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
