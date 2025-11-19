import { beforeEach, describe, expect, it, vi } from "vitest";

import { canonicalize } from "../../src/webcat/canonicalize";
import { stringToUint8Array } from "../../src/webcat/encoding";
import type {
  Enrollment,
  Manifest,
  Signatures,
} from "../../src/webcat/interfaces/bundle";
import {
  OriginStateFailed,
  OriginStateInitial,
  OriginStateVerifiedEnrollment,
  OriginStateVerifiedManifest,
} from "../../src/webcat/interfaces/originstate"; // adjust path if needed
import { SHA256 } from "../../src/webcat/utils";

// --- Mocks for external deps used by originstate.ts ---

vi.mock("sigsum/dist/verify", () => ({
  verifyMessageWithCompiledPolicy: vi.fn(async () => {
    // Always "valid" in tests unless overridden
    return true;
  }),
}));

vi.mock("../../src/webcat/validators", async () => {
  const defaultNow = Math.floor(Date.now() / 1000);

  return {
    validateCSP: vi.fn(async () => {
      return;
    }),

    witnessTimestampsFromCosignedTreeHead: vi.fn(async () => {
            return [
        defaultNow - 5000,
        defaultNow - 100000,
        defaultNow - 200000,
      ];;
    }),
  };
});



// Helper: compute the *real* enrollment_hash exactly as production does.
async function computeEnrollmentHash(
  enrollment: Enrollment,
): Promise<Uint8Array> {
  const canonical = canonicalize(enrollment);
  const bytes = stringToUint8Array(canonical);
  const digest = await SHA256(bytes);

  if (digest instanceof Uint8Array) {
    return digest;
  }
  return new Uint8Array(digest);
}

// Some dummy “keys” and policy for tests
const TEST_POLICY_B64URL = "c29tZS1zaWdzdW0tcG9saWN5"; // "some-sigsum-policy" -> base64url-ish
const SIGNER1 = "c2lnbmVyMQ"; // "signer1" in fake base64url
const SIGNER2 = "c2lnbmVyMg";
const SIGNER3 = "c2lnbmVyMw";

describe("OriginStateInitial.verifyEnrollment", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let state: OriginStateInitial;

  beforeEach(async () => {
    enrollment = {
      policy: TEST_POLICY_B64URL,
      signers: [SIGNER1, SIGNER2, SIGNER3],
      threshold: 2,
      max_age: 360000,
      cas_url: "https://cas.example.com",
    };

    enrollmentHash = await computeEnrollmentHash(enrollment);
    state = new OriginStateInitial(
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );
  });

  it("accepts a valid enrollment that matches the preload hash", async () => {
    const res = await state.verifyEnrollment(enrollment);

    expect(res).toBeInstanceOf(OriginStateVerifiedEnrollment);
    const verified = res as OriginStateVerifiedEnrollment;
    expect(verified.enrollment).toEqual(enrollment);
  });

  it("fails when enrollment does not match the preload hash", async () => {
    const differentEnrollment: Enrollment = {
      ...enrollment,
      threshold: 3, // change something so the hash differs
    };

    const res = await state.verifyEnrollment(differentEnrollment);

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;
    expect(failed.errorMessage).toBe(
      "enrollment data does not match the preload list",
    );
  });

  it("fails when signers is not an array", async () => {
    const mutated = {
      ...enrollment,
      // eslint-disable-next-line
      signers: null as any,
    };

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
    expect(failed.errorMessage).toBe("signers must be an array of strings");
  });

  it("fails when signers is empty", async () => {
    const mutated = {
      ...enrollment,
      signers: [],
    };

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
    expect(failed.errorMessage).toBe("signers cannot be empty");
  });

  it("fails when threshold is not a positive integer", async () => {
    const mutated = {
      ...enrollment,
      threshold: 0,
    };

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
    expect(failed.errorMessage).toBe("threshold must be a positive an integer");
  });

  it("fails when threshold exceeds number of signers", async () => {
    const mutated = {
      ...enrollment,
      threshold: 10,
    };

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
    expect(failed.errorMessage).toBe(
      "threshold cannot exceed number of signers",
    );
  });
});

describe("OriginStateVerifiedEnrollment.verifyManifest", () => {
  let enrollment: Enrollment;
  let enrollmentHash: Uint8Array;
  let initial: OriginStateInitial;
  let verifiedEnrollment: OriginStateVerifiedEnrollment;

  const defaultCSP =
    "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'";

  let manifest: Manifest;
  let signatures: Signatures;

  beforeEach(async () => {
    enrollment = {
      policy: TEST_POLICY_B64URL,
      signers: [SIGNER1, SIGNER2, SIGNER3],
      threshold: 2,
      max_age: 360000,
      cas_url: "https://cas.example.com",
    };

    enrollmentHash = await computeEnrollmentHash(enrollment);
    initial = new OriginStateInitial(
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );

    const res = await initial.verifyEnrollment(enrollment);
    if (!(res instanceof OriginStateVerifiedEnrollment)) {
      throw new Error(
        "verifyEnrollment did not return OriginStateVerifiedEnrollment in test setup",
      );
    }
    verifiedEnrollment = res;

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

  it("accepts a manifest when enough valid signatures are present", async () => {
    const res = await verifiedEnrollment.verifyManifest(manifest, signatures);

    expect(res).toBeInstanceOf(OriginStateVerifiedManifest);
    const verifiedManifest = res as OriginStateVerifiedManifest;
    expect(verifiedManifest.manifest).toEqual(manifest);
    expect(verifiedManifest.enrollment).toEqual(enrollment);
  });

  it("fails when not enough signatures meet the threshold", async () => {
    const tooFewSignatures: Signatures = {
      [SIGNER1]: "signature1",
    };

    const res = await verifiedEnrollment.verifyManifest(
      manifest,
      tooFewSignatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;
    expect(failed.errorMessage).toContain("found only 1 valid signatures");
  });

  it("fails when manifest has no files", async () => {
    const emptyFilesManifest: Manifest = {
      ...manifest,
      files: {},
    };

    const res = await verifiedEnrollment.verifyManifest(
      emptyFilesManifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;
    expect(failed.errorMessage).toBe("files list is empty.");
  });

  it("fails when default_csp is missing or too short", async () => {
    const badManifest: Manifest = {
      ...manifest,
      default_csp: "",
    };

    const res = await verifiedEnrollment.verifyManifest(
      badManifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;
    expect(failed.errorMessage).toBe("default_csp is empty or not set.");
  });

  it("fails when default_index or default_fallback are invalid", async () => {
    const badManifest: Manifest = {
      ...manifest,
      default_index: "/missing.html",
    };

    const res = await verifiedEnrollment.verifyManifest(
      badManifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;
    expect(failed.errorMessage).toBe(
      "default_index or default_fallback are empty or do not reference a file.",
    );
  });

  it("fails when wasm field is not set", async () => {
    const badManifest = { ...manifest } as Manifest;
    // @ts-expect-error simulate missing wasm
    delete badManifest.wasm;

    const res = await verifiedEnrollment.verifyManifest(
      badManifest,
      signatures,
    );

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;
    expect(failed.errorMessage).toBe("wasm is not set.");
  });

  it("fails when manifest median timestamp exceeds max_age", async () => {
    const now = Math.floor(Date.now() / 1000);
    const validators = await import("../../src/webcat/validators");

    // Tell TS this is actually a mock:
    const mockFn = validators.witnessTimestampsFromCosignedTreeHead as unknown as vi.Mock;

    mockFn.mockResolvedValue([
      10,
      20,
      30,
    ]);
  
    const res = await verifiedEnrollment.verifyManifest(manifest, signatures);

    expect(res).toBeInstanceOf(OriginStateFailed);
    const failed = res as OriginStateFailed;
    expect(failed.errorMessage).toMatch("manifest has expired");
  });

});

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
      policy: TEST_POLICY_B64URL,
      signers: [SIGNER1, SIGNER2],
      threshold: 1,
      max_age: 360000,
      cas_url: "https://cas.example.com",
    };

    enrollmentHash = await computeEnrollmentHash(enrollment);
    initial = new OriginStateInitial(
      "https:",
      "443",
      "example.com",
      enrollmentHash,
    );
    const res = await initial.verifyEnrollment(enrollment);
    if (!(res instanceof OriginStateVerifiedEnrollment)) {
      throw new Error(
        "verifyEnrollment did not return OriginStateVerifiedEnrollment",
      );
    }
    verifiedEnrollment = res;

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

  it("matches default CSP for root path", () => {
    const ok = verifiedManifestState.verifyCSP(defaultCSP, "/");
    expect(ok).toBe(true);
  });

  it("matches extra CSP for exact path", () => {
    const csp = "default-src 'none'; script-src 'self' 'unsafe-inline';";
    const ok = verifiedManifestState.verifyCSP(csp, "/admin");
    expect(ok).toBe(true);
  });

  it("falls back to default CSP when no extra_csp prefix matches", () => {
    const ok = verifiedManifestState.verifyCSP(defaultCSP, "/other");
    expect(ok).toBe(true);
  });

  it("returns false when CSP does not match expected policy", () => {
    const badCsp = "default-src 'self'; script-src 'self';";
    const ok = verifiedManifestState.verifyCSP(badCsp, "/");
    expect(ok).toBe(false);
  });
});
