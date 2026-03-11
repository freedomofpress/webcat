import { describe, expect, it, vi } from "vitest";

const mockVerifyArtifactPolicy = vi.fn();

vi.mock("@freedomofpress/sigstore-browser", () => {
  class PolicyError extends Error {}

  class AllOf {
    constructor(private policies: Array<{ verify: (cert: unknown) => void }>) {}

    verify(cert: unknown) {
      for (const policy of this.policies) {
        policy.verify(cert);
      }
    }
  }

  class SigstoreVerifier {
    async loadSigstoreRoot() {
      return;
    }

    async verifyArtifactPolicy(
      policy: { verify: (cert: unknown) => void },
      bundle: { cert: unknown },
    ) {
      mockVerifyArtifactPolicy(policy, bundle);
      policy.verify(bundle.cert);
      return true;
    }
  }

  return {
    AllOf,
    EXTENSION_OID_OTHERNAME: "othername-oid",
    PolicyError,
    SigstoreVerifier,
  };
});

import {
  Manifest,
  SigstoreEnrollment,
  SigstoreSignatures,
} from "../../src/webcat/interfaces/bundle";
import { verifySigstoreManifest } from "../../src/webcat/validators";

function createSanCert(san: string) {
  return {
    extSubjectAltName: {
      uri: san,
      otherName: () => undefined,
    },
    extension: () => undefined,
    notBefore: new Date(),
  };
}

function createExtensionCert(oid: string, value: string) {
  return {
    extSubjectAltName: undefined,
    extension: (extOid: string) => {
      if (extOid !== oid) {
        return undefined;
      }

      return {
        value: new TextEncoder().encode(value),
        valueObj: {},
      };
    },
    notBefore: new Date(),
  };
}

function baseEnrollment(claims: Record<string, string>): SigstoreEnrollment {
  return {
    trusted_root: "dHJ1c3Qtcm9vdA",
    max_age: 3600,
    claims,
  };
}

const manifest: Manifest = {
  version: 1,
  timestamp: "0",
  hashes: { a: "b" },
};

describe("verifySigstoreManifest claim matching", () => {
  it("matches SAN prefixes when claim is prefixed with ^", async () => {
    const enrollment = baseEnrollment({
      "2.5.29.17": "^https://github.com/example/",
    });

    const signatures = [
      { cert: createSanCert("https://github.com/example/repo") },
    ] as unknown as SigstoreSignatures;

    const result = await verifySigstoreManifest(
      enrollment,
      manifest,
      signatures,
    );

    expect(result).toBeNull();
    expect(mockVerifyArtifactPolicy).toHaveBeenCalled();
  });

  it("matches extension prefixes when claim is prefixed with ^", async () => {
    const oid = "1.2.3.4";
    const enrollment = baseEnrollment({
      [oid]: "^https://issuer.example/",
    });

    const signatures = [
      { cert: createExtensionCert(oid, "https://issuer.example/value") },
    ] as unknown as SigstoreSignatures;

    const result = await verifySigstoreManifest(
      enrollment,
      manifest,
      signatures,
    );

    expect(result).toBeNull();
  });

  it("keeps exact matching when claim is not wrapped", async () => {
    const enrollment = baseEnrollment({
      "2.5.29.17": "https://github.com/example",
    });

    const signatures = [
      { cert: createSanCert("https://github.com/example/repo") },
    ] as unknown as SigstoreSignatures;

    const result = await verifySigstoreManifest(
      enrollment,
      manifest,
      signatures,
    );

    expect(result).not.toBeNull();
  });
});
