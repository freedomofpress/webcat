import { manifest_name } from "../../config";
import { canonicalize } from "../../sigstore/canonicalize";
import { stringToUint8Array } from "../../sigstore/encoding";
import { SigstoreVerifier } from "../../sigstore/sigstore";
import { arraysEqual } from "../utils";
import { SHA256 } from "../utils";
import { validateCSP } from "../validators";
import { parseSigners, parseThreshold } from "./../parsers";
import { Policy, Signer } from "./base";
import { Manifest, ManifestDataStructure } from "./manifest";

export class OriginStateHolder {
  constructor(
    public current:
      | OriginStateBase
      | OriginStateInitial
      | OriginStateVerifiedPolicy
      | OriginStatePopulatedManifest
      | OriginStateVerifiedManifest
      | OriginStateFailed,
  ) {}
}

// The OriginState class caches origins and assumes safe defaults. We assume we are enrolled and nothing is verified.
export abstract class OriginStateBase {
  abstract status:
    | "request_sent"
    | "verified_policy"
    | "populated_manifest"
    | "verified_manifest"
    | "failed";
  public readonly fqdn: string;
  public readonly policy_hash: Uint8Array;
  public readonly manifestPromise: Promise<Response>;
  public readonly sigstore: SigstoreVerifier;
  public references: number;
  public readonly policy?: Policy;
  public readonly manifest_data?: ManifestDataStructure;
  public readonly manifest?: Manifest;
  public readonly valid_signers?: Array<Signer>;
  public readonly valid_sources?: Set<string>;

  constructor(
    sigstore: SigstoreVerifier,
    fqdn: string,
    policy_hash: Uint8Array,
  ) {
    this.fqdn = fqdn;
    this.policy_hash = policy_hash;
    this.sigstore = sigstore;
    this.manifestPromise = fetch(`https://${fqdn}/${manifest_name}`, {
      cache: "no-store",
    });
    this.references = 1;
  }
}

export class OriginStateFailed extends OriginStateBase {
  public readonly status = "failed" as const;
  public errorMessage: string;

  constructor(prev: OriginStateBase, errorMessage: string) {
    super(prev.sigstore, prev.fqdn, prev.policy_hash);
    Object.assign(this, prev);
    // We must set it again because we are copying
    this.status = "failed" as const;
    this.errorMessage = errorMessage;
  }
}

export class OriginStateInitial extends OriginStateBase {
  public status = "request_sent" as const;

  constructor(
    sigstore: SigstoreVerifier,
    fqdn: string,
    policy_hash: Uint8Array,
  ) {
    super(sigstore, fqdn, policy_hash);
  }

  public async verifyPolicy(
    normalizedHeaders: Map<string, string>,
  ): Promise<OriginStateVerifiedPolicy | OriginStateFailed> {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const signersHeader = normalizedHeaders.get("x-sigstore-signers")!;
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const thresholdHeader = normalizedHeaders.get("x-sigstore-threshold")!;

    const signers = parseSigners(signersHeader);

    // Extract X-Sigstore-Threshold

    const threshold = parseThreshold(thresholdHeader, signers.size);

    if (threshold < 1 || signers.size < 1 || threshold > signers.size) {
      return new OriginStateFailed(
        this,
        "failed to find all the necessary policy headers!",
      );
    }

    const normalizedSigners = Array.from(signers).map(([issuer, identity]) => ({
      identity,
      issuer,
    }));

    // Sort the normalized signers by identity, then issuer
    normalizedSigners.sort(
      (a, b) =>
        a.identity.localeCompare(b.identity) ||
        a.issuer.localeCompare(b.issuer),
    );

    // Create the policy object
    const policyObject = {
      "x-sigstore-signers": normalizedSigners, // Use array of objects
      "x-sigstore-threshold": threshold, // Already normalized
    };

    // Compute hash of the normalized policy
    const policyString = JSON.stringify(policyObject);
    if (
      !arraysEqual(this.policy_hash, new Uint8Array(await SHA256(policyString)))
    ) {
      return new OriginStateFailed(
        this,
        "response headers do not match the preload list.",
      );
    }

    return new OriginStateVerifiedPolicy(this, {
      signers: signers,
      threshold: threshold,
    });
  }
}

export class OriginStateVerifiedPolicy extends OriginStateBase {
  public readonly status = "verified_policy" as const;
  public readonly policy: Policy;

  constructor(prev: OriginStateInitial, policy: Policy) {
    super(prev.sigstore, prev.fqdn, prev.policy_hash);
    this.policy = policy;
  }

  public async populateManifest(): Promise<
    OriginStatePopulatedManifest | OriginStateFailed
  > {
    const manifestResponse = await this.manifestPromise;
    if (manifestResponse.ok !== true) {
      return new OriginStateFailed(this, "server error");
    }
    const manifest_data = await manifestResponse.json();
    return new OriginStatePopulatedManifest(this, manifest_data);
  }
}

export class OriginStatePopulatedManifest extends OriginStateBase {
  public readonly status = "populated_manifest" as const;
  public readonly policy: Policy;
  public readonly manifest_data: ManifestDataStructure;

  constructor(
    prev: OriginStateVerifiedPolicy,
    manifest_data: ManifestDataStructure,
  ) {
    super(prev.sigstore, prev.fqdn, prev.policy_hash);
    this.policy = prev.policy;
    this.manifest_data = manifest_data;
  }

  public async verifyManifest(): Promise<
    OriginStateVerifiedManifest | OriginStateFailed
  > {
    if (
      !this.manifest_data ||
      !this.manifest_data.signatures ||
      !this.manifest_data.manifest ||
      Object.keys(this.manifest_data.signatures).length < this.policy.threshold
    ) {
      return new OriginStateFailed(
        this,
        "either there are missing fields, or there are less signatures than the threshold.",
      );
    }

    const manifest = this.manifest_data.manifest;
    let validCount = 0;

    const valid_signers: Array<Signer> = [];
    const valid_sources: Set<string> = new Set();

    for (const signer of this.policy.signers) {
      // This automatically avoids duplicates, cause they would conflict in the json array
      if (this.manifest_data.signatures[signer[1]]) {
        // If someone attached a signature that fails validation on the manifest, even if the threshold is met
        // something is sketchy
        const res = await this.sigstore.verifyArtifact(
          signer[1],
          signer[0],
          this.manifest_data.signatures[signer[1]],
          stringToUint8Array(canonicalize({ manifest: manifest })),
        );
        if (res) {
          valid_signers.push(signer);
          validCount++;
        }
      }
    }

    // Not enough signatures to verify the manifest
    if (validCount < this.policy.threshold) {
      return new OriginStateFailed(
        this,
        `expected at least ${this.policy.threshold} valid signatures, found only ${validCount}.`,
      );
    }

    // A manifest with no files should not exists
    if (!manifest.files || Object.keys(manifest.files).length < 1) {
      return new OriginStateFailed(this, "files list is empty.");
    }

    // If there is no default CSP than the manifest is incomplete
    if (!manifest.default_csp || manifest.default_csp.length < 3) {
      return new OriginStateFailed(this, "default_csp is empty or not set.");
    }

    // Validate the default CSP
    try {
      await validateCSP(manifest.default_csp, this.fqdn, valid_sources);
    } catch (e) {
      return new OriginStateFailed(this, `failed parsing default_csp: ${e}`);
    }

    // Validate all extra CSP, it should also fill all the sources
    for (const path in manifest.extra_csp) {
      if (manifest.extra_csp.hasOwnProperty(path)) {
        const csp = manifest.extra_csp[path];
        try {
          await validateCSP(csp, this.fqdn, valid_sources);
        } catch (e) {
          return new OriginStateFailed(this, `failed parsing extra_csp: ${e}`);
        }
      } else {
        return new OriginStateFailed(this, `extra_csp path ${path} is empty.`);
      }
    }

    return new OriginStateVerifiedManifest(
      this,
      manifest,
      valid_signers,
      valid_sources,
    );
  }
}

export class OriginStateVerifiedManifest extends OriginStateBase {
  public readonly status = "verified_manifest" as const;
  public readonly policy: Policy;
  public readonly manifest_data: ManifestDataStructure;
  public readonly manifest: Manifest;
  public readonly valid_signers: Array<Signer>;
  public readonly valid_sources: Set<string> = new Set();

  constructor(
    prev: OriginStatePopulatedManifest,
    manifest: Manifest,
    valid_signers: Array<Signer>,
    valid_sources: Set<string>,
  ) {
    super(prev.sigstore, prev.fqdn, prev.policy_hash);
    this.policy = prev.policy;
    this.manifest_data = prev.manifest_data;
    this.manifest = manifest;
    this.valid_signers = valid_signers;
    this.valid_sources = valid_sources;
  }

  public verifyCSP(csp: string, pathname: string) {
    const extraCSP = this.manifest.extra_csp || {};
    const defaultCSP = this.manifest.default_csp;

    let correctCSP = "";

    // Sigh
    if (
      pathname === "/index.html" ||
      pathname === "/index.htm" ||
      pathname === "/"
    ) {
      correctCSP =
        extraCSP["/"] || extraCSP["/index.htm"] || extraCSP["/index.html"];
    }

    if (!correctCSP) {
      let bestMatch: string | null = null;
      let bestMatchLength = 0;

      for (const prefix in extraCSP) {
        if (
          prefix !== "/" &&
          pathname.startsWith(prefix) &&
          prefix.length > bestMatchLength
        ) {
          bestMatch = prefix;
          bestMatchLength = prefix.length;
        }
      }

      // Return the most specific match, or fallback to default CSP
      correctCSP = bestMatch ? extraCSP[bestMatch] : defaultCSP;
    }

    if (csp !== correctCSP) {
      return false;
    } else {
      return true;
    }
  }
}
