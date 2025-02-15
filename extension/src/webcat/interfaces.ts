import { manifest_name, version } from "../config";
import { SigstoreBundle } from "../sigstore/bundle";
import { canonicalize } from "../sigstore/canonicalize";
import { stringToUint8Array } from "../sigstore/encoding";
import { SigstoreVerifier } from "../sigstore/sigstore";
import { list_count } from "./db";
import { parseSigners, parseThreshold } from "./parsers";
import { arraysEqual } from "./utils";
import { SHA256 } from "./utils";
import { validateCSP } from "./validators";

export enum Issuers {
  google = "https://accounts.google.com",
  microsoft = "https://login.microsoftonline.com",
  github = "https://github.com/login/oauth",
  gitlab = "https://gitlab.com",
}

export enum metadataRequestSource {
  main_frame,
  sub_frame,
  worker,
}

export type Signer = [issuer: Issuers, identity: string];

export interface Policy {
  signers: Set<Signer>;
  threshold: number;
  subframes?: string[];
}

export class OriginStateHolder {
  constructor(public current: OriginStateBase) {}
}

// The OriginState class caches origins and assumes safe defaults. We assume we are enrolled and nothing is verified.
export abstract class OriginStateBase {
  abstract status:
    | "request_sent"
    | "populated_headers"
    | "populated_manifest"
    | "verified_manifest"
    | "failed";
  public readonly fqdn: string;
  public readonly policyHash: Uint8Array;
  public readonly manifestPromise: Promise<Response>;
  public readonly sigstore: SigstoreVerifier;
  public references: number;
  public manifest_data: ManifestDataStructure | undefined;
  public manifest: Manifest | undefined;
  public policy: Policy;
  public valid_signers: Array<Signer>;
  public valid_sources: Set<string>;

  constructor(
    sigstore: SigstoreVerifier,
    fqdn: string,
    policyHash: Uint8Array,
  ) {
    this.fqdn = fqdn;
    this.policyHash = policyHash;
    this.sigstore = sigstore;
    this.manifestPromise = fetch(`https://${fqdn}/${manifest_name}`, {
      cache: "no-store",
    });
    this.references = 1;
    this.policy = { signers: new Set(), threshold: 0 };
    this.valid_signers = [];
    this.valid_sources = new Set();
  }
}

export class OriginStateFailed extends OriginStateBase {
  public readonly status;
  public errorMessage: string;

  constructor(prev: OriginStateBase, errorMessage: string) {
    super(prev.sigstore, prev.fqdn, prev.policyHash);
    Object.assign(this, prev);
    // We must set it again because we are copying
    this.status = "failed" as const;
    this.errorMessage = errorMessage;
  }
}

export class OriginStateInitial extends OriginStateBase {
  public readonly status = "request_sent" as const;

  constructor(
    sigstore: SigstoreVerifier,
    fqdn: string,
    policyHash: Uint8Array,
  ) {
    super(sigstore, fqdn, policyHash);
  }

  public async populateHeaders(
    normalizedHeaders: Map<string, string>,
  ): Promise<OriginStatePopulatedHeaders | OriginStateFailed> {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const signersHeader = normalizedHeaders.get("x-sigstore-signers")!;
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const thresholdHeader = normalizedHeaders.get("x-sigstore-threshold")!;

    this.policy.signers = parseSigners(signersHeader);

    // Extract X-Sigstore-Threshold
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    this.policy.threshold = parseThreshold(
      thresholdHeader,
      this.policy.signers.size,
    );

    if (
      this.policy.threshold < 1 ||
      this.policy.signers.size < 1 ||
      this.policy.threshold > this.policy.signers.size
    ) {
      return new OriginStateFailed(
        this,
        "failed to find all the necessary policy headers!",
      );
    }

    const normalizedSigners = Array.from(this.policy.signers).map(
      ([issuer, identity]) => ({
        identity,
        issuer,
      }),
    );

    // Sort the normalized signers by identity, then issuer
    normalizedSigners.sort(
      (a, b) =>
        a.identity.localeCompare(b.identity) ||
        a.issuer.localeCompare(b.issuer),
    );

    // Create the policy object
    const policyObject = {
      "x-sigstore-signers": normalizedSigners, // Use array of objects
      "x-sigstore-threshold": this.policy.threshold, // Already normalized
    };

    // Compute hash of the normalized policy
    const policyString = JSON.stringify(policyObject);
    if (
      !arraysEqual(this.policyHash, new Uint8Array(await SHA256(policyString)))
    ) {
      return new OriginStateFailed(
        this,
        "response headers do not match the preload list.",
      );
    }

    return new OriginStatePopulatedHeaders(this);
  }
}

export class OriginStatePopulatedHeaders extends OriginStateBase {
  public readonly status;

  constructor(prev: OriginStateInitial) {
    super(prev.sigstore, prev.fqdn, prev.policyHash);
    Object.assign(this, prev);
    this.status = "populated_headers" as const;
  }

  public async populateManifest(): Promise<
    OriginStatePopulatedManifest | OriginStateFailed
  > {
    const manifestResponse = await this.manifestPromise;
    if (manifestResponse.ok !== true) {
      return new OriginStateFailed(this, "server error");
    }
    this.manifest_data = await manifestResponse.json();
    return new OriginStatePopulatedManifest(this);
  }
}

export class OriginStatePopulatedManifest extends OriginStateBase {
  public readonly status;

  constructor(prev: OriginStatePopulatedHeaders) {
    super(prev.sigstore, prev.fqdn, prev.policyHash);
    Object.assign(this, prev);
    this.status = "populated_manifest" as const;
  }

  public async validateManifest(): Promise<
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

    this.manifest = this.manifest_data.manifest;
    let validCount = 0;

    for (const signer of this.policy.signers) {
      // This automatically avoids duplicates, cause they would cinflict in the json array
      if (this.manifest_data.signatures[signer[1]]) {
        // If someone attached a signature that fails validation on the manifest, even if the threshold is met
        // something is sketchy
        const res = await this.sigstore.verifyArtifact(
          signer[1],
          signer[0],
          this.manifest_data.signatures[signer[1]],
          stringToUint8Array(canonicalize({ manifest: this.manifest })),
        );
        if (res) {
          this.valid_signers.push(signer);
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
    if (!this.manifest.files || Object.keys(this.manifest.files).length < 1) {
      return new OriginStateFailed(this, "files list is empty.");
    }

    // If there is no default CSP than the manifest is incomplete
    if (!this.manifest.default_csp || this.manifest.default_csp.length < 3) {
      return new OriginStateFailed(this, "default_csp is empty or not set.");
    }

    // Validate the default CSP
    try {
      await validateCSP(
        this.manifest.default_csp,
        this.fqdn,
        this.valid_sources,
      );
    } catch (e) {
      return new OriginStateFailed(this, `failed parsing default_csp: ${e}`);
    }

    // Validate all extra CSP, it should also fill all the sources
    for (const path in this.manifest.extra_csp) {
      if (this.manifest.extra_csp.hasOwnProperty(path)) {
        const csp = this.manifest.extra_csp[path];
        try {
          await validateCSP(csp, this.fqdn, this.valid_sources);
        } catch (e) {
          return new OriginStateFailed(this, `failed parsing extra_csp: ${e}`);
        }
      } else {
        return new OriginStateFailed(this, `extra_csp path ${path} is empty.`);
      }
    }

    return new OriginStateVerifiedManifest(this);
  }
}

export class OriginStateVerifiedManifest extends OriginStateBase {
  public readonly status;

  constructor(prev: OriginStatePopulatedManifest) {
    super(prev.sigstore, prev.fqdn, prev.policyHash);
    Object.assign(this, prev);
    this.status = "verified_manifest" as const;
  }
}

export class PopupState {
  readonly fqdn: string;
  readonly tabId: number;
  // In the popup, if undefined mark it as loading. False means a hard failure.
  valid_headers: boolean | undefined;
  valid_manifest: boolean | undefined;
  valid_csp: boolean | undefined;
  valid_index: boolean | undefined;
  valid_signers: Signer[];
  valid_sources: Set<string>;
  invalid_sources: Set<string>;
  invalid_assets: string[];
  threshold: number | undefined;
  loaded_assets: string[];
  webcat: {
    version: number;
    list_count: number;
    list_last_update: string;
  };

  constructor(fqdn: string, tabId: number) {
    // TODO these should all probably be sets
    this.fqdn = fqdn;
    this.tabId = tabId;
    this.valid_headers = undefined;
    this.valid_manifest = undefined;
    this.valid_csp = undefined;
    this.valid_index = undefined;
    this.valid_signers = [];
    this.valid_sources = new Set();
    this.invalid_sources = new Set();
    this.invalid_assets = [];
    this.loaded_assets = [];
    this.threshold = undefined;
    this.webcat = {
      version: version,
      list_count: list_count,
      // TODO
      list_last_update: new Date().toISOString(),
    };
  }
}

interface ManifestFiles {
  [filePath: string]: string;
}

interface ManifestExtraCSP {
  [matchPrefix: string]: string;
}

interface Manifest {
  app_name: string;
  app_version: string;
  comment: string;
  default_csp: string;
  extra_csp: ManifestExtraCSP;
  files: ManifestFiles;
  wasm: string[];
}

export interface ManifestDataStructure {
  manifest: Manifest;
  signatures: {
    [identity: string]: SigstoreBundle;
  };
}

export enum LogType {
  debug = "debug",
  info = "info",
  warning = "warning",
  error = "error",
}

// Log entries help track activities, including errors and warnings, by providing detailed context.
export interface LogEntry {
  timestamp: Date;
  tabId: number;
  origin: string;
  level: keyof Console; // Ensures valid console log levels
  message: string;
  stack?: string;
}
