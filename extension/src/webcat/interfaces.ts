import { SigstoreBundle } from "../sigstore/bundle";
export enum Issuers {
  google = "https://accounts.google.com",
  microsoft = "https://login.microsoftonline.com",
  github = "https://github.com/login/oauth",
  gitlab = "https://gitlab.com",
}

export type Signer = [issuer: Issuers, identity: string];

export interface Policy {
  signers: Set<Signer>;
  threshold: number;
  subframes?: string[];
}

export interface OriginState {
  // The fqdn is the key in the map, so we do not need here too
  locked: boolean;
  populated: boolean;
  version: number;
  cspHash: Uint8Array;
  csp: string;
  manifestPromise: Promise<Response>;
  manifest: DataStructure;
  policy: Policy;
  policyHash: Uint8Array;
  valid: boolean;
  errors: string[];
  references: number;
}

export class OriginState {
  constructor() {
    // Let's start with safe defaults, we assume we are enrolled and nothing is verified
    this.locked = false;
    this.populated = false;
    this.version = -1;
    this.csp = "";
    this.cspHash = new Uint8Array();
    this.policyHash = new Uint8Array();
    this.valid = false;
    this.errors = [];
    this.policy = { signers: new Set(), threshold: 0 };
    this.references = 1;
  }
}

interface ManifestInfo {
  app_version: number;
  webcat_version: number;
}

interface ManifestFiles {
  [filePath: string]: string;
}

interface Manifest {
  info: ManifestInfo;
  files: ManifestFiles;
  wasm: string[];
}

export interface DataStructure {
  manifest: Manifest;
  signatures: {
    [identity: string]: SigstoreBundle;
  };
}
