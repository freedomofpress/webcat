import { SigstoreBundle } from "../sigstore/bundle";

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

// The OriginState class caches origins and assumes safe defaults. We assume we are enrolled and nothing is verified.
export class OriginState {
  readonly fqdn: string;
  populated: boolean;
  version: number;
  cspHash: Uint8Array;
  csp: string;
  manifestPromise: Promise<Response>;
  manifest: DataStructure | undefined; // Manifest may be undefined until populated
  policy: Policy;
  policyHash: Uint8Array;
  valid_signers: Signer[];
  valid: boolean;
  errors: string[];
  references: number;

  constructor(fqdn: string) {
    this.fqdn = fqdn;
    this.populated = false;
    this.version = -1;
    this.csp = "";
    this.cspHash = new Uint8Array();
    this.policyHash = new Uint8Array();
    this.manifestPromise = fetch(`https://${fqdn}/manifest.json`, {
      cache: "no-store",
    }).then(response => { console.log("Manifest request returned immediately"); return response });
    this.manifest = undefined;
    this.policy = { signers: new Set(), threshold: 0 };
    this.valid_signers = [];
    this.valid = false;
    this.errors = [];
    this.references = 1;
  }
}

// In OriginState we cache origins. However, if we want to cache more info,
// such as whether an asset has been loaded or not, that has to happen per tab instead
// as different tabs may load different assets.
export class PopupState {
  readonly fqdn: string;
  readonly tabId: number;
  // In the popup, if undefined mark it as loading. False means a hard failure.
  valid_headers: boolean | undefined;
  valid_manifest: boolean | undefined;
  valid_index: boolean | undefined;
  valid_signers: Signer[];
  invalid_assets: string[];
  threshold: number | undefined;
  loaded_assets: string[];

  constructor(fqdn: string, tabId: number) {
    this.fqdn = fqdn;
    this.tabId = tabId;
    this.valid_headers = undefined;
    this.valid_manifest = undefined;
    this.valid_index = undefined;
    this.valid_signers = [];
    this.invalid_assets = [];
    this.loaded_assets = [];
    this.threshold = undefined;
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