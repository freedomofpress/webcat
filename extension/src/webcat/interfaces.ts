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

export interface OriginState {
  fqdn: string;  
  populated: boolean;
  version: number;
  cspHash: Uint8Array;
  csp: string;
  manifestPromise: Promise<Response>;
  manifest: DataStructure;
  policy: Policy;
  policyHash: Uint8Array;
  valid_signers: Signer[];
  valid: boolean;
  errors: string[];
  references: number;
}

export class OriginState {
  constructor(fqdn: string) {
    // Let's start with safe defaults, we assume we are enrolled and nothing is verified
    this.fqdn = fqdn;
    this.populated = false;
    this.version = -1;
    this.csp = "";
    this.cspHash = new Uint8Array();
    this.policyHash = new Uint8Array();
    this.valid_signers =[];
    this.valid = false;
    this.errors = [];
    this.policy = { signers: new Set(), threshold: 0 };
    this.references = 1;
  }
}

// In OriginState we cache origins. However, if we want to cache more info,
// such as whether an asset has been loaded or not, that has to happen per tab instead
// as different tabs may load different assets
export interface PopupState {
  fqdn: string;
  tabId: number;
  // In the popup, if undefined mark it as loading. False mean a hard failure
  valid_headers: boolean | undefined;
  valid_manifest: boolean | undefined;
  valid_index: boolean | undefined;
  valid_signers: Signer[];
  invalid_assets: string[];
  threshold: number | undefined;
  loaded_assets: string[];
}

export class PopupState {
  constructor(fqdn: string, tabId: number) {
    this.fqdn = fqdn;
    this.tabId = tabId;    
    this.valid_signers = [];
    this.loaded_assets = [];
    this.invalid_assets = [];
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

export interface LogEntry {
  timestamp: Date;
  tabId: number;
  origin: string;
  level: keyof Console;
  message: string;
  stack?: string;
}
