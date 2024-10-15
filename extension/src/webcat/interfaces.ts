export enum Issuers {
    google = "https://accounts.google.com",
    microsoft = "https://login.microsoftonline.com",
    github = "https://github.com/login/oauth",
    gitlab = "https://gitlab.com"
}
export interface TabState {
    fqdn: string;
    isEnrolled: boolean;
    validCSP: boolean;
    policyHash: Uint8Array;
    manifestPromise: Promise<Response>;
    manifest: Manifest;
    validManifest: boolean;
    validPolicy: boolean;
    errors: string[];
    policy: Policy;
}

export type Manifest = Map<string, string>;
export type Signer = [Issuers, string];

export interface Policy {
    signers: Set<Signer>;
    threshold: number;
    subframes?: string[];
}

export class TabState {
    constructor() {
        // Let's start with safe defaults, we assume we are enrolled and nothing is verified
        this.isEnrolled = true;
        this.validCSP = false;
        this.policyHash = new Uint8Array();
        this.manifest = new Map();
        this.validManifest = false;
        this.validPolicy = false;
        this.errors = [];
        this.policy = {signers: new Set(), threshold: 0}
    }
}