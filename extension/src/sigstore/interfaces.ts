import { X509Certificate } from "./x509";

export enum SigstoreRoots {
  certificateAuthorities = "certificateAuthorities",
  ctlogs = "ctlogs",
  timestampAuthorities = "timestampAuthorities",
  tlogs = "tlogs",
}

export type RawTimestampAuthorities = RawTimestampAuthority[];

export interface TrustedRoot {
  mediaType: string;
  tlogs: RawLogs;
  certificateAuthorities: RawCAs;
  ctlogs: RawLogs;
  timestampAuthorities: RawTimestampAuthorities;
}

export interface RawTimestampAuthority {
  subject: {
    organization: string;
    commonName: string;
  };
  certChain: {
    certificates: {
      rawBytes: string;
    }[];
  };
  validFor: {
    start: string;
    end?: string;
  };
}

export interface Sigstore {
  rekor: CryptoKey;
  ctfe: CryptoKey;
  fulcio: X509Certificate;
  // This is theoretically supported, but not implemented in the community sigstore
  // See https://github.com/sigstore/root-signing/issues/1389
  // And https://blog.sigstore.dev/trusted-time/
  tsa?: X509Certificate;
}

export interface RawLog {
  baseUrl: string;
  hashAlgorithm: string;
  publicKey: {
    rawBytes: string;
    keyDetails: string;
    validFor: {
      start: string;
      end?: string;
    };
  };
  logId: {
    keyId: string;
  };
}

export type RawLogs = RawLog[];

export interface RawCA {
  subject: {
    organization: string;
    commonName: string;
  };
  uri: string;
  certChain: {
    certificates: {
      rawBytes: string;
    }[];
  };
  validFor: {
    start: string;
    end: string;
  };
}

export type RawCAs = RawCA[];

export enum KeyTypes {
  Ecdsa = "ECDSA",
  Ed25519 = "Ed25519",
  RSA = "RSA",
}

export enum EcdsaTypes {
  P256 = "P-256",
  P384 = "P-384",
  P521 = "P-521",
}

export enum HashAlgorithms {
  SHA256 = "SHA-256",
  SHA384 = "SHA-384",
  SHA512 = "SHA-512",
}

export enum Roles {
  Root = "root",
  Timestamp = "timestamp",
  Snapshot = "snapshot",
  Targets = "targets",
}

export interface Key {
  keyid: string;
  keytype: string;
  scheme: string;
  keyval: {
    public: string;
  };
  keyid_hash_algorithms: string[];
}

export interface Role {
  keyids: string[];
  threshold: number;
}

export interface Target {
  custom?: {
    sigstore?: {
      status: string;
      uri?: string;
      usage: string;
    };
  };
  hashes: {
    sha256: string;
    sha512: string;
  };
  length: number;
}

export interface Signed {
  _type: string;
  spec_version: string;
  version: number;
  expires: string;
  consistent_snapshot: boolean;
  keys: {
    [key: string]: Key;
  };
  roles: {
    [role: string]: Role;
  };
  meta: Meta;
  targets: {
    [targetName: string]: Target;
  };
}

export interface Meta {
  [filename: string]: {
    length?: number;
    version: number;
    hashes?: {
      sha256?: string;
      sha512?: string;
    };
  };
}

export interface Signature {
  keyid: string;
  sig: string;
}

export interface Metafile {
  signed: Signed;
  signatures: Signature[];
}

export interface Signature {
  keyId: string;
  sig: string;
}

export interface Root {
  version: number;
  expires: Date;
  keys: Map<string, CryptoKey>;
  threshold: number;
  consistent_snapshot: boolean;
  roles: {
    [role: string]: Role;
  };
}
