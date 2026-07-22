import { Bundle, Enrollment, Manifest } from "./bundle";

export type CachePartition = { firstParty: string; incognito: boolean };

export interface OriginState {
  status:
    | "request_sent"
    | "verified_enrollment"
    | "verified_manifest"
    | "failed";
  readonly scheme: string;
  readonly port: string;
  readonly fqdn: string;
  readonly enrollment_hash: Uint8Array;
  bundle?: Bundle;
  readonly enrollment?: Enrollment;
  readonly manifest?: Manifest;
  readonly valid_signers?: Set<string>;
  readonly valid_sources?: Set<string>;
  readonly delegation?: string;
  readonly cachePartition: CachePartition;
}

export interface OriginStateHolder {
  stale: boolean;
  current: OriginState;
}
