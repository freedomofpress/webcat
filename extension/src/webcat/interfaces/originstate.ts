import {
  Bundle,
  Enrollment,
  Manifest,
  SigstoreSignatures,
  SigsumSignatures,
} from "./bundle";
import { WebcatError } from "./errors";

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
  readonly error?: WebcatError;

  verifyEnrollment(enrollment?: Enrollment, delegation?: string): Promise<void>;
  verifyManifest(
    manifest?: Manifest,
    signatures?: SigsumSignatures | SigstoreSignatures,
  ): Promise<void>;
  verifyCSP(csp: string, pathname: string): boolean;

  isEnrollmentVerified(): this is OriginStateVerifiedEnrollment;
  isManifestVerified(): this is OriginStateVerifiedManifest;
  isFailed(): this is OriginStateFailed;
}

export type OriginStateVerifiedEnrollment = OriginState & {
  status: "verified_enrollment";
  enrollment: Enrollment;
};

export type OriginStateVerifiedManifest = OriginState & {
  status: "verified_manifest";
  manifest: Manifest;
};
export type OriginStateFailed = OriginState & { status: "failed" };

export interface OriginStateHolder {
  stale: boolean;
  current: OriginState;
}
