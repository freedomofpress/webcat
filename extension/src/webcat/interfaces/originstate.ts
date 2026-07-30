import {
  Enrollment,
  Manifest,
  SigstoreSignatures,
  SigsumSignatures,
} from "./bundle";
import { WebcatError } from "./errors";

export type CachePartition = { firstParty: string; incognito: boolean };

export type OriginStateObject = {
  status: "verified_manifest";
  enrollment_hash: string;
  manifest: Manifest;
  delegation?: string;
};

export interface OriginState {
  readonly enrollment_hash: Uint8Array;
  readonly enrollment?: Enrollment;
  readonly manifest?: Manifest;
  readonly delegation?: string;
  readonly error?: WebcatError;

  stale: boolean;

  verifyEnrollment(enrollment?: Enrollment, delegation?: string): Promise<void>;
  verifyManifest(
    manifest?: Manifest,
    signatures?: SigsumSignatures | SigstoreSignatures,
  ): Promise<void>;
  verifyCSP(csp: string, pathname: string): boolean;

  isRequestSent(): boolean;
  isEnrollmentVerified(): this is OriginStateVerifiedEnrollment;
  isManifestVerified(): this is OriginStateVerifiedManifest;
  isFailed(): this is OriginStateFailed;
}

export type OriginStateVerifiedEnrollment = OriginState & {
  enrollment: Enrollment;
};
export type OriginStateVerifiedManifest = OriginState & {
  manifest: Manifest;
  toPOJO(): OriginStateObject;
};
export type OriginStateFailed = OriginState & {
  error: WebcatError;
};
