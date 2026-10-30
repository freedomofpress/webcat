import { SigstoreBundle, TrustedRoot } from "@freedomofpress/sigstore-browser";

export enum EnrollmentTypes {
  Sigsum = "sigsum",
  Sigstore = "sigstore",
}

export interface BaseEnrollment {
  /** Absent on enrollments that predate versioning (spec server.md). */
  enrollment_schema?: 1;
  max_age: number;
}

export interface SigsumEnrollment extends BaseEnrollment {
  type: EnrollmentTypes.Sigsum;
  signers: string[];
  threshold: number;
  policy: string;
  /** @deprecated Only in enrollments without `enrollment_schema`. */
  cas_url?: string;
  logs: Record<string, string>;
}

export interface SigstoreEnrollment extends BaseEnrollment {
  type: EnrollmentTypes.Sigstore;
  trusted_root: TrustedRoot;
  claims: Record<string, string>;
}

export type Enrollment = SigsumEnrollment | SigstoreEnrollment;

export interface Manifest {
  /** Absent on manifests that predate versioning (spec manifest.md). */
  manifest_schema?: 1;
  /** @deprecated Replaced by `source`; only in manifests without `manifest_schema`. */
  app?: string;
  /** Git repository the application is built from; auditors rebuild from it. */
  source?: string;
  /** Release archive URL template with `${version}`; auditors fetch it. */
  artifact?: string;
  version: string;
  default_csp: string;
  extra_csp: {
    [matchPrefix: string]: string;
  };
  // Hashes accepted at any path on top-level navigation only: error pages,
  // SPA catch-alls, but not for subresources. For auditing, each is also
  // served at /.well-known/webcat/<hash>; browsers do not check that.
  fallback_hashes?: string[];
  /** @deprecated Rewritten into files and fallback_hashes on load. */
  default_index?: string;
  /** @deprecated Rewritten into fallback_hashes on load. */
  default_fallback?: string;
  timestamp?: string; // Used only for sigsum
  files: {
    [filePath: string]: string;
  };
  wasm: string[];
}

export interface SigsumSignatures {
  [pubKey: string]: string;
}

export type SigstoreSignatures = SigstoreBundle[];

export interface Bundle {
  enrollment: Enrollment;
  manifest: Manifest;
  signatures: SigsumSignatures | SigstoreSignatures;
}
