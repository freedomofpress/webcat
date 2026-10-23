import { SigstoreBundle, TrustedRoot } from "@freedomofpress/sigstore-browser";

export enum EnrollmentTypes {
  Sigsum = "sigsum",
  Sigstore = "sigstore",
}

export interface BaseEnrollment {
  max_age: number;
}

export interface SigsumEnrollment extends BaseEnrollment {
  type: EnrollmentTypes.Sigsum;
  signers: string[];
  threshold: number;
  policy: string;
  cas_url: string;
  logs: Record<string, string>;
}

export interface SigstoreEnrollment extends BaseEnrollment {
  type: EnrollmentTypes.Sigstore;
  trusted_root: TrustedRoot;
  claims: Record<string, string>;
}

export type Enrollment = SigsumEnrollment | SigstoreEnrollment;

export interface Manifest {
  app: string;
  version: string;
  default_csp: string;
  extra_csp: {
    [matchPrefix: string]: string;
  };
  // Hashes of files, each also a value in files, accepted at any path on
  // top-level navigation only: error pages, SPA catch-alls, but not for
  // subresources. The duplication in the files map is to ease auditing.
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
