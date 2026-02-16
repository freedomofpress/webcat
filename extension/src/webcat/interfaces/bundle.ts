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
  name: string;
  version: string;
  default_csp: string;
  extra_csp: {
    [matchPrefix: string]: string;
  };
  default_index: string;
  default_fallback: string;
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
