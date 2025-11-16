export interface Enrollment {
  // < 4k
  policy: string;
  // ed25519 base64url encoded public keys
  signers: string[];
  // >= number of signers
  threshold: number;
  // < 1 year
  max_age: number;
  // not really important here for validation
  cas_url: string;
}

export interface Manifest {
  name: string;
  version: string;
  default_csp: string;
  extra_csp: {
    [matchPrefix: string]: string;
  };
  default_index: string;
  default_fallback: string;
  timestamp: string;
  files: {
    [filePath: string]: string;
  };
  wasm: string[];
}

export interface Signatures {
  [pubKey: string]: string;
}

export interface Bundle {
  enrollment: Enrollment;
  manifest: Manifest;
  signatures: Signatures;
}
