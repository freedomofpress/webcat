export interface Enrollment {
  signers: string[];
  policy: string;
  threshold: number;
  cas_url: string;
}

export interface Manifest {
  name: string;
  version: string;
  default_csp: string;
  extra_csp?: {
    [matchPrefix: string]: string;
  };
  default_index: string;
  default_fallback: string;
  timestamp: string;
  files: {
    [filePath: string]: string;
  };
  wasm?: string[];
}

export interface Bundle {
  enrollment?: Enrollment;
  manifest: Manifest;
  signatures: {
    [pubKey: string]: string;
  };
}
