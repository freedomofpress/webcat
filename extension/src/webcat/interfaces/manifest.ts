import { SigstoreBundle } from "../../sigstore/bundle";

interface ManifestFiles {
  [filePath: string]: string;
}

interface ManifestExtraCSP {
  [matchPrefix: string]: string;
}

export interface Manifest {
  app_name: string;
  app_version: string;
  comment: string;
  default_csp: string;
  extra_csp: ManifestExtraCSP;
  files: ManifestFiles;
  wasm: string[];
}

export interface ManifestDataStructure {
  manifest: Manifest;
  signatures: {
    [identity: string]: SigstoreBundle;
  };
}
