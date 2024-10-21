export interface SigstoreBundle {
  mediaType: string;
  verificationMaterial: VerificationMaterial;
  messageSignature: MessageSignature;
}

export interface VerificationMaterial {
  certificate: Certificate;
  tlogEntries: TLogEntry[];
}

export interface Certificate {
  rawBytes: string; // Base64-encoded certificate bytes
}

export interface TLogEntry {
  logIndex: string;
  logId: LogId;
  kindVersion: KindVersion;
  integratedTime: string; // UNIX timestamp
  inclusionPromise?: InclusionPromise;
  inclusionProof?: InclusionProof;
  canonicalizedBody: string; // Base64-encoded JSON body of the log entry
}

export interface LogId {
  keyId: string; // Base64-encoded key ID
}

export interface KindVersion {
  kind: string;
  version: string;
}

export interface InclusionPromise {
  signedEntryTimestamp: string; // Base64-encoded signature over the entry
}

export interface InclusionProof {
  logIndex: string;
  rootHash: string; // Base64-encoded root hash of the Merkle tree
  treeSize: string; // Number of entries in the Merkle tree
  hashes: string[]; // Base64-encoded sibling hashes in the Merkle tree
  checkpoint: Checkpoint;
}

export interface Checkpoint {
  envelope: string; // Signed envelope from the transparency log
}

export interface MessageSignature {
  messageDigest: MessageDigest;
  signature: string; // Base64-encoded signature over the message digest
}

export interface MessageDigest {
  algorithm: string; // Hashing algorithm, e.g., "SHA2_256"
  digest: string; // Base64-encoded message digest
}
