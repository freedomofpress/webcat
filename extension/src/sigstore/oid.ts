// From https://github.com/sigstore/sigstore-js/blob/main/packages/core/src/oid.ts

export const ECDSA_SIGNATURE_ALGOS: Record<string, string> = {
  "1.2.840.10045.4.3.1": "sha224",
  "1.2.840.10045.4.3.2": "sha256",
  "1.2.840.10045.4.3.3": "sha384",
  "1.2.840.10045.4.3.4": "sha512",
};

export const SHA2_HASH_ALGOS: Record<string, string> = {
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

export const ECDSA_CURVE_NAMES: Record<string, string> = {
  "1.2.840.10045.3.1.7": "secp256r1",
  "1.3.132.0.34": "secp384r1",
  "1.3.132.0.35": "secp521r1",
};
