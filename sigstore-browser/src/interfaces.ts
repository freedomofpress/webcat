export enum KeyEncodingTypes {
    Hex,
    PEM
}

export enum KeyTypes {
    Ecdsa = "ECDSA",
    Ed25519 = "Ed25519",
    RSA = "RSA"
}

export enum EcdsaTypes {
    P256 = "P-256",
    P384 = "P-384",
    P521 = "P-521"
}

export enum HashAlgorithms {
    SHA256 = "SHA-256",
    SHA384 = "SHA-384",
    SHA512 = "SHA-512"
}

export enum SignatureSchemes {
    "rsassa-pss-sha256",
    "ed25519",
    "ecdsa-sha2-nistp256"
}

export interface Key {
    keyid: string;
    keytype: string;
    scheme: string;
    keyval: {
        public: string;
    };
    keyid_hash_algorithms: string[];
}

export interface Role {
    keyids: string[];
    threshold: number;
}

export interface Signed {
    _type: string;
    spec_version: string;
    version: number;
    expires: string;
    keys: {
        [key: string]: Key;
    };
    roles: {
        [role: string]: Role;
    };
}

export interface Signature {
    keyid: string;
    sig: string;
}

export interface Metafile {
    signed: Signed;
    signatures: Signature[];
}

export interface ImportedKey {
    [keyId: string]: CryptoKey;
}

export interface Signature {
    keyId: string,
    sig: string
}