import { Uint8ArrayToHex, stringToUint8Array, hexToUint8Array, base64ToUint8Array, Uint8ArrayToBase64, Uint8ArrayToString } from "./encoding";
import { canonicalize } from "./canonicalize";
import { toDER } from "./pem";
import { ASN1Obj } from "./asn1";
import { ECDSA_CURVE_NAMES, ECDSA_SIGNATURE_ALGOS } from "./oid"
import { X509Certificate } from './x509';

import { Signed, Signature, EcdsaTypes, HashAlgorithms, KeyTypes } from "./interfaces";

export async function validateCert(cert: Uint8Array|string, key?: CryptoKey) {
    const x509cert = X509Certificate.parse(cert);

    console.log(x509cert.publicKey)
    console.log(x509cert.notBefore)
    console.log(x509cert.notAfter)
    //console.log(Uint8ArrayToString(x509cert.issuer))
    console.log(Uint8ArrayToString(x509cert.subject))
    x509cert.verify()



    // Let's keep this "documentation" for now
    /*const tbsCertificate = asn1cert.subs[0];
    const signatureAlgorithm = ECDSA_SIGNATURE_ALGOS[asn1cert.subs[1].subs[0].toOID()];
    // The verifySignature already does ASN1, so this object is ready
    
    // TODO: This is a terrible hack to remove a leading NULL byte that breaks everything
    // Would be nice to figure out why
    const signature = hexToUint8Array(Uint8ArrayToHex(asn1cert.subs[2].value).substring(2));

    if (key === undefined) {
        // Extract the key from the cert
        const keydata = Uint8ArrayToBase64(tbsCertificate.subs[6].toDER());
        const keycurve = ECDSA_CURVE_NAMES[tbsCertificate.subs[6].subs[0].subs[1].toOID()];

        key = await importKey(KeyTypes.Ecdsa, keycurve, keydata);
    }

    try {
    if (!await verifySignature(key, tbsCertificate.toDER(), signature, signatureAlgorithm)) {
        throw new Error("Failed to verify certificate signature");
    }} catch (e) {
        console.log(e)
    }*/
}


// We use this to remove to select from the root keys only the ones allowed for a specific role
export function getRoleKeys(keys: Map<string, CryptoKey>, keyids: string[]): Map<string, CryptoKey> {
    var roleKeys = new Map(keys);

    for (let key of keys.keys()) {
        if (!keyids.includes(key)) {
            roleKeys.delete(key);
        }
    }
    return roleKeys;
}

export async function loadKeys(keys: Signed["keys"]): Promise<Map<string, CryptoKey>> {
    var importedKeys: Map<string, CryptoKey> = new Map();
    for (const keyId in keys) {
        /* Two mandatory ordered logic steps:
            Compute id manually
            And then check for duplicates
        */
        /* A KEYID, which MUST be correct for the specified KEY. Clients MUST calculate each KEYID to verify this is correct for the associated key. Clients MUST ensure that for any KEYID represented in this key list and in other files, only one unique key has that KEYID. */
        /* https://github.com/sigstore/root-signing/issues/1387 */
        const key = keys[keyId];
        const verified_keyId = Uint8ArrayToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", stringToUint8Array(canonicalize(key)))));
        // Check for key duplicates
        if (importedKeys.has(verified_keyId)) {
            throw new Error("Duplicate keyId found!");
        }
        if (verified_keyId !== keyId) {
            // Either bug on calculation or foul play, this is a huge problem
            throw new Error("Computed keyId does not match the provided one!");
        }
        importedKeys.set(verified_keyId, await importKey(key.keytype, key.scheme, key.keyval.public));
    }
    return importedKeys;
}

export async function importKey(keytype: string, scheme: string, key: string): Promise<CryptoKey> {
    
    class importParams {
        format: "raw"|"spki" = "spki";
        keyData: ArrayBuffer = new Uint8Array();
        algorithm: {
            name: "ECDSA"|"Ed25519"|"RSASSA-PKCS1-v1_5"|"RSA-PSS"|"RSA-OAEP";
            namedCurve?: EcdsaTypes;
        } = {name: "ECDSA"};
        extractable: boolean = true;
        usage: Array<KeyUsage> = ["verify"];
    }

    var params = new importParams();
    // Let's try to detect the encoding
    if (key.includes("BEGIN")) {
        // If it has a begin then it is a PEM
        params.format = "spki";
        params.keyData = toDER(key);
    } else if (/^[0-9A-Fa-f]+$/.test(key)) {
        // Is it hex?
        params.format = "raw";
        params.keyData = hexToUint8Array(key);
    } else {
        // It might be base64, without the PEM header, as in sigstore trusted_root
        params.format = "spki";
        params.keyData = base64ToUint8Array(key);
    }

    // Let's see supported key types
    if (keytype.toLowerCase().includes("ecdsa")) {
        // Let'd find out the key size, and retrieve the proper naming for crypto.subtle
        if (scheme.includes("256")) {
            params.algorithm = {name: 'ECDSA', namedCurve: EcdsaTypes.P256}
        } else if (scheme.includes("384")) {
            params.algorithm = {name: 'ECDSA', namedCurve: EcdsaTypes.P384}
        } else if (scheme.includes("521")) {
            params.algorithm = {name: 'ECDSA', namedCurve: EcdsaTypes.P521}
        } else {
            throw new Error("Cannot determine ECDSA key size.");
        }
    } else if ((keytype.toLowerCase().includes("ed25519"))) {
        // Ed2559 eys can be only one size, we do not need more info
        params.algorithm = { name: "Ed25519" };
    } else if ((keytype.toLowerCase().includes("rsa"))) {
        // Is it even worth to think of supporting it?
        throw new Error("TODO (or maybe not): impleent RSA keys support.");
    } else {
        throw new Error(`Unsupported ${keytype}`)
    }

    //console.log(params);
    return await crypto.subtle.importKey(params.format, params.keyData, params.algorithm, params.extractable, params.usage);
}

export async function verifySignature(key: CryptoKey, signed: Uint8Array, sig: Uint8Array, scheme: string = "ecdsa-sha2-nistp256"): Promise<boolean> {
    // TODO
    // Different hash support is fake for now: its the key that defines the supported signing scheme and that info
    // Is lost when we translate those into CryptoKey, we should extend the keys map to include scheme

    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
    var options: {
        name: string,
        hash?: {
            name: string
        }
    } = {
        name: key.algorithm.name
    }
    
    if (key.algorithm.name === KeyTypes.Ecdsa) {
        options.hash = { name: ""};
        // Then we need to select an hashing algorithm
        if (scheme.includes("256")) {
            options.hash.name = HashAlgorithms.SHA256;
        } else if (scheme.includes("384")) {
            options.hash.name = HashAlgorithms.SHA384;
        } else if (scheme.includes("512")) {
            options.hash.name = HashAlgorithms.SHA512;
        } else {
            throw new Error("Cannot determine hashing algorithm;");
        }
    } else if (key.algorithm.name === KeyTypes.Ed25519) {
        // No need to specify hash in this case, the crypto API does not take it as input for this key type
    } else if (key.algorithm.name === KeyTypes.RSA) {
        throw new Error("RSA could work, if only someone coded the support :)");
    } else {
        throw new Error("Unsupported key type!");
    }
  
    // For posterity: this mess is because the web crypto API supports only
    // IEEE P1363, so we etract r and s from the DER sig and manually ancode
    // big endian and append them one after each other
  
    // The verify option will do hashing internally
    // const signed_digest = await crypto.subtle.digest(hash_alg, signed)

    const asn1_sig = ASN1Obj.parseBuffer(sig);
    let r = asn1_sig.subs[0].toInteger();
    let s = asn1_sig.subs[1].toInteger();

    // One would think that if you hex encode something by a native function, you get a string with an even number
    // of characters. Turns out toString omit leading zeros, leading to nasty bugs.
    const padStringToEvenLength = (str: string): string => str.length % 2 ? '0' + str : str;
    const binr = hexToUint8Array(padStringToEvenLength(r.toString(16)));
    const bins = hexToUint8Array(padStringToEvenLength(s.toString(16)));

    let raw_signature = new Uint8Array(binr.length + bins.length);
    raw_signature.set(binr, 0);
    raw_signature.set(bins, binr.length);
  
    //console.log(options)
    return await crypto.subtle.verify(options, key, raw_signature, signed);
}

export async function checkSignatures(keys: Map<string, CryptoKey>, signed: Object, signatures: Signature[], threshold: number): Promise<boolean> {
    // If no threshold is provided this is probably a root file, but in any case
    // let's fail safe and expect everybody to sign if the threshold doesnt make sense
    //if (threshold < 1) {
    //    threshold = keys.size;
    //}
    // This does not work, because it is not granted that all the keys in a root will sign that root

    if (threshold > keys.size) {
        throw new Error("Threshold is bigger than the number of keys provided, something is wrong.");
    }

    // Let's keep this set as a reference to verify that there are no duplicate keys used
    var keyIds = new Set(keys.keys());

    // Let's canonicalize first the body
    const signed_canon = canonicalize(signed);

    var valid_signatures = 0;
    for (const signature of signatures) {
        // Step 1, check if keyid is in the keyIds array
        if (keyIds.has(signature.keyid) !== true) {
            continue;
            // Originally we would throw an error: but it make sense for a new signer to sign the new manifest
            // we just have to be sure not to count it and hit the threshold
            //throw new Error("Signature has an unknown keyId");
        }

        // Step 2, remove the keyid from the available ones
        // We are attempting verification with that keyid, if it fails we should
        // something is wrong anyway, let's pop the keyid to be safe anyway 
        keyIds.delete(signature.keyid);

        // Step 3, grab the correct CryptoKey
        const key = keys.get(signature.keyid);
        const sig = hexToUint8Array(signature.sig)

        // We checked before that the key exists
        if (await verifySignature(key!, stringToUint8Array(signed_canon), sig) !== true) {
            throw new Error("Failed verifying signature");
        }
        valid_signatures++;
      }

    if (valid_signatures >= threshold) {
        return true;
    } else {
        return false;
    }
}

export function bufferEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.byteLength !== b.byteLength) {
      return false;
    }
    
    for (let i = 0; i < a.byteLength; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }