import { Buffer } from './buffer';
import { toDER } from './pem';

export type KeyObject = CryptoKey;
export type BinaryLike = string | ArrayBuffer | Uint8Array | Buffer;
export type KeyLike = CryptoKey | KeyObject;

class Hash {
  private algorithm: "SHA-256" | "SHA-384" | "SHA-512";
  private value: ArrayBuffer;

  constructor(algorithm: string) {
      if (algorithm.includes("512")) {
        this.algorithm = "SHA-512";
      } else if (algorithm.includes("384")) {
        this.algorithm = "SHA-384";
      } else {
        this.algorithm = "SHA-256";
      }
  }

  update(data: BinaryLike): void {
      if (typeof data === 'string') {
          data = Buffer.from(data, 'utf8');
      }
      // Now concat
      var tmp = new Uint8Array(this.value.byteLength + data.byteLength);
      tmp.set(new Uint8Array(this.value), 0);
      tmp.set(new Uint8Array(data), this.value.byteLength);
      this.value = tmp;
  }

  digest(encoding?: "hex" | "base64"): Buffer {
    // This should fail if called multiple times; we con't care right now
    var digest: ArrayBuffer;
    crypto.subtle.digest(this.algorithm, this.value).then(function(result) {
      digest = result;
    });
    //if (encoding == "hex") {
      // TODO
    //} else if (encoding == "base64") {
      // TODO
    //} else {
    return new Buffer(digest);
    //}
  }
}

export function createPublicKey(
  key: Object | string | ArrayBuffer | Buffer | DataView
): KeyObject {
  
  // There is some sad asymmetry in this API: ECDSA pubkeys can be imported as raw or SubjectPublicKeyInfo
  // while RSA keys only as SubjectPublicKeyInfo. Apparently both get bytes, so we should decode the PEM first anyway

  var keyBuffer: ArrayBuffer;
  var format: "pkcs8" | "raw" | "spki";
  var options: RsaHashedImportParams | EcKeyImportParams;

  if (typeof key == 'object') {
    if (key["type"] == "spki") {
      options = {name: "ECDSA", hash: "P-256"};
    } else {
      // Then it's PKCS1 and it's RSA then
      options = {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"};
    }
    format = "spki";
    keyBuffer = key[0];
  } else if (typeof key == 'string') {
    // If it's a string, hopefully it's pem and we can import it as "spki"
    // but we need to decode it to a ArrayBuffer first
    options = {name: "ECDSA", namedCurve: "P-256"};
    format = "spki";
    keyBuffer = toDER(key);
  }

  var key_object: KeyObject;
  crypto.subtle.importKey(
    format,
    keyBuffer,
    options,
    true,
    ['verify']
  ).then(function(result) {
    key_object = result;
  })
  return key_object;
}

export function createHash(algorithm: string): Hash {
  return new Hash(algorithm);
}


export function verify(
  algorithm: string,
  data: ArrayBuffer,
  key: KeyObject,
  signature: ArrayBuffer
): boolean {
  /*try {
    return await crypto.subtle.verify(
      { name: algorithm, saltLength: 32 },
      key,
      signature,
      data
    );
  } catch (e) {
    return false;
  }*/
 return false;
}

// See https://github.com/w3c/webcrypto/issues/270
// Inefficient but correct; do the sigstore comparison for comparison need to be time constant anyway?
// I'd say no. Le'ts implement both and eventually measure the difference

/*export function bufferEqual(a: Buffer, b: Buffer): boolean {
  const algorithm = { name: 'HMAC', hash: 'SHA-256' };
  const key = crypto.subtle.generateKey(algorithm, false, ['sign', 'verify']);
  const hmac = crypto.subtle.sign(algorithm, key, a);
  const equal = crypto.subtle.verify(algorithm, key, hmac, b);
  return equal;
}*/

// Non constant time
export function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  
  const aView = new Uint8Array(a);
  const bView = new Uint8Array(b);

  for (let i = 0; i < a.byteLength; i++) {
    if (aView[i] !== bView[i]) return false;
  }
  return true;
}
