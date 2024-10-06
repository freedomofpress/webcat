import { base64ToUint8Array } from "./encoding";

// https://github.com/lsd-cat/sigstore-js-browser/blob/master/src/core/pem.ts

const PEM_HEADER = /-----BEGIN (.*)-----/;
const PEM_FOOTER = /-----END (.*)-----/;

export function PEMToBytes(pem: string): Uint8Array {
  let bytes = '';

  pem.split('\n').forEach((line) => {
    if (line.match(PEM_HEADER) || line.match(PEM_FOOTER)) {
      return;
    }

    bytes += line;
  });

  return base64ToUint8Array(bytes);
}