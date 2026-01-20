export function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const length = binaryString.length;
  const bytes = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    bytes[i] = binaryString.charCodeAt(i); // Convert binary string to byte array
  }

  return bytes;
}

export function Uint8ArrayToBase64(uint8Array: Uint8Array): string {
  let binaryString = "";

  for (let i = 0; i < uint8Array.length; i++) {
    binaryString += String.fromCharCode(uint8Array[i]);
  }

  return btoa(binaryString);
}

export function stringToUint8Array(str: string): Uint8Array {
  // Defaults to utf-8, but utf-8 is ascii compatible
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

// This is silly, but it is a hack to be consistent with the original test suite
export function Uint8ArrayToString(uint8Array: Uint8Array): string {
  const decoder = new TextDecoder("ascii");
  return decoder.decode(uint8Array);
}

export function base64UrlToUint8Array(base64url: string): Uint8Array {
  // Convert Base64URL → Base64
  const base64 = base64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(base64url.length + ((4 - (base64url.length % 4)) % 4), "=");

  return base64ToUint8Array(base64);
}

export function Uint8ArrayToBase64Url(uint8Array: Uint8Array): string {
  return Uint8ArrayToBase64(uint8Array)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function hexToUint8Array(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Hex string contains invalid characters");
  }

  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }

  const uint8Array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < uint8Array.length; i++) {
    uint8Array[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return uint8Array;
}

export function Uint8ArrayToHex(uint8Array: Uint8Array): string {
  return Array.from(uint8Array)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
