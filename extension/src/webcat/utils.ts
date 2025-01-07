export function getFQDN(url: string): string {
  const urlobj = new URL(url);
  return urlobj.hostname;
}

export function isExtensionRequest(
  details: browser.webRequest._OnBeforeRequestDetails,
): boolean {
  return (
    details.originUrl !== undefined &&
    details.documentUrl !== undefined &&
    details.originUrl.substring(0, 16) === "moz-extension://" &&
    details.documentUrl.substring(0, 16) === "moz-extension://" &&
    details.tabId === -1
  );
}

export async function SHA256(data: ArrayBuffer | Uint8Array | string) {
  // Sometimes we hash strings, such as the FQDN, sometimes we hash bytes, such as page content
  let inputData: Uint8Array | ArrayBuffer;
  if (typeof data === "string") {
    inputData = new TextEncoder().encode(data);
  } else {
    inputData = data;
  }
  const hash = await window.crypto.subtle.digest("SHA-256", inputData);

  return hash;
}

export function arrayBufferToHex(buffer: Uint8Array | ArrayBuffer) {
  const array = Array.from(new Uint8Array(buffer));
  return array.map((b) => b.toString(16).padStart(2, "0")).join("");
}
