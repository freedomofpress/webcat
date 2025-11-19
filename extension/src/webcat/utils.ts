import { WebcatError } from "./interfaces/errors";

export function getFQDN(url: string): string {
  const urlobj = new URL(url);
  return urlobj.hostname;
}

export function getFQDNSafe(url: string): string {
  if (!/^https?:\/\//i.test(url)) {
    url = `https://${url}`;
  }
  return getFQDN(url);
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

export async function SHA256(
  data: ArrayBuffer | Uint8Array | string,
): Promise<ArrayBuffer> {
  let input: ArrayBuffer;

  if (typeof data === "string") {
    input = new TextEncoder().encode(data).buffer;
  } else if (data instanceof Uint8Array) {
    input = data.slice().buffer;
  } else {
    input = data;
  }

  return crypto.subtle.digest("SHA-256", input);
}

export function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function errorpage(tabId: number, error?: WebcatError) {
  // TODO, what if the error happens in the background? We should probably hunt all tabs with
  // that main frame or subframe and error them
  if (tabId > 0) {
    browser.tabs.update(tabId, {
      url: browser.runtime.getURL(`pages/error.html#${error?.code}`),
    });
  }
}
