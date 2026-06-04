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

export function isNewerSemver(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);

  const len = Math.max(pa.length, pb.length);

  for (let i = 0; i < len; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;

    if (na > nb) return true;
    if (na < nb) return false;
  }

  return false;
}

export async function clearBrowserCaches(fqdns: string[]) {
  // Caching is complicated. See:
  //  - https://github.com/freedomofpress/webcat/issues/18
  //  - https://dl.acm.org/doi/10.1145/3774904.3792624
  //  - https://github.com/freedomofpress/webcat/issues/137
  //  - https://bugzilla.mozilla.org/show_bug.cgi?id=1797376
  if (fqdns.length === 0) {
    return;
  }
  await browser.browsingData.remove(
    { hostnames: fqdns },
    { serviceWorkers: true },
  );
  await browser.browsingData.remove({}, { cache: true });
  // TODO: This call fails silently if invoked more than 20 times
  // in 10 minutes. Figure out a way to deal with it safely. See
  // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/handlerBehaviorChanged
  await browser.webRequest.handlerBehaviorChanged();
}

export function getFirstParty(
  details: browser.webRequest._OnBeforeRequestDetails,
): string {
  // TODO: if details.tabId === -1 parse worker first party origin from the URL
  if (!details.frameAncestors?.length) {
    return new URL(details.url).origin;
  }
  return new URL(details.frameAncestors[details.frameAncestors.length - 1].url)
    .origin;
}
