import permissions from "../browser/permissions";

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

export function isSameOriginURL(target: string, base: string) {
  try {
    const baseURL = new URL(base);
    const targetURL = new URL(target, baseURL);
    return targetURL.origin === baseURL.origin;
  } catch {
    return false;
  }
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

permissions.require("browsingData")(clearBrowserCaches);
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
}
