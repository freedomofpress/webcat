import { firstPartyMarker } from "../globals";
import { logger } from "./logger";

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

/**
 * Determines the first-party origin (FPO) for a given request
 */
export async function getFirstParty(
  details: browser.webRequest._OnBeforeRequestDetails,
): Promise<string> {
  if (details.tabId === -1 || details.frameId === 0) {
    // This might be a SharedWorker or a ServiceWorker,
    // or a Worker request affected by https://bugzilla.mozilla.org/show_bug.cgi?id=2048884
    for (const url of [details.url, details.documentUrl, details.originUrl]) {
      if (url === undefined) continue;
      const markerIndex = url?.indexOf(firstPartyMarker);
      if (markerIndex !== -1) {
        // FPO found in a SharedWorker or Worker URL hash, added there via hooked API
        return url.substring(
          markerIndex + firstPartyMarker.length + ":".length,
        );
      }
    }
    // No FPO found in URL hash; fall through
  }
  if (details.frameAncestors?.length) {
    // This is a request with frameAncestors; FPO is the origin of the topmost (last) ancestor
    return new URL(
      details.frameAncestors[details.frameAncestors.length - 1].url,
    ).origin;
  }
  if (details.frameId !== 0) {
    // Subresource of a Worker in a frame; no frameAncestors available; check the tab
    const frames = await browser.webNavigation.getAllFrames({
      tabId: details.tabId,
    });
    if (frames.find((frame) => frame.frameId === details.frameId)) {
      // Frame still exists; FPO is the origin of the frame with frameId === 0
      return new URL(frames.find((frame) => frame.frameId === 0)?.url || "")
        .origin;
    }
    logger.addLog(
      "warn",
      `Cannot determine first-party origin for '${details.url}'; using unique cache partition`,
      details.tabId,
      getFQDN(details.url),
    );
    return details.requestId;
  }
  if (details.documentUrl) {
    // Loading into the top-level document; FPO is the origin of documentUrl
    return new URL(details.documentUrl).origin;
  }
  if (details.type === "main_frame") {
    // Top-level navigation; FPO is the origin of the request URL
    return new URL(details.url).origin;
  }
  logger.addLog(
    "error",
    `No first-party origin found for '${details.url}'`,
    details.tabId,
    getFQDN(details.url),
  );
  return details.requestId;
}
