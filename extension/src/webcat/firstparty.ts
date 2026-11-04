import { BeforeRequestDetails } from "../browser/requests";

/** A frame of a tab, as reported by `webNavigation.getAllFrames`. */
export type Frame = { frameId: number; url: string };

/**
 * Resolves the first-party origin of a request from what the browser reports
 * about it. Every input comes from the browser; the page is never consulted.
 * A request that no row covers throws, and the caller cancels it: nothing is
 * fetched on behalf of a request whose first party is unknown.
 *
 * | Request | Inputs | First party |
 * |---|---|---|
 * | has frame ancestors: a framed document, its subresources, a worker script it creates | `frameAncestors` | origin of the topmost ancestor |
 * | top-level navigation | `type` | origin of the request URL |
 * | bound to a tab, no ancestors: a top-level document's subresources; loads from inside a dedicated worker or worklet (ESR reports those under frameId 0, Firefox 155+ under the owning frame or, for a worker created by a worker, frameId -1, see bug 2048884) | `tabId`, `frameId`, the tab's frames, `documentUrl` | origin of frame 0, provided the request's frame and the origin of its owning document are still in the tab; otherwise the tab navigated away or closed and the request throws |
 * | no tab, has a document: a SharedWorker or ServiceWorker script and what it loads | `documentUrl` | origin of `documentUrl`; third-party ones were cancelled by {@link isThirdPartyWorkerScript} before getting here |
 * | no tab, no document: a ServiceWorker update check | `thirdParty` | the request's own origin if the browser reports it is not cross-site; otherwise throws |
 *
 * An opaque origin, `about:blank` or `data:` at the top level, is nobody's
 * first party; the request gets a partition of its own, its `requestId`.
 *
 * @param details The request, as passed to `webRequest.onBeforeRequest`.
 * @param getFrames Lists the frames of a tab. Rejects if the tab is gone,
 *   resolves `null` if it was discarded.
 */
export async function resolveFirstParty(
  details: BeforeRequestDetails,
  getFrames: (tabId: number) => Promise<Frame[] | null> = (tabId) =>
    browser.webNavigation.getAllFrames({ tabId }),
): Promise<string> {
  const originOf = (url: string) => {
    const origin = new URL(url).origin;
    return origin === "null" ? details.requestId : origin;
  };
  if (details.frameAncestors?.length) {
    return originOf(
      details.frameAncestors[details.frameAncestors.length - 1].url,
    );
  }
  if (details.type === "main_frame") {
    return new URL(details.url).origin;
  }
  if (details.tabId !== -1) {
    const frames = await getFrames(details.tabId);
    // A worker is same-origin with its document
    const owner = new URL(details.documentUrl ?? details.url).origin;
    if (
      frames &&
      (details.frameId === -1 ||
        frames.find((frame) => frame.frameId === details.frameId)) &&
      frames.some((frame) => new URL(frame.url).origin === owner)
    ) {
      return originOf(frames.find((frame) => frame.frameId === 0)?.url || "");
    }
    throw new Error(`no live frame for '${details.url}'`);
  }
  if (details.documentUrl) {
    return new URL(details.documentUrl).origin;
  }
  if (!details.thirdParty) {
    return new URL(details.url).origin;
  }
  throw new Error(`no first party for '${details.url}'`);
}

/**
 * Whether a request is the script of a SharedWorker or ServiceWorker loading
 * in a third-party context: it has no tab, the browser flags it third-party,
 * and it is same-origin with the document that loads it. The last condition
 * excludes a first-party worker fetching another site, which is cross-origin.
 * Such a request has no first party the browser would name, so it is
 * cancelled; the scripts it would import never load.
 */
export function isThirdPartyWorkerScript(details: BeforeRequestDetails) {
  return (
    details.tabId === -1 &&
    details.thirdParty === true &&
    details.documentUrl !== undefined &&
    new URL(details.url).origin === new URL(details.documentUrl).origin
  );
}
