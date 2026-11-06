import { BeforeRequestDetails } from "../browser/requests";

/** A frame of a tab, as reported by `webNavigation.getAllFrames`. */
export type Frame = { frameId: number; url: string };

/**
 * Resolves the first-party origin of a request from the fields of
 * `webRequest.onBeforeRequest` and, for tab-bound requests, the tab's frame
 * tree. A request no row covers throws, and the handler cancels it.
 *
 * | Request | Inputs | First party |
 * |---|---|---|
 * | has frame ancestors | `frameAncestors` | origin of the topmost ancestor |
 * | top-level navigation | `type` | origin of the request URL |
 * | bound to a tab, no ancestors | `tabId`, `frameId`, `documentUrl`, the tab's frames | origin of frame 0, if the request's frame and a frame of the owning document's origin are both in the tab; otherwise throws |
 * | no tab, has a document | `documentUrl` | its origin |
 * | no tab, no document | `thirdParty` | the request's own origin if the flag is `false`; otherwise throws |
 *
 * Tab-bound requests without ancestors are a top-level document's
 * subresources and the loads of dedicated workers and worklets. Firefox ESR
 * reports worker loads under frameId 0 with the worker script as
 * `documentUrl`; Firefox 155+ reports them under the owning frame, or under
 * frameId -1 for a worker created by a worker
 * (https://bugzilla.mozilla.org/show_bug.cgi?id=2048884). A worker is
 * same-origin with its document, so the owner's origin identifies it.
 *
 * Tab-less requests are SharedWorker and ServiceWorker scripts and what they
 * load. {@link isThirdPartyWorkerScript} cancels a main script loading in a
 * third-party context, so every worker that runs is first-party and
 * `documentUrl` names its first party. A document-less request is a
 * ServiceWorker update check.
 *
 * Limitations. The frame lookup is asynchronous: a tab that navigates between
 * the request and the lookup answers with the next document's frames. A
 * request of the outgoing page then throws, unless the next site frames the
 * owner's origin, in which case it is filed under the next site, the
 * partition such a visit creates anyway. A discarded tab has no frames, so
 * every request still pending on it throws.
 *
 * An opaque top-level origin, `about:blank` or `data:`, is nobody's first
 * party; the request gets a partition of its own, its `requestId`.
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
  if (details.thirdParty === false) {
    return new URL(details.url).origin;
  }
  throw new Error(`no first party for '${details.url}'`);
}

/**
 * Whether a request is the main script of a SharedWorker or ServiceWorker
 * loading in a third-party context: no tab, `thirdParty` not `false`, and
 * same-origin with its document. A first-party worker fetching another site
 * is cross-origin with its document and does not match. The browser names no
 * first party for such a script, so it is cancelled and nothing it would
 * import loads. A missing flag counts as third-party.
 */
export function isThirdPartyWorkerScript(details: BeforeRequestDetails) {
  return (
    details.tabId === -1 &&
    details.thirdParty !== false &&
    details.documentUrl !== undefined &&
    new URL(details.url).origin === new URL(details.documentUrl).origin
  );
}
