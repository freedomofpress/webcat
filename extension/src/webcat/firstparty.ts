import { BeforeRequestDetails } from "../browser/requests";

/** A frame of a tab, as reported by `webNavigation.getAllFrames`. */
export type Frame = { frameId: number; url: string };

export const getAllFrames = (tabId: number) =>
  browser.webNavigation.getAllFrames({ tabId });

/**
 * Resolves the first-party origin of a request from `webRequest` fields and
 * the tab's frames. Requests outside the table should throw.
 *
 * | Request | Inputs | First party |
 * |---|---|---|
 * | has frame ancestors | `frameAncestors` | origin of the topmost ancestor |
 * | top-level navigation | `type` | origin of the request URL |
 * | bound to a tab, no ancestors | `tabId`, `frameId`, `documentUrl`, the tab's frames | origin of frame 0, if the request's frame and a frame of the owner's origin are in the tab; else throws |
 * | tabId -1, has a document | `documentUrl` | its origin |
 * | tabId -1, document-less | `thirdParty` | the request's own origin if `false`; else throws |
 *
 * A worker load names the worker script as `documentUrl`. Firefox ESR reports
 * it under frameId 0, Firefox 155+ under the owning frame or, for a worker
 * created by a worker, frameId -1
 * (https://bugzilla.mozilla.org/show_bug.cgi?id=2048884); `documentId` is
 * missing in all Firefox versions
 * (https://bugzilla.mozilla.org/show_bug.cgi?id=2089453). Tab-less requests
 * are SharedWorker and ServiceWorker scripts and their loads;
 * {@link isThirdPartyWorkerScript} cancels a main script loading cross-site.
 * A document-less request should be a ServiceWorker update check. An opaque
 * top-level origin like `about:blank` or `data:` is partitioned by
 * `requestId`.
 *
 * The frame lookup is asynchronous, so a worker still issuing requests while
 * its tab navigates could be resolved against the next document's frames:
 *
 * - The tab leaves a page whose worker is busy. A load of that worker
 *   arriving after the commit throws, or is filed under the next document's
 *   partition when that document frames the owner's origin.
 *   test/test_navigation.py::test_navigation_race
 * - A framed page's worker is busy and the tab navigates to that page's own
 *   origin. On Firefox ESR the load reports frameId 0, which exists, and its
 *   owner's origin is now frame 0, so it is filed under that origin's
 *   top-level partition. Firefox 155+ reports the dead frame's id and throws.
 *   test/test_navigation.py::test_navigation_race_to_owner
 *
 * A discarded tab reports an empty frame list, so everything pending on it
 * throws.
 *
 * @param details The request, as passed to `webRequest.onBeforeRequest`.
 * @param getFrames Lists the frames of a tab. Rejects if the tab is gone,
 *   resolves `null` if it was discarded.
 */
export async function resolveFirstParty(
  details: BeforeRequestDetails,
  getFrames: (tabId: number) => Promise<Frame[] | null> = getAllFrames,
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
 * loading in a third-party context: tabId -1, `thirdParty` true or missing,
 * and same-origin with its document. A first-party worker fetching another
 * site is cross-origin with its document and should not match. A missing
 * flag counts as third-party.
 */
export function isThirdPartyWorkerScript(details: BeforeRequestDetails) {
  return (
    details.tabId === -1 &&
    details.thirdParty !== false &&
    details.documentUrl !== undefined &&
    new URL(details.url).origin === new URL(details.documentUrl).origin
  );
}
