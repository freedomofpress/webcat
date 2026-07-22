import {
  BeforeRequestDetails,
  HeadersReceivedDetails,
  RequestEvent,
  RequestHandler,
} from "../browser/requests";
import { ContentScript } from "../browser/scripting";
import { origins, tabs } from "../globals";
import { CacheKey } from "./cache";
import { HookBuilder } from "./hookbuilder";
import { WebcatError } from "./interfaces/errors";
import {
  OriginStateHolder,
  OriginStateVerifiedManifest,
} from "./interfaces/originstate";
import { CachePartition, Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import { ResponseValidator } from "./response";
import { errorpage } from "./ui";
import { getFQDN, isExtensionRequest, isNewerSemver } from "./utils";

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export interface WebcatRequestHandler extends RequestHandler {
  addEventListener: RequestHandler["addEventListener"] &
    ((
      type: "beforeframeload",
      callback: (event: RequestEvent<BeforeRequestDetails>) => void,
    ) => void);
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export class WebcatRequestHandler extends RequestHandler {
  readonly #hooks = new HookBuilder();
  readonly #contentScript = new ContentScript(this.#hooks.getStaticHookPath());
  readonly #responseValidator = new ResponseValidator(this.#hooks);

  constructor() {
    super();
    this.addEventListener("beforerequest", this.#onRequest);
    this.addEventListener("headersreceived", this.#onHeaders);
  }

  async bind(fqdns: string[]): Promise<string[]> {
    super.bind(fqdns);
    return this.#contentScript.bind(fqdns);
  }

  async #initializeState(
    details: BeforeRequestDetails,
  ): Promise<Stateful<BeforeRequestDetails>> {
    return Object.assign(details, {
      state: {
        fqdn: getFQDN(details.url),
        cachePartition: {
          firstParty: await this.#getFirstParty(details),
          incognito: !!details.incognito,
        },
        isFrame: FRAME_TYPES.includes(details.type),
      },
    });
  }

  async #onRequest(event: RequestEvent<BeforeRequestDetails>) {
    using blockingResponse = event.blockingResponse;
    if (isExtensionRequest(event.details)) {
      return;
    }
    const details = await this.#initializeState(event.details);

    // Frame-only pre-setup: retry pending list updates
    if (details.state.isFrame) {
      logger.info(`Loading ${details.type} ${details.url}`, details);
      const beforeframeload = new RequestEvent(
        "beforeframeload",
        event.details,
      );
      this.dispatchEvent(beforeframeload);
      await beforeframeload.blockingResponse.ready();
      blockingResponse.set(beforeframeload.blockingResponse);
    }

    // For non-frames, check for cached origin
    if (!details.state.isFrame) {
      details.state.pendingOrigin = origins.get(
        CacheKey(details.state.fqdn, details.state.cachePartition),
      );
    }

    // If no origin was available in cache, perform full validation;
    // for frames, this is done every time
    if (!details.state.pendingOrigin) {
      const result = await validateOrigin(details);
      if (result instanceof WebcatError) {
        if (details.state.isFrame) {
          tabs.delete(details.tabId);
          errorpage(details, result);
        }
        return blockingResponse.set({ cancel: true });
      }
      if (result) {
        // HTTPS redirect; browser reissues under a fresh requestId.
        if (details.state.isFrame) {
          logger.info(`Redirecting to https`, details);
        }
        return blockingResponse.set(result);
      }
    }

    // No holder means the fqdn isn't enrolled
    if (!details.state.pendingOrigin) {
      return;
    }

    await this.#responseValidator.validateContent(details);
  }

  async #onHeaders(event: RequestEvent<HeadersReceivedDetails>) {
    using blockingResponse = event.blockingResponse;
    const details = event.details as Stateful<HeadersReceivedDetails>;

    // Skip non-enrolled and extension requests
    if (!details.state || isExtensionRequest(details)) {
      return;
    }

    if (!details.state.pendingOrigin) {
      throw new Error("missing pendingOrigin in request state");
    }

    const result = await this.#responseValidator.validateHeaders(details);
    if (result instanceof WebcatError) {
      logger.error(
        `Error when parsing response headers: ${result}: ${result.details?.join(", ")}`,
        details,
      );
      tabs.delete(details.tabId);
      errorpage(details, result);
      return blockingResponse.set({ cancel: true });
    }

    this.#commitVerifiedOrigin(
      details.state.fqdn,
      details.state.pendingOrigin,
      details.state.cachePartition,
    );

    this.#responseValidator.markContent(event.details);

    // Here we must have already validated the enrollment and the manifest
    // and thus should have all the information, but we haven't started
    // sending data back, so it's a good time to register a listener since
    // we cannot inject yet. if the state of the tab is not yet "OnCommitted"
    // injecting the content_script fails silently

    // We thus want to inject as soon as the context is ready fro injection,
    // but not before. Since we repeat this procedure each navigation to an
    // enrolled main_frame, we want a one shot self deleting listener. The listener
    // has to be redefined each time, otherwise if it was a global function
    // Firefox would not re-record it

    // Also, we want to target the correct frame for the following cases:
    // - if a sub_frame is enrolled, but the main_frame not, we should only inject in the sub_frame
    // - if a main_frame is enrolled, it could contain frames from other enrolled origins
    //   and those would have different hooks with their own wasm allowlist
    // - a an enrolled main_frame might contain non enrolled sub_frames, and those should not receive any hooks
    //   (currently this is forbidden, but might change in the future)

    if (
      FRAME_TYPES.includes(details.type) &&
      details.state.pendingOrigin.current.manifest
    ) {
      const wasm = details.state.pendingOrigin.current.manifest.wasm;

      const listener = async (
        navDetails: browser.webNavigation._OnDOMContentLoadedDetails,
      ) => {
        if (navDetails.tabId !== details.tabId) return;
        if (navDetails.frameId !== details.frameId) return;

        browser.webNavigation.onDOMContentLoaded.removeListener(listener);

        await browser.tabs.executeScript(details.tabId, {
          code: await this.#hooks.getContentScriptHooks(
            wasm,
            details.state.cachePartition.firstParty,
            details.state.cachePartition.firstParty ===
              new URL(details.url).origin,
          ),
          runAt: "document_start",
          frameId: details.frameId,
        });
      };

      browser.webNavigation.onDOMContentLoaded.addListener(listener);
    }

    return;
  }

  #commitVerifiedOrigin(
    fqdn: string,
    holder: OriginStateHolder,
    cachePartition: CachePartition,
  ): void {
    if (holder.stale) {
      return;
    }
    if (holder.current.status !== "verified_manifest") {
      return;
    }
    const incoming = (holder.current as OriginStateVerifiedManifest).manifest
      .version;
    const existing = origins.get(CacheKey(fqdn, cachePartition));
    if (existing && existing.current.status === "verified_manifest") {
      const current = (existing.current as OriginStateVerifiedManifest).manifest
        .version;
      if (!isNewerSemver(incoming, current)) {
        return;
      }
    }
    origins.set(CacheKey(fqdn, cachePartition), holder);
  }

  /**
   * Determines the first-party origin (FPO) for a given request
   */
  async #getFirstParty(details: BeforeRequestDetails): Promise<string> {
    if (details.tabId === -1 || details.frameId === 0) {
      // This might be a SharedWorker or a ServiceWorker,
      // or a Worker request affected by https://bugzilla.mozilla.org/show_bug.cgi?id=2048884
      for (const url of [details.url, details.documentUrl, details.originUrl]) {
        if (url === undefined) continue;
        try {
          // Try to decrypt the URL fragment; if successful, the result is the FPO
          return await this.#hooks.decryptFragment(url);
        } catch {
          // The fragment was not a valid encrypted FPO; ignore
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
}
