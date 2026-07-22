import {
  BeforeRequestDetails,
  HeadersReceivedDetails,
  RequestEvent,
  RequestHandler,
} from "../browser/requests";
import { origins, tabs } from "../globals";
import { CacheKey } from "./cache";
import { getHooks } from "./genhooks";
import { hooksType } from "./interfaces/base";
import { WebcatError } from "./interfaces/errors";
import {
  OriginStateHolder,
  OriginStateVerifiedManifest,
} from "./interfaces/originstate";
import { CachePartition, Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import {
  markResponseContent,
  validateResponseContent,
  validateResponseHeaders,
} from "./response";
import { errorpage } from "./ui";
import {
  getFirstParty,
  getFQDN,
  isExtensionRequest,
  isNewerSemver,
} from "./utils";

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
  constructor() {
    super();
    this.addEventListener("beforerequest", this.#onRequest);
    this.addEventListener("headersreceived", this.#onHeaders);
  }

  async #initializeState(
    details: BeforeRequestDetails,
  ): Promise<Stateful<BeforeRequestDetails>> {
    return Object.assign(details, {
      state: {
        fqdn: getFQDN(details.url),
        cachePartition: {
          firstParty: await getFirstParty(details),
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

    await validateResponseContent(details);
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

    const result = await validateResponseHeaders(details);
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

    markResponseContent(event.details);

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
          code: await getHooks(
            hooksType.content_script,
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
}
