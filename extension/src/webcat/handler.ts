import { updater } from "../background";
import {
  BeforeHeadersDetails,
  BeforeRequestDetails,
  CompletedDetails,
  ErrorOccurredDetails,
  HeadersReceivedDetails,
  RequestEvent,
  RequestHandler,
} from "../browser/requests";
import { origins, requestInfo, tabs } from "../globals";
import { CacheKey } from "./cache";
import { getHooks } from "./genhooks";
import { hooksType, metadataRequestSource } from "./interfaces/base";
import { WebcatError } from "./interfaces/errors";
import {
  OriginStateHolder,
  OriginStateVerifiedManifest,
} from "./interfaces/originstate";
import { CachePartition, RequestInfo } from "./interfaces/requestinfo";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import {
  hookResponseContent,
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

export class WebcatRequestHandler extends RequestHandler {
  constructor() {
    super();
    this.addEventListener("beforerequest", this.#onRequest);
    this.addEventListener("beforeheaders", this.#onBeforeHeaders);
    this.addEventListener("headersreceived", this.#onHeaders);
    this.addEventListener("erroroccurred", this.#onErrorOccurred);
    this.addEventListener("completed", this.#onCompleted);
  }

  async #onRequest(event: RequestEvent<BeforeRequestDetails>) {
    using blockingResponse = event.blockingResponse;
    const details = event.details;
    if (isExtensionRequest(details)) {
      return;
    }

    const fqdn = getFQDN(details.url);
    const cachePartition = {
      firstParty: await getFirstParty(details),
      incognito: !!details.incognito,
    };

    const isFrame = FRAME_TYPES.includes(details.type);

    // Frame-only pre-setup: retry pending list updates
    if (isFrame) {
      logger.addLog(
        "info",
        `Loading ${details.type} ${details.url}`,
        details.tabId,
        fqdn,
      );
      await updater.retryIfFailed();
    }

    let originStateHolder: OriginStateHolder | undefined;
    if (!isFrame) {
      originStateHolder = origins.get(CacheKey(fqdn, cachePartition));
      if (originStateHolder) {
        requestInfo.set(
          details.requestId,
          new RequestInfo({
            pendingOrigin: originStateHolder,
            cachePartition,
          }),
        );
      }
    }

    if (!originStateHolder) {
      const result = await validateOrigin(
        fqdn,
        details.url,
        details.tabId,
        isFrame
          ? metadataRequestSource.main_frame
          : metadataRequestSource.sub_resource,
        details.requestId,
        cachePartition,
      );
      if (result instanceof WebcatError) {
        requestInfo.delete(details.requestId);
        if (isFrame) {
          tabs.delete(details.tabId);
          errorpage(details.tabId, fqdn, result, !isFrame);
        }
        return blockingResponse.set({ cancel: true });
      }
      if (result) {
        // HTTPS redirect; browser reissues under a fresh requestId.
        if (isFrame) {
          logger.addLog("info", `Redirecting to https`, details.tabId, fqdn);
        }
        return blockingResponse.set(result);
      }
      originStateHolder = requestInfo.get(details.requestId)?.pendingOrigin;
    }

    // No holder means the fqdn isn't enrolled
    if (!originStateHolder) {
      return;
    }

    await validateResponseContent(details, originStateHolder, cachePartition);
  }

  #onBeforeHeaders(event: RequestEvent<BeforeHeadersDetails>) {
    using blockingResponse = event.blockingResponse;
    const details = event.details;
    if (details.type !== "script") {
      return;
    }
    if (!details.requestHeaders) {
      console.error("FATAL: request headers not available");
      return blockingResponse.set({ cancel: true });
    }
    for (const header of details.requestHeaders) {
      if (header.name.toLowerCase() === "sec-fetch-dest") {
        switch (header.value) {
          case "worker":
          case "serviceworker":
          case "sharedworker":
          case "audioworklet":
          case "paintworklet":
            hookResponseContent(details);
        }
        break;
      }
    }
    return;
  }

  async #onHeaders(event: RequestEvent<HeadersReceivedDetails>) {
    using blockingResponse = event.blockingResponse;
    const details = event.details;
    const fqdn = getFQDN(details.url);
    const info = requestInfo.get(details.requestId);

    // Skip non-enrolled and extension requests
    if (!info || isExtensionRequest(details)) {
      return;
    }

    const { pendingOrigin: originStateHolder, cachePartition } = info;

    if (!originStateHolder) {
      throw new Error("No originState while starting to parse response.");
    }

    const result = await validateResponseHeaders(
      originStateHolder,
      details,
      cachePartition,
    );
    if (result instanceof WebcatError) {
      logger.addLog(
        "error",
        `Error when parsing response headers: ${result}: ${result.details?.join(", ")}`,
        details.tabId,
        fqdn,
      );
      requestInfo.delete(details.requestId);
      tabs.delete(details.tabId);
      errorpage(
        details.tabId,
        fqdn,
        result,
        !FRAME_TYPES.includes(details.type),
      );
      return blockingResponse.set({ cancel: true });
    }

    this.#commitVerifiedOrigin(fqdn, originStateHolder, cachePartition);

    markResponseContent(details);

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
      originStateHolder.current.manifest
    ) {
      const wasm = originStateHolder.current.manifest.wasm;

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
            cachePartition.firstParty,
            cachePartition.firstParty === new URL(details.url).origin,
          ),
          runAt: "document_start",
          frameId: details.frameId,
        });
      };

      browser.webNavigation.onDOMContentLoaded.addListener(listener);
    }

    return;
  }

  #onErrorOccurred(event: RequestEvent<ErrorOccurredDetails>) {
    // Ensure pending objects do not leak
    const details = event.details as ErrorOccurredDetails;
    const info = requestInfo.get(details.requestId);
    if (info) {
      info.fail();
      requestInfo.delete(details.requestId);
    }
  }

  #onCompleted(event: RequestEvent<CompletedDetails>) {
    const details = event.details;
    const info = requestInfo.get(details.requestId);
    if (info) {
      info.complete();
      requestInfo.delete(details.requestId);
    }
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
