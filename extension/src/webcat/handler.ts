import { NamespacedKVStore } from "../browser/kvstore";
import {
  BeforeRequestDetails,
  HeadersReceivedDetails,
  RequestEvent,
  RequestHandler,
} from "../browser/requests";
import { ContentScript } from "../browser/scripting";
import { Mutex } from "../browser/sync";
import { CacheKey, isInPartition } from "./cache";
import { HookBuilder } from "./hookbuilder";
import { Database } from "./interfaces/database";
import { WebcatError } from "./interfaces/errors";
import { CachePartition, OriginState } from "./interfaces/originstate";
import { Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { BundleFetcherConfig } from "./originstate";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import { ResponseValidator } from "./response";
import { errorpage, getErrorPageURL, setErrorIcon } from "./ui";
import {
  clearBrowserCaches,
  getFQDN,
  isExtensionRequest,
  isNewerSemver,
  isSameOriginURL,
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
  readonly #db: Database & NamespacedKVStore;
  readonly #config: BundleFetcherConfig;
  readonly #hooks: HookBuilder;
  readonly #contentScript: ContentScript;
  readonly #responseValidator: ResponseValidator;
  readonly #mutex = new Mutex();
  readonly #bindLock = this.#mutex.createLock();
  readonly #requestLock = this.#mutex.createLock();

  constructor(db: Database & NamespacedKVStore, config: BundleFetcherConfig) {
    super();
    this.#db = db;
    this.#config = config;
    this.#hooks = new HookBuilder(db.namespace("hooks"));
    this.#contentScript = new ContentScript(this.#hooks.getStaticHookPath());
    this.#responseValidator = new ResponseValidator(this.#db, this.#hooks);
    this.addEventListener("beforerequest", this.#onRequest);
    this.addEventListener("headersreceived", this.#onHeaders);
    browser.webNavigation.onCommitted.addListener(
      this.#onErrorPageNavigation.bind(this),
      {
        url: [
          {
            urlPrefix: getErrorPageURL(),
          },
        ],
      },
    );
    browser.windows.onRemoved.addListener(this.#onWindowClosed.bind(this));

    // Block requests until first bind
    this.#mutex.acquire(this.#bindLock);
  }

  override async bind(fqdns: string[]) {
    using _lock = await this.#mutex.acquire(this.#bindLock);
    super.bind(fqdns);
    const newFqdns = await this.#contentScript.bind(fqdns);
    await clearBrowserCaches(newFqdns);
  }

  /**
   * Binds the handler to `<all_urls>`. Unlike {@link bind}, does not bind
   * content scripts. The bindAll method can be called synchronously before
   * FQDNs are available, but it should be always followed by a call to
   * {@link bind} to both restrict the scope of the binding and bind content
   * scripts.
   */
  bindAll() {
    super.bind(["<all_urls>"]);
  }

  protected override getListenerOptions(fqdns: string[], type: "beforerequest"): [browser.webRequest.RequestFilter, browser.webRequest.OnBeforeRequestOptions[]]; // prettier-ignore
  protected override getListenerOptions(fqdns: string[], type: "beforeheaders"): [browser.webRequest.RequestFilter, browser.webRequest.OnBeforeSendHeadersOptions[]]; // prettier-ignore
  protected override getListenerOptions(fqdns: string[], type: "headersreceived"): [browser.webRequest.RequestFilter, browser.webRequest.OnHeadersReceivedOptions[]]; // prettier-ignore
  protected override getListenerOptions(fqdns: string[], type: "erroroccurred" | "completed"): [browser.webRequest.RequestFilter]; // prettier-ignore
  protected override getListenerOptions(fqdns: string[], type: string) {
    let all = false;
    for (let i: number; (i = fqdns.indexOf("<all_urls>")) !== -1; ) {
      // If fqdns contains <all_urls>, remove it before continuing
      fqdns = [...fqdns.slice(0, i), ...fqdns.slice(i + 1)];
      all = true;
    }
    let result: ReturnType<RequestHandler["getListenerOptions"]>;
    if (type === "beforeheaders") {
      // Request headers are only needed for script requests;
      // avoid attaching listeners unnecessarily
      const [filter, options] = super.getListenerOptions(fqdns, type);
      filter.types = ["script"];
      result = [filter, options];
    } else {
      result = super.getListenerOptions(fqdns, type);
    }
    if (all) {
      // Add the previously removed <all_urls>
      result[0].urls.push("<all_urls>");
    }
    return result;
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

    // Block until the handler has been fully bound
    using _ = await this.#mutex.acquire(this.#requestLock);

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
      const cached = await this.#db.origins.get(
        CacheKey(details.state.fqdn, details.state.cachePartition),
      );
      const now = Math.floor(Date.now() / 1000);
      if (cached?.validUntil && cached.validUntil > now) {
        details.state.pendingOrigin = cached;
      }
    }

    // If no origin was available in cache, perform full validation;
    // for frames, this is done every time
    if (!details.state.pendingOrigin) {
      const result = await validateOrigin(this.#db, details, this.#config);
      if (result instanceof WebcatError) {
        if (details.state.isFrame) {
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

    // No origin state means the fqdn isn't enrolled
    if (!details.state.pendingOrigin) {
      return;
    }

    await this.#responseValidator.validateContent(details);
  }

  async #onHeaders(event: RequestEvent<HeadersReceivedDetails>) {
    using blockingResponse = event.blockingResponse;
    const details = event.details as Stateful<HeadersReceivedDetails>;

    // Extension requests (such as bundle fetches) must never redirect
    // cross-origin: cancel before the browser follows the Location header.
    // Same-origin hops land back here, so the whole chain is checked.
    if (isExtensionRequest(details)) {
      const location = details.responseHeaders?.find(
        (header) => header.name.toLowerCase() === "location",
      )?.value;
      if (location && !isSameOriginURL(location, details.url)) {
        return blockingResponse.set({ cancel: true });
      }
      return;
    }

    // Skip non-enrolled requests
    if (!details.state) {
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
      errorpage(details, result);
      return blockingResponse.set({ cancel: true });
    }

    await this.#commitVerifiedOrigin(
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
      details.state.pendingOrigin.manifest
    ) {
      const wasm = details.state.pendingOrigin.manifest.wasm;

      const listener = async (
        navDetails: browser.webNavigation._OnDOMContentLoadedDetails,
      ) => {
        if (navDetails.tabId !== details.tabId) return;
        if (navDetails.frameId !== details.frameId) return;

        browser.webNavigation.onDOMContentLoaded.removeListener(listener);

        const [func, args] = await this.#hooks.getContentScriptHooks(
          wasm,
          details.state.cachePartition.firstParty,
          details.state.cachePartition.firstParty ===
            new URL(details.url).origin,
        );
        await browser.scripting.executeScript({
          target: {
            tabId: details.tabId,
            frameIds: [details.frameId],
          },
          func,
          args,
          injectImmediately: true,
          world: "ISOLATED",
        });
      };

      browser.webNavigation.onDOMContentLoaded.addListener(listener);
    }

    return;
  }

  async #commitVerifiedOrigin(
    fqdn: string,
    newState: OriginState,
    cachePartition: CachePartition,
  ): Promise<void> {
    if (newState.stale) {
      return;
    }
    if (!newState.isManifestVerified()) {
      return;
    }
    const incoming = newState.manifest.version;
    const currentState = await this.#db.origins.get(
      CacheKey(fqdn, cachePartition),
    );
    if (currentState && currentState.isManifestVerified()) {
      const current = currentState.manifest.version;
      if (
        !isNewerSemver(incoming, current) &&
        currentState.validUntil >= newState.validUntil
      ) {
        return;
      }
    }
    await this.#db.origins.set(CacheKey(fqdn, cachePartition), newState);
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

  #onErrorPageNavigation(details: browser.webNavigation._OnCommittedDetails) {
    setErrorIcon(details.tabId);
  }

  async #onWindowClosed() {
    // Handle incognito sessions ending
    const windows = await browser.windows.getAll();
    if (windows.filter((win) => win.incognito).length === 0) {
      for (const key of await this.#db.origins.keys()) {
        if (isInPartition(key, { incognito: true })) {
          this.#db.origins.delete(key);
        }
      }
      for (const value of await this.#db.nonOrigins.values()) {
        if (isInPartition(value, { incognito: true })) {
          this.#db.nonOrigins.delete(value);
        }
      }
    }
  }
}
