import { NamespacedKVStore } from "../browser/kvstore";
import permissions from "../browser/permissions";
import {
  BeforeRequestDetails,
  HeadersReceivedDetails,
  RequestEvent,
  RequestHandler,
} from "../browser/requests";
import { ContentScript } from "../browser/scripting";
import { Mutex } from "../browser/sync";
import { CacheKey, isInPartition } from "./cache";
import { HookBuilder, HookBuilderConfig } from "./hookbuilder";
import { Database } from "./interfaces/database";
import { WebcatError } from "./interfaces/errors";
import { CachePartition, OriginState } from "./interfaces/originstate";
import { Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { BundleFetcherConfig } from "./originstate";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import { ResponseValidator } from "./response";
import { isNewerSemver } from "./semver";
import { WebcatUI } from "./ui";
import {
  clearBrowserCaches,
  getFQDN,
  isExtensionRequest,
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

@permissions.require("scripting")
@permissions.require("webNavigation")
@permissions.require("<all_urls>")
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export class WebcatRequestHandler extends RequestHandler {
  readonly #db: Database & NamespacedKVStore;
  readonly #ui: WebcatUI;
  readonly #config: BundleFetcherConfig;
  readonly #hooks: HookBuilder;
  readonly #contentScript: ContentScript;
  readonly #responseValidator: ResponseValidator;
  readonly #mutex = new Mutex();
  readonly #requestLock = this.#mutex.createLock();

  #bindLock? = this.#mutex.createLock();

  constructor(
    db: Database & NamespacedKVStore,
    ui: WebcatUI,
    config: BundleFetcherConfig & HookBuilderConfig,
  ) {
    super();
    this.#db = db;
    this.#ui = ui;
    this.#config = config;
    this.#hooks = new HookBuilder(ui, config);
    this.#contentScript = new ContentScript(this.#hooks.getStaticHookPath());
    this.#responseValidator = new ResponseValidator(
      this.#db,
      this.#ui,
      this.#hooks,
    );
    this.addEventListener("beforerequest", this.#onRequest);
    this.addEventListener("headersreceived", this.#onHeaders);
    browser.windows.onRemoved.addListener(this.#onWindowClosed.bind(this));

    // Block requests until first bind
    this.#mutex.acquire(this.#bindLock);
  }

  override async bind(fqdns: string[]) {
    // On first call, acquire #bindLock, locked in the constructor; on
    // subsequent calls, acquire a unique lock. This ensures request handling
    // doesn't run before the first bind and binds don't interleave each other.
    const lock = this.#bindLock;
    this.#bindLock = undefined;
    using _ = await this.#mutex.acquire(lock);

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
    for (let i: number; (i = fqdns.indexOf("<all_urls>")) !== -1;) {
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
          cookieStoreId: details.cookieStoreId ?? "firefox-default",
        },
        isFrame: FRAME_TYPES.includes(details.type),
      },
    });
  }

  async #onRequest(event: RequestEvent<BeforeRequestDetails>) {
    using blockingResponse = event.createBlockingResponse();
    if (isExtensionRequest(event.details)) {
      blockingResponse.cancel = false;
      return;
    }
    if (isThirdPartyWorkerScript(event.details)) {
      // There is no tab to read the first party from and webRequest does not
      // expose the partition the browser uses, so the origin state could only
      // be filed under the worker's own origin. Cancel the load instead.
      logger.info(`Cancelling third-party worker script ${event.details.url}`);
      blockingResponse.cancel = true;
      return;
    }
    let details: Stateful<BeforeRequestDetails>;
    try {
      details = await this.#initializeState(event.details);
    } catch (error) {
      // A request that cannot be attributed to a first party cannot be
      // partitioned, so it is not fetched
      logger.warn(
        `Unattributable request ${event.details.url}`,
        undefined,
        error,
      );
      return;
    }

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
      // A cancel from the beforeframeload listeners ends the request stage;
      // allowing is left to the checks below
      const frameResult = await beforeframeload.ready();
      if (frameResult.cancel) {
        return blockingResponse.set(frameResult);
      }
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
      const result = await validateOrigin(
        this.#db,
        this.#ui,
        details,
        this.#config,
      );
      if (result instanceof WebcatError) {
        if (details.state.isFrame) {
          this.#ui.showErrorPage(details, result);
        }
        return blockingResponse.set({ cancel: true });
      }
      if (result) {
        // HTTPS redirect; browser reissues under a fresh requestId.
        if (details.state.isFrame) {
          logger.info(`Redirecting to https`, details);
        }
        return blockingResponse.set({ ...result, cancel: false });
      }
    }

    // No origin state means the fqdn isn't enrolled
    if (!details.state.pendingOrigin) {
      blockingResponse.cancel = false;
      return;
    }

    await this.#responseValidator.validateContent(details);
    blockingResponse.cancel = false;
  }

  async #onHeaders(event: RequestEvent<HeadersReceivedDetails>) {
    using blockingResponse = event.createBlockingResponse();
    const details = event.details as Stateful<HeadersReceivedDetails>;

    // Extension requests (such as bundle fetches) must never redirect
    // cross-origin: cancel before the browser follows the Location header.
    // Same-origin hops land back here, so the whole chain is checked.
    if (isExtensionRequest(details)) {
      const location = details.responseHeaders?.find(
        (header) => header.name.toLowerCase() === "location",
      )?.value;
      if (location && !isSameOriginURL(location, details.url)) {
        return;
      }
      blockingResponse.cancel = false;
      return;
    }

    // Requests without state started before this background instance was
    // running, so #onRequest never saw them. That happens right after
    // startup, when bindAll has been called but bind hasn't yet: the
    // <all_urls> listener sees the headers of a non-enrolled origin's request
    // that was already in flight. It's extremely rare, but we shouldn't block.
    if (!details.state) {
      blockingResponse.cancel = false;
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
      this.#ui.showErrorPage(details, result);
      return blockingResponse.set({ cancel: true });
    }

    await this.#commitVerifiedOrigin(
      details.state.fqdn,
      details.state.pendingOrigin,
      details.state.cachePartition,
    );

    // Frame navigations only. Isolates same-site frames like cross-site ones
    // under most circumstances. Added when frames were allowed globally, see
    // https://github.com/freedomofpress/webcat/issues/237
    if (details.state.isFrame) {
      blockingResponse.setHeader("Origin-Agent-Cluster", "?1");
    }

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
    // - an enrolled main_frame might contain non enrolled sub_frames, and those should not receive any hooks

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

        const [func, args] = await this.#hooks.getContentScriptHooks(wasm);
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

    blockingResponse.cancel = false;
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
    // An opaque top-level document (about:blank, data:) is nobody's first
    // party; state loaded under one is kept to that request
    const originOf = (url: string) => {
      const origin = new URL(url).origin;
      return origin === "null" ? details.requestId : origin;
    };
    if (details.frameAncestors?.length) {
      // This is a request with frameAncestors; FPO is the origin of the topmost (last) ancestor
      return originOf(
        details.frameAncestors[details.frameAncestors.length - 1].url,
      );
    }
    if (details.type === "main_frame") {
      // Top-level navigation; FPO is the origin of the request URL
      return new URL(details.url).origin;
    }
    if (details.tabId !== -1) {
      // Subresource of a Worker, no frameAncestors. The first party of a
      // request bound to a tab is the tab's top-level document, so read it
      // from the tab rather than from documentUrl, which is the worker script.
      // Before bug 2048884 (fixed in Firefox 155, not in ESR 140 or 153, so
      // not in Tor Browser 15 or 16) these requests are reported under
      // frameId 0 even when the worker belongs to a cross-origin frame; since
      // the fix, a worker created by another worker is reported with
      // frameId -1 while keeping its tabId.
      // Rejects if the tab is gone, resolves null if it was discarded
      const frames = await browser.webNavigation.getAllFrames({
        tabId: details.tabId,
      });
      // The document that owns the request (a worker is same-origin with its
      // document) must still be in the tab, otherwise the tab has navigated
      // away and frame 0 belongs to the next site
      const owner = new URL(details.documentUrl ?? details.url).origin;
      if (
        frames &&
        (details.frameId === -1 ||
          frames.find((frame) => frame.frameId === details.frameId)) &&
        frames.some((frame) => new URL(frame.url).origin === owner)
      ) {
        // FPO is the origin of the frame with frameId === 0
        return originOf(frames.find((frame) => frame.frameId === 0)?.url || "");
      }
      throw new Error(`no live frame for '${details.url}'`);
    }
    if (details.documentUrl) {
      // No tab: a SharedWorker or ServiceWorker, or a script it loads.
      // Third-party ones are cancelled in #onRequest, so documentUrl is
      // first-party and its origin is the first party.
      return new URL(details.documentUrl).origin;
    }
    if (!details.thirdParty) {
      // No tab and no document, e.g. a ServiceWorker update check: the
      // browser reports it is not cross-site, so its own origin is the first party
      return new URL(details.url).origin;
    }
    throw new Error(`no first party for '${details.url}'`);
  }

  async #onWindowClosed() {
    // Handle incognito sessions ending
    const windows = await browser.windows.getAll();
    if (windows.filter((win) => win.incognito).length === 0) {
      for (const key of await this.#db.origins.keys()) {
        if (isInPartition(key, { cookieStoreId: "firefox-private" })) {
          this.#db.origins.delete(key);
        }
      }
      for (const value of await this.#db.nonOrigins.values()) {
        if (isInPartition(value, { cookieStoreId: "firefox-private" })) {
          this.#db.nonOrigins.delete(value);
        }
      }
    }
  }
}

/**
 * Whether a request is the script of a SharedWorker or ServiceWorker loading
 * in a third-party context: it has no tab, the browser flags it third-party,
 * and it is same-origin with the document that loads it. The last condition
 * excludes a first-party worker fetching another site, which is cross-origin.
 * Scripts imported by such a worker never load, since this cancels the
 * worker's main script first.
 */
function isThirdPartyWorkerScript(details: BeforeRequestDetails): boolean {
  return (
    details.tabId === -1 &&
    details.thirdParty === true &&
    details.documentUrl !== undefined &&
    new URL(details.url).origin === new URL(details.documentUrl).origin
  );
}
