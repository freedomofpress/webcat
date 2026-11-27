import { NamespacedKVStore } from "../browser/kvstore";
import permissions from "../browser/permissions";
import {
  BeforeRequestDetails,
  HeadersReceivedDetails,
  RequestDetails,
  RequestEvent,
  RequestHandler,
} from "../browser/requests";
import { ContentScript } from "../browser/scripting";
import { Mutex } from "../browser/sync";
import { CacheKey, isInPartition, parseCacheKey } from "./cache";
import {
  getAllFrames,
  isThirdPartyWorkerScript,
  resolveFirstParty,
} from "./firstparty";
import { HookBuilder, HookBuilderConfig } from "./hookbuilder";
import { Database } from "./interfaces/database";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { CachePartition, OriginState } from "./interfaces/originstate";
import { Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { BundleFetcherConfig } from "./originstate";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import { fetchDestination, ResponseValidator } from "./response";
import { isNewerSemver } from "./semver";
import { WebcatUI } from "./ui";
import {
  clearBrowserCaches,
  getFQDN,
  isExtensionRequest,
  isSameOriginURL,
} from "./utils";
import { WorkerRegistry } from "./workers";

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
@permissions.require("history")
@permissions.require("publicSuffix")
@permissions.require("<all_urls>")
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export class WebcatRequestHandler extends RequestHandler {
  readonly #db: Database & NamespacedKVStore;
  readonly #ui: WebcatUI;
  readonly #config: BundleFetcherConfig;
  readonly #hooks: HookBuilder;
  readonly #contentScript: ContentScript;
  readonly #responseValidator: ResponseValidator;
  readonly #workers: WorkerRegistry;
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
    this.#workers = new WorkerRegistry(db.namespace("workers"));
    this.addEventListener("beforerequest", this.#guarded(this.#onRequest));
    this.addEventListener("headersreceived", this.#guarded(this.#onHeaders));
    browser.windows.onRemoved.addListener(this.#onWindowClosed.bind(this));
    browser.history.onVisitRemoved.addListener(this.#onVisitRemoved.bind(this));
    // History may have been cleared while the extension was not running.
    void this.#onVisitRemoved({ allHistory: false, urls: [] });
    browser.webNavigation.onCommitted.addListener(({ tabId, frameId }) => {
      if (frameId === 0) void this.#workers.navigated(tabId);
    });
    browser.tabs.onRemoved.addListener(
      (tabId) => void this.#workers.forget(tabId),
    );

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
          firstParty: await resolveFirstParty(
            details,
            getAllFrames,
            this.#db,
            this.#workers,
          ),
          cookieStoreId: details.cookieStoreId ?? "firefox-default",
        },
        isFrame: FRAME_TYPES.includes(details.type),
      },
    });
  }

  #guarded<T extends RequestDetails>(
    listener: (event: RequestEvent<T>) => Promise<void>,
  ) {
    return async (event: RequestEvent<T>) => {
      try {
        await listener.call(this, event);
      } catch (error) {
        const details = event.details as Stateful<RequestDetails>;
        const attributed = "state" in details ? details : undefined;
        logger.error(
          `Unexpected error handling ${details.url}`,
          attributed,
          error,
        );
        if (attributed?.state.isFrame) {
          this.#ui.showErrorPage(
            attributed,
            new WebcatError(WebcatErrorCode.Internal.UNEXPECTED, [
              String(error),
            ]),
          );
        }
      }
    };
  }

  async #onRequest(event: RequestEvent<BeforeRequestDetails>) {
    using blockingResponse = event.createBlockingResponse();
    if (isExtensionRequest(event.details)) {
      blockingResponse.cancel = false;
      return;
    }
    if (isThirdPartyWorkerScript(event.details)) {
      // No tab and missing first party: nothing to partition under
      logger.info(`Cancelling third-party worker script ${event.details.url}`);
      blockingResponse.cancel = true;
      return;
    }
    let details: Stateful<BeforeRequestDetails>;
    try {
      details = await this.#initializeState(event.details);
    } catch (error) {
      // Everything is missing
      logger.warn(
        `Unattributable request ${event.details.url}`,
        undefined,
        error,
      );
      return;
    }
    logger.debug(
      `Attributed ${details.url} to ${details.state.cachePartition.firstParty}`,
      details,
    );

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

    if (details.tabId !== -1 && fetchDestination(details) === "worker") {
      // Before the body reaches the worker, so its loads find the record
      await this.#workers.record(
        details.tabId,
        details.url,
        details.state.cachePartition.firstParty,
      );
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

    this.#responseValidator.markContent(details);

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

        const [func, args] = this.#hooks.getContentScriptHooks(wasm);
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

  // Forgets cached state and baselines the user's history no longer covers.
  async #onVisitRemoved({
    allHistory,
    urls,
  }: browser.history._OnVisitRemovedRemoved) {
    if (allHistory) {
      await this.#db.origins.clear();
      await this.#db.nonOrigins.clear();
      await this.#db.baselines.clear();
      return;
    }
    try {
      // Firefox forgets a site by its registrable domain, with IPs and
      // unknown suffixes taken as they come.
      const site = (host: string) =>
        browser.publicSuffix.getDomain(host, {
          allowIPAddress: true,
          allowUnknownSuffix: true,
          allowPlainSuffix: true,
        }) ?? host;
      // file: and about: pages have no host, which getDomain rejects.
      const removed = urls
        .map((url) => new URL(url).hostname)
        .filter(Boolean)
        .map(site);
      // Places matches text against URLs and titles, so filter by site.
      const inHistory = new Map<string, Promise<boolean>>();
      const stillVisited = (s: string) => {
        let known = inHistory.get(s);
        if (!known) {
          known = browser.history
            .search({ text: s, startTime: 0, maxResults: 1000 })
            .then((items) =>
              items.some((i) => i.url && site(new URL(i.url).hostname) === s),
            );
          inHistory.set(s, known);
        }
        return known;
      };
      // We delete an entry when the site the user was on has no page left in
      // history, or when the enrolled site itself was in the event and has no
      // page left either. Embedded origins have no pages of their own, so
      // only the first rule ever reaches them.
      const forgotten = async (key: CacheKey<CachePartition>) => {
        // The first party of an opaque origin is a request id, not a URL.
        const [fqdn, { firstParty }] = parseCacheKey(key);
        const top = URL.parse(firstParty)?.hostname;
        return (
          (removed.includes(site(fqdn)) && !(await stillVisited(site(fqdn)))) ||
          (top !== undefined && !(await stillVisited(site(top))))
        );
      };
      for (const key of await this.#db.origins.keys()) {
        if (await forgotten(key)) await this.#db.origins.delete(key);
      }
      for (const key of await this.#db.nonOrigins.values()) {
        if (await forgotten(key)) await this.#db.nonOrigins.delete(key);
      }
      for (const key of await this.#db.baselines.getKeys()) {
        if (await forgotten(key as CacheKey<CachePartition>)) {
          await this.#db.baselines.remove(key);
        }
      }
    } catch (error) {
      // Forgetting too much beats keeping what the user deleted.
      logger.warn(
        "History purge failed, clearing everything",
        undefined,
        error,
      );
      await this.#onVisitRemoved({ allHistory: true, urls: [] });
    }
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
      await this.#db.baselines.clear("", "session");
    }
  }
}
