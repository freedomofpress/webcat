import { buildUrlPatterns } from "./utils";

type RegisteredListeners = {
  before?: (
    details: browser.webRequest._OnBeforeRequestDetails,
  ) => Promise<browser.webRequest.BlockingResponse>;
  beforeHeaders?: (
    details: browser.webRequest._OnBeforeSendHeadersDetails,
  ) => Promise<browser.webRequest.BlockingResponse>;
  headers?: (
    details: browser.webRequest._OnHeadersReceivedDetails,
  ) => Promise<browser.webRequest.BlockingResponse>;
  errorOccurred?: (details: browser.webRequest._OnErrorOccurredDetails) => void;
  completed?: (details: browser.webRequest._OnCompletedDetails) => void;
};

/** @internal */
export class RequestDetailsBase {
  /**
   * Resolved when the request completes or rejected if a network error occurs.
   */
  readonly completed: Promise<void>;

  #resolve: () => void;
  #reject: () => void;

  constructor() {
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    this.completed = promise;
    this.#resolve = resolve;
    this.#reject = reject;
  }

  /** @internal */
  complete() {
    this.#resolve();
  }

  /** @internal */
  fail() {
    this.#reject();
  }
}

/** @interface */
export type BeforeRequestDetails = RequestDetailsBase &
  browser.webRequest._OnBeforeRequestDetails;
/** @interface */
export type BeforeHeadersDetails = BeforeRequestDetails &
  browser.webRequest._OnBeforeSendHeadersDetails;
/** @interface */
export type HeadersReceivedDetails = BeforeHeadersDetails &
  browser.webRequest._OnHeadersReceivedDetails;
/** @interface */
export type ErrorOccurredDetails = BeforeRequestDetails &
  browser.webRequest._OnErrorOccurredDetails;
/** @interface */
export type CompletedDetails = HeadersReceivedDetails &
  browser.webRequest._OnCompletedDetails;
export type RequestDetails =
  | BeforeHeadersDetails
  | BeforeHeadersDetails
  | HeadersReceivedDetails
  | ErrorOccurredDetails
  | CompletedDetails;

/**
 * The return value for a blocking {@link RequestEvent}. Implements the
 * {@link Disposable} interface. To return a value using a BlockingResponse
 * instance, a synchronous handler may simply assign values to it, or use the
 * {@link set} method. To return a value from an asynchronous handler, include
 * a {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/using using declaration}
 * before the first await expression.
 *
 * @example
 * handler.addEventListener("beforeheaders", async (event) => {
 *  using blockingResponse = event.blockingResponse;
 *  try {
 *    await doSomething(event.details);
 *  } catch {
 *    blockingResponse.cancel = true;
 *  }
 * });
 */
export class BlockingResponse
  implements browser.webRequest.BlockingResponse, Disposable
{
  #promise: Promise<BlockingResponse>;
  #resolve: (br: BlockingResponse) => void;
  #pendingScopes: number;

  cancel?: boolean | undefined;
  redirectUrl?: string | undefined;
  upgradeToSecure?: boolean | undefined;
  requestHeaders?: browser.webRequest.HttpHeaders | undefined;
  responseHeaders?: browser.webRequest.HttpHeaders | undefined;
  authCredentials?:
    | browser.webRequest._BlockingResponseAuthCredentials
    | undefined;

  constructor() {
    const { promise, resolve } = Promise.withResolvers<BlockingResponse>();
    this.#promise = promise;
    this.#resolve = resolve;
    this.#pendingScopes = 0;
  }

  /**
   * Implements the {@link Disposable} interface.
   */
  get [Symbol.dispose]() {
    this.#pendingScopes++;
    const disposed = false;
    return () => {
      if (disposed) {
        return;
      }
      this.#pendingScopes--;
      if (this.#pendingScopes === 0) {
        this.#resolve(this);
      }
    };
  }

  /**
   * @returns A Promise that resolves to this BlockingResponse after disposal.
   */
  async ready() {
    if (this.#pendingScopes === 0) {
      this.#resolve(this);
    }
    return await this.#promise;
  }

  /**
   * @param value An object whose properties are copied to this BlockingResponse.
   */
  set(value: browser.webRequest.BlockingResponse) {
    Object.assign(this, value);
  }
}

if (!Symbol.dispose) {
  // Workaround for a bug in TypeScript downleveling
  const { get } = Object.getOwnPropertyDescriptor(
    BlockingResponse.prototype,
    Symbol.dispose,
  ) as PropertyDescriptor;
  Object.defineProperty(
    BlockingResponse.prototype,
    Symbol.for("Symbol.dispose"),
    { get },
  );
  delete BlockingResponse.prototype[Symbol.dispose];
}

/**
 * Event type for events dispatched by RequestHandlers.
 */
export class RequestEvent<T extends RequestDetails> extends Event {
  /**
   * Details of the request this event concerns.
   */
  readonly details: T;

  /**
   * A {@link BlockingResponse} instance that can be used to respond to this
   * event.
   */
  readonly blockingResponse = new BlockingResponse();

  /** @internal */
  constructor(type: string, details: T) {
    super(type);
    this.details = details;
  }
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export interface RequestHandler extends EventTarget {
  addEventListener: EventTarget["addEventListener"] &
    ((
      type: "beforerequest",
      callback: (event: RequestEvent<BeforeRequestDetails>) => void,
    ) => void) &
    ((
      type: "beforeheaders",
      callback: (event: RequestEvent<BeforeHeadersDetails>) => void,
    ) => void) &
    ((
      type: "headersreceived",
      callback: (event: RequestEvent<HeadersReceivedDetails>) => void,
    ) => void) &
    ((
      type: "erroroccurred",
      callback: (event: RequestEvent<ErrorOccurredDetails>) => void,
    ) => void) &
    ((
      type: "completed",
      callback: (event: RequestEvent<CompletedDetails>) => void,
    ) => void);
}

/**
 * Handles web requests and responses for specific FQDNs. Manages the entire
 * lifecycle of a request and aggregates details such as request headers and
 * response headers to make them available in later stages.
 */
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export class RequestHandler extends EventTarget {
  readonly #details = new Map<string, RequestDetails>();

  #currentListeners: RegisteredListeners = {};

  /**
   * Binds the handler to the given list of FQDNs. When called, the handler
   * starts handling requests for the FQDNs in the list and stops handling
   * requests for any previously bound FQDNs that are not in the new list.
   *
   * @param fqdns A list of fully-qualified domain names to bind to.
   */
  bind(fqdns: string[]) {
    // The registration needs to be different from the existing one
    const before = (details: browser.webRequest._OnBeforeRequestDetails) =>
      this.#beforeRequest(details);
    const beforeHeaders = (
      details: browser.webRequest._OnBeforeSendHeadersDetails,
    ) => this.#beforeHeaders(details);
    const headers = (details: browser.webRequest._OnHeadersReceivedDetails) =>
      this.#headersReceived(details);
    const errorOccurred = (
      details: browser.webRequest._OnErrorOccurredDetails,
    ) => this.#errorOccurred(details);
    const completed = (details: browser.webRequest._OnCompletedDetails) =>
      this.#completed(details);

    // Add new listeners first, then remove the old ones
    browser.webRequest.onBeforeRequest.addListener(
      before,
      ...this.getListenerOptions(fqdns, "beforerequest"),
    );
    browser.webRequest.onBeforeSendHeaders.addListener(
      beforeHeaders,
      ...this.getListenerOptions(fqdns, "beforeheaders"),
    );
    browser.webRequest.onHeadersReceived.addListener(
      headers,
      ...this.getListenerOptions(fqdns, "headersreceived"),
    );
    browser.webRequest.onErrorOccurred.addListener(
      errorOccurred,
      ...this.getListenerOptions(fqdns, "erroroccurred"),
    );
    browser.webRequest.onCompleted.addListener(
      completed,
      ...this.getListenerOptions(fqdns, "completed"),
    );

    const previous = this.#currentListeners;
    this.#currentListeners = {
      before,
      beforeHeaders,
      headers,
      errorOccurred,
      completed,
    };
    if (previous.before) {
      browser.webRequest.onBeforeRequest.removeListener(previous.before);
    }
    if (previous.beforeHeaders) {
      browser.webRequest.onBeforeSendHeaders.removeListener(
        previous.beforeHeaders,
      );
    }
    if (previous.headers) {
      browser.webRequest.onHeadersReceived.removeListener(previous.headers);
    }
    if (previous.errorOccurred) {
      browser.webRequest.onErrorOccurred.removeListener(previous.errorOccurred);
    }
    if (previous.completed) {
      browser.webRequest.onCompleted.removeListener(previous.completed);
    }

    console.log(
      `[webcat] RequestHandler.bind: registered listeners for ${fqdns.length} URL(s)`,
    );
  }

  /** @internal */
  protected getListenerOptions(fqdns: string[], type: "beforerequest"): [browser.webRequest.RequestFilter, browser.webRequest.OnBeforeRequestOptions[]]; // prettier-ignore
  /** @internal */
  protected getListenerOptions(fqdns: string[], type: "beforeheaders"): [browser.webRequest.RequestFilter, browser.webRequest.OnBeforeSendHeadersOptions[]]; // prettier-ignore
  /** @internal */
  protected getListenerOptions(fqdns: string[], type: "headersreceived"): [browser.webRequest.RequestFilter, browser.webRequest.OnHeadersReceivedOptions[]]; // prettier-ignore
  /** @internal */
  protected getListenerOptions(fqdns: string[], type: "erroroccurred" | "completed"): [browser.webRequest.RequestFilter]; // prettier-ignore
  /**
   * Returns a tuple consisting of a request filter and an optional options
   * array, used when registering webRequest listeners. Overriding this method
   * allows changing the registration behavior.
   *
   * @param fqdns Fully-qualified domain names to handle requests for.
   * @param type The type of event to handle.
   */
  protected getListenerOptions(fqdns: string[], type: string): [browser.webRequest.RequestFilter] | [browser.webRequest.RequestFilter, (browser.webRequest.OnBeforeRequestOptions[] | browser.webRequest.OnBeforeSendHeadersOptions[] | browser.webRequest.OnHeadersReceivedOptions[])]; // prettier-ignore
  protected getListenerOptions(fqdns: string[], type: string) {
    const urls = buildUrlPatterns(fqdns);
    switch (type) {
      case "beforerequest":
        return [{ urls }, ["blocking"]];
      case "beforeheaders":
        return [{ urls }, ["blocking", "requestHeaders"]];
      case "headersreceived":
        return [{ urls }, ["blocking", "responseHeaders"]];
      case "erroroccurred":
      case "completed":
        return [{ urls }];
      default:
        throw new TypeError(`unrecognized handler type '${type}'`);
    }
  }

  async #beforeRequest(
    d: browser.webRequest._OnBeforeRequestDetails,
  ): Promise<browser.webRequest.BlockingResponse> {
    const details = Object.assign(new RequestDetailsBase(), d);
    this.#details.set(details.requestId, details);
    const event = new RequestEvent("beforerequest", details);
    this.dispatchEvent(event);
    return await event.blockingResponse.ready();
  }

  async #beforeHeaders(
    d: browser.webRequest._OnBeforeSendHeadersDetails,
  ): Promise<browser.webRequest.BlockingResponse> {
    const base = this.#details.get(d.requestId) ?? new RequestDetailsBase();
    const details = Object.assign(base, d);
    const event = new RequestEvent("beforeheaders", details);
    this.dispatchEvent(event);
    return await event.blockingResponse.ready();
  }

  async #headersReceived(
    d: browser.webRequest._OnHeadersReceivedDetails,
  ): Promise<browser.webRequest.BlockingResponse> {
    const base = this.#details.get(d.requestId) ?? new RequestDetailsBase();
    const details = Object.assign(base, d);
    const event = new RequestEvent("headersreceived", details);
    this.dispatchEvent(event);
    return await event.blockingResponse.ready();
  }

  #errorOccurred(d: browser.webRequest._OnErrorOccurredDetails) {
    const base = this.#details.get(d.requestId) ?? new RequestDetailsBase();
    const details = Object.assign(base, d);
    details.fail();
    const event = new RequestEvent("erroroccurred", details);
    this.dispatchEvent(event);
    this.#details.delete(details.requestId);
  }

  #completed(d: browser.webRequest._OnCompletedDetails) {
    const base = this.#details.get(d.requestId) ?? new RequestDetailsBase();
    const details = Object.assign(base, d);
    details.complete();
    const event = new RequestEvent("completed", details);
    this.dispatchEvent(event);
    this.#details.delete(details.requestId);
  }
}
