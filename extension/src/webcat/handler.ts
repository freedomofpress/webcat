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

export type BeforeRequestDetails = browser.webRequest._OnBeforeRequestDetails;
export type BeforeHeadersDetails = BeforeRequestDetails &
  browser.webRequest._OnBeforeSendHeadersDetails;
export type HeadersReceivedDetails = BeforeHeadersDetails &
  browser.webRequest._OnHeadersReceivedDetails;
export type ErrorOccurredDetails = browser.webRequest._OnErrorOccurredDetails;
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
  #promise: Promise<BlockingResponse> | BlockingResponse = this;

  cancel?: boolean | undefined;
  redirectUrl?: string | undefined;
  upgradeToSecure?: boolean | undefined;
  requestHeaders?: browser.webRequest.HttpHeaders | undefined;
  responseHeaders?: browser.webRequest.HttpHeaders | undefined;
  authCredentials?:
    | browser.webRequest._BlockingResponseAuthCredentials
    | undefined;

  get [Symbol.dispose]() {
    const { promise, resolve } = Promise.withResolvers<void>();
    this.#promise = Promise.all([this.#promise, promise]).then(() => this);
    return () => {
      resolve();
    };
  }

  /**
   * @returns A Promise that resolves to this BlockingResponse after disposal.
   */
  async ready() {
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

  constructor(type: string, details: T) {
    super(type);
    this.details = details;
  }
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export interface RequestHandler extends EventTarget {
  addEventListener(
    type: "beforerequest",
    callback: (event: RequestEvent<BeforeRequestDetails>) => void,
  ): void;
  addEventListener(
    type: "beforeheaders",
    callback: (event: RequestEvent<BeforeHeadersDetails>) => void,
  ): void;
  addEventListener(
    type: "headersreceived",
    callback: (event: RequestEvent<HeadersReceivedDetails>) => void,
  ): void;
  addEventListener(
    type: "erroroccurred",
    callback: (event: RequestEvent<ErrorOccurredDetails>) => void,
  ): void;
  addEventListener(
    type: "completed",
    callback: (event: RequestEvent<CompletedDetails>) => void,
  ): void;
  addEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: AddEventListenerOptions | boolean,
  ): void;
}

/**
 * Handles web requests and responses for specific FQDNs. Manages the entire
 * lifecycle of a request and aggregates details such as request headers and
 * response headers to make them available in later stages.
 */
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export class RequestHandler extends EventTarget {
  static buildUrlPatterns(fqdns: string[]): string[] {
    const urls: string[] = [];
    for (const fqdn of fqdns) {
      urls.push(`http://${fqdn}/*`);
      urls.push(`https://${fqdn}/*`);
    }
    return urls;
  }

  readonly #details = new Map<string, RequestDetails>();

  #currentListeners: RegisteredListeners = {};

  /**
   * Binds the handler to the given list of FQDNs. When called, the handler
   * starts handling requests for the URLs in the list and stops handling
   * requests for any previously bound URLs that are not in the new list.
   *
   * @param urls A list of URL patterns to bind to.
   */
  bind(urls: string[]) {
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
    browser.webRequest.onBeforeRequest.addListener(before, { urls }, [
      "blocking",
    ]);
    browser.webRequest.onBeforeSendHeaders.addListener(
      beforeHeaders,
      { urls },
      ["blocking", "requestHeaders"],
    );
    browser.webRequest.onHeadersReceived.addListener(headers, { urls }, [
      "blocking",
      "responseHeaders",
    ]);
    browser.webRequest.onErrorOccurred.addListener(errorOccurred, { urls });
    browser.webRequest.onCompleted.addListener(completed, { urls });

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
      `[webcat] RequestHandler.bind: registered listeners for ${urls.length} URL(s)`,
    );
  }

  async #beforeRequest(
    details: BeforeRequestDetails,
  ): Promise<browser.webRequest.BlockingResponse> {
    details = Object.assign({}, details);
    this.#details.set(details.requestId, Object.assign({}, details));
    const event = new RequestEvent("beforerequest", details);
    this.dispatchEvent(event);
    return await event.blockingResponse.ready();
  }

  async #beforeHeaders(
    details: BeforeHeadersDetails,
  ): Promise<browser.webRequest.BlockingResponse> {
    details = Object.assign(
      this.#details.get(details.requestId) as BeforeRequestDetails,
      details,
    );
    const event = new RequestEvent("beforeheaders", details);
    this.dispatchEvent(event);
    return await event.blockingResponse.ready();
  }

  async #headersReceived(
    details: HeadersReceivedDetails,
  ): Promise<browser.webRequest.BlockingResponse> {
    details = Object.assign(
      this.#details.get(details.requestId) as BeforeRequestDetails,
      details,
    );
    const event = new RequestEvent("headersreceived", details);
    this.dispatchEvent(event);
    return await event.blockingResponse.ready();
  }

  #errorOccurred(details: ErrorOccurredDetails) {
    details = Object.assign(
      this.#details.get(details.requestId) as ErrorOccurredDetails,
      details,
    );
    const event = new RequestEvent("erroroccurred", details);
    this.dispatchEvent(event);
    this.#details.delete(details.requestId);
  }

  #completed(details: CompletedDetails) {
    details = Object.assign(
      this.#details.get(details.requestId) as HeadersReceivedDetails,
      details,
    );
    const event = new RequestEvent("completed", details);
    this.dispatchEvent(event);
    this.#details.delete(details.requestId);
  }
}
