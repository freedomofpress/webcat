import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  BlockingResponse,
  RequestDetails,
  RequestEvent,
  RequestHandler,
} from "../../src/browser/requests";

const mockWebRequest = {
  onBeforeRequest: {
    addListener: vi.fn(),
    removeListener: vi.fn(),
  },
  onBeforeSendHeaders: {
    addListener: vi.fn(),
    removeListener: vi.fn(),
  },
  onHeadersReceived: {
    addListener: vi.fn(),
    removeListener: vi.fn(),
  },
  onErrorOccurred: {
    addListener: vi.fn(),
    removeListener: vi.fn(),
  },
  onCompleted: {
    addListener: vi.fn(),
    removeListener: vi.fn(),
  },
};

(globalThis as Record<string, unknown>).browser = {
  webRequest: mockWebRequest,
};

describe("BlockingResponse", () => {
  let br: BlockingResponse;

  beforeEach(() => {
    br = new BlockingResponse();
  });

  it("should block until disposed in all scopes", async () => {
    const events = [];
    {
      events.push("entering sync scope");
      using _disposable = br;
      {
        events.push("entering nested scope");
        using _disposable = br;
        events.push("exiting nested scope");
      }
      (async () => {
        events.push("entering async scope");
        using _disposable = br;
        await new Promise((resolve) => {
          setTimeout(resolve, 100);
        });
        (async () => {
          events.push("entering nested async scope");
          using _disposable = br;
          await new Promise((resolve) => {
            setTimeout(resolve, 100);
          });
          events.push("exiting nested async scope");
        })();
        events.push("exiting async scope");
      })();
      events.push("exiting sync scope");
    }
    events.push("calling ready()");
    br.ready().then(() => events.push("resolved"));

    await expect(br.ready()).resolves.toBe(br);
    expect(events).toEqual([
      "entering sync scope",
      "entering nested scope",
      "exiting nested scope",
      "entering async scope",
      "exiting sync scope",
      "calling ready()",
      "entering nested async scope",
      "exiting async scope",
      "exiting nested async scope",
      "resolved",
    ]);
  });

  it("should not block when not used as a disposable", async () => {
    await expect(br.ready()).resolves.toBe(br);
  });

  it("should copy properties from any object passed to set", () => {
    const original = {
      responseHeaders: [{ name: "Server", value: "nginx" }],
      requestHeaders: [{ name: "X-Requested-With", value: "XMLHttpRequest" }],
      redirectUrl: "https://example.com/",
      cancal: false,
    };
    br.set(original);
    expect(br).toEqual(original);
  });
});

describe("RequestHandler", () => {
  let handler: RequestHandler;
  let beforeRequest: Set<(event: Record<string, unknown>) => void>;
  let beforeSendHeaders: Set<(event: Record<string, unknown>) => void>;
  let headersReceived: Set<(event: Record<string, unknown>) => void>;
  let errorOccurred: Set<(event: Record<string, unknown>) => void>;
  let completed: Set<(event: Record<string, unknown>) => void>;

  beforeEach(() => {
    beforeRequest = new Set();
    mockWebRequest.onBeforeRequest.addListener.mockImplementation(
      (listener: () => void) => {
        beforeRequest.add(listener);
      },
    );
    beforeSendHeaders = new Set();
    mockWebRequest.onBeforeSendHeaders.addListener.mockImplementation(
      (listener: () => void) => {
        beforeSendHeaders.add(listener);
      },
    );
    headersReceived = new Set();
    mockWebRequest.onHeadersReceived.addListener.mockImplementation(
      (listener: () => void) => {
        headersReceived.add(listener);
      },
    );
    errorOccurred = new Set();
    mockWebRequest.onErrorOccurred.addListener.mockImplementation(
      (listener: () => void) => {
        errorOccurred.add(listener);
      },
    );
    completed = new Set();
    mockWebRequest.onCompleted.addListener.mockImplementation(
      (listener: () => void) => {
        completed.add(listener);
      },
    );

    beforeSendHeaders = new Set();

    handler = new RequestHandler();
  });

  it("should register new listeners", () => {
    handler.bind(["example.com", "webcat.tech"]);

    const urls = [
      "http://example.com/*",
      "https://example.com/*",
      "http://webcat.tech/*",
      "https://webcat.tech/*",
    ];
    expect(mockWebRequest.onBeforeRequest.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
      ["blocking"],
    );
    expect(mockWebRequest.onBeforeSendHeaders.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
      ["blocking", "requestHeaders"],
    );
    expect(mockWebRequest.onHeadersReceived.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
      ["blocking", "responseHeaders"],
    );
    expect(mockWebRequest.onErrorOccurred.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
    );
    expect(mockWebRequest.onCompleted.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
    );
  });

  it("should unregister removed listeners", () => {
    handler.bind(["example.com", "example.org", "webcat.tech"]);
    handler.bind(["example.org"]);
    expect(mockWebRequest.onBeforeRequest.removeListener).toHaveBeenCalledWith(
      beforeRequest.values().next().value,
    );
    expect(
      mockWebRequest.onBeforeSendHeaders.removeListener,
    ).toHaveBeenCalledWith(beforeSendHeaders.values().next().value);
    expect(
      mockWebRequest.onHeadersReceived.removeListener,
    ).toHaveBeenCalledWith(headersReceived.values().next().value);
    expect(mockWebRequest.onErrorOccurred.removeListener).toHaveBeenCalledWith(
      errorOccurred.values().next().value,
    );
    expect(mockWebRequest.onCompleted.removeListener).toHaveBeenCalledWith(
      completed.values().next().value,
    );
  });

  it("should register added listeners", async () => {
    handler.bind(["example.com", "webcat.tech"]);
    handler.bind(["example.org"]);
    const urls = ["http://example.org/*", "https://example.org/*"];
    expect(mockWebRequest.onBeforeRequest.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
      ["blocking"],
    );
    expect(mockWebRequest.onBeforeSendHeaders.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
      ["blocking", "requestHeaders"],
    );
    expect(mockWebRequest.onHeadersReceived.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
      ["blocking", "responseHeaders"],
    );
    expect(mockWebRequest.onErrorOccurred.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
    );
    expect(mockWebRequest.onCompleted.addListener).toHaveBeenCalledWith(
      expect.any(Function),
      { urls },
    );
  });

  it("should reuse the details object in events when requestId matches", () => {
    handler.bind(["example.com"]);
    const detailsById = new Map<string, RequestDetails>();
    const listener = (event: RequestEvent<RequestDetails>) => {
      let details = detailsById.get(event.details.requestId);
      if (!details) {
        detailsById.set(event.details.requestId, event.details);
        details = event.details;
      }
      expect(event.details).toBe(details);
    };
    handler.addEventListener("beforerequest", listener);
    beforeRequest.values().next().value?.({
      requestId: "123",
    });
    handler.addEventListener("beforeheaders", listener);
    beforeSendHeaders.values().next().value?.({
      requestId: "123",
    });
    handler.addEventListener("headersreceived", listener);
    headersReceived.values().next().value?.({
      requestId: "123",
    });
    handler.addEventListener("completed", listener);
    completed.values().next().value?.({
      requestId: "123",
    });
    handler.addEventListener("beforerequest", listener);
    beforeRequest.values().next().value?.({
      requestId: "456",
    });
    handler.addEventListener("erroroccurred", listener);
    errorOccurred.values().next().value?.({
      requestId: "456",
    });
    expect(Array.from(detailsById.keys())).toEqual(["123", "456"]);
    expect(detailsById.get("123")).not.toBe(detailsById.get("456"));
  });
});
