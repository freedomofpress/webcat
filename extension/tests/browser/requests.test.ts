import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

import {
  BlockingResponse,
  HeadersReceivedDetails,
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

  it("should block until the using scope exits", async () => {
    const events: string[] = [];
    br.ready().then(() => events.push("resolved"));

    const { promise: gate, resolve: open } = Promise.withResolvers<void>();
    const listener = (async () => {
      using blockingResponse = br;
      await gate;
      blockingResponse.cancel = false;
      events.push("listener done");
    })();

    await Promise.resolve();
    expect(events).toEqual([]);

    open();
    await listener;
    await expect(br.ready()).resolves.toBe(br);
    expect(events).toEqual(["listener done", "resolved"]);
    expect(br.cancel).toBe(false);
  });

  it("should copy properties from any object passed to set", () => {
    const original = {
      responseHeaders: [{ name: "Server", value: "nginx" }],
      requestHeaders: [{ name: "X-Requested-With", value: "XMLHttpRequest" }],
      redirectUrl: "https://example.com/",
      cancal: false,
    };
    br.set(original);
    expect(br).toMatchObject(original);
  });

  it("should replace a response header, keeping the others", () => {
    const details = {
      responseHeaders: [
        { name: "origin-agent-cluster", value: "?0" },
        { name: "Origin-Agent-Cluster", value: "?1" },
        { name: "Content-Type", value: "text/html" },
      ],
    } as HeadersReceivedDetails;
    br = new BlockingResponse(details);
    br.setHeader("Origin-Agent-Cluster", "?1");
    expect(br.responseHeaders).toStrictEqual([
      { name: "Content-Type", value: "text/html" },
      { name: "Origin-Agent-Cluster", value: "?1" },
    ]);
    br.setHeader("X-Test", "1");
    expect(br.responseHeaders).toHaveLength(3);
    br = new BlockingResponse();
    br.setHeader("X-Test", "1");
    expect(br.responseHeaders).toStrictEqual([{ name: "X-Test", value: "1" }]);
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
    expect(detailsById.get("456")?.completed).rejects.toBeUndefined();
  });

  it("should mark RequestDetails as completed when the onCompleted event fires", async () => {
    handler.bind(["example.com"]);
    const promises: Promise<string>[] = [];
    const listener = (type: string) => {
      return (event: RequestEvent<RequestDetails>) => {
        promises.push(event.details.completed.then(() => type));
      };
    };
    handler.addEventListener("beforerequest", listener("beforerequest"));
    handler.addEventListener("beforeheaders", listener("beforeheaders"));
    handler.addEventListener("headersreceived", listener("headersreceived"));
    handler.addEventListener("completed", listener("completed"));
    beforeRequest.values().next().value?.({});
    beforeSendHeaders.values().next().value?.({});
    headersReceived.values().next().value?.({});
    completed.values().next().value?.({});

    await expect(Promise.all(promises)).resolves.toEqual([
      "beforerequest",
      "beforeheaders",
      "headersreceived",
      "completed",
    ]);
  });

  it("should mark RequestDetails as failed when the onErrorOccurred event fires", async () => {
    handler.bind(["example.com"]);
    const promises: Promise<string>[] = [];
    const listener = (type: string) => {
      return (event: RequestEvent<RequestDetails>) => {
        promises.push(event.details.completed.catch(() => type));
      };
    };
    handler.addEventListener("beforerequest", listener("beforerequest"));
    handler.addEventListener("beforeheaders", listener("beforeheaders"));
    handler.addEventListener("headersreceived", listener("headersreceived"));
    handler.addEventListener("erroroccurred", listener("erroroccurred"));
    beforeRequest.values().next().value?.({});
    beforeSendHeaders.values().next().value?.({});
    headersReceived.values().next().value?.({});
    errorOccurred.values().next().value?.({});

    await expect(Promise.all(promises)).resolves.toEqual([
      "beforerequest",
      "beforeheaders",
      "headersreceived",
      "erroroccurred",
    ]);
  });

  describe("fails closed", () => {
    const dispatch = () =>
      beforeRequest.values().next().value?.({ requestId: "1" }) as unknown;

    beforeEach(() => {
      handler.bind(["example.com"]);
    });

    it("cancels when a listener throws after creating its response", async () => {
      // A throw disposes the response with cancel still at its default.
      // Dispatched through EventTarget the exception would also be reported
      // as uncaught, which is fine in the browser but fails the test runner,
      // so the listener body is run directly here.
      const event = new RequestEvent("beforerequest", {} as RequestDetails);
      expect(() => {
        using _response = event.createBlockingResponse();
        throw new Error("boom");
      }).toThrow("boom");
      await expect(event.ready()).resolves.toMatchObject({ cancel: true });
    });

    it("cancels when one listener never allows and another allows later", async () => {
      handler.addEventListener("beforerequest", (event) => {
        using _response = event.createBlockingResponse();
      });
      handler.addEventListener("beforerequest", async (event) => {
        using blockingResponse = event.createBlockingResponse();
        await new Promise((resolve) => setTimeout(resolve, 10));
        blockingResponse.cancel = false;
      });
      await expect(dispatch()).resolves.toMatchObject({ cancel: true });
    });

    it("merges the responses when every listener allows", async () => {
      handler.addEventListener("beforerequest", (event) => {
        using blockingResponse = event.createBlockingResponse();
        blockingResponse.redirectUrl = "https://example.com/";
        blockingResponse.cancel = false;
      });
      handler.addEventListener("beforerequest", (event) => {
        using blockingResponse = event.createBlockingResponse();
        blockingResponse.cancel = false;
      });
      await expect(dispatch()).resolves.toEqual({
        cancel: false,
        redirectUrl: "https://example.com/",
      });
    });

    it("allows when no listener responds", async () => {
      await expect(dispatch()).resolves.toMatchObject({ cancel: false });
    });
  });
});
