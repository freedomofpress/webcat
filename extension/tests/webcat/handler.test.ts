import { describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
    addEventListener: vi.fn(),
  },
}));

import { RequestDetailsBase, RequestEvent } from "../../src/browser/requests";
import { defaults } from "../../src/config";
import { WebcatDatabase } from "../../src/webcat/db";
import { WebcatRequestHandler } from "../../src/webcat/handler";
import { WebcatUI } from "../../src/webcat/ui";

const mockStorageGet = vi.fn().mockResolvedValue({});
const mockStorageSet = vi.fn();
const mockAddOnCommitted = vi.fn();
const mockGetURL = vi.fn();
const mockAddOnConnect = vi.fn();
const mockAddOnRemoved = vi.fn();
const mockAddOnBeforeRequest = vi.fn();
const mockRemoveOnBeforeRequest = vi.fn();
const mockAddOnBeforeSendHeaders = vi.fn();
const mockRemoveOnBeforeSendHeaders = vi.fn();
const mockAddOnHeadersReceived = vi.fn();
const mockRemoveOnHeadersReceived = vi.fn();
const mockAddOnErrorOccurred = vi.fn();
const mockRemoveOnErrorOccurred = vi.fn();
const mockAddOnCompleted = vi.fn();
const mockRemoveOnCompleted = vi.fn();
const mockGetRegisteredConentScripts = vi.fn().mockResolvedValue([]);
const mockRegisterContentScripts = vi.fn();
const mockUnregisterContentScripts = vi.fn();
const mockRemoveBrowsingData = vi.fn();
const mockGetAllFrames = vi.fn();

vi.stubGlobal("browser", {
  storage: {
    session: {
      get: mockStorageGet,
      set: mockStorageSet,
    },
  },
  webNavigation: {
    onCommitted: {
      addListener: mockAddOnCommitted,
    },
    getAllFrames: mockGetAllFrames,
  },
  runtime: {
    getURL: mockGetURL,
    onConnect: {
      addListener: mockAddOnConnect,
    },
  },
  windows: {
    onRemoved: {
      addListener: mockAddOnRemoved,
    },
  },
  webRequest: {
    onBeforeRequest: {
      addListener: mockAddOnBeforeRequest,
      removeListener: mockRemoveOnBeforeRequest,
    },
    onBeforeSendHeaders: {
      addListener: mockAddOnBeforeSendHeaders,
      removeListener: mockRemoveOnBeforeSendHeaders,
    },
    onHeadersReceived: {
      addListener: mockAddOnHeadersReceived,
      removeListener: mockRemoveOnHeadersReceived,
    },
    onErrorOccurred: {
      addListener: mockAddOnErrorOccurred,
      removeListener: mockRemoveOnErrorOccurred,
    },
    onCompleted: {
      addListener: mockAddOnCompleted,
      removeListener: mockRemoveOnCompleted,
    },
  },
  scripting: {
    getRegisteredContentScripts: mockGetRegisteredConentScripts,
    registerContentScripts: mockRegisterContentScripts,
    unregisterContentScripts: mockUnregisterContentScripts,
  },
  browsingData: {
    remove: mockRemoveBrowsingData,
  },
  tabs: {
    update: vi.fn().mockResolvedValue({}),
  },
});

vi.stubGlobal("window", {
  matchMedia: vi.fn().mockReturnValue({ matches: false }),
});

describe("WebcatRequestHandler", () => {
  it("should bind atomically", async () => {
    // Mock browser.scripting.getRegisteredContentScripts so that the first
    // call gets delayed and only resolves after the second.
    mockGetRegisteredConentScripts
      .mockImplementationOnce(() => {
        return {
          then(f: (x: unknown) => void) {
            queueMicrotask(() => f([]));
          },
        };
      })
      .mockImplementationOnce(() => {
        return {
          then(f: (x: unknown) => void) {
            f([]);
          },
        };
      });

    // Race two bind calls
    const db = new WebcatDatabase(defaults);
    const ui = new WebcatUI(db, db.namespace("ui"), defaults);
    const wrh = new WebcatRequestHandler(db, ui, defaults);
    const bind1 = wrh.bind(["example.com"]);
    const bind2 = wrh.bind(["example.org"]);
    await Promise.all([bind1, bind2]);

    // Check the mock call order
    expect(mockRegisterContentScripts).toHaveBeenCalledTimes(2);
    expect(
      mockRegisterContentScripts.mock.calls[0][0][0].matches,
    ).toStrictEqual(["http://example.com/*", "https://example.com/*"]);
    expect(
      mockRegisterContentScripts.mock.calls[1][0][0].matches,
    ).toStrictEqual(["http://example.org/*", "https://example.org/*"]);
  });

  it("should keep its verdict when an embedder listener allows the request later", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    const db = new WebcatDatabase(defaults);
    const ui = new WebcatUI(db, db.namespace("ui"), defaults);
    const wrh = new WebcatRequestHandler(db, ui, defaults);
    // An embedding extension adds its own policy check on the same event;
    // it is satisfied and allows, finishing after WEBCAT rejected the response
    wrh.addEventListener("headersreceived", async (event) => {
      using blockingResponse = event.createBlockingResponse();
      await new Promise((resolve) => setTimeout(resolve, 20));
      blockingResponse.cancel = false;
    });
    // No responseHeaders: WEBCAT's header validation fails with HEADERS_MISSING
    const details = Object.assign(new RequestDetailsBase(), {
      requestId: "1",
      tabId: 7,
      url: "https://example.com/",
      state: { fqdn: "example.com", isFrame: true, pendingOrigin: {} },
    });
    const event = new RequestEvent("headersreceived", details as never);
    wrh.dispatchEvent(event);

    await expect(event.ready()).resolves.toMatchObject({ cancel: true });
    errorLog.mockRestore();
  });

  it("partitions origin state by container", async () => {
    const db = new WebcatDatabase(defaults);
    const ui = new WebcatUI(db, db.namespace("ui"), defaults);
    const wrh = new WebcatRequestHandler(db, ui, defaults);
    mockGetAllFrames.mockResolvedValue([
      { frameId: 0, url: "https://embedder.example/page" },
    ]);
    const details = Object.assign(new RequestDetailsBase(), {
      requestId: "2",
      tabId: 7,
      frameId: 5,
      type: "script",
      url: "https://enrolled.example/app.js",
      documentUrl: "https://enrolled.example/",
      frameAncestors: [{ url: "https://embedder.example/page", frameId: 0 }],
      cookieStoreId: "firefox-container-2",
    }) as RequestDetailsBase & {
      state?: { cachePartition: { firstParty: string; cookieStoreId: string } };
    };
    wrh.dispatchEvent(new RequestEvent("beforerequest", details as never));

    await vi.waitFor(() => expect(details.state).toBeDefined());
    expect(details.state?.cachePartition).toMatchObject({
      firstParty: "https://embedder.example",
      cookieStoreId: "firefox-container-2",
    });
  });

  it("cancels a request it cannot attribute to a first party", async () => {
    mockGetAllFrames.mockRejectedValue(new Error("Invalid tab ID: 7"));
    const db = new WebcatDatabase(defaults);
    const ui = new WebcatUI(db, db.namespace("ui"), defaults);
    const wrh = new WebcatRequestHandler(db, ui, defaults);
    const details = Object.assign(new RequestDetailsBase(), {
      requestId: "6",
      tabId: 7,
      frameId: 0,
      type: "script",
      url: "https://enrolled.example/workers/import.js",
      documentUrl: "https://enrolled.example/workers/worker.js",
    });
    const event = new RequestEvent("beforerequest", details as never);
    wrh.dispatchEvent(event);

    await expect(event.ready()).resolves.toMatchObject({ cancel: true });
  });

  it("lets a first-party worker script through to attribution", async () => {
    const db = new WebcatDatabase(defaults);
    const ui = new WebcatUI(db, db.namespace("ui"), defaults);
    const wrh = new WebcatRequestHandler(db, ui, defaults);
    const details = Object.assign(new RequestDetailsBase(), {
      requestId: "4",
      tabId: -1,
      frameId: -1,
      type: "script",
      thirdParty: false,
      url: "https://enrolled.example/workers/shared.js",
      documentUrl: "https://enrolled.example/",
    }) as RequestDetailsBase & {
      state?: { cachePartition: { firstParty: string } };
    };
    wrh.dispatchEvent(new RequestEvent("beforerequest", details as never));

    await vi.waitFor(() => expect(details.state).toBeDefined());
    expect(details.state?.cachePartition.firstParty).toBe(
      "https://enrolled.example",
    );
  });

  it("refuses the script of a worker running in a third-party context", async () => {
    const db = new WebcatDatabase(defaults);
    const ui = new WebcatUI(db, db.namespace("ui"), defaults);
    const wrh = new WebcatRequestHandler(db, ui, defaults);
    // A SharedWorker created by enrolled.example while embedded cross-site:
    // no tab, flagged third-party, same-origin with its document
    const details = Object.assign(new RequestDetailsBase(), {
      requestId: "3",
      tabId: -1,
      frameId: -1,
      type: "script",
      thirdParty: true,
      url: "https://enrolled.example/workers/shared.js",
      documentUrl: "https://enrolled.example/",
    });
    const event = new RequestEvent("beforerequest", details as never);
    wrh.dispatchEvent(event);

    await expect(event.ready()).resolves.toMatchObject({ cancel: true });
  });
});
