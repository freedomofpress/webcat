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
  },
  runtime: {
    getURL: mockGetURL,
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
    const wrh = new WebcatRequestHandler(
      new WebcatDatabase(defaults),
      new WebcatUI(defaults),
      defaults,
    );
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
});
