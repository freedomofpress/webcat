import { describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
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
const mockTabsUpdate = vi.fn().mockResolvedValue({});

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
    update: mockTabsUpdate,
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
    const wrh = new WebcatRequestHandler(
      new WebcatDatabase(defaults),
      new WebcatUI(defaults),
      defaults,
    );
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

  it("should fail closed with an error page when a listener throws", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    const wrh = new WebcatRequestHandler(
      new WebcatDatabase(defaults),
      new WebcatUI(defaults),
      defaults,
    );
    // The headersreceived listener throws on state without a pendingOrigin
    const details = Object.assign(new RequestDetailsBase(), {
      requestId: "1",
      tabId: 7,
      url: "https://example.com/",
      state: { fqdn: "example.com", isFrame: true },
    });
    const event = new RequestEvent("headersreceived", details as never);
    wrh.dispatchEvent(event);

    await expect(event.blockingResponse.ready()).resolves.toMatchObject({
      cancel: true,
    });
    expect(mockTabsUpdate).toHaveBeenCalledWith(
      7,
      expect.objectContaining({
        url: expect.stringContaining("ERR_WEBCAT_INTERNAL_UNEXPECTED"),
      }),
    );
    errorLog.mockRestore();
  });
});
