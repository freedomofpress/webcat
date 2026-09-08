import { describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

import { defaults } from "../../src/config";
import { WebcatDatabase } from "../../src/webcat/db";
import { WebcatRequestHandler } from "../../src/webcat/handler";

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
});
