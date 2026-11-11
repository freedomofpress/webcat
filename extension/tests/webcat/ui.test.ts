import { describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
    addEventListener: vi.fn(),
  },
}));

import { defaults } from "../../src/config";
import { WebcatDatabase } from "../../src/webcat/db";
import { WebcatUI } from "../../src/webcat/ui";

const mockQuery = vi.fn();
const mockGetAllFrames = vi.fn();
const mockDuplicate = vi.fn().mockResolvedValue({});
const mockRemove = vi.fn().mockResolvedValue(undefined);
const mockRemoveBrowsingData = vi.fn().mockResolvedValue(undefined);

vi.stubGlobal("browser", {
  storage: { session: { get: vi.fn().mockResolvedValue({}), set: vi.fn() } },
  webNavigation: {
    onCommitted: { addListener: vi.fn() },
    getAllFrames: mockGetAllFrames,
  },
  runtime: { getURL: vi.fn(), onConnect: { addListener: vi.fn() } },
  windows: { onRemoved: { addListener: vi.fn() } },
  browsingData: { remove: mockRemoveBrowsingData },
  tabs: {
    query: mockQuery,
    duplicate: mockDuplicate,
    remove: mockRemove,
    update: vi.fn().mockResolvedValue({}),
    onRemoved: { addListener: vi.fn() },
  },
});

vi.stubGlobal("window", {
  matchMedia: vi.fn().mockReturnValue({ matches: false }),
});

describe("WebcatUI.reloadTabsShowing", () => {
  const tabs = {
    // Top-level document of the host
    1: [{ frameId: 0, url: "https://enrolled.example/" }],
    // The host framed by another site
    2: [
      { frameId: 0, url: "https://other.example/" },
      { frameId: 3, url: "https://enrolled.example/widget" },
    ],
    // Unrelated
    3: [{ frameId: 0, url: "https://other.example/" }],
    // Discarded
    4: null,
  };

  it("replaces every tab with a document of the host in any frame", async () => {
    mockQuery.mockResolvedValue(
      Object.keys(tabs).map((id) => ({
        id: +id,
        url: tabs[id as unknown as keyof typeof tabs]?.[0].url,
        windowId: 9,
        index: +id,
        active: id === "1",
        pinned: false,
        cookieStoreId: "firefox-default",
      })),
    );
    mockGetAllFrames.mockImplementation(({ tabId }) =>
      Promise.resolve(tabs[tabId as keyof typeof tabs]),
    );
    const db = new WebcatDatabase(defaults);
    const ui = new WebcatUI(db, db.namespace("ui"), defaults);

    await ui.reloadTabsShowing(new Set(["enrolled.example"]));

    expect(mockRemove.mock.calls.map(([id]) => id).sort()).toEqual([1, 2]);
    expect(mockDuplicate.mock.calls.sort()).toEqual([
      [1, { active: true, index: 2 }],
      [2, { active: false, index: 3 }],
    ]);
    expect(mockRemoveBrowsingData).toHaveBeenCalledWith(
      { hostnames: ["enrolled.example"] },
      { serviceWorkers: true },
    );
  });

  it("does nothing when no tab shows the hosts", async () => {
    mockDuplicate.mockClear();
    mockRemoveBrowsingData.mockClear();
    mockQuery.mockResolvedValue([{ id: 3 }]);
    const db = new WebcatDatabase(defaults);
    const ui = new WebcatUI(db, db.namespace("ui"), defaults);

    await ui.reloadTabsShowing(new Set(["enrolled.example"]));

    expect(mockDuplicate).not.toHaveBeenCalled();
    expect(mockRemoveBrowsingData).not.toHaveBeenCalled();
  });
});
