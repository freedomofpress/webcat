import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CHECK_INTERVAL_MS, UPDATE_INTERVAL_MS } from "../../src/config";
import {
  handleUpdateAlarm,
  initializeScheduledUpdates,
  retryUpdateIfFailed,
  shouldDoScheduledUpdate,
  update,
} from "../../src/webcat/update";

// Mock the heavy crypto dependencies
vi.mock("@freedomofpress/cometbft/dist/commit", () => ({
  importCommit: vi.fn(() => ({ header: {} })),
}));

vi.mock("@freedomofpress/cometbft/dist/lightclient", () => ({
  verifyCommit: vi.fn(() => ({
    ok: true,
    appHash: new Uint8Array([1, 2, 3]),
    headerTime: { seconds: 1000n },
  })),
}));

vi.mock("@freedomofpress/cometbft/dist/validators", () => ({
  importValidators: vi.fn(() => ({
    proto: {},
    cryptoIndex: {},
  })),
}));

vi.mock("@freedomofpress/ics23/dist/webcat", () => ({
  verifyWebcatProof: vi.fn(() => [["example.com", "abc123"]]),
}));

vi.mock("../../src/webcat/encoding", () => ({
  hexToUint8Array: vi.fn(() => new Uint8Array([1, 2, 3])),
  Uint8ArrayToBase64: vi.fn(() => "AQID"),
}));

vi.mock("../../src/webcat/utils", () => ({
  arraysEqual: vi.fn(() => true),
}));

// Mock the validator set import
vi.mock("../../src/validator_set.json", () => ({
  default: {},
}));

// Mock browser.alarms API
const mockAlarms = {
  get: vi.fn(),
  create: vi.fn(),
};
(globalThis as Record<string, unknown>).browser = {
  alarms: mockAlarms,
  runtime: {
    getURL: vi.fn((path: string) => `moz-extension://test-id/${path}`),
  },
};

// Create a mock database
function createMockDb() {
  return {
    setLastChecked: vi.fn(),
    setLastUpdated: vi.fn(),
    getLastUpdated: vi.fn(),
    getLastBlockTime: vi.fn(),
    setLastBlockTime: vi.fn(),
    setRootHash: vi.fn(),
    updateList: vi.fn(),
  };
}

// Create a mock fetch that returns valid block and leaves responses
function setupFetchMock() {
  const blockJson = { height: "100", commit: {} };
  const leavesJson = {
    proof: {
      app_hash: "010203",
      canonical_root_hash: "aabbcc",
    },
    leaves: [],
  };

  globalThis.fetch = vi.fn((url: string) => {
    const body = (url as string).includes("block.json")
      ? blockJson
      : leavesJson;
    return Promise.resolve({
      json: () => Promise.resolve(body),
    } as Response);
  });

  return { blockJson, leavesJson };
}

describe("shouldDoScheduledUpdate", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns true when lastUpdated is null (never updated)", () => {
    expect(shouldDoScheduledUpdate(null)).toBe(true);
  });

  it("returns true when lastUpdated is exactly UPDATE_INTERVAL_MS ago", () => {
    const now = Date.now();
    expect(shouldDoScheduledUpdate(now - UPDATE_INTERVAL_MS)).toBe(true);
  });

  it("returns true when lastUpdated is older than UPDATE_INTERVAL_MS", () => {
    const now = Date.now();
    expect(shouldDoScheduledUpdate(now - UPDATE_INTERVAL_MS - 1)).toBe(true);
  });

  it("returns false when lastUpdated is less than UPDATE_INTERVAL_MS ago", () => {
    const now = Date.now();
    expect(shouldDoScheduledUpdate(now - UPDATE_INTERVAL_MS + 1)).toBe(false);
  });

  it("returns false when lastUpdated is very recent", () => {
    const now = Date.now();
    expect(shouldDoScheduledUpdate(now - 1000)).toBe(false);
  });

  it("returns false when lastUpdated is now", () => {
    const now = Date.now();
    expect(shouldDoScheduledUpdate(now)).toBe(false);
  });

  it("returns true after time advances past the interval", () => {
    const baseTime = Date.now();
    const lastUpdated = baseTime;

    // Just updated, should not need update
    expect(shouldDoScheduledUpdate(lastUpdated)).toBe(false);

    // Advance time by 59 minutes, still should not need update
    vi.advanceTimersByTime(59 * 60 * 1000);
    expect(shouldDoScheduledUpdate(lastUpdated)).toBe(false);

    // Advance time by 1 more minute (total 60 min), now should need update
    vi.advanceTimersByTime(1 * 60 * 1000);
    expect(shouldDoScheduledUpdate(lastUpdated)).toBe(true);
  });
});

describe("update", () => {
  let db: ReturnType<typeof createMockDb>;

  beforeEach(() => {
    db = createMockDb();
    db.getLastBlockTime.mockResolvedValue(null);
    setupFetchMock();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches from the network endpoint when bundled is false", async () => {
    await update(db as never, "https://example.com/");

    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/list.json",
      expect.any(Object),
    );
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/block.json",
      expect.any(Object),
    );
  });

  it("fetches from bundled URLs when bundled is true", async () => {
    await update(db as never, "https://example.com/", true);

    expect(fetch).toHaveBeenCalledWith(
      "moz-extension://test-id/data/list.json",
      expect.any(Object),
    );
    expect(fetch).toHaveBeenCalledWith(
      "moz-extension://test-id/data/block.json",
      expect.any(Object),
    );
  });

  it("calls setLastUpdated only for non-bundled updates", async () => {
    await update(db as never, "https://example.com/", false);
    expect(db.setLastUpdated).toHaveBeenCalled();

    db.setLastUpdated.mockClear();
    await update(db as never, "https://example.com/", true);
    expect(db.setLastUpdated).not.toHaveBeenCalled();
  });

  it("always calls setLastChecked", async () => {
    await update(db as never, "https://example.com/", true);
    expect(db.setLastChecked).toHaveBeenCalled();

    db.setLastChecked.mockClear();
    await update(db as never, "https://example.com/", false);
    expect(db.setLastChecked).toHaveBeenCalled();
  });

  it("updates the list and block time on success", async () => {
    await update(db as never, "https://example.com/");

    expect(db.updateList).toHaveBeenCalledWith([["example.com", "abc123"]]);
    expect(db.setLastBlockTime).toHaveBeenCalledWith(1000n);
    expect(db.setRootHash).toHaveBeenCalledWith("aabbcc");
  });

  it("skips update when block is already applied", async () => {
    // Block time from verifyCommit mock returns 1000n
    db.getLastBlockTime.mockResolvedValue(1000n);

    await update(db as never, "https://example.com/");

    expect(db.updateList).not.toHaveBeenCalled();
    expect(db.setLastBlockTime).not.toHaveBeenCalled();
  });

  it("throws and sets failure flag on block verification failure", async () => {
    const { verifyCommit } =
      await import("@freedomofpress/cometbft/dist/lightclient");
    (verifyCommit as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
    });

    await expect(update(db as never, "https://example.com/")).rejects.toThrow(
      "Block verification failed",
    );
  });

  it("throws when app_hash mismatches", async () => {
    const { arraysEqual } = await import("../../src/webcat/utils");
    (arraysEqual as ReturnType<typeof vi.fn>).mockReturnValueOnce(false);

    await expect(update(db as never, "https://example.com/")).rejects.toThrow(
      "app hash mismatch",
    );
  });

  it("throws when proof verification fails", async () => {
    const { verifyWebcatProof } =
      await import("@freedomofpress/ics23/dist/webcat");
    (verifyWebcatProof as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
      false,
    );

    await expect(update(db as never, "https://example.com/")).rejects.toThrow(
      "proof did not verify",
    );
  });
});

describe("handleUpdateAlarm", () => {
  let db: ReturnType<typeof createMockDb>;

  beforeEach(() => {
    db = createMockDb();
    setupFetchMock();
    db.getLastBlockTime.mockResolvedValue(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("runs update when lastUpdated is null", async () => {
    db.getLastUpdated.mockResolvedValue(null);

    await handleUpdateAlarm(db as never, "https://example.com/");

    expect(db.updateList).toHaveBeenCalled();
  });

  it("runs update when update interval has elapsed", async () => {
    db.getLastUpdated.mockResolvedValue(Date.now() - UPDATE_INTERVAL_MS - 1000);

    await handleUpdateAlarm(db as never, "https://example.com/");

    expect(db.updateList).toHaveBeenCalled();
  });

  it("skips update when interval has not elapsed", async () => {
    db.getLastUpdated.mockResolvedValue(Date.now() - 1000);

    await handleUpdateAlarm(db as never, "https://example.com/");

    expect(db.updateList).not.toHaveBeenCalled();
  });

  it("does not throw when update fails", async () => {
    db.getLastUpdated.mockResolvedValue(null);
    globalThis.fetch = vi.fn(() => Promise.reject(new Error("network error")));

    await expect(
      handleUpdateAlarm(db as never, "https://example.com/"),
    ).resolves.toBeUndefined();
  });

  it("does not throw when db.getLastUpdated fails", async () => {
    db.getLastUpdated.mockRejectedValue(new Error("db error"));

    await expect(
      handleUpdateAlarm(db as never, "https://example.com/"),
    ).resolves.toBeUndefined();
  });
});

describe("retryUpdateIfFailed", () => {
  let db: ReturnType<typeof createMockDb>;

  beforeEach(() => {
    db = createMockDb();
    setupFetchMock();
    db.getLastBlockTime.mockResolvedValue(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not run update when no prior failure", async () => {
    // Ensure a successful update first to clear the failure flag
    db.getLastUpdated.mockResolvedValue(null);
    await handleUpdateAlarm(db as never, "https://example.com/");

    db.updateList.mockClear();
    await retryUpdateIfFailed(db as never, "https://example.com/");

    expect(db.updateList).not.toHaveBeenCalled();
  });

  it("retries update after a prior failure", async () => {
    // Trigger a failure to set lastUpdateFailed = true
    db.getLastUpdated.mockResolvedValue(null);
    globalThis.fetch = vi.fn(() => Promise.reject(new Error("network error")));
    await handleUpdateAlarm(db as never, "https://example.com/");

    // Now restore fetch and retry
    setupFetchMock();
    db.updateList.mockClear();
    await retryUpdateIfFailed(db as never, "https://example.com/");

    expect(db.updateList).toHaveBeenCalled();
  });

  it("does not throw when retry itself fails", async () => {
    // Trigger initial failure
    db.getLastUpdated.mockResolvedValue(null);
    globalThis.fetch = vi.fn(() => Promise.reject(new Error("network error")));
    await handleUpdateAlarm(db as never, "https://example.com/");

    // Retry also fails — should not throw
    await expect(
      retryUpdateIfFailed(db as never, "https://example.com/"),
    ).resolves.toBeUndefined();
  });
});

describe("initializeScheduledUpdates", () => {
  let db: ReturnType<typeof createMockDb>;

  beforeEach(() => {
    db = createMockDb();
    setupFetchMock();
    db.getLastBlockTime.mockResolvedValue(null);
    mockAlarms.get.mockResolvedValue(undefined);
    mockAlarms.create.mockReturnValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("creates the alarm", async () => {
    db.getLastUpdated.mockResolvedValue(Date.now());

    await initializeScheduledUpdates(db as never, "https://example.com/");

    expect(mockAlarms.create).toHaveBeenCalledWith("webcat-scheduled-update", {
      periodInMinutes: CHECK_INTERVAL_MS / 60000,
    });
  });

  it("does not create a duplicate alarm", async () => {
    db.getLastUpdated.mockResolvedValue(Date.now());
    mockAlarms.get.mockResolvedValue({ name: "webcat-scheduled-update" });

    await initializeScheduledUpdates(db as never, "https://example.com/");

    expect(mockAlarms.create).not.toHaveBeenCalled();
  });

  it("runs an overdue update and creates the alarm", async () => {
    db.getLastUpdated.mockResolvedValue(null);

    await initializeScheduledUpdates(db as never, "https://example.com/");

    expect(db.updateList).toHaveBeenCalled();
    expect(mockAlarms.create).toHaveBeenCalled();
  });

  it("still creates alarm when checkAndUpdate throws", async () => {
    db.getLastUpdated.mockRejectedValue(new Error("db error"));

    await initializeScheduledUpdates(db as never, "https://example.com/");

    expect(mockAlarms.create).toHaveBeenCalled();
  });
});
