import { ValidatorJson } from "@freedomofpress/cometbft/dist/types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EnrollmentUpdater } from "../../src/webcat/updater";

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
  stringToUint8Array: vi.fn((s: string) => new TextEncoder().encode(s)),
  Uint8ArrayToBase64Url: vi.fn(() => "AQID"),
}));

vi.mock("../../src/webcat/utils", () => ({
  arraysEqual: vi.fn(() => true),
}));

// Mock browser.alarms API
const mockAlarms = {
  get: vi.fn(),
  create: vi.fn(),
  onAlarm: {
    addListener: vi.fn(),
  },
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
    getBlockMeta: vi.fn(),
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

describe("isDue", () => {
  let db: ReturnType<typeof createMockDb>;
  let updater: EnrollmentUpdater;

  beforeEach(() => {
    db = createMockDb();
    updater = new EnrollmentUpdater({
      endpoint: "https://example.com/",
      database: db as never,
      validatorSet: {} as ValidatorJson,
    });
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns true when lastUpdated is null (never updated)", () => {
    db.getLastUpdated.mockResolvedValue(null);
    expect(updater.isDue()).resolves.toBe(true);
  });

  it("returns true when lastUpdated is exactly UPDATE_INTERVAL_MS ago", () => {
    db.getLastUpdated.mockResolvedValue(
      Date.now() - EnrollmentUpdater.DefaultUpdateInterval,
    );
    expect(updater.isDue()).resolves.toBe(true);
  });

  it("returns true when lastUpdated is older than UPDATE_INTERVAL_MS", () => {
    db.getLastUpdated.mockResolvedValue(
      Date.now() - EnrollmentUpdater.DefaultUpdateInterval - 1,
    );
    expect(updater.isDue()).resolves.toBe(true);
  });

  it("returns false when lastUpdated is less than UPDATE_INTERVAL_MS ago", () => {
    db.getLastUpdated.mockResolvedValue(
      Date.now() - EnrollmentUpdater.DefaultUpdateInterval + 1,
    );
    expect(updater.isDue()).resolves.toBe(false);
  });

  it("returns false when lastUpdated is very recent", () => {
    db.getLastUpdated.mockResolvedValue(Date.now() - 1000);
    expect(updater.isDue()).resolves.toBe(false);
  });

  it("returns false when lastUpdated is now", () => {
    db.getLastUpdated.mockResolvedValue(Date.now());
    expect(updater.isDue()).resolves.toBe(false);
  });

  it("returns true after time advances past the interval", async () => {
    const baseTime = Date.now();
    const lastUpdated = baseTime;

    // Just updated, should not need update
    db.getLastUpdated.mockResolvedValue(lastUpdated);
    expect(await updater.isDue()).toBe(false);

    // Advance time by 59 minutes, still should not need update
    vi.advanceTimersByTime(59 * 60 * 1000);
    expect(await updater.isDue()).toBe(false);

    // Advance time by 1 more minute (total 60 min), now should need update
    vi.advanceTimersByTime(1 * 60 * 1000);
    expect(await updater.isDue()).toBe(true);
  });
});

describe("update", () => {
  let db: ReturnType<typeof createMockDb>;
  let updater: EnrollmentUpdater;

  beforeEach(() => {
    db = createMockDb();
    updater = new EnrollmentUpdater({
      endpoint: "https://example.com/",
      database: db as never,
      validatorSet: {} as ValidatorJson,
    });
    db.getBlockMeta.mockResolvedValue(null);
    setupFetchMock();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("fetches from the network endpoint when bundled is false", async () => {
    await updater.update();

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
    await updater.update(true);

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
    await updater.update(false);
    expect(db.setLastUpdated).toHaveBeenCalled();

    db.setLastUpdated.mockClear();
    await updater.update(true);
    expect(db.setLastUpdated).not.toHaveBeenCalled();
  });

  it("always calls setLastChecked", async () => {
    await updater.update(true);
    expect(db.setLastChecked).toHaveBeenCalled();

    db.setLastChecked.mockClear();
    await updater.update(false);
    expect(db.setLastChecked).toHaveBeenCalled();
  });

  it("updates the list and block time on success", async () => {
    await updater.update();

    expect(db.updateList).toHaveBeenCalledWith([["example.com", "abc123"]], {
      blockTime: 1000,
      rootHash: "aabbcc",
    });
  });

  it("skips update when block is already applied", async () => {
    // Block time from verifyCommit mock returns 1000n
    db.getBlockMeta.mockResolvedValue({ blockTime: 1000 });

    await updater.update();

    expect(db.updateList).not.toHaveBeenCalled();
  });

  it("throws and sets failure flag on block verification failure", async () => {
    const { verifyCommit } =
      await import("@freedomofpress/cometbft/dist/lightclient");
    (verifyCommit as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
    });

    await expect(updater.update()).rejects.toThrow("Block verification failed");
  });

  it("throws when app_hash mismatches", async () => {
    const { arraysEqual } = await import("../../src/webcat/utils");
    (arraysEqual as ReturnType<typeof vi.fn>).mockReturnValueOnce(false);

    await expect(updater.update()).rejects.toThrow("app hash mismatch");
  });

  it("throws when proof verification fails", async () => {
    const { verifyWebcatProof } =
      await import("@freedomofpress/ics23/dist/webcat");
    (verifyWebcatProof as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
      false,
    );

    await expect(updater.update()).rejects.toThrow("proof did not verify");
  });
});

describe("handleUpdateAlarm", () => {
  let db: ReturnType<typeof createMockDb>;
  let updater: EnrollmentUpdater;
  let updated: Promise<void>;
  let handle: (alarm: { name: string }) => Promise<void>;

  beforeEach(async () => {
    db = createMockDb();
    updater = new EnrollmentUpdater({
      endpoint: "https://example.com/",
      database: db as never,
      validatorSet: {} as ValidatorJson,
    });
    let resolveUpdated: (() => void) | null = null;
    updated = new Promise<void>((r) => (resolveUpdated = r));
    updater.addEventListener("updated", resolveUpdated);
    setupFetchMock();
    db.getBlockMeta.mockResolvedValue(null);
    mockAlarms.onAlarm.addListener.mockImplementation(function (callback) {
      handle = callback;
    });
    mockAlarms.get.mockResolvedValue(undefined);
    db.getLastUpdated.mockResolvedValue(null);
    updater.start();
    await updated;
    db.updateList.mockClear();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("runs update when lastUpdated is null", async () => {
    db.getLastUpdated.mockResolvedValue(null);

    await handle({ name: "webcat-scheduled-update:https://example.com/" });

    expect(db.updateList).toHaveBeenCalled();
  });

  it("runs update when update interval has elapsed", async () => {
    db.getLastUpdated.mockResolvedValue(
      Date.now() - EnrollmentUpdater.DefaultUpdateInterval - 1000,
    );

    await handle({ name: "webcat-scheduled-update:https://example.com/" });

    expect(db.updateList).toHaveBeenCalled();
  });

  it("skips update when interval has not elapsed", async () => {
    db.getLastUpdated.mockResolvedValue(Date.now() - 1000);

    await handle({ name: "webcat-scheduled-update:https://example.com/" });

    expect(db.updateList).not.toHaveBeenCalled();
  });

  it("does not throw when update fails", async () => {
    db.getLastUpdated.mockResolvedValue(null);
    globalThis.fetch = vi.fn(() => Promise.reject(new Error("network error")));

    await expect(
      handle({ name: "webcat-scheduled-update:https://example.com/" }),
    ).resolves.toBeUndefined();
  });

  it("does not throw when db.getLastUpdated fails", async () => {
    db.getLastUpdated.mockRejectedValue(new Error("db error"));

    await expect(
      handle({ name: "webcat-scheduled-update:https://example.com/" }),
    ).resolves.toBeUndefined();
  });
});

describe("retryIfFailed", () => {
  let db: ReturnType<typeof createMockDb>;
  let updater: EnrollmentUpdater;

  beforeEach(() => {
    db = createMockDb();
    updater = new EnrollmentUpdater({
      endpoint: "https://example.com/",
      database: db as never,
      validatorSet: {} as ValidatorJson,
    });
    setupFetchMock();
    db.getBlockMeta.mockResolvedValue(null);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("does not run update when no prior failure", async () => {
    // Ensure a successful update first to clear the failure flag
    db.getLastUpdated.mockResolvedValue(null);
    await updater.update();

    db.updateList.mockClear();
    await updater.retryIfFailed();

    expect(db.updateList).not.toHaveBeenCalled();
  });

  it("retries update after a prior failure", async () => {
    // Trigger a failure to set lastUpdateFailed = true
    db.getLastUpdated.mockResolvedValue(null);
    globalThis.fetch = vi.fn(() => Promise.reject(new Error("network error")));
    try {
      await updater.update();
    } catch {}

    // Now restore fetch and retry
    setupFetchMock();
    db.updateList.mockClear();
    await updater.retryIfFailed();

    expect(db.updateList).toHaveBeenCalled();
  });

  it("does not throw when retry itself fails", async () => {
    // Trigger initial failure
    db.getLastUpdated.mockResolvedValue(null);
    globalThis.fetch = vi.fn(() => Promise.reject(new Error("network error")));
    try {
      await updater.update();
    } catch {}

    // Retry also fails — should not throw
    await expect(updater.retryIfFailed()).resolves.toBeUndefined();
  });
});

describe("start", () => {
  let db: ReturnType<typeof createMockDb>;
  let updater: EnrollmentUpdater;
  let scheduled: Promise<void>;
  let updated: Promise<void>;

  beforeEach(() => {
    db = createMockDb();
    updater = new EnrollmentUpdater({
      endpoint: "https://example.com/",
      database: db as never,
      validatorSet: {} as ValidatorJson,
    });
    let resolveScheduled: (() => void) | null = null;
    scheduled = new Promise<void>((r) => (resolveScheduled = r));
    updater.addEventListener("scheduled", resolveScheduled);
    let resolveUpdated: (() => void) | null = null;
    updated = new Promise<void>((r) => (resolveUpdated = r));
    updater.addEventListener("updated", resolveUpdated);
    setupFetchMock();
    db.getBlockMeta.mockResolvedValue(null);
    mockAlarms.get.mockResolvedValue(undefined);
    mockAlarms.create.mockReturnValue(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("creates the alarm", async () => {
    db.getLastUpdated.mockResolvedValue(Date.now());

    updater.start();
    await scheduled;

    expect(mockAlarms.create).toHaveBeenCalledWith(
      "webcat-scheduled-update:https://example.com/",
      {
        periodInMinutes: EnrollmentUpdater.DefaultCheckInterval / 60000,
      },
    );
  });

  it("does not create a duplicate alarm", async () => {
    db.getLastUpdated.mockResolvedValue(Date.now());
    mockAlarms.get.mockResolvedValue({
      name: "webcat-scheduled-update:https://example.com/",
    });

    updater.start();
    await scheduled;

    expect(mockAlarms.create).not.toHaveBeenCalled();
  });

  it("runs an overdue update and creates the alarm", async () => {
    db.getLastUpdated.mockResolvedValue(null);

    updater.start();
    await updated;

    expect(db.updateList).toHaveBeenCalled();
    expect(mockAlarms.create).toHaveBeenCalled();
  });

  it("still creates alarm when checkAndUpdate throws", async () => {
    db.getLastUpdated.mockRejectedValue(new Error("db error"));

    updater.start();
    await scheduled;

    expect(mockAlarms.create).toHaveBeenCalled();
  });
});
