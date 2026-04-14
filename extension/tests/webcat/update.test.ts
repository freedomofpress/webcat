import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  shouldDoScheduledUpdate,
  UPDATE_INTERVAL_MS,
} from "../../src/webcat/update";

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
