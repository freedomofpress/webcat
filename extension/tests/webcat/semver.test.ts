import { describe, expect, it } from "vitest";

import { isNewerSemver } from "../../src/webcat/semver";

describe("isNewerSemver", () => {
  it("should return true for newer patch versions", () => {
    expect(isNewerSemver("1.2.4", "1.2.3")).toBe(true);
    expect(isNewerSemver("1.2.4", "1.2")).toBe(true);
  });

  it("should return true for newer minor versions", () => {
    expect(isNewerSemver("1.3.3", "1.2.3")).toBe(true);
    expect(isNewerSemver("1.3.3", "1.2")).toBe(true);
    expect(isNewerSemver("1.3", "1.2.3")).toBe(true);
    expect(isNewerSemver("1.3.3", "1")).toBe(true);
  });

  it("should return true for newer major versions", () => {
    expect(isNewerSemver("2.2.3", "1.2.3")).toBe(true);
    expect(isNewerSemver("2", "1.2.3")).toBe(true);
    expect(isNewerSemver("2.2.3", "1")).toBe(true);
  });

  it("should return false for the same version", () => {
    expect(isNewerSemver("1.2.3", "1.2.3")).toBe(false);
    expect(isNewerSemver("1.0.0", "1")).toBe(false);
    expect(isNewerSemver("1", "1.0.0")).toBe(false);
  });

  it("should return false for older major versions", () => {
    expect(isNewerSemver("1.2.3", "2.2.3")).toBe(false);
    expect(isNewerSemver("1.3.3", "2.2.3")).toBe(false);
    expect(isNewerSemver("1.2.4", "2.2.3")).toBe(false);
    expect(isNewerSemver("1.3.4", "2.2.3")).toBe(false);
    expect(isNewerSemver("1.3.4", "2.2.3")).toBe(false);
  });

  it("should return false for older minor versions", () => {
    expect(isNewerSemver("1.2.3", "1.3.3")).toBe(false);
    expect(isNewerSemver("1.2.4", "1.3.3")).toBe(false);
  });

  it("should return false for an older patch version", () => {
    expect(isNewerSemver("1.2.3", "1.2.4")).toBe(false);
    expect(isNewerSemver("1.2", "1.2.4")).toBe(false);
  });

  it("ranks prereleases per SemVer 2.0.0 section 11", () => {
    expect(isNewerSemver("1.0.0", "1.0.0-rc.1")).toBe(true);
    expect(isNewerSemver("1.0.0-rc.1", "1.0.0")).toBe(false);
    expect(isNewerSemver("1.0.0-rc.2", "1.0.0-rc.1")).toBe(true);
    expect(isNewerSemver("1.0.0-rc.10", "1.0.0-rc.2")).toBe(true);
    expect(isNewerSemver("1.0.0-rc.1", "1.0.0-rc.1")).toBe(false);
    expect(isNewerSemver("1.0.0-beta", "1.0.0-alpha")).toBe(true);
    expect(isNewerSemver("1.0.0-alpha", "1.0.0-1")).toBe(true);
    expect(isNewerSemver("1.0.0-alpha.1", "1.0.0-alpha")).toBe(true);
    expect(isNewerSemver("1.0.0-rc-2", "1.0.0-rc-1")).toBe(true);
    expect(isNewerSemver("1.0.1-rc.1", "1.0.0")).toBe(true);
  });

  it("orders the example chain from semver.org section 11", () => {
    const chain = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];
    for (let i = 1; i < chain.length; i++) {
      expect(isNewerSemver(chain[i], chain[i - 1])).toBe(true);
      expect(isNewerSemver(chain[i - 1], chain[i])).toBe(false);
    }
  });

  it("tolerates leading v and ignores build metadata", () => {
    expect(isNewerSemver("v32.0.0", "v31.1.8")).toBe(true);
    expect(isNewerSemver("vv1.1", "v1.0")).toBe(true);
    expect(isNewerSemver("V1.1", "1.0")).toBe(true);
    expect(isNewerSemver("1.0.0+build.2", "1.0.0+build.1")).toBe(false);
  });
});
