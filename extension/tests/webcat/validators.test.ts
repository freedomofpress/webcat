import { beforeEach, describe, expect, it, vi } from "vitest";

import { OriginState } from "../../src/webcat/interfaces";
import { logger } from "./../../src/webcat/logger";
import { validateCSP } from "./../../src/webcat/validators";

vi.mock("./../../src/webcat/logger", () => ({
  logger: {
    addLog: vi.fn(),
  },
}));

// Mock isFQDNEnrolled from the correct module
vi.mock("../../src/webcat/db", () => ({
  isFQDNEnrolled: vi.fn(async (fqdn: string) => fqdn === "trusted.com"),
  getCount: vi.fn(async (storeName: string) => {
    if (storeName === "list") {
      return 42; // Mocked count value
    }
    return 0;
  }),
}));

describe("validateCSP", () => {
  let originState: OriginState;

  beforeEach(() => {
    originState = new OriginState("example.com");
  });

  it("should pass for a valid CSP configuration", async () => {
    const csp =
      "script-src 'self' 'sha256-abc'; style-src 'self'; object-src 'none'";
    const result = await validateCSP(csp, "trusted.com", 1, originState);
    expect(result).toBe(true);
  });

  it("should throw an error if a required directive is missing", async () => {
    const csp = "script-src 'self'; style-src 'self'";
    await expect(
      validateCSP(csp, "trusted.com", 1, originState),
    ).rejects.toThrow("Missing required directive: object-src");
  });

  it("should throw an error if a object-src is not 'none'", async () => {
    const csp =
      "script-src 'self' 'sha256-abc'; style-src 'self'; object-src 'self'";
    await expect(
      validateCSP(csp, "trusted.com", 1, originState),
    ).rejects.toThrow("object-src must be 'none'");
  });

  it("should throw an error if a object-src is not 'none'", async () => {
    const csp =
      "script-src 'self' 'sha256-abc' 'unsafe-inline'; style-src 'self'; object-src 'self'";
    await expect(
      validateCSP(csp, "trusted.com", 1, originState),
    ).rejects.toThrow("Invalid source in script-src: 'unsafe-inline'");
  });

  it("should throw an error for invalid script-src sources", async () => {
    const csp = "script-src evil.com; style-src 'self'; object-src 'none'";
    await expect(
      validateCSP(csp, "trusted.com", 1, originState),
    ).rejects.toThrow("Invalid source in script-src: evil.com");
  });

  it("should throw an error for invalid style-src sources", async () => {
    const csp = "script-src 'self'; style-src evil.com; object-src 'none'";
    await expect(
      validateCSP(csp, "trusted.com", 1, originState),
    ).rejects.toThrow("Invalid source in style-src: evil.com");
  });

  it("should throw an error if object-src is not 'none'", async () => {
    const csp = "script-src 'self'; style-src 'self'; object-src 'self'";
    await expect(
      validateCSP(csp, "trusted.com", 1, originState),
    ).rejects.toThrow("object-src must be 'none'");
  });

  it("should throw an error for wildcard in child-src", async () => {
    const csp =
      "script-src 'self'; style-src 'self'; object-src 'none'; child-src *";
    await expect(
      validateCSP(csp, "trusted.com", 1, originState),
    ).rejects.toThrow("Wildcards not allowed child-src/frame-src: *");
  });

  it("should throw an error for untrusted child-src URLs", async () => {
    const csp =
      "script-src 'self'; style-src 'self'; object-src 'none'; child-src evil.com";
    await expect(
      validateCSP(csp, "trusted.com", 1, originState),
    ).rejects.toThrow(
      "Invalid source in child-src/frame-src/worker-src: evil.com",
    );
  });

  // Nope it should not for now :)
  /*it("should pass with enrolled FQDNs in script-src", async () => {
    const csp =
      "script-src https://trusted.com; style-src 'self'; object-src 'none'";
    const result = await validateCSP(csp, "trusted.com", 1);
    expect(result).toBe(true);
  });*/

  it("should log parsing and validation success", async () => {
    const csp = "script-src 'self'; style-src 'self'; object-src 'none'";
    await validateCSP(csp, "trusted.com", 1, originState);
    expect(logger.addLog).toHaveBeenCalledWith(
      "info",
      expect.stringContaining("Parsed CSP"),
      1,
      "trusted.com",
    );
    expect(logger.addLog).toHaveBeenCalledWith(
      "info",
      "CSP validation successful!",
      1,
      "trusted.com",
    );
  });
});
