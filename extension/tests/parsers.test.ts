import { describe, expect, it } from "vitest";

import { Issuers } from "./../src/webcat/interfaces";
import {
  parseContentSecurityPolicy,
  parseSigners,
  parseThreshold,
} from "./../src/webcat/parsers";

describe("parseSigners", () => {
  it("should parse valid signers JSON into a Set", () => {
    const input = JSON.stringify([
      { issuer: Issuers.google, identity: "user@example.com" },
      { issuer: Issuers.github, identity: "admin@domain.com" },
    ]);
    const expected = new Set([
      [Issuers.google, "user@example.com"],
      [Issuers.github, "admin@domain.com"],
    ]);

    const result = parseSigners(input);
    expect(result).toEqual(expected);
  });

  it("should throw an error for invalid JSON", () => {
    const input = "{invalid JSON}";

    expect(() => parseSigners(input)).toThrow(
      "Error parsing JSON in x-sigstore-signers",
    );
  });

  it("should throw an error if the input is not an array", () => {
    const input = JSON.stringify({
      issuer: Issuers.google,
      identity: "user@example.com",
    });

    expect(() => parseSigners(input)).toThrow(
      "Header x-sigstore-signers does not JSON decode to an array.",
    );
  });

  it("should throw an error for invalid issuer or identity", () => {
    const input = JSON.stringify([
      { issuer: "InvalidIssuer", identity: "user@example.com" },
    ]);

    expect(() => parseSigners(input)).toThrow(
      "InvalidIssuer is not a valid OIDC issuer.",
    );
  });

  it("should throw an error for identity with invalid length", () => {
    const input = JSON.stringify([{ issuer: Issuers.google, identity: "a" }]);

    expect(() => parseSigners(input)).toThrow(
      "a is not a valid OIDC identity.",
    );
  });
});

describe("parseThreshold", () => {
  it("should return the numeric threshold when valid", () => {
    const result = parseThreshold("3", 5);
    expect(result).toBe(3);
  });

  it("should throw an error if threshold is less than 1", () => {
    expect(() => parseThreshold("0", 5)).toThrow(
      "Signing threshold is less than 1.",
    );
    expect(() => parseThreshold("-2", 5)).toThrow(
      "Signing threshold is less than 1.",
    );
  });

  it("should throw an error if threshold is greater than the number of signers", () => {
    expect(() => parseThreshold("6", 5)).toThrow(
      "Signing threshold is greater than the number of possible signers.",
    );
  });

  it("should throw an error for non-numeric input", () => {
    expect(() => parseThreshold("abc", 5)).toThrow(
      "Signing threshold must be an integer.",
    );
    expect(() => parseThreshold("", 5)).toThrow(
      "Signing threshold must be an integer.",
    );
  });

  it("should throw an error for decimal input", () => {
    expect(() => parseThreshold("2.9", 5)).toThrow(
      "Signing threshold must be an integer.",
    );
    expect(() => parseThreshold("3.0", 5)).not.toThrow();
  });

  it("should allow a threshold equal to the number of signers", () => {
    const result = parseThreshold("5", 5);
    expect(result).toBe(5);
  });
});

describe("parseContentSecurityPolicy", () => {
  it("should correctly parse a valid CSP with multiple directives", () => {
    const policy =
      "default-src 'self'; script-src 'unsafe-eval' scripts.example; object-src; style-src styles.example";
    const result = parseContentSecurityPolicy(policy);

    expect(result.size).toBe(4);
    expect(result.get("default-src")).toEqual(["'self'"]);
    expect(result.get("script-src")).toEqual([
      "'unsafe-eval'",
      "scripts.example",
    ]);
    expect(result.get("object-src")).toEqual([]);
    expect(result.get("style-src")).toEqual(["styles.example"]);
  });

  it("should handle extra whitespace between directives", () => {
    const policy =
      " default-src   'self'  ;   script-src  'unsafe-eval'  scripts.example ; object-src  ;  ";
    const result = parseContentSecurityPolicy(policy);

    expect(result.size).toBe(3);
    expect(result.get("default-src")).toEqual(["'self'"]);
    expect(result.get("script-src")).toEqual([
      "'unsafe-eval'",
      "scripts.example",
    ]);
    expect(result.get("object-src")).toEqual([]);
  });

  it("should ignore malformed directives with non-ASCII characters", () => {
    const policy = "default-src 'self'; script-src 𝔘𝔫𝔰𝔞𝔣𝔢; object-src";
    const result = parseContentSecurityPolicy(policy);

    expect(result.size).toBe(2);
    expect(result.get("default-src")).toEqual(["'self'"]);
    expect(result.get("object-src")).toEqual([]);
    expect(result.has("script-src")).toBe(false);
  });

  it("should handle duplicated directives and keep the first occurrence", () => {
    const policy =
      "default-src 'self'; script-src scripts.example; script-src 'unsafe-eval'";
    const result = parseContentSecurityPolicy(policy);

    expect(result.size).toBe(2);
    expect(result.get("default-src")).toEqual(["'self'"]);
    expect(result.get("script-src")).toEqual(["scripts.example"]);
  });

  it("should treat directive names as case-insensitive", () => {
    const policy =
      "DEFAULT-SRC 'self'; default-src 'none'; SCRIPT-SRC scripts.example";
    const result = parseContentSecurityPolicy(policy);

    expect(result.size).toBe(2);
    expect(result.get("default-src")).toEqual(["'self'"]);
    expect(result.get("script-src")).toEqual(["scripts.example"]);
  });

  it("should ignore empty directives", () => {
    const policy =
      "default-src 'self'; ;; script-src scripts.example; ; object-src";
    const result = parseContentSecurityPolicy(policy);

    expect(result.size).toBe(3);
    expect(result.get("default-src")).toEqual(["'self'"]);
    expect(result.get("script-src")).toEqual(["scripts.example"]);
    expect(result.get("object-src")).toEqual([]);
  });

  it("should handle a policy with only semicolons", () => {
    const policy = ";;;";
    const result = parseContentSecurityPolicy(policy);
    expect(result.size).toBe(0);
  });

  it("should handle policies with directives without values", () => {
    const policy = "upgrade-insecure-requests; block-all-mixed-content";
    const result = parseContentSecurityPolicy(policy);

    expect(result.size).toBe(2);
    expect(result.get("upgrade-insecure-requests")).toEqual([]);
    expect(result.get("block-all-mixed-content")).toEqual([]);
  });

  it("should handle directives with mixed casing and extra whitespace", () => {
    const policy =
      "  ScRipT-SrC   scripts.example  'unsafe-eval'  ;   STYLE-src  styles.example  ";
    const result = parseContentSecurityPolicy(policy);

    expect(result.size).toBe(2);
    expect(result.get("script-src")).toEqual([
      "scripts.example",
      "'unsafe-eval'",
    ]);
    expect(result.get("style-src")).toEqual(["styles.example"]);
  });
});
