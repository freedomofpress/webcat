import { describe, expect, it } from "vitest";

import { Issuers } from "./../src/webcat/interfaces";
import { parseSigners, parseThreshold } from "./../src/webcat/parsers";

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
