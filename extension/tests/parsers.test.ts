import { describe, expect, it } from "vitest";

import { Issuers } from "./../src/webcat/interfaces";
import { parseSigners } from "./../src/webcat/parsers";

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
