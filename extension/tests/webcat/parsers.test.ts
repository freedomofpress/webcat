import { describe, expect, it } from "vitest";

import { parseContentSecurityPolicy } from "./../../src/webcat/parsers";

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
