import { describe, expect, it, vi } from "vitest";

import {
  WebcatError,
  WebcatErrorCode,
} from "../../src/webcat/interfaces/errors";
import { extractAndValidateHeaders } from "../../src/webcat/validators";

vi.mock("../../src/webcat/logger", () => ({
  logger: { addLog: vi.fn() },
}));

vi.mock("../../src/webcat/db", () => ({
  WebcatDatabase: vi.fn().mockImplementation(() => ({})),
}));

function makeDetails(
  headers: Array<{ name: string; value?: string }>,
  overrides: Partial<browser.webRequest._OnHeadersReceivedDetails> = {},
): browser.webRequest._OnHeadersReceivedDetails {
  return {
    responseHeaders: headers,
    fromCache: false,
    statusCode: 200,
    ...overrides,
  } as browser.webRequest._OnHeadersReceivedDetails;
}

describe("extractAndValidateHeaders – forbidden headers", () => {
  it("rejects Refresh header", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Refresh", value: "5; url=https://evil.com" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.FORBIDDEN,
    );
  });

  it("rejects Link header", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Link", value: "</style.css>; rel=preload" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.FORBIDDEN,
    );
  });

  it("rejects forbidden headers case-insensitively", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "REFRESH", value: "0" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.FORBIDDEN,
    );
  });
});

describe("extractAndValidateHeaders – Location header", () => {
  it("allows safe relative Location /path", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Location", value: "/login" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(Map);
  });

  it("allows safe relative Location ./path", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Location", value: "./other" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(Map);
  });

  it("allows safe relative Location ../path", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Location", value: "../parent" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(Map);
  });

  it("rejects absolute Location URLs", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Location", value: "https://evil.com" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.LOCATION_EXTERNAL,
    );
  });

  it("rejects protocol-relative Location URLs", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Location", value: "//evil.com" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.LOCATION_EXTERNAL,
    );
  });

  it("rejects Location with backslash", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Location", value: "/\\evil.com" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.LOCATION_EXTERNAL,
    );
  });
});

describe("extractAndValidateHeaders – duplicate critical headers", () => {
  it("rejects duplicate CSP headers", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Content-Security-Policy", value: "default-src 'self'" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.DUPLICATE,
    );
  });

  it("detects duplicates case-insensitively", () => {
    const details = makeDetails([
      { name: "content-security-policy", value: "default-src 'none'" },
      { name: "Content-Security-Policy", value: "default-src 'self'" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.DUPLICATE,
    );
  });
});

describe("extractAndValidateHeaders – missing responseHeaders", () => {
  it("returns error when responseHeaders is undefined", () => {
    const details = {
      fromCache: false,
      statusCode: 200,
    } as browser.webRequest._OnHeadersReceivedDetails;
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(WebcatErrorCode.Headers.MISSING);
  });
});

describe("extractAndValidateHeaders – valid responses", () => {
  it("normalizes header names to lowercase in returned map", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "X-Custom-Header", value: "foo" },
    ]);
    const result = extractAndValidateHeaders(details) as Map<string, string>;
    expect(result).toBeInstanceOf(Map);
    expect(result.has("content-security-policy")).toBe(true);
    expect(result.has("x-custom-header")).toBe(true);
    expect(result.get("content-security-policy")).toBe("default-src 'none'");
  });

  it("skips headers without name or value", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "", value: "orphan" },
      { name: "X-Empty" },
    ]);
    const result = extractAndValidateHeaders(details) as Map<string, string>;
    expect(result).toBeInstanceOf(Map);
    // Only CSP should be present
    expect(result.size).toBe(1);
  });

  it("allows non-critical duplicate headers (e.g. set-cookie)", () => {
    const details = makeDetails([
      { name: "Content-Security-Policy", value: "default-src 'none'" },
      { name: "Set-Cookie", value: "a=1" },
      { name: "Set-Cookie", value: "b=2" },
    ]);
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(Map);
  });
});

describe("extractAndValidateHeaders – cache and 304 edge cases", () => {
  it("allows missing CSP when fromCache is true even with statusCode 200", () => {
    const details = makeDetails([{ name: "X-Other", value: "val" }], {
      fromCache: true,
      statusCode: 200,
    });
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(Map);
  });

  it("requires CSP when fromCache is false and statusCode is not 304", () => {
    const details = makeDetails([{ name: "X-Other", value: "val" }], {
      fromCache: false,
      statusCode: 200,
    });
    const result = extractAndValidateHeaders(details);
    expect(result).toBeInstanceOf(WebcatError);
    expect((result as WebcatError).code).toBe(
      WebcatErrorCode.Headers.MISSING_CRITICAL,
    );
  });
});
