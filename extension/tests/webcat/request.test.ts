import { describe, expect, it } from "vitest";

import {
  enforceHTTPS,
  validateProtocolAndPort,
} from "../../src/webcat/request";

describe("validateProtocolAndPort", () => {
  it("allows https with default port", () => {
    const url = new URL("https://example.com");
    expect(validateProtocolAndPort(url)).toBe(true);
  });

  it("allows https with explicit port 443", () => {
    const url = new URL("https://example.com:443");
    expect(validateProtocolAndPort(url)).toBe(true);
  });

  it("allows http with default port", () => {
    const url = new URL("http://example.com");
    expect(validateProtocolAndPort(url)).toBe(true);
  });

  it("allows http with explicit port 80", () => {
    const url = new URL("http://example.com:80");
    expect(validateProtocolAndPort(url)).toBe(true);
  });

  it("rejects https with a non-standard port", () => {
    const url = new URL("https://example.com:8443");
    expect(validateProtocolAndPort(url)).toBe(false);
  });

  it("rejects http with a non-standard port", () => {
    const url = new URL("http://example.com:8080");
    expect(validateProtocolAndPort(url)).toBe(false);
  });

  it("rejects unsupported protocol (ftp)", () => {
    const url = new URL("ftp://example.com");
    expect(validateProtocolAndPort(url)).toBe(false);
  });

  it("rejects unsupported protocol (file)", () => {
    const url = new URL("file:///etc/passwd");
    expect(validateProtocolAndPort(url)).toBe(false);
  });

  it("rejects data: URLs", () => {
    const url = new URL("data:text/plain,hello");
    expect(validateProtocolAndPort(url)).toBe(false);
  });
});

describe("enforceHTTPS", () => {
  it("redirects http to https for normal domains", () => {
    const url = new URL("http://example.com/path");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBe("https://example.com/path");
    expect(url.protocol).toBe("https:");
  });

  it("does nothing for already-https URLs", () => {
    const url = new URL("https://example.com/path");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBeUndefined();
    expect(url.protocol).toBe("https:");
  });

  it("does not redirect .onion domains", () => {
    const url = new URL("http://example.onion/path");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBeUndefined();
    expect(url.protocol).toBe("http:");
  });

  it("handles localhost correctly (redirects to https)", () => {
    const url = new URL("http://localhost:8080/path");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBe("https://localhost:8080/path");
    expect(url.protocol).toBe("https:");
  });

  it("handles subdomains correctly", () => {
    const url = new URL("http://a.b.c.example.com/");
    const redirect = enforceHTTPS(url);

    expect(redirect).toBe("https://a.b.c.example.com/");
  });

  it("is idempotent when called twice", () => {
    const url = new URL("http://example.com/");
    const first = enforceHTTPS(url);
    const second = enforceHTTPS(url);

    expect(first).toBe("https://example.com/");
    expect(second).toBeUndefined();
    expect(url.protocol).toBe("https:");
  });
});
