import { describe, expect, it } from "vitest";

import {
  arrayBufferToHex,
  arraysEqual,
  getFQDN,
  isExtensionRequest,
  SHA256,
} from "./../../src/webcat/utils";

describe("getFQDN", () => {
  it("should extract the hostname from a valid URL", () => {
    expect(getFQDN("https://example.com/path")).toBe("example.com");
    expect(getFQDN("http://sub.domain.example.com:8080/test")).toBe(
      "sub.domain.example.com",
    );
  });

  it("should handle URLs with query parameters and fragments", () => {
    expect(getFQDN("https://example.com?query=123#fragment")).toBe(
      "example.com",
    );
  });

  // This actually should work because we now prepend a scheme, and not-a-url can be a valid hostname
  //it("should throw an error for invalid URLs", () => {
  //  expect(() => getFQDN("not-a-url")).toThrow();
  //});
});

describe("isExtensionRequest", () => {
  it("should return true for valid extension requests", () => {
    const details = {
      originUrl: "moz-extension://abc123/page.html",
      documentUrl: "moz-extension://abc123/frame.html",
      tabId: -1,
    } as browser.webRequest._OnBeforeRequestDetails;

    expect(isExtensionRequest(details)).toBe(true);
  });

  it("should return false if originUrl is not a moz-extension URL", () => {
    const details = {
      originUrl: "https://example.com",
      documentUrl: "moz-extension://abc123/frame.html",
      tabId: -1,
    } as browser.webRequest._OnBeforeRequestDetails;

    expect(isExtensionRequest(details)).toBe(false);
  });

  it("should return false if tabId is not -1", () => {
    const details = {
      originUrl: "moz-extension://abc123/page.html",
      documentUrl: "moz-extension://abc123/frame.html",
      tabId: 1,
    } as browser.webRequest._OnBeforeRequestDetails;

    expect(isExtensionRequest(details)).toBe(false);
  });
});

describe("SHA256", () => {
  it("should correctly hash a string input", async () => {
    const hashBuffer = await SHA256("test");
    const hashHex = arrayBufferToHex(hashBuffer);
    expect(hashHex).toBe(
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    );
  });

  it("should correctly hash a Uint8Array input", async () => {
    const input = new TextEncoder().encode("test");
    const hashBuffer = await SHA256(input);
    const hashHex = arrayBufferToHex(hashBuffer);
    expect(hashHex).toBe(
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    );
  });
});

describe("arrayBufferToHex", () => {
  it("should convert an ArrayBuffer to a hexadecimal string", () => {
    const buffer = new Uint8Array([0, 255, 16, 32]).buffer;
    expect(arrayBufferToHex(buffer)).toBe("00ff1020");
  });
});

describe("arraysEqual", () => {
  it("should return true for identical arrays", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(arraysEqual(a, b)).toBe(true);
  });

  it("should return false for arrays with different lengths", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(arraysEqual(a, b)).toBe(false);
  });

  it("should return false for arrays with different values", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([3, 2, 1]);
    expect(arraysEqual(a, b)).toBe(false);
  });
});
