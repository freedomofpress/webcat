import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

import {
  arraysEqual,
  clearBrowserCaches,
  getFQDN,
  getFQDNSafe,
  isExtensionRequest,
  isNewerSemver,
  isSameOriginURL,
  SHA256,
} from "./../../src/webcat/utils";

const mockRemove = vi.fn();
vi.stubGlobal("browser", {
  browsingData: {
    remove: mockRemove,
  },
});

function arrayBufferToHex(buffer: Uint8Array | ArrayBuffer) {
  const array = Array.from(new Uint8Array(buffer));
  return array.map((b) => b.toString(16).padStart(2, "0")).join("");
}

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

  it("should throw an error for invalid URLs", () => {
    expect(() => getFQDN("not-a-url")).toThrow();
  });
});

describe("getFQDNSafe", () => {
  it("should extract the hostname from a valid URL with a scheme", () => {
    expect(getFQDNSafe("https://example.com/path")).toBe("example.com");
    expect(getFQDNSafe("http://sub.domain.example.com:8080/test")).toBe(
      "sub.domain.example.com",
    );
  });

  it("should prepend https and extract hostname for URLs without a scheme", () => {
    expect(getFQDNSafe("example.com")).toBe("example.com");
    expect(getFQDNSafe("sub.domain.example.com")).toBe(
      "sub.domain.example.com",
    );
  });

  it("should handle URLs with query parameters and fragments", () => {
    expect(getFQDNSafe("example.com?query=123#fragment")).toBe("example.com");
    expect(getFQDNSafe("https://example.com?query=123#fragment")).toBe(
      "example.com",
    );
  });

  it("should throw an error for clearly invalid URLs", () => {
    expect(() => getFQDNSafe("not a valid url")).toThrow();
    expect(() => getFQDNSafe("http://")).toThrow();
    expect(() => getFQDNSafe("https://")).toThrow();
    expect(() => getFQDNSafe("")).toThrow();
  });
});

describe("isSameOriginURL", () => {
  it("allows absolute-path relative locations", () => {
    expect(isSameOriginURL("/", "https://example.com/path/?q=1")).toBe(true);
    expect(isSameOriginURL("/login", "https://example.com/path/?q=1")).toBe(
      true,
    );
    expect(isSameOriginURL("/a/b/c", "https://example.com/path/?q=1")).toBe(
      true,
    );
  });

  it("allows parent-relative paths", () => {
    expect(isSameOriginURL("../login", "https://example.com/path/?q=1")).toBe(
      true,
    );
    expect(isSameOriginURL("../a/b", "https://example.com/path/?q=1")).toBe(
      true,
    );
  });

  it("allows same-relative paths", () => {
    expect(isSameOriginURL("./login", "https://example.com/path/?q=1")).toBe(
      true,
    );
  });

  it("allows whitespace", () => {
    expect(isSameOriginURL(" /login ", "https://example.com/path/?q=1")).toBe(
      true,
    );
    expect(isSameOriginURL("  ../login", "https://example.com/path/?q=1")).toBe(
      true,
    );
  });

  it("rejects cross-origin protocol-relative URLs", () => {
    expect(isSameOriginURL("//evil.com", "https://example.com/path/?q=1")).toBe(
      false,
    );
    expect(
      isSameOriginURL("///evil.com", "https://example.com/path/?q=1"),
    ).toBe(false);
  });

  it("allows same-origin protocol-relative URLs", () => {
    expect(
      isSameOriginURL("//example.com", "https://example.com/path/?q=1"),
    ).toBe(true);
    expect(
      isSameOriginURL("///example.com", "https://example.com/path/?q=1"),
    ).toBe(true);
  });

  it("rejects cross-origin URLs with schemes", () => {
    expect(
      isSameOriginURL("https://evil.com", "https://example.com/path/?q=1"),
    ).toBe(false);
    expect(
      isSameOriginURL("http://evil.com", "https://example.com/path/?q=1"),
    ).toBe(false);
    expect(
      isSameOriginURL("ftp://evil.com", "https://example.com/path/?q=1"),
    ).toBe(false);
    expect(
      isSameOriginURL("javascript:alert(1)", "https://example.com/path/?q=1"),
    ).toBe(false);
    expect(isSameOriginURL("blob:abcd", "https://example.com/path/?q=1")).toBe(
      false,
    );
    expect(
      isSameOriginURL("data:text/plain,hi", "https://example.com/path/?q=1"),
    ).toBe(false);
  });

  it("allows same-origin URLs with schemes", () => {
    expect(
      isSameOriginURL("https://example.com", "https://example.com/path/?q=1"),
    ).toBe(true);
    expect(
      isSameOriginURL(
        "https://example.com/index.html",
        "https://example.com/path/?q=1",
      ),
    ).toBe(true);
  });

  it("rejects backslash-based paths", () => {
    expect(
      isSameOriginURL("\\/evil.com", "https://example.com/path/?q=1"),
    ).toBe(false);
    expect(
      isSameOriginURL("/\\evil.com", "https://example.com/path/?q=1"),
    ).toBe(false);
    expect(
      isSameOriginURL("\\\\evil.com", "https://example.com/path/?q=1"),
    ).toBe(false);
  });

  it("allows bare relative paths", () => {
    expect(isSameOriginURL("login", "https://example.com/path/?q=1")).toBe(
      true,
    );
  });

  it("allows encoded slashes (no decoding is performed)", () => {
    expect(
      isSameOriginURL("/%2f%2fevil.com", "https://example.com/path/?q=1"),
    ).toBe(true);
    expect(
      isSameOriginURL("%2f%2fevil.com", "https://example.com/path/?q=1"),
    ).toBe(true);
  });

  it("allows control characters (current behavior)", () => {
    expect(isSameOriginURL("/foo\nbar", "https://example.com/path/?q=1")).toBe(
      true,
    );
    expect(isSameOriginURL("/foo\rbar", "https://example.com/path/?q=1")).toBe(
      true,
    );
    expect(isSameOriginURL("/foo\tbar", "https://example.com/path/?q=1")).toBe(
      true,
    );
  });

  it("rejects invalid URLs", () => {
    expect(isSameOriginURL("https://", "https://example.com/path?q=1")).toBe(
      false,
    );
  });
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

  it("should correctly hash an ArrayBuffer input", async () => {
    const input = new TextEncoder().encode("test").buffer;
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
});

describe("clearBrowserCaches", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("should remove workers and all caches", async () => {
    await clearBrowserCaches(["example.com", "example.org"]);
    expect(mockRemove).toHaveBeenCalledTimes(2);
    expect(mockRemove).toHaveBeenNthCalledWith(
      1,
      { hostnames: ["example.com", "example.org"] },
      { serviceWorkers: true },
    );
    expect(mockRemove).toHaveBeenNthCalledWith(2, {}, { cache: true });
  });

  it("should do nothing when no FQDNs are given", async () => {
    await clearBrowserCaches([]);
    expect(mockRemove).not.toHaveBeenCalled();
  });
});
