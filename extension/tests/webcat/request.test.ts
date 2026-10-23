import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

import { Database } from "../../src/webcat/interfaces/database";
import {
  WebcatError,
  WebcatErrorCode,
} from "../../src/webcat/interfaces/errors";
import { CachePartition } from "../../src/webcat/interfaces/originstate";
import {
  BundleFetcher,
  BundleFetcherConfig,
  OriginState,
} from "../../src/webcat/originstate";
import {
  enforceHTTPS,
  validateOrigin,
  validateProtocolAndPort,
} from "../../src/webcat/request";
import { WebcatUI } from "../../src/webcat/ui";

vi.mock("../../src/webcat/originstate", () => {
  return {
    BundleFetcher: vi.fn(
      class {
        awaitAll = vi.fn();
      },
    ),
    OriginState: vi.fn(
      class {
        readonly fetcher: BundleFetcher;
        readonly enrollment_hash: Uint8Array;
        constructor(
          _db: Database,
          fetcher: BundleFetcher,
          enrollment_hash: Uint8Array,
          _cachePartition: CachePartition,
        ) {
          this.fetcher = fetcher;
          this.enrollment_hash = enrollment_hash;
        }
      },
    ),
  };
});

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

describe("validateOrigin", () => {
  let db: Database, ui: WebcatUI, cfg: BundleFetcherConfig;
  beforeEach(() => {
    vi.clearAllMocks();
    db = {
      origins: {
        get: vi.fn(),
      },
      getFQDNEnrollment: vi.fn(),
    } as unknown as Database;
    ui = {
      showIcon: vi.fn(),
    } as unknown as WebcatUI;
    cfg = {} as BundleFetcherConfig;
  });

  it("calls ui.showIcon on enrolled frames", async () => {
    vi.mocked(db.getFQDNEnrollment).mockResolvedValue(
      new Uint8Array([1, 2, 3]),
    );
    await validateOrigin(
      db,
      ui,
      {
        url: "https://example.com/",
        tabId: 34,
        state: {
          isFrame: true,
        },
      },
      cfg,
    );
    expect(ui.showIcon).toHaveBeenCalledExactlyOnceWith(34);
  });

  it("does not call ui.showIcon on non-frames", async () => {
    vi.mocked(db.getFQDNEnrollment).mockResolvedValue(
      new Uint8Array([1, 2, 3]),
    );
    await validateOrigin(
      db,
      ui,
      {
        url: "https://example.com/",
        tabId: 34,
        state: {
          isFrame: false,
        },
      },
      cfg,
    );
    expect(ui.showIcon).not.toHaveBeenCalled();
  });

  it("skips all validation for non-enrolled URLs", async () => {
    vi.mocked(db.getFQDNEnrollment).mockResolvedValue(new Uint8Array());
    const result = await validateOrigin(
      db,
      ui,
      {
        url: "https://example.com/",
        tabId: 34,
        state: {
          isFrame: true,
        },
      },
      cfg,
    );
    expect(result).toBeUndefined();
    expect(ui.showIcon).not.toHaveBeenCalled();
    expect(db.origins.get).not.toHaveBeenCalled();
    expect(BundleFetcher).not.toHaveBeenCalled();
    expect(OriginState).not.toHaveBeenCalled();
  });

  it("returns an error for an unsupported protocol", async () => {
    vi.mocked(db.getFQDNEnrollment).mockResolvedValue(
      new Uint8Array([1, 2, 3]),
    );
    const result = (await validateOrigin(
      db,
      ui,
      {
        url: "ftp://example.com/",
        tabId: 34,
        state: {
          isFrame: true,
        },
      },
      cfg,
    )) as WebcatError;
    expect(result).toBeInstanceOf(WebcatError);
    expect(result.code).toBe(WebcatErrorCode.URL.UNSUPPORTED);
    expect(result.details).toStrictEqual(["ftp:", "default"]);
  });

  it("returns an error for a non-standard port", async () => {
    vi.mocked(db.getFQDNEnrollment).mockResolvedValue(
      new Uint8Array([1, 2, 3]),
    );
    const result = (await validateOrigin(
      db,
      ui,
      {
        url: "https://example.com:1234/",
        tabId: 34,
        state: {
          isFrame: true,
        },
      },
      cfg,
    )) as WebcatError;
    expect(result).toBeInstanceOf(WebcatError);
    expect(result.code).toBe(WebcatErrorCode.URL.UNSUPPORTED);
    expect(result.details).toStrictEqual(["https:", "1234"]);
  });

  it("returns a redirect for an HTTP URL", async () => {
    vi.mocked(db.getFQDNEnrollment).mockResolvedValue(
      new Uint8Array([1, 2, 3]),
    );
    const result = await validateOrigin(
      db,
      ui,
      {
        url: "http://example.com/some/path",
        tabId: 34,
        state: {
          isFrame: true,
        },
      },
      cfg,
    );
    expect(result).toStrictEqual({
      redirectUrl: "https://example.com/some/path",
    });
  });

  it("sets pending origin from cache if available", async () => {
    const originState = {
      validUntil: Date.now() / 1000 + 60,
    } as OriginState;
    vi.mocked(db.getFQDNEnrollment).mockResolvedValue(
      new Uint8Array([1, 2, 3]),
    );
    vi.mocked(db.origins.get).mockResolvedValue(originState);
    const details = {
      url: "https://example.com/",
      tabId: 34,
      state: {
        isFrame: true,
        pendingOrigin: undefined,
      },
    };
    const result = await validateOrigin(db, ui, details, cfg);
    expect(result).toBeUndefined();
    expect(details.state.pendingOrigin).toBe(originState);
  });

  it("does not use an origin from an expired cache", async () => {
    const originState = {
      validUntil: Date.now() / 1000 - 1,
    } as OriginState;
    vi.mocked(db.getFQDNEnrollment).mockResolvedValue(
      new Uint8Array([1, 2, 3]),
    );
    vi.mocked(db.origins.get).mockResolvedValue(originState);
    const details = {
      url: "https://example.com/",
      tabId: 34,
      state: {
        isFrame: true,
        pendingOrigin: undefined,
      },
    };
    const result = await validateOrigin(db, ui, details, cfg);
    expect(result).toBeUndefined();
    expect(details.state.pendingOrigin).not.toBe(originState);
    expect(details.state.pendingOrigin).toStrictEqual(
      expect.objectContaining({
        enrollment_hash: new Uint8Array([1, 2, 3]),
      }),
    );
  });
});
