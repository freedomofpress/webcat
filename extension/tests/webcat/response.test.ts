import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

import {
  BeforeRequestDetails,
  HeadersReceivedDetails,
} from "../../src/browser/requests";
import { WebcatDatabase } from "../../src/webcat/db";
import { HookBuilder } from "../../src/webcat/hookbuilder";
import {
  WebcatError,
  WebcatErrorCode,
} from "../../src/webcat/interfaces/errors";
import { Stateful } from "../../src/webcat/interfaces/requeststate";
import { ResponseValidator } from "../../src/webcat/response";
import { WebcatUI } from "../../src/webcat/ui";

// --- Mocks ---
const mockFilterResponseData = vi.fn();
vi.stubGlobal("browser", {
  webRequest: {
    filterResponseData: mockFilterResponseData,
  },
});

describe("ResponseValidator.validateHeaders", () => {
  let ui: WebcatUI;
  let rv: ResponseValidator;
  let details: Stateful<HeadersReceivedDetails>;

  beforeEach(() => {
    ui = {
      showOKIcon: vi.fn(),
      showPartialIcon: vi.fn(),
    } as unknown as WebcatUI;
    rv = new ResponseValidator({} as WebcatDatabase, ui, {} as HookBuilder);
    rv.extractAndValidateHeaders = vi.fn();
    details = {
      url: "https://example.com/",
      type: "main_frame",
      tabId: 123,
      state: {
        pendingOrigin: {
          isRequestSent: vi.fn().mockReturnValue(false),
          isManifestVerified: vi.fn().mockReturnValue(true),
          isFailed: vi.fn().mockReturnValue(false),
          verifyEnrollment: vi.fn(),
          verifyManifest: vi.fn(),
          verifyCSP: vi.fn().mockReturnValue(true),
        },
      },
    };
  });

  it("rejects when pendingOrigin is unavailable", async () => {
    delete details.state.pendingOrigin;
    const result = rv.validateHeaders(details);
    await expect(result).rejects.toThrow(
      "missing pendingOrigin in request state",
    );
  });

  it("returns an error when extractAndValidateheaders returns an error", async () => {
    const error = new WebcatError(WebcatErrorCode.Headers.MISSING);
    vi.mocked(rv.extractAndValidateHeaders).mockReturnValueOnce(error);
    const result = await rv.validateHeaders(details);
    expect(result).toBe(error);
  });

  it("shows the OK icon when everything is as expected", async () => {
    vi.mocked(rv.extractAndValidateHeaders).mockReturnValueOnce(
      new Map([["content-security-policy", "policy"]]),
    );
    const result = await rv.validateHeaders(details);
    expect(result).toBeUndefined();
    expect(
      details.state.pendingOrigin.verifyCSP,
    ).toHaveBeenCalledExactlyOnceWith("policy", "/");
    expect(ui.showOKIcon).toHaveBeenCalledExactlyOnceWith(
      details.tabId,
      details.state,
      undefined,
    );
  });

  it("shows the partial icon for a sub_frame", async () => {
    vi.mocked(rv.extractAndValidateHeaders).mockReturnValueOnce(
      new Map([["content-security-policy", "policy"]]),
    );
    details.type = "sub_frame";
    const result = await rv.validateHeaders(details);
    expect(result).toBeUndefined();
    expect(ui.showOKIcon).not.toHaveBeenCalled();
    expect(ui.showPartialIcon).toHaveBeenCalledExactlyOnceWith(
      details.tabId,
      details.state,
    );
  });

  it("verifies the enrollment and manifest when in the request_sent state", async () => {
    vi.mocked(rv.extractAndValidateHeaders).mockReturnValueOnce(
      new Map([["content-security-policy", "policy"]]),
    );
    details.state.pendingOrigin.isRequestSent.mockReturnValueOnce(true);
    const result = await rv.validateHeaders(details);
    expect(result).toBeUndefined();
    expect(
      details.state.pendingOrigin.verifyEnrollment,
    ).toHaveBeenCalledExactlyOnceWith(undefined, undefined);
    expect(
      details.state.pendingOrigin.verifyManifest,
    ).toHaveBeenCalledExactlyOnceWith();
    expect(
      details.state.pendingOrigin.verifyCSP,
    ).toHaveBeenCalledExactlyOnceWith("policy", "/");
    expect(ui.showOKIcon).toHaveBeenCalledExactlyOnceWith(
      details.tabId,
      details.state,
      undefined,
    );
  });

  it("accepts an enrollment in a header", async () => {
    vi.mocked(rv.extractAndValidateHeaders).mockReturnValueOnce(
      new Map([
        ["content-security-policy", "policy"],
        ["x-webcat-enrollment", "e30="],
      ]),
    );
    details.state.pendingOrigin.isRequestSent.mockReturnValueOnce(true);
    const result = await rv.validateHeaders(details);
    expect(result).toBeUndefined();
    expect(
      details.state.pendingOrigin.verifyEnrollment,
    ).toHaveBeenCalledExactlyOnceWith({}, undefined);
    expect(
      details.state.pendingOrigin.verifyManifest,
    ).toHaveBeenCalledExactlyOnceWith();
    expect(
      details.state.pendingOrigin.verifyCSP,
    ).toHaveBeenCalledExactlyOnceWith("policy", "/");
    expect(ui.showOKIcon).toHaveBeenCalledExactlyOnceWith(
      details.tabId,
      details.state,
      undefined,
    );
  });

  it("returns an error on a bad enrollment header", async () => {
    vi.mocked(rv.extractAndValidateHeaders).mockReturnValueOnce(
      new Map([
        ["content-security-policy", "policy"],
        ["x-webcat-enrollment", "bad"],
      ]),
    );
    details.state.pendingOrigin.isRequestSent.mockReturnValueOnce(true);
    const result = await rv.validateHeaders(details);
    expect(result).toStrictEqual(
      new WebcatError(WebcatErrorCode.Headers.ENROLLMENT_MALFORMED),
    );
  });

  it("returns an error when enrollment fails to verify", async () => {
    vi.mocked(rv.extractAndValidateHeaders).mockReturnValueOnce(
      new Map([["content-security-policy", "policy"]]),
    );
    details.state.pendingOrigin.isRequestSent.mockReturnValueOnce(true);
    details.state.pendingOrigin.verifyEnrollment.mockImplementationOnce(() => {
      details.state.pendingOrigin.error = "bad enrollment";
      details.state.pendingOrigin.isFailed.mockReturnValueOnce(true);
    });
    const result = await rv.validateHeaders(details);
    expect(result).toStrictEqual("bad enrollment");
  });

  it("returns an error when manifest fails to verify", async () => {
    vi.mocked(rv.extractAndValidateHeaders).mockReturnValueOnce(
      new Map([["content-security-policy", "policy"]]),
    );
    details.state.pendingOrigin.isRequestSent.mockReturnValueOnce(true);
    details.state.pendingOrigin.verifyManifest.mockImplementationOnce(() => {
      details.state.pendingOrigin.error = "bad manifest";
      details.state.pendingOrigin.isFailed.mockReturnValueOnce(true);
    });
    const result = await rv.validateHeaders(details);
    expect(result).toStrictEqual("bad manifest");
  });
});

describe("ResponseValidator.extractAndValidateHeaders", () => {
  let rv: ResponseValidator;

  beforeEach(() => {
    rv = new ResponseValidator(
      {} as WebcatDatabase,
      {} as WebcatUI,
      {} as HookBuilder,
    );
  });

  it("requires CSP for non-cached responses", () => {
    const details = {
      responseHeaders: [{ name: "x-webcat-version", value: "1.2.3" }],
      fromCache: false,
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.MISSING_CRITICAL,
    );
  });

  it("blocks Origin-Agent-Cluster opt-out", () => {
    const details = {
      responseHeaders: [
        { name: "Origin-Agent-Cluster", value: "?0" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "main_frame",
      state: { isFrame: true },
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.FORBIDDEN,
    );
  });

  it("allows missing CSP for fully cached responses", () => {
    const details = {
      responseHeaders: [{ name: "x-webcat-version", value: "1.2.3" }],
      fromCache: true,
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Map);
    expect((result as Map<string, string>).has("content-security-policy")).toBe(
      false,
    );
  });

  it("allows missing CSP for 304 responses", () => {
    const details = {
      responseHeaders: [{ name: "x-webcat-version", value: "1.2.3" }],
      fromCache: false,
      statusCode: 304,
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Map);
    expect((result as Map<string, string>).has("content-security-policy")).toBe(
      false,
    );
  });

  it("blocks Location header on sub-resource requests (script)", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "/other.js" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "script",
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.LOCATION_SUBRESOURCE,
    );
  });

  it("blocks Location header on sub-resource requests (stylesheet)", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "/other.css" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "stylesheet",
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.LOCATION_SUBRESOURCE,
    );
  });

  it("blocks Location header on sub-resource requests (xmlhttprequest)", () => {
    const details = {
      responseHeaders: [
        { name: "Location", value: "/api/other" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "xmlhttprequest",
      state: {},
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.LOCATION_SUBRESOURCE,
    );
  });

  it("allows safe relative Location header on main_frame", () => {
    const details = {
      url: "https://example.com/",
      responseHeaders: [
        { name: "Location", value: "/login" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "main_frame",
      state: { isFrame: true },
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Map);
  });

  it("allows safe relative Location header on sub_frame", () => {
    const details = {
      url: "https://example.com/",
      responseHeaders: [
        { name: "Location", value: "/embed" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "sub_frame",
      state: { isFrame: true },
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Map);
  });

  it("blocks external Location header even on main_frame", () => {
    const details = {
      url: "https://example.com/",
      responseHeaders: [
        { name: "Location", value: "https://evil.com" },
        { name: "Content-Security-Policy", value: "default-src 'self'" },
      ],
      fromCache: false,
      type: "main_frame",
      state: { isFrame: true },
    } as Stateful<HeadersReceivedDetails>;

    const result = rv.extractAndValidateHeaders(details);

    expect(result).toBeInstanceOf(Error);
    expect((result as { code: string }).code).toBe(
      WebcatErrorCode.Headers.LOCATION_EXTERNAL,
    );
  });
});

describe("ResponseValidator.validateContent", () => {
  let ui: WebcatUI;
  let rv: ResponseValidator;
  let filter: {
    onstart?: () => void;
    ondata?: (event: unknown) => void;
    onstop?: () => Promise<void>;
    close: () => void;
    disconnect: () => void;
    write: () => void;
  };
  let verified: boolean;
  let details: Stateful<BeforeRequestDetails>;

  beforeEach(() => {
    vi.clearAllMocks();
    ui = {
      showErrorPage: vi.fn(),
      showOKIcon: vi.fn(),
      showPartialIcon: vi.fn(),
    } as unknown as WebcatUI;
    rv = new ResponseValidator({} as WebcatDatabase, ui, {} as HookBuilder);
    filter = {
      close: vi.fn(),
      disconnect: vi.fn(),
      write: vi.fn(),
    };
    verified = false;
    details = {
      requestId: "request-id",
      url: "https://example.com/path",
      state: {
        pendingOrigin: {
          isManifestVerified() {
            return verified;
          },
          manifest: {
            files: {},
          },
        },
      },
      type: "other",
    };
  });

  it("rejects when no pendingOrigin is available", async () => {
    delete details.state.pendingOrigin;
    await expect(rv.validateContent(details)).rejects.toThrow(
      "missing pendingOrigin in request state",
    );
  });

  it("throws when manifest is unverified", async () => {
    mockFilterResponseData.mockReturnValueOnce(filter);
    const result = await rv.validateContent(details);
    expect(result).toBeUndefined();
    expect(mockFilterResponseData).toHaveBeenCalledExactlyOnceWith(
      "request-id",
    );

    details.responseHeaders = [];
    expect(filter.onstart).toThrow();
  });

  it("throws when response headers are unavailable", async () => {
    mockFilterResponseData.mockReturnValueOnce(filter);
    const result = await rv.validateContent(details);
    expect(result).toBeUndefined();
    expect(mockFilterResponseData).toHaveBeenCalledExactlyOnceWith(
      "request-id",
    );

    verified = true;
    expect(filter.onstart).toThrow();
  });

  it("allows a pass-through type unfiltered", async () => {
    mockFilterResponseData.mockReturnValueOnce(filter);
    const result = await rv.validateContent(details);
    expect(result).toBeUndefined();
    expect(mockFilterResponseData).toHaveBeenCalledExactlyOnceWith(
      "request-id",
    );

    verified = true;
    details.responseHeaders = [];
    filter.onstart?.();
    expect(filter.close).not.toHaveBeenCalled();
    expect(filter.disconnect).toHaveBeenCalledExactlyOnceWith();
  });

  it("denies a response with a mismatching hash", async () => {
    mockFilterResponseData.mockReturnValueOnce(filter);
    const result = await rv.validateContent(details);
    expect(result).toBeUndefined();
    expect(mockFilterResponseData).toHaveBeenCalledExactlyOnceWith(
      "request-id",
    );

    const data = new TextEncoder().encode("data").buffer;
    verified = true;
    details.state.pendingOrigin.manifest.files["/path"] = "hash";
    details.responseHeaders = [];
    filter.onstart?.();
    filter.ondata?.({ data });
    await filter.onstop?.();
    expect(filter.write).toHaveBeenCalledExactlyOnceWith(
      new Uint8Array([68, 69, 78, 73, 69, 68]),
    );
    expect(filter.close).toHaveBeenCalledExactlyOnceWith();
    expect(filter.disconnect).not.toHaveBeenCalled();
    expect(ui.showErrorPage).toHaveBeenCalledExactlyOnceWith(
      details,
      new WebcatError(WebcatErrorCode.File.MISMATCH, [
        "/path",
        "hash",
        "Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc",
      ]),
      true,
    );
  });

  it("allows a response with a matching hash", async () => {
    mockFilterResponseData.mockReturnValueOnce(filter);
    const result = await rv.validateContent(details);
    expect(result).toBeUndefined();
    expect(mockFilterResponseData).toHaveBeenCalledExactlyOnceWith(
      "request-id",
    );

    const data = new TextEncoder().encode("data").buffer;
    verified = true;
    details.state.pendingOrigin.manifest.files["/path"] =
      "Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc";
    details.responseHeaders = [];
    filter.onstart?.();
    filter.ondata?.({ data });
    await filter.onstop?.();
    expect(filter.write).toHaveBeenCalledExactlyOnceWith(data);
    expect(filter.close).toHaveBeenCalledExactlyOnceWith();
    expect(filter.disconnect).not.toHaveBeenCalled();
    expect(ui.showErrorPage).not.toHaveBeenCalled();
    expect(ui.showOKIcon).not.toHaveBeenCalled();
    expect(ui.showPartialIcon).not.toHaveBeenCalled();
  });

  it("shows the partial icon for a verified sub_frame", async () => {
    details.type = "sub_frame";
    details.tabId = 123;
    // Frames require the end marker; capture it from markContent
    const marker = { onstart: () => {}, write: vi.fn() };
    mockFilterResponseData.mockReturnValueOnce(marker);
    rv.markContent(details);
    marker.onstart();

    mockFilterResponseData.mockReturnValueOnce(filter);
    await rv.validateContent(details);

    const data = new TextEncoder().encode("data").buffer;
    verified = true;
    details.state.pendingOrigin.manifest.files["/path"] =
      "Om6weQ85rIfJTzhWst0sXREOaBFgImGpqSPTuyOtyLc";
    details.responseHeaders = [];
    filter.onstart?.();
    filter.ondata?.({ data: marker.write.mock.calls[0][0].slice().buffer });
    filter.ondata?.({ data });
    await filter.onstop?.();
    expect(filter.write).toHaveBeenCalledExactlyOnceWith(data);
    expect(ui.showOKIcon).not.toHaveBeenCalled();
    expect(ui.showPartialIcon).toHaveBeenCalledExactlyOnceWith(
      123,
      details.state,
    );
  });
});
