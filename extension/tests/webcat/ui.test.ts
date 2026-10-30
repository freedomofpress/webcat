import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
    addEventListener: vi.fn(),
    getMissing: vi.fn().mockReturnValue(new Set()),
  },
}));

import { NamespacedKVStore } from "../../src/browser/kvstore";
import { Database } from "../../src/webcat/interfaces/database";
import { RequestState } from "../../src/webcat/interfaces/requeststate";
import { WebcatUI } from "../../src/webcat/ui";

const mockSetPopup = vi.fn();
const mockGetPopup = vi.fn();
const mockGetTitle = vi.fn();
const mockOnBeforeRequest = vi.fn();
vi.stubGlobal("browser", {
  runtime: { getURL: (path: string) => `moz-extension://id/${path}` },
  i18n: { getMessage: (key: string) => key },
  webNavigation: { onCommitted: { addListener: vi.fn() } },
  webRequest: { onBeforeRequest: { addListener: mockOnBeforeRequest } },
  pageAction: {
    setTitle: vi.fn(),
    getTitle: mockGetTitle,
    setIcon: vi.fn(),
    setPopup: mockSetPopup,
    getPopup: mockGetPopup,
    show: vi.fn(),
  },
});

const state = (fqdn: string): RequestState => ({
  fqdn,
  isFrame: false,
  cachePartition: { firstParty: "example.com", incognito: false },
});

describe("WebcatUI popup", () => {
  let ui: WebcatUI;
  beforeEach(() => {
    vi.clearAllMocks();
    ui = new WebcatUI(
      {} as Database,
      { namespace: () => ({}) } as unknown as NamespacedKVStore,
      { iconPaths: ({ name }) => name, pagePaths: ({ name }) => name },
    );
  });

  it("sets a popup with the origin entry and delegation", async () => {
    await ui.showOKIcon(1, state("example.com"), "parent.com");
    const popup = new URL(mockSetPopup.mock.calls[0][0].popup);
    const params = new URLSearchParams(popup.hash.slice(1));
    expect(JSON.parse(params.get("origin") ?? "")).toEqual({
      fqdn: "example.com",
      key: "example.com?firstParty=example.com,incognito=false",
    });
    expect(params.get("delegation")).toBe("parent.com");
  });

  it("appends verified frames to an existing OK popup", async () => {
    mockGetTitle.mockResolvedValue("WEBCAT_webcatVerifying");
    mockGetPopup.mockResolvedValueOnce("");
    await ui.showPartialIcon(1, state("frame.com"));
    expect(mockSetPopup).not.toHaveBeenCalled();

    await ui.showOKIcon(1, state("example.com"));
    mockGetPopup.mockResolvedValueOnce(mockSetPopup.mock.calls[0][0].popup);
    await ui.showPartialIcon(1, state("frame.com"));
    const popup = new URL(mockSetPopup.mock.calls[1][0].popup);
    const params = new URLSearchParams(popup.hash.slice(1));
    expect(JSON.parse(params.get("origin") ?? "").fqdn).toBe("example.com");
    expect(params.getAll("frame").map((f) => JSON.parse(f).fqdn)).toEqual([
      "frame.com",
    ]);

    // The same frame verifying twice (headers, then body) is listed once
    mockGetPopup.mockResolvedValueOnce(popup.href);
    await ui.showPartialIcon(1, state("frame.com"));
    expect(mockSetPopup).toHaveBeenCalledTimes(2);
  });

  it("marks a not-enrolled tab partial with a frames-only popup", async () => {
    mockGetTitle.mockResolvedValue("WEBCAT_webcatNotEnrolled");
    mockGetPopup.mockResolvedValueOnce("");
    await ui.showPartialIcon(1, state("frame.com"));
    const popup = new URL(mockSetPopup.mock.calls[0][0].popup);
    const params = new URLSearchParams(popup.hash.slice(1));
    expect(params.get("origin")).toBeNull();
    expect(params.getAll("frame")).toHaveLength(1);
  });

  it("serves a stored origin part as a data: JSON redirect", async () => {
    const manifest = { version: "1", files: {} };
    const db = {
      origins: {
        get: vi.fn(async (key: string) =>
          key === "example.com?firstParty=example.com,incognito=false"
            ? {
                isManifestVerified: () => true,
                toPOJO: () => ({ manifest, signatures: ["sig"] }),
              }
            : undefined,
        ),
      },
    } as unknown as Database;
    new WebcatUI(
      db,
      { namespace: () => ({}) } as unknown as NamespacedKVStore,
      { iconPaths: ({ name }) => name, pagePaths: ({ name }) => name },
    );
    const listener = mockOnBeforeRequest.mock.calls.at(-1)?.[0];
    const key = encodeURIComponent(
      "example.com?firstParty=example.com,incognito=false",
    );
    const { redirectUrl } = await listener({
      url: `${WebcatUI.JSON_ORIGIN}/manifest/${key}`,
    });
    expect(redirectUrl).toMatch(/^data:application\/json;charset=utf-8,/);
    expect(JSON.parse(decodeURIComponent(redirectUrl.split(",")[1]))).toEqual({
      manifest,
      signatures: ["sig"],
    });
    const fromPage = await listener({
      url: `${WebcatUI.JSON_ORIGIN}/manifest/${key}`,
      originUrl: "https://attacker.example/",
    });
    expect(fromPage).toEqual({ cancel: true });
    const fromPopup = await listener({
      url: `${WebcatUI.JSON_ORIGIN}/manifest/${key}`,
      originUrl: "moz-extension://id/pages/popup.html",
    });
    expect(fromPopup.redirectUrl).toMatch(/^data:application\/json/);
    const other = await listener({
      url: `${WebcatUI.JSON_ORIGIN}/status/${key}`,
    });
    expect(other.redirectUrl).toContain(encodeURIComponent('"error"'));
    const missing = await listener({
      url: `${WebcatUI.JSON_ORIGIN}/manifest/nope`,
    });
    expect(
      JSON.parse(decodeURIComponent(missing.redirectUrl.split(",")[1])),
    ).toEqual({ error: "WEBCAT_detailsUnavailable" });
  });
});
