import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

import { BrowserChromeController } from "../../src/browser/chrome";

const mockMatchMedia = vi.fn().mockReturnValue({ matches: false });

vi.stubGlobal("window", {
  matchMedia: mockMatchMedia,
});

const mockSetTitle = vi.fn();
const mockSetIcon = vi.fn();
const mockShow = vi.fn();
const mockUpdate = vi.fn();
vi.stubGlobal("browser", {
  runtime: {
    getURL: (path: string) =>
      new URL(
        path,
        "moz-extension://3a3a9fbd-c94e-42b7-b590-a5842e2c4ed8",
      ).toString(),
  },
  pageAction: {
    setTitle: mockSetTitle,
    setIcon: mockSetIcon,
    show: mockShow,
  },
  tabs: {
    update: mockUpdate,
  },
});

describe("BrowserChromeController", () => {
  const iconPaths = vi.fn();
  const pagePaths = vi.fn();
  let bcc: BrowserChromeController;
  beforeEach(() => {
    bcc = new BrowserChromeController({
      iconPaths,
      pagePaths,
    });
    vi.clearAllMocks();
  });

  it("should detect the color scheme based on a media query", () => {
    mockMatchMedia.mockReturnValueOnce({
      matches: true,
    });
    expect(bcc.getColorScheme()).toBe("dark");
    expect(mockMatchMedia).toHaveBeenCalledExactlyOnceWith(
      "(prefers-color-scheme: dark)",
    );

    mockMatchMedia.mockClear();
    mockMatchMedia.mockReturnValueOnce({
      matches: false,
    });
    expect(bcc.getColorScheme()).toBe("light");
    expect(mockMatchMedia).toHaveBeenCalledExactlyOnceWith(
      "(prefers-color-scheme: dark)",
    );
  });

  it("resolves page URLs", () => {
    pagePaths.mockImplementationOnce(({ name }) => `path/${name}.html`);
    expect(bcc.getPageURL("hello-world")).toBe(
      "moz-extension://3a3a9fbd-c94e-42b7-b590-a5842e2c4ed8/path/hello-world.html",
    );
  });

  it("sets the page action icon correctly", async () => {
    iconPaths.mockImplementationOnce(({ name }) => `icons/${name}.png`);
    await expect(
      bcc.showIcon(123, "warning", "Warning!"),
    ).resolves.toBeUndefined();
    expect(mockSetIcon).toHaveBeenCalledExactlyOnceWith({
      tabId: 123,
      path: "icons/warning.png",
    });
    expect(mockSetTitle).toHaveBeenCalledExactlyOnceWith({
      tabId: 123,
      title: "Warning!",
    });
    expect(mockShow).toHaveBeenCalledExactlyOnceWith(123);
  });

  it("doesn't throw when setting the icon for an invalid tabId", async () => {
    await expect(
      bcc.showIcon(-1, "warning", "Warning!"),
    ).resolves.toBeUndefined();
    expect(mockSetIcon).not.toHaveBeenCalled();
    expect(mockSetTitle).not.toHaveBeenCalled();
    expect(mockShow).not.toHaveBeenCalled();
  });

  it("loads a page correctly", async () => {
    pagePaths.mockImplementationOnce(({ name }) => `${name}-page.html`);
    await expect(
      bcc.loadPage(321, "settings", {
        query: "key=value",
        fragment: "fragment",
      }),
    ).resolves.toBeUndefined();
    expect(mockUpdate).toHaveBeenCalledExactlyOnceWith(321, {
      url: "moz-extension://3a3a9fbd-c94e-42b7-b590-a5842e2c4ed8/settings-page.html?key=value#fragment",
      loadReplace: false,
    });
  });

  it("replaces a page correctly", async () => {
    pagePaths.mockImplementationOnce(({ name }) => `${name}-page.html`);
    await expect(
      bcc.loadPage(321, "settings", {
        replace: true,
      }),
    ).resolves.toBeUndefined();
    expect(mockUpdate).toHaveBeenCalledExactlyOnceWith(321, {
      url: "moz-extension://3a3a9fbd-c94e-42b7-b590-a5842e2c4ed8/settings-page.html",
      loadReplace: true,
    });
  });

  it("doesn't throw when loading a page to an invalid tabId", async () => {
    await expect(bcc.loadPage(-1, "settings")).resolves.toBeUndefined();
    expect(mockUpdate).not.toHaveBeenCalled();
  });
});
