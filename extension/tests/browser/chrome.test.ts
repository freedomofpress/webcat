import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

import { BrowserChromeController } from "../../src/browser/chrome";

const mockSetTitle = vi.fn();
const mockSetIcon = vi.fn();
const mockSetPopup = vi.fn();
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
    setPopup: mockSetPopup,
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

  it("resolves page URLs", () => {
    pagePaths.mockImplementationOnce(({ name }) => `path/${name}.html`);
    expect(bcc.getPageURL("hello-world")).toBe(
      "moz-extension://3a3a9fbd-c94e-42b7-b590-a5842e2c4ed8/path/hello-world.html",
    );
  });

  it("shows the default page action icon", async () => {
    await expect(bcc.showIcon(345)).resolves.toBeUndefined();
    expect(mockSetIcon).not.toHaveBeenCalled();
    expect(mockSetTitle).not.toHaveBeenCalled();
    expect(mockSetPopup).not.toHaveBeenCalled();
  });

  it("sets the page action icon correctly", async () => {
    iconPaths.mockImplementationOnce(({ name }) => `icons/${name}.png`);
    pagePaths.mockImplementationOnce(({ name }) => `pages/${name}.html`);
    await expect(
      bcc.showIcon(123, {
        name: "warning",
        title: "Warning!",
        popup: { name: "popup" },
      }),
    ).resolves.toBeUndefined();
    expect(mockSetIcon).toHaveBeenCalledExactlyOnceWith({
      tabId: 123,
      path: "icons/warning.png",
    });
    expect(mockSetTitle).toHaveBeenCalledExactlyOnceWith({
      tabId: 123,
      title: "Warning!",
    });
    expect(mockSetPopup).toHaveBeenCalledExactlyOnceWith({
      tabId: 123,
      popup:
        "moz-extension://3a3a9fbd-c94e-42b7-b590-a5842e2c4ed8/pages/popup.html",
    });
    expect(mockShow).toHaveBeenCalledExactlyOnceWith(123);
  });

  it("doesn't throw when setting the icon for an invalid tabId", async () => {
    await expect(
      bcc.showIcon(-1, { name: "warning", title: "Warning!" }),
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

  it("resets an icon to the manifest defaults", async () => {
    await expect(bcc.resetIcon(456)).resolves.toBeUndefined();
    expect(mockSetTitle).toHaveBeenCalledExactlyOnceWith({
      tabId: 456,
      title: null,
    });
    expect(mockSetPopup).toHaveBeenCalledExactlyOnceWith({
      tabId: 456,
      popup: null,
    });
    expect(mockSetIcon).toHaveBeenCalledExactlyOnceWith({ tabId: 456 });
  });
});
