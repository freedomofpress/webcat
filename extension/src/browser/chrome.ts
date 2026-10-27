import permissions from "./permissions";

/** Properties passed to {@link PathTemplate} functions. */
export type PathTemplateProperties = {
  /** The name of the resource. */
  name: string;
};

/**
 * A template for a file path.
 *
 * @example
 * const icons: PathTemplate = ({ name }) => `icons/${name}.svg`;
 */
export type PathTemplate = (p: PathTemplateProperties) => string;

/** @internal @inline */
export type IconOptions = {
  /** The name of the icon. */
  name?: string;
  /** The title displayed in the icon's tooltip. */
  title?: string;
  /** The popup page to display on click. */
  popup?: {
    name: string;
    query?: string | URLSearchParams;
    fragment?: string | URLSearchParams;
  };
};

/** @internal @inline */
export type BrowserChromeControllerConfig = {
  /**
   * Template for icon paths. The extension supports both a light and a dark
   * color scheme: use an icon with a `prefers-color-scheme` media query where
   * available.
   */
  iconPaths: PathTemplate;
  /** Template for page paths. */
  pagePaths: PathTemplate;
};

/**
 * A class for interacting with browser chrome and extension internal pages.
 */
@permissions.require("tabs")
export class BrowserChromeController {
  readonly #iconPaths: PathTemplate;
  readonly #pagePaths: PathTemplate;

  constructor(config: BrowserChromeControllerConfig) {
    this.#iconPaths = config.iconPaths;
    this.#pagePaths = config.pagePaths;
  }

  /**
   * Computes the URL of a named page.
   *
   * @param name The name of the page.
   * @param options
   * @returns The absolute URL of the page.
   */
  getPageURL(
    name: string,
    options?: {
      query?: string | URLSearchParams;
      fragment?: string | URLSearchParams;
    },
  ) {
    let url = browser.runtime.getURL(this.#pagePaths({ name }));
    if (options?.query) {
      url += `?${options.query.toString()}`;
    }
    if (options?.fragment) {
      url += `#${options.fragment.toString()}`;
    }
    return url;
  }

  /**
   * Displays an icon in the browser's URL bar.
   *
   * @param tabId The ID of the tab to display the icon in.
   * @param options
   */
  async showIcon(tabId: number, options?: IconOptions) {
    if (tabId < 0) {
      return;
    }
    if (options?.title) {
      browser.pageAction.setTitle({ tabId, title: options.title });
    }
    if (options?.name) {
      const path = this.#iconPaths({ name: options.name });
      await browser.pageAction.setIcon({ tabId, path });
    }
    if (options?.popup) {
      const popup = this.getPageURL(options.popup.name, options.popup);
      browser.pageAction.setPopup({ tabId, popup });
    }
    await browser.pageAction.show(tabId);
  }

  /**
   * Resets the icon, title and popup of a specific tab to the manifest
   * defaults.
   *
   * @param tabId The ID of the tab to reset.
   */
  async resetIcon(tabId: number) {
    browser.pageAction.setTitle({ tabId, title: null });
    browser.pageAction.setPopup({ tabId, popup: null });
    await browser.pageAction.setIcon({ tabId });
  }

  /**
   * Loads a named page in the specified tab.
   *
   * @param tabId The ID of the tab to load the page in.
   * @param name The name of the page.
   * @param options
   */
  async loadPage(
    tabId: number,
    name: string,
    options?: {
      replace?: boolean;
      query?: string | URLSearchParams;
      fragment?: string | URLSearchParams;
    },
  ) {
    if (tabId < 0) {
      return;
    }
    await browser.tabs.update(tabId, {
      url: this.getPageURL(name, options),
      loadReplace: options?.replace ?? false,
    });
  }
}
