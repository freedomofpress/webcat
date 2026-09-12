import permissions from "./permissions";

/** @inline */
type ColorScheme = "dark" | "light";

/** Properties passed to {@link PathTemplate} functions. */
export type PathTemplateProperties = {
  /** The name of the resource. */
  name: string;
  /** The current color scheme of the browser. */
  colorScheme: ColorScheme;
};

/**
 * A template for a file path.
 *
 * @example
 * const icons: PathTemplate = ({ name, colorScheme }) => `icons/${name}-${colorScheme}.png`;
 */
export type PathTemplate = (p: PathTemplateProperties) => string;

/** @internal @inline */
export type BrowserChromeControllerConfig = {
  /** Template for icon paths. */
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
   * Determines the browser color scheme currently in use.
   *
   * @returns The current color scheme.
   */
  getColorScheme(): ColorScheme {
    if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
    return "light";
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
    let url = browser.runtime.getURL(
      this.#pagePaths({ name, colorScheme: this.getColorScheme() }),
    );
    if (options?.query) {
      url += `?${options.query.toString()}`;
    }
    if (options?.fragment) {
      url += `#${options.fragment.toString()}`;
    }
    return url;
  }

  /**
   * Displays a named icon in the browser's URL bar.
   *
   * @param tabId The ID of the tab to display the icon in.
   * @param name The name of the icon.
   * @param title A title text for the icon.
   */
  async showIcon(tabId: number, name: string, title: string) {
    if (tabId < 0) {
      return;
    }
    browser.pageAction.setTitle({ tabId, title });
    const path = this.#iconPaths({ name, colorScheme: this.getColorScheme() });
    await browser.pageAction.setIcon({ tabId, path });
    await browser.pageAction.show(tabId);
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
