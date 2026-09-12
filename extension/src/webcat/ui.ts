import {
  BrowserChromeController,
  BrowserChromeControllerConfig,
} from "../browser/chrome";
import permissions from "../browser/permissions";
import { RequestDetails } from "../browser/requests";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { clearBrowserCaches, getFQDN } from "./utils";

/**
 * Manages the UI for WEBCAT.
 */
@permissions.require("webNavigation")
export class WebcatUI extends BrowserChromeController {
  constructor(config: BrowserChromeControllerConfig) {
    super(config);
    browser.webNavigation.onCommitted.addListener(
      this.#onErrorPageNavigation.bind(this),
      { url: [{ urlPrefix: this.getPageURL("error") }] },
    );
  }

  /**
   * Displays the default icon in the browser's URL bar.
   *
   * @param tabId The ID of the tab to display the icon in.
   */
  async showIcon(tabId: number) {
    await super.showIcon(
      tabId,
      "webcat",
      browser.i18n.getMessage("webcatIsRunning"),
    );
  }

  /**
   * Displays the OK icon in the browser's URL bar.
   *
   * @param tabId The ID of the tab to display the icon in.
   * @param delegation Optional delegation information to include in the title
   *   text.
   */
  async showOKIcon(tabId: number, delegation?: string) {
    logger.addLog(
      "info",
      delegation
        ? `Setting ok icon (delegation: ${delegation})`
        : "Setting ok icon",
      tabId,
      "",
    );
    let message = browser.i18n.getMessage("webcatVerificationSuccessful");
    if (delegation) {
      message += ` (${delegation})`;
    }
    await super.showIcon(tabId, "webcat-ok", message);
  }

  /**
   * Displays the error icon in the browser's URL bar.
   *
   * @param tabId The ID of the tab to display the icon in.
   */
  async showErrorIcon(tabId: number) {
    await super.showIcon(
      tabId,
      "webcat-error",
      browser.i18n.getMessage("webcatVerificationFailed"),
    );
  }

  /**
   * Loads the error page in the tab(s) indicated by details.
   *
   * @param details Details for the request that triggered the error.
   * @param error The error information.
   * @param replace true to replace the current history entry, false to add a
   *   new one.
   */
  async showErrorPage(
    details: Stateful<RequestDetails>,
    error: WebcatError,
    replace = !details.state.isFrame,
  ) {
    const tabIds = new Set<number>();
    const frameLookups = [];
    if (details.tabId < 0) {
      const tabs = await browser.tabs.query({});
      for (const tab of tabs) {
        if (
          tab.url &&
          tab.id &&
          /https?:\/\//i.test(tab.url) &&
          details.state.fqdn === getFQDN(tab.url)
        ) {
          tabIds.add(tab.id);
        } else if (tab.id) {
          frameLookups.push(
            browser.webNavigation
              .getAllFrames({ tabId: tab.id })
              .then((frames) =>
                frames.forEach((frame) => {
                  if (
                    /https?:\/\//i.test(frame.url) &&
                    details.state.fqdn === getFQDN(frame.url)
                  ) {
                    tabIds.add(frame.tabId);
                  }
                }),
              ),
          );
        }
      }
      await Promise.all(frameLookups);
    } else {
      tabIds.add(details.tabId);
    }

    const code = error?.code ?? "WEBCAT_ERROR_UNDEFINED";

    const params = new URLSearchParams({ code, host: details.state.fqdn });

    if (
      (code === WebcatErrorCode.File.MISMATCH ||
        code === WebcatErrorCode.File.MISSING) &&
      error?.details?.[0]
    ) {
      params.set("file", error.details[0]);
    }

    const tabUpdates: Promise<void>[] = [];
    tabIds.forEach((tabId) =>
      tabUpdates.push(
        this.loadPage(tabId, "error", {
          fragment: params,
          replace,
        }),
      ),
    );
    await Promise.all(tabUpdates);

    await clearBrowserCaches([details.state.fqdn]);
  }

  #onErrorPageNavigation(details: browser.webNavigation._OnCommittedDetails) {
    this.showErrorIcon(details.tabId);
  }
}
