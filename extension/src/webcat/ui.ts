import {
  BrowserChromeController,
  BrowserChromeControllerConfig,
  IconOptions,
} from "../browser/chrome";
import { NamespacedKVStore } from "../browser/kvstore";
import permissions from "../browser/permissions";
import { RequestDetails } from "../browser/requests";
import { Database } from "./interfaces/database";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { clearBrowserCaches, getFQDN } from "./utils";

/**
 * Manages the UI for WEBCAT.
 */
@permissions.require("webNavigation")
export class WebcatUI extends BrowserChromeController {
  readonly #db: Database;
  readonly #warnings: NamespacedKVStore;

  #showWarnings = false;

  /**
   * @param db The database to load enrollments from.
   * @param store The store to use for persistence.
   * @param config
   */
  constructor(
    db: Database,
    store: NamespacedKVStore,
    config: BrowserChromeControllerConfig,
  ) {
    super(config);
    this.#db = db;
    this.#warnings = store.namespace("warnings");
    permissions.addEventListener(
      "permissionerror",
      this.#onPermissionsChanged.bind(this),
    );
    permissions.addEventListener(
      "permissionrestored",
      this.#onPermissionsChanged.bind(this),
    );
    browser.webNavigation.onCommitted.addListener(
      this.#onErrorPageNavigation.bind(this),
      { url: [{ urlPrefix: this.getPageURL("error") }] },
    );
  }

  /**
   * Displays the default WEBCAT icon in the browser's URL bar. If the UI has
   * warnings, shows the warning icon instead.
   *
   * @param tabId The ID of the tab to display the icon in.
   * @param options Icon options.
   */
  async showIcon(tabId: number, options?: IconOptions) {
    if (this.#showWarnings) {
      await this.showWarningIcon(tabId);
      return;
    }
    await super.showIcon(tabId, {
      name: options?.name ?? "webcat",
      title:
        options?.title ?? browser.i18n.getMessage("WEBCAT_webcatIsRunning"),
      popup: options?.popup,
    });
  }

  /**
   * Displays the warning icon in the browser's URL bar. Clicking on the icon
   * opens the popup with full warning info.
   *
   * @param tabId The ID of the tab to display the icon in.
   */
  async showWarningIcon(tabId: number) {
    const warnings = {} as Record<string, { message: string; url?: string }>;
    for (const key of await this.#warnings.getKeys()) {
      warnings[key] = await this.#warnings.get(key);
    }
    await super.showIcon(tabId, {
      // We don't have a separate icon for warnings, at least for now
      name: "webcat-error",
      title: browser.i18n.getMessage("WEBCAT_webcatNotOperational"),
      popup: {
        name: "popup",
        fragment: new URLSearchParams({ warnings: JSON.stringify(warnings) }),
      },
    });
  }

  /**
   * Displays the OK icon in the browser's URL bar. If the UI has warnings,
   * shows the warning icon instead.
   *
   * @param tabId The ID of the tab to display the icon in.
   * @param delegation Optional delegation information to include in the title
   *   text.
   */
  async showOKIcon(tabId: number, delegation?: string) {
    if (this.#showWarnings) {
      await this.showWarningIcon(tabId);
      return;
    }
    logger.addLog(
      "info",
      delegation
        ? `Setting ok icon (delegation: ${delegation})`
        : "Setting ok icon",
      tabId,
      "",
    );
    let title = browser.i18n.getMessage("WEBCAT_webcatVerificationSuccessful");
    if (delegation) {
      title += ` (${delegation})`;
    }
    await super.showIcon(tabId, {
      name: "webcat-ok",
      title,
    });
  }

  /**
   * Displays the error icon in the browser's URL bar.
   *
   * @param tabId The ID of the tab to display the icon in.
   */
  async showErrorIcon(tabId: number) {
    await super.showIcon(tabId, {
      name: "webcat-error",
      title: browser.i18n.getMessage("WEBCAT_webcatVerificationFailed"),
    });
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

    const code = error.code;

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

  /**
   * Sets the message for the specified warning.
   *
   * @param id The ID of the warning.
   * @param message The warning message.
   * @param url An optional URL containing additional info about the warning.
   */
  async setWarning(id: string, message: string, url?: string) {
    await this.#warnings.set({
      [id]: { message, url },
    });
    if (this.#showWarnings === false) {
      // Warnings are not yet being shown, so make sure to show them
      browser.webNavigation.onCommitted.addListener(this.#onNavigation);
      const tabs = await browser.tabs.query({});
      // For all tabs not already showing the error icon, show the warning icon
      await Promise.all(
        tabs.map(async (tab) => {
          const title = await browser.pageAction.getTitle({
            tabId: tab.id as number,
          });
          if (
            title !== browser.i18n.getMessage("WEBCAT_webcatVerificationFailed")
          ) {
            this.showWarningIcon(tab.id as number);
          }
        }),
      );
    }
    this.#showWarnings = true;
  }

  /**
   * Clears a specific warning from the UI.
   *
   * @param id The ID of the warning to clear.
   */
  async clearWarning(id: string) {
    await this.#warnings.remove(id);
    const warnings = await this.#warnings.getKeys();
    if (warnings.length === 0) {
      this.#showWarnings = false;
      browser.webNavigation.onCommitted.removeListener(this.#onNavigation);
      const tabs = await browser.tabs.query({});
      await Promise.all(
        tabs.map(async (tab) => {
          const title = await browser.pageAction.getTitle({
            tabId: tab.id as number,
          });
          if (
            title === browser.i18n.getMessage("WEBCAT_webcatNotOperational")
          ) {
            await this.hideIcon(tab.id as number);
          }
        }),
      );
    }
  }

  async #onPermissionsChanged() {
    const missing = permissions.getMissing();
    if (missing.size > 0) {
      await this.setWarning(
        "permissions",
        browser.i18n.getMessage(
          "WEBCAT_missingPermissions",
          Array.from(missing).join("\n"),
        ),
        // TODO: build a help page that tells the user how to resolve a
        // permission issue; pass its URL to the warning UI here
        //this.getPageURL("help", { fragment: "permissions" }),
      );
    } else {
      await clearBrowserCaches(await this.#db.listAllFQDNs());
      this.clearWarning("permissions");
    }
  }

  async #onErrorPageNavigation(
    details: browser.webNavigation._OnCommittedDetails,
  ) {
    await this.showErrorIcon(details.tabId);
  }

  readonly #onNavigation = async function (
    this: WebcatUI,
    details: browser.webNavigation._OnCommittedDetails,
  ) {
    // Ignore subrames
    if (details.frameId !== 0) {
      return;
    }
    // If not already showing the error icon, show the warning icon
    const title = await browser.pageAction.getTitle({ tabId: details.tabId });
    if (title !== browser.i18n.getMessage("WEBCAT_webcatVerificationFailed")) {
      this.showWarningIcon(details.tabId);
    }
  }.bind(this);
}
