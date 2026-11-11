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
        options?.title ?? browser.i18n.getMessage("WEBCAT_webcatIsVerifying"),
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
   * Marks a tab whose top-level site is not enrolled as embedding verified
   * content.
   *
   * @param tabId The ID of the tab to display the icon in.
   */
  async showPartialIcon(tabId: number) {
    if (tabId < 0) {
      return;
    }
    if (this.#showWarnings) {
      await this.showWarningIcon(tabId);
      return;
    }
    const title = await browser.pageAction.getTitle({ tabId });
    if (title !== browser.i18n.getMessage("WEBCAT_webcatNotEnrolled")) {
      return;
    }
    await super.showIcon(tabId, {
      name: "webcat",
      title: browser.i18n.getMessage("WEBCAT_webcatPartiallyVerified"),
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
    const tabIds =
      details.tabId < 0
        ? (await this.tabsShowing(new Set([details.state.fqdn]))).tabs.map(
            (tab) => tab.id as number,
          )
        : [details.tabId];

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
   * Finds the tabs with a document of any of the given hosts in any frame.
   *
   * @param fqdns The hosts to look for.
   * @returns The tabs found and the hosts they show.
   */
  async tabsShowing(fqdns: ReadonlySet<string>) {
    const tabs: browser.tabs.Tab[] = [];
    const hosts = new Set<string>();
    await Promise.all(
      (await browser.tabs.query({})).map(async (tab) => {
        if (tab.id === undefined) {
          return;
        }
        // A discarded tab reports null; it loads afresh when activated
        const frames =
          (await browser.webNavigation.getAllFrames({ tabId: tab.id })) ?? [];
        const shown = frames
          .map((frame) => /https?:\/\//i.test(frame.url) && getFQDN(frame.url))
          .filter((fqdn) => fqdn && fqdns.has(fqdn));
        if (shown.length > 0) {
          tabs.push(tab);
          shown.forEach((fqdn) => hosts.add(fqdn as string));
        }
      }),
    );
    return { tabs, hosts };
  }

  /**
   * Replaces every tab with a document of any of the given hosts in any frame
   * by a duplicate, so that a document loaded before its host was enrolled
   * gets verified. A reload would stay in the tab's browsing context group,
   * where Firefox keeps the origin site-keyed and the Origin-Agent-Cluster
   * check fails; a duplicate starts a new group and keeps the tab's container
   * and history, which `tabs.create` could not without the cookies
   * permission. The hosts' caches and service workers are cleared first.
   *
   * @param fqdns The hosts whose documents to reload.
   */
  async reloadTabsShowing(fqdns: ReadonlySet<string>) {
    const { tabs, hosts } = await this.tabsShowing(fqdns);
    if (tabs.length === 0) {
      return;
    }
    logger.info(`Replacing ${tabs.length} tab(s) of newly enrolled hosts`);
    await clearBrowserCaches([...hosts]);
    await Promise.all(
      tabs.map(async (tab) => {
        try {
          await browser.tabs.duplicate(tab.id as number, {
            active: tab.active,
            index: tab.index + 1,
          });
          await browser.tabs.remove(tab.id as number);
        } catch (error) {
          // The tab may have been closed since the scan
          logger.error(`Replacing tab ${tab.id} failed`, undefined, error);
        }
      }),
    );
  }

  /**
   * Sets the message for the specified warning.
   *
   * @param id The ID of the warning.
   * @param args The arguments of the warning. Must be serializable as JSON.
   */
  async setWarning(id: string, ...args: unknown[]) {
    await this.#warnings.set({ [id]: args });
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
            await this.resetIcon(tab.id as number);
          }
        }),
      );
    }
  }

  async #onPermissionsChanged() {
    const missing = permissions.getMissing();
    if (missing.size > 0) {
      await this.setWarning("permissions", Array.from(missing).sort());
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
