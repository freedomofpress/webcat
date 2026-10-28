import {
  BrowserChromeController,
  BrowserChromeControllerConfig,
  IconOptions,
} from "../browser/chrome";
import { NamespacedKVStore } from "../browser/kvstore";
import permissions from "../browser/permissions";
import { RequestDetails } from "../browser/requests";
import { Mutex } from "../browser/sync";
import { CacheKey } from "./cache";
import { Database } from "./interfaces/database";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { CachePartition } from "./interfaces/originstate";
import { RequestState, Stateful } from "./interfaces/requeststate";
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
  // Serializes read-modify-write of the per-tab popup URL (frames)
  readonly #popupLock = new Mutex();

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
    browser.webRequest.onBeforeRequest.addListener(
      this.#onJSONRequest.bind(this),
      { urls: [`${WebcatUI.JSON_ORIGIN}/*`], types: ["main_frame"] },
      ["blocking"],
    );
  }

  /**
   * Origin of the synthetic URLs the popup opens for a verified origin's
   * manifest or enrollment: `<origin>/<part>/<cache key>`. The request is
   * redirected to a data: URL before it leaves the browser, and the tab runs
   * in a web process, where Firefox's JSON viewer renders it.
   */
  static readonly JSON_ORIGIN = "https://json.webcat.invalid";

  async #onJSONRequest(details: { url: string; originUrl?: string }) {
    // Only navigations started by the extension's own pages are served
    if (
      details.originUrl &&
      !details.originUrl.startsWith(browser.runtime.getURL(""))
    ) {
      return { cancel: true };
    }
    const [, part, key] = new URL(details.url).pathname.split("/");
    const origin = await this.#db.origins.get(
      decodeURIComponent(key) as CacheKey<CachePartition>,
    );
    const pojo = origin?.isManifestVerified() ? origin.toPOJO() : undefined;
    // The manifest view includes its signatures
    const value =
      pojo && part === "manifest"
        ? { manifest: pojo.manifest, signatures: pojo.signatures }
        : pojo && part === "enrollment"
          ? pojo.enrollment
          : undefined;
    // Firefox allows top-level data: navigations for JSON, PDF and images, so
    // the unavailable case is JSON as well
    const payload = value ?? {
      error: browser.i18n.getMessage("WEBCAT_detailsUnavailable"),
    };
    const redirectUrl =
      "data:application/json;charset=utf-8," +
      encodeURIComponent(JSON.stringify(payload, null, 2));
    return { redirectUrl };
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
   * @param state The verified request state, shown in the popup.
   * @param delegation Optional delegation information to include in the title
   *   text.
   */
  async showOKIcon(tabId: number, state: RequestState, delegation?: string) {
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
    // The popup reads the verified origin from storage; only identifiers go
    // in the URL. Verified sub-frames are appended by showPartialIcon.
    const fragment = new URLSearchParams({ origin: this.#popupEntry(state) });
    if (delegation) {
      fragment.set("delegation", delegation);
    }
    await super.showIcon(tabId, {
      name: "webcat-ok",
      title,
      popup: { name: "popup", fragment },
    });
  }

  #popupEntry(state: RequestState) {
    return JSON.stringify({
      fqdn: state.fqdn,
      key: CacheKey(state.fqdn, state.cachePartition),
    });
  }

  /**
   * Records a verified sub-frame on its tab: a tab whose top-level site is
   * not enrolled gets the partial icon, and the frame is listed in the popup
   * of partial and OK tabs. Verifying and error tabs keep their state.
   *
   * @param tabId The ID of the tab containing the frame.
   * @param state The verified request state of the frame.
   */
  async showPartialIcon(tabId: number, state: RequestState) {
    if (tabId < 0) {
      return;
    }
    if (this.#showWarnings) {
      await this.showWarningIcon(tabId);
      return;
    }
    using _lock = await this.#popupLock.acquire();
    const title = await browser.pageAction.getTitle({ tabId });
    const popup = await browser.pageAction.getPopup({ tabId });
    if (title === browser.i18n.getMessage("WEBCAT_webcatNotEnrolled")) {
      await super.showIcon(tabId, {
        name: "webcat",
        title: browser.i18n.getMessage("WEBCAT_webcatPartiallyVerified"),
        popup: {
          name: "popup",
          fragment: new URLSearchParams({ frame: this.#popupEntry(state) }),
        },
      });
    } else if (popup.startsWith(this.getPageURL("popup"))) {
      const url = new URL(popup);
      const fragment = new URLSearchParams(url.hash.slice(1));
      const entry = this.#popupEntry(state);
      // The same frame arrives once at headers time and again after the body
      if (fragment.getAll("frame").includes(entry)) {
        return;
      }
      fragment.append("frame", entry);
      url.hash = fragment.toString();
      browser.pageAction.setPopup({ tabId, popup: url.href });
    }
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
