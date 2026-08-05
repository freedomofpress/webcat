import { RequestDetails } from "../browser/requests";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { clearBrowserCaches, getFQDN } from "./utils";

let iconsPath = "icons";
let pagesPath = "pages";

export function setIconsPath(path: string) {
  iconsPath = path;
}

export function setPagesPath(path: string) {
  pagesPath = path;
}

export function isDarkTheme(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}
export function setIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  logger.addLog("debug", "Setting standard icon", tabId, "");

  browser.pageAction.show(tabId);
  browser.pageAction.setIcon({
    tabId: tabId,
    path: `${iconsPath}/${theme}/webcat.SVG`,
  });
  browser.pageAction.setTitle({
    tabId,
    title: browser.i18n.getMessage("webcatIsRunning"),
  });
}

export function setOKIcon(tabId: number, delegation?: string) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  logger.addLog(
    "info",
    delegation
      ? `Setting ok icon (delegation: ${delegation})`
      : "Setting ok icon",
    tabId,
    "",
  );
  browser.pageAction.show(tabId);
  browser.pageAction.setIcon({
    tabId: tabId,
    path: `${iconsPath}/${theme}/webcat-ok.SVG`,
  });

  let message = browser.i18n.getMessage("webcatVerificationSuccessful");
  if (delegation) {
    message += ` (${delegation})`;
  }

  browser.pageAction.setTitle({
    tabId: tabId,
    title: message,
  });
}

export function setErrorIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  logger.addLog("debug", "Setting error icon", tabId, "");
  browser.pageAction.show(tabId);
  browser.pageAction.setIcon({
    tabId: tabId,
    path: `${iconsPath}/${theme}/webcat-error.SVG`,
  });
  browser.pageAction.setTitle({
    tabId: tabId,
    title: browser.i18n.getMessage("webcatVerificationFailed"),
  });
}

export async function errorpage(
  details: Stateful<RequestDetails>,
  error?: WebcatError,
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
          browser.webNavigation.getAllFrames({ tabId: tab.id }).then((frames) =>
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

  const tabUpdates: Promise<browser.tabs.Tab>[] = [];
  tabIds.forEach((tabId) =>
    tabUpdates.push(
      browser.tabs.update(tabId, {
        url: getErrorPageURL(params),
        loadReplace: !details.state.isFrame,
      }),
    ),
  );
  await Promise.all(tabUpdates);

  await clearBrowserCaches([details.state.fqdn]);
}

export function getErrorPageURL(params?: URLSearchParams) {
  if (params) {
    return (
      browser.runtime.getURL(`${pagesPath}/error.html`) +
      `#${params.toString()}`
    );
  }
  return browser.runtime.getURL(`${pagesPath}/error.html`);
}
