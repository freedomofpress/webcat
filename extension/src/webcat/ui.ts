import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { logger } from "./logger";
import { clearBrowserCaches, getFQDN } from "./utils";

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
    path: `icons/${theme}/webcat.SVG`,
  });
  browser.pageAction.setTitle({ tabId, title: browser.i18n.getMessage("webcatIsRunning") });
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
    path: `icons/${theme}/webcat-ok.SVG`,
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
    path: `icons/${theme}/webcat-error.SVG`,
  });
  browser.pageAction.setTitle({
    tabId: tabId,
    title: browser.i18n.getMessage("webcatVerificationFailed"),
  });
}

export async function errorpage(
  tabId: number,
  fqdn: string,
  error?: WebcatError,
) {
  const tabIds = new Set<number>();
  const frameLookups = [];
  if (tabId < 0) {
    const tabs = await browser.tabs.query({});
    for (const tab of tabs) {
      if (
        tab.url &&
        tab.id &&
        /https?:\/\//i.test(tab.url) &&
        fqdn === getFQDN(tab.url)
      ) {
        tabIds.add(tab.id);
      } else if (tab.id) {
        frameLookups.push(
          browser.webNavigation.getAllFrames({ tabId: tab.id }).then((frames) =>
            frames.forEach((frame) => {
              if (
                /https?:\/\//i.test(frame.url) &&
                fqdn === getFQDN(frame.url)
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
    tabIds.add(tabId);
  }

  const code = error?.code ?? "WEBCAT_ERROR_UNDEFINED";

  const params = new URLSearchParams({ code, host: fqdn });

  if (
    (code === WebcatErrorCode.File.MISMATCH ||
      code === WebcatErrorCode.File.MISSING) &&
    error?.details?.[0]
  ) {
    params.set("file", error.details[0]);
  }

  const errorPageUrl =
    browser.runtime.getURL("pages/error.html") + `#${params.toString()}`;

  const tabUpdates: Promise<browser.tabs.Tab>[] = [];
  tabIds.forEach((tabId) =>
    tabUpdates.push(
      browser.tabs.update(tabId, { url: errorPageUrl, loadReplace: true }),
    ),
  );
  await Promise.all(tabUpdates);

  await clearBrowserCaches([fqdn]);
}
