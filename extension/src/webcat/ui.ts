import { WebcatError } from "./interfaces/errors";
import { logger } from "./logger";
import { getFQDN } from "./utils";

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
  browser.pageAction.setTitle({ tabId, title: "WEBCAT is running" });
}

export function setOKIcon(tabId: number, delegation?: string) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  logger.addLog("debug", "Setting ok icon", tabId, "");
  browser.pageAction.show(tabId);
  browser.pageAction.setIcon({
    tabId: tabId,
    path: `icons/${theme}/webcat-ok.SVG`,
  });

  let message = "WEBCAT verification successful";
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
    title: "WEBCAT verification failed",
  });
}

export async function errorpage(
  tabId: number,
  fqdn: string,
  error?: WebcatError,
) {
  const tabIds = [];
  if (tabId < 0) {
    const tabs = await browser.tabs.query({});
    for (const tab of tabs) {
      if (
        tab.url &&
        tab.id &&
        /https?:\/\//i.test(tab.url) &&
        fqdn === getFQDN(tab.url)
      ) {
        tabIds.push(tab.id);
      }
    }
  } else {
    tabIds.push(tabId);
  }

  const code = error?.code ?? "WEBCAT_ERROR_UNDEFINED";

  const errorPageUrl =
    browser.runtime.getURL("pages/error.html") + `#${encodeURIComponent(code)}`;

  const tabUpdates = tabIds.map((tabId) =>
    browser.tabs.update(tabId, { url: errorPageUrl }),
  );
  await Promise.all(tabUpdates);

  // See https://github.com/freedomofpress/webcat/issues/137
  await browser.browsingData.remove({ hostnames: [fqdn] }, { cache: true });
  await browser.webRequest.handlerBehaviorChanged();
}
