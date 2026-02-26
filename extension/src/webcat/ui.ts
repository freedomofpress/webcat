import { WebcatError } from "./interfaces/errors";
import { logger } from "./logger";

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

export async function errorpage(tabId: number, error?: WebcatError) {
  const code = error?.code ?? "WEBCAT_ERROR_UNDEFINED";

  const errorPageUrl =
    browser.runtime.getURL("pages/error.html") + `#${encodeURIComponent(code)}`;

  await browser.tabs.update(tabId, { url: errorPageUrl });
}
