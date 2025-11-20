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
    path: `icons/${theme}/webcat.png`,
  });
  browser.pageAction.setTitle({ tabId, title: "Click for info!" });
}

export function setOKIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  logger.addLog("debug", "Setting ok icon", tabId, "");
  browser.pageAction.show(tabId);
  browser.pageAction.setIcon({
    tabId: tabId,
    path: `icons/${theme}/webcat-ok.png`,
  });
  browser.pageAction.setTitle({
    tabId: tabId,
    title: "WEBCAT verification successful",
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
    path: `icons/${theme}/webcat-error.png`,
  });
  browser.pageAction.setTitle({
    tabId: tabId,
    title: "WEBCAT verification failed",
  });
}
