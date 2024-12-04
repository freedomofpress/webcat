import {logger } from "./logger";

export function isDarkTheme(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}
export function setIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  logger.addLog("debug", "Setting standard icon", tabId, "")

  browser.browserAction.enable(tabId);
  browser.browserAction.setIcon({
    tabId: tabId,
    path: {
      16: `icons/${theme}/webcat.svg`,
      32: `icons/${theme}/webcat.svg`,
      48: `icons/${theme}/webcat.svg`,
      64: `icons/${theme}/webcat.svg`,
      96: `icons/${theme}/webcat.svg`,
      128: `icons/${theme}/webcat.svg`,
      256: `icons/${theme}/webcat.svg`,
    },
  });
  browser.browserAction.setPopup({ tabId, popup: "pages/popup.html" });
  browser.browserAction.setTitle({ tabId, title: "Click for info!" });

}

export function setOKIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  logger.addLog("debug", "Setting ok icon", tabId, "")
  browser.browserAction.enable(tabId);
  browser.browserAction.setIcon({
    tabId: tabId,
    path: {
      16: `icons/${theme}/webcat-ok.svg`,
      32: `icons/${theme}/webcat-ok.svg`,
      48: `icons/${theme}/webcat-ok.svg`,
      64: `icons/${theme}/webcat-ok.svg`,
      96: `icons/${theme}/webcat-ok.svg`,
      128: `icons/${theme}/webcat-ok.svg`,
      256: `icons/${theme}/webcat-ok.svg`,
    },
  });
  browser.browserAction.setPopup({ tabId, popup: "pages/popup.html" });
  browser.browserAction.setTitle({
    tabId: tabId,
    title: "Web integrity verification successful. Click for info!",
  });
}

export function setErrorIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  logger.addLog("debug", "Setting error icon", tabId, "")
  browser.browserAction.enable(tabId);
  browser.browserAction.setIcon({
    tabId: tabId,
    path: {
      16: `icons/${theme}/webcat-error.svg`,
      32: `icons/${theme}/webcat-error.svg`,
      48: `icons/${theme}/webcat-error.svg`,
      64: `icons/${theme}/webcat-error.svg`,
      96: `icons/${theme}/webcat-error.svg`,
      128: `icons/${theme}/webcat-error.svg`,
      256: `icons/${theme}/webcat-error.svg`,
    },
  });
  browser.browserAction.setPopup({ tabId, popup: "pages/popup.html" });
  browser.browserAction.setTitle({
    tabId: tabId,
    title: "Web integrity verification failed. Click for info!",
  });
}
