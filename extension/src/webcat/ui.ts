export function isDarkTheme(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}
export function setIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  console.log("Setting standard icon")
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
}

export function setOKIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  console.log("Setting ok icon")
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
  browser.browserAction.setTitle({
    tabId: tabId,
    title: "Webcat verification successful. Click for info!",
  });
}

export function setErrorIcon(tabId: number) {
  if (tabId < 0) {
    return;
  }

  const theme = isDarkTheme() ? "dark" : "light";

  console.log("Setting error icon")
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
  browser.browserAction.setTitle({
    tabId: tabId,
    title: "Webcat verification failed. Click for info!",
  });
}
