export function isDarkTheme(): boolean {
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
}
export function setIcon(tabId: number) {
    if (tabId < 0) {
        return;
    }

    const theme = isDarkTheme() ? "dark" : "light";

    browser.pageAction.setIcon({
        tabId: tabId,
        path: {
            16: `icons/${theme}/16/webcat.png`,
            32: `icons/${theme}/32/webcat.png`,
            48: `icons/${theme}/48/webcat.png`,
            64: `icons/${theme}/64/webcat.png`,
            96: `icons/${theme}/96/webcat.png`,
            128: `icons/${theme}/128/webcat.png`,
            256: `icons/${theme}/256/webcat.png`
          }
      })
    browser.pageAction.setTitle({
        tabId: tabId,
        title: "webcat is running \\0/"
    });
    browser.pageAction.show(tabId);
}

export function setOKIcon(tabId: number) {
    if (tabId < 0) {
        return;
    }

    const theme = isDarkTheme() ? "dark" : "light";

    browser.pageAction.setIcon({
        tabId: tabId,
        path: {
          16: `icons/${theme}/16/webcat-ok.png`,
          32: `icons/${theme}/32/webcat-ok.png`,
          48: `icons/${theme}/48/webcat-ok.png`,
          64: `icons/${theme}/64/webcat-ok.png`,
          96: `icons/${theme}/96/webcat-ok.png`,
          128: `icons/${theme}/128/webcat-ok.png`,
          256: `icons/${theme}/256/webcat-ok.png`
        }
      });
      browser.pageAction.setTitle({
        tabId: tabId,
        title: "webcat verification successful!"
    });
    browser.pageAction.show(tabId);
}

export function setErrorIcon(tabId: number) {
    if (tabId < 0) {
        return;
    }

    const theme = isDarkTheme() ? "dark" : "light";

    browser.pageAction.setIcon({
        tabId: tabId,
        path: {
          16: `icons/${theme}/16/webcat-error.png`,
          32: `icons/${theme}/32/webcat-error.png`,
          48: `icons/${theme}/48/webcat-error.png`,
          64: `icons/${theme}/64/webcat-error.png`,
          96: `icons/${theme}/96/webcat-error.png`,
          128: `icons/${theme}/128/webcat-error.png`,
          256: `icons/${theme}/256/webcat-error.png`
        }
      });
      browser.pageAction.setTitle({
        tabId: tabId,
        title: "webcat verification failed :("
    });
    browser.pageAction.show(tabId);
}