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

export async function errorpage(tabId: number, error?: WebcatError) {
  const code = error?.code ?? "WEBCAT_ERROR_UNDEFINED";
  const errorPageUrl = browser.runtime.getURL("pages/error.html");

  // Things that do not work:
  // - Creating a blob dynamically
  // - Rewriting the page without a redirect

  // Things that are nice to avoid
  // - Query/fragment parameter passing
  // - Messaging

  // Current solution is: navigate and then inject a conte script
  // Avoids messaging, scripts in the page itself, and weird urls

  // 1. Navigate to the error page
  await browser.tabs.update(tabId, { url: errorPageUrl });

  // 2. Wait until the extension page loads
  await new Promise<void>((resolve) => {
    const listener = (
      updatedTabId: number,
      changeInfo: browser.tabs._OnUpdatedChangeInfo,
    ) => {
      if (updatedTabId === tabId && changeInfo.status === "complete") {
        browser.tabs.onUpdated.removeListener(listener);
        resolve();
      }
    };
    browser.tabs.onUpdated.addListener(listener);
  });

  // Wait for DOM to be fully loaded
  await browser.tabs.executeScript(tabId, {
    code: `
      new Promise(resolve => {
        if (document.readyState === "complete" || document.readyState === "interactive") {
          resolve();
        } else {
          document.addEventListener("DOMContentLoaded", () => resolve(), { once: true });
        }
      });
    `,
  });

  // 3. Dynamically inject a script *into the error page*
  await browser.tabs.executeScript(tabId, {
    code: `
      document.getElementById("error-code").textContent = ${JSON.stringify(code)};
    `,
  });
}
