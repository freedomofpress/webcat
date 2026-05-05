import { endpoint } from "./config";
import { db } from "./globals";
import {
  installEnrolledListeners,
  installListener,
  startupListener,
  tabCloseListener,
} from "./webcat/listeners";
import { setErrorIcon } from "./webcat/ui";
import {
  handleUpdateAlarm,
  initializeScheduledUpdates,
  update,
} from "./webcat/update";

console.log("[webcat] Starting up background");

(async () => {
  try {
    console.log("[webcat] Importing bundled list");
    await update(db, endpoint, true);
  } catch (error) {
    console.error("[webcat] Bundled list import failed:", error);
  }

  try {
    await installEnrolledListeners(db);
  } catch (error) {
    console.error("[webcat] Initial listener install failed:", error);
  }

  console.log("[webcat] Attempting network update");
  await initializeScheduledUpdates(db, endpoint);
})();

// Listen for the update alarm
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "webcat-scheduled-update") {
    handleUpdateAlarm(db, endpoint);
  }
});

// Let's count references to origin in case we ever need pruning policies
browser.tabs.onRemoved.addListener(tabCloseListener);

// Edit: moved the update logic directly in this file to ensure
// it always runs
// On first extension installation download and verify a full list
browser.runtime.onInstalled.addListener(installListener);

// On every startup download the diff(s)
browser.runtime.onStartup.addListener(startupListener);

// Not the best performance idea to act on all tab just for this
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const errorUrl = browser.runtime.getURL("pages/error.html");
  if (changeInfo.status === "complete" && tab.url?.startsWith(errorUrl)) {
    setErrorIcon(tabId);
  }
});

// Grey out and make page action unclickable unless a website is enrolled
browser.tabs.onCreated.addListener((tab) => {
  if (tab.id !== undefined) {
    browser.pageAction.hide(tab.id);
  }
});
