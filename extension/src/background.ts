import { BeforeRequestDetails, RequestEvent } from "./browser/requests";
import { ContentScript } from "./browser/scripting";
import {
  CHECK_INTERVAL_MS,
  endpoint,
  FETCH_TIMEOUT_MS,
  UPDATE_INTERVAL_MS,
} from "./config";
import { db, nonOrigins, origins } from "./globals";
import validator_set from "./validator_set.json";
import { isInPartition } from "./webcat/cache";
import { WebcatRequestHandler } from "./webcat/handler";
import { setErrorIcon } from "./webcat/ui";
import { EnrollmentUpdater } from "./webcat/updater";
import { clearBrowserCaches } from "./webcat/utils";

console.log("[webcat] Starting up background");

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

// Handle incognito sessions ending
browser.windows.onRemoved.addListener(async () => {
  const windows = await browser.windows.getAll();
  if (windows.filter((win) => win.incognito).length === 0) {
    for (const key of origins.keys()) {
      if (isInPartition(key, { incognito: true })) {
        origins.delete(key);
      }
    }
    for (const value of nonOrigins.values()) {
      if (isInPartition(value, { incognito: true })) {
        nonOrigins.delete(value);
      }
    }
  }
});

const requestHandler = new WebcatRequestHandler();
const contentScript = new ContentScript("dist/hooks/content.js");
const updater = new EnrollmentUpdater({
  endpoint: endpoint,
  database: db,
  validatorSet: validator_set,
  checkInterval: CHECK_INTERVAL_MS,
  updateInterval: UPDATE_INTERVAL_MS,
  fetchTimeout: FETCH_TIMEOUT_MS,
});

requestHandler.addEventListener(
  "beforeframeload",
  async (event: RequestEvent<BeforeRequestDetails>) => {
    using _blockingResponse = event.blockingResponse;
    await updater.retryIfFailed();
  },
);

updater.addEventListener("updated", async () => {
  try {
    const fqdns = await db.listAllFQDNs();
    requestHandler.bind(fqdns);
    const newFqdns = await contentScript.bind(fqdns);
    await clearBrowserCaches(newFqdns);
  } catch (error) {
    console.error("[webcat] Bundled list import failed:", error);
  }
});
updater.start();
