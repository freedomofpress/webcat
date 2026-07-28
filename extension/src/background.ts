import { BeforeRequestDetails, RequestEvent } from "./browser/requests";
import {
  CHECK_INTERVAL_MS,
  endpoint,
  FETCH_TIMEOUT_MS,
  UPDATE_INTERVAL_MS,
} from "./config";
import validator_set from "./validator_set.json";
import { isInPartition } from "./webcat/cache";
import { WebcatDatabase } from "./webcat/db";
import { WebcatRequestHandler } from "./webcat/handler";
import { setErrorIcon } from "./webcat/ui";
import { EnrollmentUpdater } from "./webcat/updater";
import { clearBrowserCaches } from "./webcat/utils";

console.log("[webcat] Starting up background");

const db = new WebcatDatabase();

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
    for (const key of db.origins.keys()) {
      if (isInPartition(key, { incognito: true })) {
        db.origins.delete(key);
      }
    }
    for (const value of db.nonOrigins.values()) {
      if (isInPartition(value, { incognito: true })) {
        db.nonOrigins.delete(value);
      }
    }
  }
});

const requestHandler = new WebcatRequestHandler(db);
const updater = new EnrollmentUpdater({
  endpoint: endpoint,
  database: db,
  validatorSet: validator_set,
  checkInterval: CHECK_INTERVAL_MS,
  updateInterval: UPDATE_INTERVAL_MS,
  fetchTimeout: FETCH_TIMEOUT_MS,
});

requestHandler.bindAll();
requestHandler.addEventListener(
  "beforeframeload",
  async (event: RequestEvent<BeforeRequestDetails>) => {
    using _blockingResponse = event.blockingResponse;
    await updater.retryIfFailed();
  },
);

let firstUpdate = true;
updater.addEventListener("updated", async (event) => {
  if (!event.success && !firstUpdate) {
    return;
  }
  try {
    const fqdns = await db.listAllFQDNs();
    const newFqdns = await requestHandler.bind(fqdns);
    await clearBrowserCaches(newFqdns);
    firstUpdate = false;
  } catch (error) {
    console.error("[webcat] Bundled list import failed:", error);
  }
});
updater.start();

declare const __IS_TESTING__: boolean;
if (__IS_TESTING__) {
  Object.defineProperty(globalThis, "state", {
    value: {
      origins: db.origins,
      nonOrigins: db.nonOrigins,
    },
  });
}
