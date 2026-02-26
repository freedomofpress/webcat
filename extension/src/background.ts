import { endpoint } from "./config";
import { db } from "./globals";
import {
  headersListener,
  installListener,
  requestListener,
  startupListener,
  tabCloseListener,
} from "./webcat/listeners";
import { FRAME_TYPES } from "./webcat/resources";
import { setErrorIcon } from "./webcat/ui";
import { update } from "./webcat/update";
import { initializeScheduledUpdates } from "./webcat/update";

console.log("[webcat] Starting up background");

setTimeout(async () => {
  console.log("[webcat] Importing bundled list");
  await update(db, endpoint, true);

  console.log("[webcat] Attempting network update");
  await initializeScheduledUpdates(db, endpoint);
}, 0);

// Let's count references to origin in case we ever need pruning policies
browser.tabs.onRemoved.addListener(tabCloseListener);

// Edit: moved the update logic directly in this file to ensure
// it always runs
// On first extension installation download and verify a full list
browser.runtime.onInstalled.addListener(installListener);

// On every startup download the diff(s)
browser.runtime.onStartup.addListener(startupListener);

// This is our request listener to start catching everything
browser.webRequest.onBeforeRequest.addListener(
  requestListener,
  // We intercept http too because if a website is enrolled but not TLS enabled we want to drop
  // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/ResourceType
  {
    // New strategy: we detect here if a website is enrolled and then add a per-origin
    // listener that intercwpts everything. This way we can always try to match a resource
    // to the manifest first, including images, etc
    urls: ["http://*/*", "https://*/*"],
    types: FRAME_TYPES,
  },
  // Allowed remaining are beacon, csp_report, font, image, imageset, media, object_subrequest, ping, speculative, websocket, xmlhttprequest
  ["blocking"],
);

// To check if the headers were modified by another extension and abort, we could use
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onResponseStarted
browser.webRequest.onHeadersReceived.addListener(
  headersListener,
  // Here HTTP should no longer be a concern, we should have dropped the request before receiving headers anyway
  // However that would not be the case for .onion domains
  {
    // Same as above, add more precise listener when something enrolled is detected
    urls: ["http://*/*", "https://*/*"],
    types: FRAME_TYPES,
  },
  // Do we want this to be "blocking"? If we detect an anomaly we should stop
  ["blocking", "responseHeaders"],
);

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
