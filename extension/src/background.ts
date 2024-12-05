import {
  injectorListener,
  installListener,
  startupListener,
  messageListener,
  requestListener,
  headersListener,
  tabCloseListener,
} from "./webcat/listeners";

import { setErrorIcon } from "./webcat/ui";

// Let's count references to origin in case we ever need pruning policies
browser.tabs.onRemoved.addListener(tabCloseListener);

// On first extension installation download and verify a full list
browser.runtime.onInstalled.addListener(installListener);

// On every startup download the diff(s)
browser.runtime.onStartup.addListener(startupListener);

// This is our request listener to start catching everything
browser.webRequest.onBeforeRequest.addListener(
  requestListener,
  // We intercept http too because if a website is enrolled but not TLS enabled we want to drop
  { urls: ["http://*/*", "https://*/*"] },
  ["blocking"],
);

// To check if the headers were modified by another extension and abort, we could use
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onResponseStarted
browser.webRequest.onHeadersReceived.addListener(
  headersListener,
  // Here HTTP should no longer be a concern, we should have dropped the request before receiving headers anyway
  // However that would not be the case for .onion domains
  { urls: ["http://*/*", "https://*/*"] },
  // Do we want this to be "blocking"? If we detect an anomaly we should stop
  ["blocking", "responseHeaders"],
);

browser.runtime.onMessage.addListener(messageListener);

// Not the best performance idea to act on all tab just for this
// TODO
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    if (tab.url === browser.runtime.getURL("pages/error.html")) {
      setErrorIcon(tabId);
    }
  }
});

browser.webNavigation.onCommitted.addListener(injectorListener);

// Grey out and make page action unclickable unless a website is enrolled
browser.tabs.onCreated.addListener(() => {
  browser.browserAction.disable();
});