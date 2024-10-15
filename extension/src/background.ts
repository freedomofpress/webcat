import { installListener, startupListener, requestListener, headersListener, tabCloseListener } from './webcat/listeners';

// Let's keep things clean and prune our array when a tab is closed
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
	["blocking"]
);

// To check if the headers were modified by another extension and abort, we could use
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onResponseStarted
browser.webRequest.onHeadersReceived.addListener(
    headersListener,
    // Here HTTP should no longer be a concern, we should have dropped the request before receiving headers anyway
    // However that would not be the case for .onion domains
    { urls: ["http://*/*", "https://*/*"] },
    // Do we want this to be "blocking"? If we detect an anomaly we should stop
    ["blocking", "responseHeaders"]
);

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Hooked:', message.type, 'with details:', message.details, 'sender', sender);
});
  

    //await updateTUF();
    /*const root = await loadSigstoreRoot();

    const file = await fetch(browser.runtime.getURL("assets/test_file.txt"));
    const signature = await fetch(browser.runtime.getURL("assets/test_file.txt.sigstore.json"));
    
    const fileraw = new Uint8Array(await file.arrayBuffer());
    const sigjson: SigstoreBundle = await signature.json()

    console.time('test');
    console.log(await verifyArtifact(root, "giulio@freedom.press", "https://accounts.google.com", sigjson, fileraw));
    console.timeEnd('test');*/
