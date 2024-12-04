import { updateTUF } from "../sigstore/tuf";
import { loadSigstoreRoot } from "../sigstore/sigstore";
import { Sigstore } from "../sigstore/interfaces";
import { OriginState } from "./interfaces";
import { validateResponseHeaders, validateResponseContent } from "./response";
import { validateMainFrame } from "./request";
import { getFQDN, isExtensionRequest, isFQDNEnrolled } from "./utils";
import { Uint8ArrayToHex } from "../sigstore/encoding";
import { logger } from "./logger";

const origins: Map<string, OriginState> = new Map();
const tabs: Map<number, string> = new Map();

let sigstore: Sigstore;
const allowed_types: string[] = [
  "image",
  "font",
  "media",
  // TODO, can we avoid "object"? We are discussing to enforce this in the CSP anyway
  //"object",
  "xmlhttprequest",
  "websocket",
];

function cleanup(tabId: number) {
  if (tabs.has(tabId)) {
    const fqdn = tabs.get(tabId);
    /* DEVELOPMENT GUARD */
    /* It's not possible that we have reference for a object that does not exists */
    if (!origins.has(fqdn!)) {
      console.error(
        "When deleting a tab, we found an enrolled tab with no matching origin",
      );
    }
    /* END */
    const originState = origins.get(fqdn!);
    originState!.references--;
    /* Here we could check if references are 0, and delete the origin object too */
    tabs.delete(tabId);
  }
}

export async function installListener() {
  // Initial list download here
  // We probably want do download the most recent list, verify signature and log inclusion
  // Then index persistently in indexeddb. We do this at every startup anyway, so there is no reason for
  // not just calling the startup listener
  await startupListener();
}

export async function startupListener() {
  await updateTUF();
  sigstore = await loadSigstoreRoot();
  // Here we probably want to check for a diff update to the list
  // Stills needs to check signature and inclusion proof
  // But db update should be on average very very small
}

export function tabCloseListener(
  tabId: number,
  removeInfo?: browser.tabs._OnRemovedRemoveInfo,
) {
  cleanup(tabId);
}

export async function headersListener(
  details: browser.webRequest._OnHeadersReceivedDetails,
): Promise<browser.webRequest.BlockingResponse> {
  // Skip allowed types, etensions request, and not enrolled tabs
  const fqdn = getFQDN(details.url);

  if (
    // Skip extensionr equests
    isExtensionRequest(details) ||
    // Skip allowed file types
    allowed_types.includes(details.type) ||
    // Skip non-enrolled tabs
    (!tabs.has(details.tabId) && details.tabId > 0) ||
    // Skip non-enrolled workers
    // TODO what at browser restart?
    // FIXME 
    (details.tabId < 0 && !origins.has(fqdn))
  ) {
    // This is too much noise to really log
    console.debug(`headersListener: skipping ${details.url}`);
    return {};
  }

  // We checked for enrollment back when the request was fired
  // For tabs only we could do this, but for workers nope
  //const fqdn = tabs.get(details.tabId);
  // So instead let's get that again

  /* DEVELOPMENT GUARD */
  if (!origins.has(fqdn)) {
    console.error(
      "When validating response headers a tab, we found an enrolled tab with no matching origin",
    );
  }
  /* END */

  try {
    await validateResponseHeaders(sigstore, origins.get(fqdn)!, details);
  } catch (error) {
    logger.addLog("error", `Error when parsing response headers: ${error}`, details.tabId, fqdn);
    return { redirectUrl: browser.runtime.getURL("pages/error.html") };
  }

  return {};
}

export async function requestListener(
  details: browser.webRequest._OnBeforeRequestDetails,
): Promise<browser.webRequest.BlockingResponse> {
  const fqdn = getFQDN(details.url);

  if (
    isExtensionRequest(details) ||
    allowed_types.includes(details.type) ||
    (details.tabId < 0 && !origins.has(fqdn))
  ) {
    // We will always wonder, is this check reasonable?
    // Might be redundant anyway if we skip xmlhttprequest
    // But we probably want to also ensure other extensions work
    console.debug(`requestListener: skipping ${details.url}`);
    return {};
  }

  if (details.type == "main_frame") {
    // User is navigatin to a new context, whether is enrolled or not better to reset
    cleanup(details.tabId);

    logger.addLog("info", `Loading main_frame ${details.url}`, details.tabId, fqdn);

    try {
      // This just checks some basic stuff, like TLS/Onion usage and populate the cache if it doesnt exists
      await validateMainFrame(tabs, origins, fqdn, details.url, details.tabId);
    } catch (error) {
      logger.addLog("error", `Error loading main_frame: ${error}`, details.tabId, fqdn);
      return { cancel: true };
    }
  }

  /* DEVELOPMENT GUARD */
  /*it's here for development: meaning if we reach this stage
    and the fqdn is enrolled, but a entry in the origin map has nor been created, there is a critical security bug */
  if ((await isFQDNEnrolled(fqdn)) === true && !origins.has(fqdn)) {
    console.error(
      "FATAL: loading from an enrolled origin but the state does not exists.",
    );
    return { cancel: true };
  }
  /* END */

  // if we know the tab is enrolled, or it is a worker background connction then we should verify
  if (tabs.has(details.tabId) === true || details.tabId < 0) {
    validateResponseContent(origins.get(fqdn)!, details);
  }

  // See https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/BlockingResponse
  // Returning a response here is a very powerful tool, let's think about it later
  return {};
}

// sender should be of type browser.runtime.MessageSender but it's missing things...
export function messageListener(message: any, sender: any, sendResponse: any) {

  // First, is this coming from the hooks or the extension?
  if (sender.id === browser.runtime.id) {
    // And now see from which component
    if (sender.url?.endsWith("/popup.html")) {
      if (message.type === "populatePopup") {
        browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
          if (tabs.length === 0 || !tabs[0].id || !tabs[0].url) {
              sendResponse({ error: "This functionality is disabled on this tab." });
              return;
          }

          const tabId = tabs[0].id;
          const url = new URL(tabs[0].url);
          const origin = getFQDN(url.origin);

          console.log("sending respoinse");
          console.log(origins.get(origin));
          sendResponse({ tabId: tabId, originState: origins.get(origin)!.manifest});
        }).catch((error) => {
          console.error("Error getting active tab:", error);
          sendResponse({ error: error.message });
        });
        return true;
      }

    } else if (sender.url?.endsWith("/settings.html")) {
    
    } else if (sender.url?.endsWith("/logs.html")) {

    }
  }

  const fqdn = getFQDN(sender.origin);
  /* DEVELOPMENT GUARD */
  if (!origins.has(fqdn) && sender.tab && tabs.has(sender.tab.id!)) {
    throw new Error(
      "FATAL: WASM origin is not present but its execution tab is.",
    );
  }
  if (origins.has(fqdn) && !origins.get(fqdn)!.populated) {
    throw new Error(
      "FATAL: WASM is being executed before the manifest is populated and verified.",
    );
  }
  /* END DEVELOPMENT GUARD */

  // Removed as we now inject only on enrolled websites anyway, see https://github.com/freedomofpress/webcat/issues/2
  if (!origins.has(fqdn)) {
  // TODO: this could be abused to detect the extension presence if we sent a response
  // By not sending it, we disallow non-enrolled wbesite to know if the extension exists
    logger.addLog("debug", `${fqdn} is not enrolled, skipping WASM validation.`, sender.tabId, fqdn);
  //sendResponse(true);
    return;
  }

  const hash = Uint8ArrayToHex(new Uint8Array(message.details));
  const originState = origins.get(fqdn);

  if (originState!.manifest.manifest.wasm.includes(hash)) {
    logger.addLog("info", `Validated WASM ${hash}`, sender.tabId, fqdn);
    sendResponse(true);
  } else {
    logger.addLog("error", `Invalid WASM ${hash}`, sender.tabId, fqdn);
    sendResponse(false);
    browser.tabs.update(sender.tab.id, { url: browser.runtime.getURL("pages/error.html") });
  }
}

export function injectorListener(details: browser.webNavigation._OnCommittedDetails) {
  // TODO: a security audit should find out if this is bypassable: can an onCommitted even race the
  // population of the origins? Perhaps it would be better to do this on a tabid basis
  const fqdn = getFQDN(details.url);
  if (origins.has(fqdn)) {
    logger.addLog("debug", `Injecting WASM hooks`,details.tabId, fqdn)
    browser.tabs.executeScript(details.tabId, {
      file: "hooks/inject.js",
      runAt: "document_start",
      // We are doing allFrames in the hope of https://github.com/freedomofpress/webcat/issues/3
      allFrames: true
    });
  }
}