import { updateTUF } from "../sigstore/tuf";
import { loadSigstoreRoot } from "../sigstore/sigstore";
import { Sigstore } from "../sigstore/interfaces";
import { OriginState } from "./interfaces";
import { validateResponseHeaders, validateResponseContent } from "./response";
import { validateMainFrame } from "./request";
import { getFQDN, isExtensionRequest, isFQDNEnrolled } from "./utils";
import { setIcon, setErrorIcon } from "./ui";
import { Uint8ArrayToHex } from "../sigstore/encoding";

const origins: Map<string, OriginState> = new Map();
const tabs: Map<number, string> = new Map();

let sigstore: Sigstore;
const allowed_types: string[] = [
  "image",
  "font",
  "media",
  "object",
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
    /* Also remove the address bar icon */
    browser.pageAction.hide(tabId);
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
    (details.tabId < 0 && !origins.has(fqdn))
  ) {
    console.log(`headersListener: skipping ${details.url}`);
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
    console.log("Error when parsing response headers:", error);
    setErrorIcon(details.tabId);
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
    console.log(`requestListener: skipping ${details.url}`);
    return {};
  }

  if (details.type == "main_frame") {
    // User is navigatin to a new context, whether is enrolled or not better to reset
    cleanup(details.tabId);

    console.log(`Loading main_frame ${details.url}`);

    try {
      // This just checks some basic stuff, like TLS/Onion usage and populate the cache if it doesnt exists
      await validateMainFrame(tabs, origins, fqdn, details.url, details.tabId);
    } catch (error) {
      console.error("Error loading main_frame: ", error);
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

// sender should be browser.runtime.MessageSender but it's missing things...
export function messageListener(message: any, sender: any, sendResponse: any) {
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

  if (!origins.has(fqdn)) {
    console.log(`${fqdn} is not enrolled, skipping WASM validation.`)
    sendResponse(true);
    return;
  }

  const hash = Uint8ArrayToHex(new Uint8Array(message.details));
  const originState = origins.get(fqdn);

  if (originState!.manifest.manifest.wasm.includes(hash)) {
    console.log("Validated WASM", hash);
    sendResponse(true);
  } else {
    console.log("Invalid WASM", hash);
    sendResponse(false);
  }
}
