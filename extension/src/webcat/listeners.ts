import { updateTUF } from "../sigstore/tuf";
import { loadSigstoreRoot } from "../sigstore/sigstore";
import { Sigstore } from "../sigstore/interfaces";
import { OriginState } from "./interfaces";
import { validateResponseHeaders, validateResponseContent } from "./response";
import { validateMainFrame } from "./request";
import { getFQDN, isExtensionRequest, isFQDNEnrolled } from "./utils";

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

export async function headersListener(
  details: browser.webRequest._OnHeadersReceivedDetails,
): Promise<browser.webRequest.BlockingResponse> {
  // Skip allowed types, etensions request, and not enrolled tabs
  if (
    isExtensionRequest(details) ||
    allowed_types.includes(details.type) ||
    (!tabs.has(details.tabId) && details.tabId > 0)
  ) {
    console.log(`headersListener: skipping ${details.url}`);
    return {};
  }

  // We checked for enrollment back when the request was fired
  // For tabs only we could do this, but for workers nope
  //const fqdn = tabs.get(details.tabId);
  // So instead let's get that again
  const fqdn = getFQDN(details.url);

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
    return { cancel: true };
  }

  return {};
}

export async function requestListener(
  details: browser.webRequest._OnBeforeRequestDetails,
): Promise<browser.webRequest.BlockingResponse> {
  if (isExtensionRequest(details) || allowed_types.includes(details.type)) {
    // We will always wonder, is this check reasonable?
    // Might be redundant anyway if we skip xmlhttprequest
    // But we probably want to also ensure other extensions work
    console.log(`requestListener: skipping ${details.url}`);
    return {};
  }

  const fqdn = getFQDN(details.url);

  if (details.type == "main_frame") {
    console.log(`Loading main_frame ${details.url}`);
    console.log(
      `documenturl = ${details.documentUrl}; url =  ${details.url}; origin = ${details.originUrl};`,
    );

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
