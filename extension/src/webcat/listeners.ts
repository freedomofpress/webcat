import {
  tuf_sigstore_namespace,
  tuf_sigstore_root,
  tuf_sigstore_url,
} from "../config";
import { origins, popups, tabs } from "../globals";
import { TrustedRoot } from "../sigstore/interfaces";
import { SigstoreVerifier } from "../sigstore/sigstore";
import { TUFClient } from "../sigstore/tuf";
import { ensureDBOpen, isFQDNEnrolled } from "./db";
import { metadataRequestSource } from "./interfaces";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { validateResponseContent, validateResponseHeaders } from "./response";
import { errorpage, getFQDN } from "./utils";

export let sigstore: SigstoreVerifier;

async function getSigstore(update: boolean = false): Promise<SigstoreVerifier> {
  const tuf_client = await new TUFClient(
    tuf_sigstore_url,
    tuf_sigstore_root,
    tuf_sigstore_namespace,
  );
  if (update) {
    try {
      await tuf_client.updateTUF();
    } catch (e) {
      console.log(e);
    }
  }
  const newSigstore = new SigstoreVerifier();
  await newSigstore.loadSigstoreRoot(
    (await tuf_client.getTarget("trusted_root.json")) as TrustedRoot,
  );
  return newSigstore;
}

function cleanup(tabId: number) {
  if (tabs.has(tabId)) {
    const fqdn = tabs.get(tabId);
    /* DEVELOPMENT GUARDS */
    /* It's not possible that we have reference for a object that does not exists */
    if (!fqdn) {
      throw new Error(
        "When deleting a tab, we found an enrolled tab with fqdn",
      );
    }
    const originState = origins.get(fqdn);
    if (!originState) {
      throw new Error(
        "When deleting a tab, we found an enrolled tab with no associated originState",
      );
    }
    /* END */
    originState.references--;
    /* Here we could check if references are 0, and delete the origin object too */
    tabs.delete(tabId);
    popups.delete(tabId);
  }
}

export async function installListener() {
  console.log("[webcat] Running installListener");
  // Initial list download here
  // We probably want do download the most recent list, verify signature and log inclusion
  // Then index persistently in indexeddb. We do this at every startup anyway, so there is no reason for
  // not just calling the startup listener
  await startupListener();
}

export async function startupListener() {
  console.log("[webcat] Running startupListener");

  // Force the database to be initialized if it isn
  await ensureDBOpen();
  // Update TUF only at startup
  sigstore = await getSigstore(true);
}

export function tabCloseListener(
  tabId: number,
  //removeInfo?: browser.tabs._OnRemovedRemoveInfo,
) {
  cleanup(tabId);
}

export async function headersListener(
  details: browser.webRequest._OnHeadersReceivedDetails,
): Promise<browser.webRequest.BlockingResponse> {
  // Skip allowed types, etensions request, and not enrolled tabs
  const fqdn = getFQDN(details.url);

  if (!sigstore) {
    sigstore = await getSigstore(false);
  }

  if (
    // Skip non-enrolled tabs
    (!tabs.has(details.tabId) && details.tabId > 0) ||
    // Skip non-enrolled workers
    // What at browser restart?
    (details.tabId < 0 && !(await isFQDNEnrolled(fqdn, details.tabId)))
  ) {
    // This is too much noise to really log
    //console.debug(`headersListener: skipping ${details.url}`);
    return {};
  }

  // We checked for enrollment back when the request was fired
  // For tabs only we could do this, but for workers nope
  //const fqdn = tabs.get(details.tabId);
  // So instead let's get that again

  if (!origins.has(fqdn)) {
    // We are dealing with a background request, probably a serviceworker
    logger.addLog(
      "info",
      `Loading metadata for a background request to ${fqdn}`,
      details.tabId,
      fqdn,
    );
    await validateOrigin(
      tabs,
      popups,
      fqdn,
      details.url,
      details.tabId,
      metadataRequestSource.worker,
    );
  }

  /* DEVELOPMENT GUARD */
  const originState = origins.get(fqdn);
  const popupState = popups.get(details.tabId);

  if (!originState) {
    throw new Error("No originState while starting to pass response.");
  }

  try {
    await validateResponseHeaders(sigstore, originState, popupState, details);
  } catch (error) {
    logger.addLog(
      "error",
      `Error when parsing response headers: ${error}`,
      details.tabId,
      fqdn,
    );
    origins.delete(fqdn);
    tabs.delete(details.tabId);
    errorpage(details.tabId);
    return { cancel: true };
  }

  return {};
}

export async function requestListener(
  details: browser.webRequest._OnBeforeRequestDetails,
): Promise<browser.webRequest.BlockingResponse> {
  const fqdn = getFQDN(details.url);

  if (details.tabId < 0 && !origins.has(fqdn)) {
    // We will always wonder, is this check reasonable?
    // Might be redundant anyway if we skip xmlhttprequest
    // But we probably want to also ensure other extensions work
    //console.debug(`requestListener: skipping ${details.url}`);
    return {};
  }

  if (details.type === "main_frame") {
    // User is navigatin to a new context, whether is enrolled or not better to reset
    cleanup(details.tabId);

    logger.addLog(
      "info",
      `Loading main_frame ${details.url}`,
      details.tabId,
      fqdn,
    );

    try {
      // This just checks some basic stuff, like TLS/Onion usage and populate the cache if it doesnt exists
      await validateOrigin(
        tabs,
        popups,
        fqdn,
        details.url,
        details.tabId,
        metadataRequestSource.main_frame,
      );
    } catch (error) {
      logger.addLog(
        "error",
        `Error loading main_frame: ${error}`,
        details.tabId,
        fqdn,
      );
      errorpage(details.tabId);
      return { cancel: true };
    }
  }

  /* DEVELOPMENT GUARD */
  /*it's here for development: meaning if we reach this stage
    and the fqdn is enrolled, but a entry in the origin map has nor been created, there is a critical security bug */
  if ((await isFQDNEnrolled(fqdn, details.tabId)) === true) {
    console.error(
      "FATAL: loading from an enrolled origin but the state does not exists.",
    );
    return { cancel: true };
  }
  /* END */

  // if we know the tab is enrolled, or it is a worker background connction then we should verify
  if (tabs.has(details.tabId) === true || details.tabId < 0) {
    await validateResponseContent(popups.get(details.tabId), details);
  }

  // See https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/BlockingResponse
  // Returning a response here is a very powerful tool, let's think about it later
  return {};
}

// sender should be of type browser.runtime.MessageSender but it's missing things... like origin
// eslint-disable-next-line
export function messageListener(message: any, sender: any, sendResponse: any) {
  // First, is this coming from the hooks or the extension?
  if (sender.id === browser.runtime.id) {
    // And now see from which component
    if (sender.url?.endsWith("/popup.html")) {
      if (message.type === "populatePopup") {
        // NOTE: for some reason using async/await here breaks the functionality
        browser.tabs
          .query({ active: true, currentWindow: true })
          .then((tabs) => {
            if (tabs.length === 0 || !tabs[0].id || !tabs[0].url) {
              sendResponse({
                error: "This functionality is disabled on this tab.",
              });
              return;
            }

            const tabId = tabs[0].id;
            const popupState = popups.get(tabId);

            if (!popupState) {
              throw new Error("Missing popupState");
            }

            const originState = origins.get(popupState.fqdn);
            popupState.valid_sources.add(popupState.fqdn);

            function traverseValidSources(
              source: string,
              valid_sources: Set<string>,
            ) {
              valid_sources.add(source);

              const sourceState = origins.get(source);
              if (!sourceState) {
                return;
              }
              const newValidSources = sourceState.valid_sources || [];

              for (const newSource of newValidSources) {
                if (!valid_sources.has(newSource)) {
                  traverseValidSources(newSource, valid_sources);
                }
              }
            }

            if (originState) {
              for (const source of originState.valid_sources) {
                traverseValidSources(source, popupState.valid_sources);
              }
            }

            sendResponse({ tabId: tabId, popupState: popupState });
          })
          .catch((error) => {
            console.error("Error getting active tab:", error);
            sendResponse({ error: error.message });
          });
        return true;
      }
      //} else if (sender.url?.endsWith("/settings.html")) {
      //} else if (sender.url?.endsWith("/logs.html")) {
    }
  }
}
