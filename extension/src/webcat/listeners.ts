import { verifyHash } from "sigsum";
import { RawPublicKey } from "sigsum/dist/types";

import {
  tuf_sigstore_namespace,
  tuf_sigstore_root,
  tuf_sigstore_url,
  update_server_key,
  update_url,
} from "../config";
import { origins, popups, tabs } from "../globals";
import { hexToUint8Array, Uint8ArrayToHex } from "../sigstore/encoding";
import { TrustedRoot } from "../sigstore/interfaces";
import { SigstoreVerifier } from "../sigstore/sigstore";
import { TUFClient } from "../sigstore/tuf";
import {
  ensureDBOpen,
  getFQDNPolicy,
  getListMetadata,
  list_db,
  updateDatabase,
  updateLastChecked,
} from "./db";
import { metadataRequestSource } from "./interfaces/base";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { validateResponseContent, validateResponseHeaders } from "./response";
import { errorpage, getFQDN, jsonToSigsumAscii, SHA256 } from "./utils";

export let sigstore: SigstoreVerifier;

declare const __TESTING__: boolean;

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

async function updateList(db: IDBDatabase) {
  if (__TESTING__) {
    console.log("[webcat] Running test list updater");
    updateLastChecked(db);
    // updateDatabase has also a __TESTING__ condition; later we might want to move everything into the same place
    await updateDatabase(db, "", 1337, new Uint8Array());
  } else {
    const req = fetch(`${update_url}/update.json`, { cache: "no-store" });

    console.log("[webcat] Running production list updater");

    const metadata = await getListMetadata(db);

    const response = await req;
    if (!response.ok) {
      throw new Error("Failed to fetch update.json from server");
    }

    const sigsumPolicyRequest = await fetch(
      browser.runtime.getURL("assets/sigsum_policy"),
    );
    const policyText = await sigsumPolicyRequest.text();
    const proofJson = await response.json();
    const proofText = jsonToSigsumAscii(proofJson);
    const hash = proofJson.message_hash;

    console.log(hash);
    if (
      (await verifyHash(
        hexToUint8Array(hash),
        hexToUint8Array(update_server_key) as RawPublicKey,
        policyText,
        proofText,
      )) !== true
    ) {
      throw new Error(`Failed to verify update`);
    }
    updateLastChecked(db);

    // Here check if new hash != old hash
    // Check if new tree_size > old tree_size

    if (
      !metadata ||
      (hash != metadata.hash && proofJson.tree_head.size >= metadata.treeHead)
    ) {
      const responseList = await fetch(`${update_url}/${hash}.bin`, {
        cache: "no-store",
      });
      if (!responseList.ok) {
        throw new Error(`Failed to fetch ${update_url}/${hash}.bin`);
      }

      const binaryList = new Uint8Array(await responseList.arrayBuffer());
      const binaryListHash = Uint8ArrayToHex(
        new Uint8Array(await SHA256(binaryList)),
      );

      if (binaryListHash !== hash) {
        throw new Error(
          "Hash mismatch between signed metadata and list binary file",
        );
      }

      await updateDatabase(
        db,
        binaryListHash,
        proofJson.tree_head.size,
        binaryList,
      );

      console.log("[webcat] List successfully updated");
    } else {
      console.log("[webcat] No list update is available");
    }
  }
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
    originState.current.references--;
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

  // Run the list updater
  try {
    await updateList(list_db);
  } catch (e) {
    console.error(`[webcat] List updater failed: ${e}`);
  }

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
    (!tabs.has(details.tabId) &&
      details.tabId > 0 &&
      (await getFQDNPolicy(fqdn)).length === 0) ||
    // Skip non-enrolled workers
    (details.tabId < 0 && (await getFQDNPolicy(fqdn)).length === 0)
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
      fqdn,
      details.url,
      details.tabId,
      metadataRequestSource.worker,
    );
  }

  const originStateHolder = origins.get(fqdn);
  const popupStateHolder = popups.get(details.tabId);

  if (!originStateHolder) {
    throw new Error("No originState while starting to parse response.");
  }

  try {
    await validateResponseHeaders(originStateHolder, popupStateHolder, details);
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

  if (details.type === "main_frame" || details.type === "sub_frame") {
    // User is navigatin to a new context, whether is enrolled or not better to reset
    cleanup(details.tabId);

    logger.addLog(
      "info",
      `Loading ${details.type} ${details.url}`,
      details.tabId,
      fqdn,
    );

    try {
      // This just checks some basic stuff, like TLS/Onion usage and populate the cache if it doesnt exists
      const redirect = await validateOrigin(
        fqdn,
        details.url,
        details.tabId,
        metadataRequestSource.main_frame,
      );
      if (redirect) {
        logger.addLog("info", `Redirecting to https`, details.tabId, fqdn);
        return redirect;
      }
    } catch (error) {
      logger.addLog(
        "error",
        `Error loading ${details.type}: ${error}`,
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
  if ((await getFQDNPolicy(fqdn)).length !== 0 && !origins.has(fqdn)) {
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
              if (!sourceState?.current) {
                return;
              }
              const newValidSources = sourceState.current.valid_sources || [];

              for (const newSource of newValidSources) {
                if (!valid_sources.has(newSource)) {
                  traverseValidSources(newSource, valid_sources);
                }
              }
            }

            if (originState?.current) {
              for (const source of originState.current.valid_sources
                ? originState.current.valid_sources
                : new Set<string>()) {
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
