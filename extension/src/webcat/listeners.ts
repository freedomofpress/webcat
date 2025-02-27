import {
  sigsum_log_key,
  sigsum_signing_key,
  sigsum_witness_key,
  tuf_sigstore_namespace,
  tuf_sigstore_root,
  tuf_sigstore_url,
} from "../config";
import { origins, popups, tabs } from "../globals";
import { TrustedRoot } from "../sigstore/interfaces";
import { SigstoreVerifier } from "../sigstore/sigstore";
import { TUFClient } from "../sigstore/tuf";
import { SigsumProof, SigsumVerifier } from "../sigsum/sigsum";
import { ensureDBOpen, getFQDNPolicy } from "./db";
import { metadataRequestSource } from "./interfaces/base";
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
  const proofJson =
    '{"version":2,"log_key_hash":"c9e525b98f412ede185ff2ac5abf70920a2e63a6ae31c88b1138b85de328706b","leaf":{"key_hash":"3bf814d25abaa9bfa5f5911454a78c6a4645335bcad63a016c8fb18a94f008fd","signature":"6afcf1636218bff7cdd45587940e88a308a320cc69523f2c66538cf35300cd2849d83b59a21da5e3e4d69ef0f1c651df532bfdd9c91ccaff3127a9ef3f1f3901"},"tree_head":{"size":37179,"root_hash":"eabbccf99dc8e4ca1983a69c10961ebdea86a69c1fc2b63f89665e2e737a6df6","signature":"65a18115ba535a4ce189b71b9ebc273e5107644c0dac470f9d5d83a84d4169935719516e06c19680db10c872e2e78fe1484c81559625301dccb042f544e77108","cosignatures":[{"keyhash":"1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c","timestamp":1740605441,"signature":"d13c24560c605c16e65c6d364ce99aa82464df771527f0421589c3da0153214d4afd5f41c374956b0a1fbe28900ca2b5d9cb57d6ddcb2df88be319c80d879c0d"},{"keyhash":"42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8","timestamp":1740605441,"signature":"83b6c48f3a44516aa863f11b3a1ed81d36c11736f62b0905202b5991e203461e4672b9ca7878b37cae861cdd6387deaf79cbd8c2afb45dbcb6c2a09b5873020e"},{"keyhash":"e923764535cac36836d1af682a2a3e5352e2636ec29c1d34c00160e1f4946d31","timestamp":1740605441,"signature":"0abc5babd58f7491d6211781ac7def66f305e627a554ef7d336f4a98c4cdba33bf11b856786d1d3c2dab5b44120f4506ae6cf016b381f3a86148c151f0b2360d"},{"keyhash":"70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc","timestamp":1740605441,"signature":"62ed968553a445845dc9d37a690a846934fd8898d8b3051f9243c8f8785da6f0eddb7ecb6486bd649e6b7ce638f471bf81f4810402baad60356949347285140b"}]},"inclusion_proof":{"leaf_index":37178,"node_hashes":["60e6504751997926b707c30ae121fa56c6cab7c97644ac7576ae6e2dddac453d","004452e1fa2afe5cc2332fc06d164e794741e0ea41a1a22a3f4ef6aea806320c","179690e99532f6ed37211881dee5d5d4e2627c9b31f208a7fc021e8c29e24460","b2d594003d85d0165cf93766cf2ee74f65f5f54edb70dbc816d3e082a6bf326b","6b8b4ba9a3d2796d3913b2849611b122ec61cbc9d16d6bfe34c79ea66be9936d","d9d64f73c2c84f369c482dad27b9cbbab7692dbbc43a10be108dc25f0d3748cb","a30888d947b9587c2d78375cf2532ef91ef462487edb22548ec135387a6cb6fd"]},"message_hash":"f8bb2e1b5f13940eeb2b880780a22008a0506b1491ca2726eab522a2ad7be87b"}';
  const sigsum = await SigsumVerifier.create(
    sigsum_log_key,
    sigsum_witness_key,
    sigsum_signing_key,
  );
  let proof: SigsumProof;
  try {
    proof = JSON.parse(proofJson) as SigsumProof;
  } catch (error) {
    throw new Error("Failed to parse Sigsum proof JSON: " + error);
  }
  console.log(sigsum.verify(proof));
  console.log(sigsum);

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
