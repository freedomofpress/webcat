import { importCommit } from "@freedomofpress/cometbft/dist/commit";
import { verifyCommit } from "@freedomofpress/cometbft/dist/lightclient";
import { CommitJson, ValidatorJson } from "@freedomofpress/cometbft/dist/types";
import { importValidators } from "@freedomofpress/cometbft/dist/validators";
import {
  verifyWebcatProof,
  WebcatLeavesFile,
} from "@freedomofpress/ics23/dist/webcat";

import { origins, tabs } from "../globals";
import {
  ensureDBOpen,
  getFQDNEnrollment,
  insertWebcatLeaves,
  list_db,
  updateDatabase,
  updateLastChecked,
} from "./db";
import { hexToUint8Array, Uint8ArrayToBase64 } from "./encoding";
import { metadataRequestSource } from "./interfaces/base";
import { WebcatError } from "./interfaces/errors";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import { validateResponseContent, validateResponseHeaders } from "./response";
import { errorpage } from "./ui";
import { arraysEqual, getFQDN, isExtensionRequest } from "./utils";

declare const __TESTING__: boolean;

async function updateList(db: IDBDatabase) {
  if (__TESTING__) {
    console.log("[webcat] Running test list updater");
    updateLastChecked(db);
    // updateDatabase has also a __TESTING__ condition; later we might want to move everything into the same place
    await updateDatabase(db, "", 1337, new Uint8Array());
  } else {
    // Running update procedure from webcat-infra-chain
    // Steps:
    // 1. Load validatorSet from disk (must be bundled with the extension for now, we could support validatorSet updates in the future)
    // 2. Fetch latest block
    // 3. Verify block against validatorSet
    // 4. Check block date is > than last update block date
    // 5. Fetch leaves file
    // 6. Verify leaves file app_hash matches the block one
    // 7. Verify leaves against app_hash (leaf by leaf)
    // 8. Update local database

    // 1 TODO SECURITY: load validatorSet from disk
    console.log("[webcat] Running production list updater");
    const start = performance.now();
    // 2 Fetch latest block
    const blockResponse = await fetch(
      "https://raw.githubusercontent.com/freedomofpress/webcat-infra-chain/refs/heads/main/test_data/block.json",
      { cache: "no-store" },
    );
    const block = await blockResponse.json();
    console.log("[webcat] Update block fetched");
    // 3 Verify block against validatorSet
    const { proto: vset, cryptoIndex } = await importValidators(
      block.validator_set as ValidatorJson,
    );
    const sh = importCommit(block as CommitJson);
    const out = await verifyCommit(sh, vset, cryptoIndex);

    if (out.ok) {
      console.log(
        "[webcat] Block verified, app_hash: ",
        Uint8ArrayToBase64(out.appHash),
        "time: ",
        out.headerTime,
      );
    } else {
      throw new Error(`Block verification failed: out`);
    }

    // 4 TODO SECURITY: Check block date is > than last update block date

    // 5 Fetch leaves file
    const leavesResponse = await fetch(
      "https://raw.githubusercontent.com/freedomofpress/webcat-infra-chain/refs/heads/main/test_data/leaves.json",
      { cache: "no-store" },
    );
    const leaves = (await leavesResponse.json()) as WebcatLeavesFile;

    // 6 Verify leaves file app_hash matches the block one
    if (!arraysEqual(hexToUint8Array(leaves.proof.app_hash), out.appHash)) {
      throw new Error("app hash mismatch");
    }

    // 7 Verify leaves against the canonical_root_hash and app_hash
    const verifiedLeaves = await verifyWebcatProof(leaves);

    if (verifiedLeaves === false) {
      throw new Error("proof did not verify against app hash");
    }

    await insertWebcatLeaves(db, verifiedLeaves);
    updateLastChecked(db);
    const end = performance.now();
    console.log(`[webcat] List updated successfully in ${end - start} ms`);
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
    // TODO: if we do, we should also cleanup the listeners
    /*
    if (originState.current.references === 0) {
      browser.webRequest.onBeforeRequest.removeListener(
          originState.current.onBeforeRequest
      );
      browser.webRequest.onHeadersReceived.removeListener(
          originState.current.onHeadersReceived
      );
      origins.delete(fqdn);
    }
    */
    tabs.delete(tabId);
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

  if (
    // Skip non-enrolled tabs
    (!tabs.has(details.tabId) &&
      details.tabId > 0 &&
      (await getFQDNEnrollment(fqdn)).length === 0) ||
    // Skip non-enrolled workers
    (details.tabId < 0 && (await getFQDNEnrollment(fqdn)).length === 0) ||
    isExtensionRequest(details)
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
    const result = await validateOrigin(
      fqdn,
      details.url,
      details.tabId,
      metadataRequestSource.worker,
    );
    if (result instanceof WebcatError) {
      origins.delete(fqdn);
      tabs.delete(details.tabId);
      errorpage(details.tabId, result);
      return { cancel: true };
    }
  }

  const originStateHolder = origins.get(fqdn);

  if (!originStateHolder) {
    throw new Error("No originState while starting to parse response.");
  }

  const result = await validateResponseHeaders(originStateHolder, details);
  if (result instanceof WebcatError) {
    logger.addLog(
      "error",
      `Error when parsing response headers: ${result}`,
      details.tabId,
      fqdn,
    );
    origins.delete(fqdn);
    tabs.delete(details.tabId);
    errorpage(details.tabId, result);
    return { cancel: true };
  }

  return {};
}

export async function requestListener(
  details: browser.webRequest._OnBeforeRequestDetails,
): Promise<browser.webRequest.BlockingResponse> {
  const fqdn = getFQDN(details.url);

  if (
    (details.tabId < 0 && !origins.has(fqdn)) ||
    isExtensionRequest(details)
  ) {
    // TODO: is this still relevant? it seems like it
    // should apply to workers (no tab id) if they do
    // a fetch request and the origin doesn't exists
    // To be safe maybe we should check for enrollment again?
    return {};
  }

  // TODO: why does this happen for sub_frames?
  //if (details.type === "main_frame" || details.type === "sub_frame") {
  if (FRAME_TYPES.includes(details.type)) {
    // User is navigatin to a new context, whether is enrolled or not better to reset
    cleanup(details.tabId);

    logger.addLog(
      "info",
      `Loading ${details.type} ${details.url}`,
      details.tabId,
      fqdn,
    );

    const result = await validateOrigin(
      fqdn,
      details.url,
      details.tabId,
      metadataRequestSource.main_frame,
    );
    if (result instanceof WebcatError) {
      origins.delete(fqdn);
      tabs.delete(details.tabId);
      errorpage(details.tabId, result);
      return { cancel: true };
    }
    if (result) {
      logger.addLog("info", `Redirecting to https`, details.tabId, fqdn);
      return result;
    }
  }

  /* DEVELOPMENT GUARD */
  /*it's here for development: meaning if we reach this stage
    and the fqdn is enrolled, but a entry in the origin map has nor been created, there is a critical security bug */
  if ((await getFQDNEnrollment(fqdn)).length !== 0 && !origins.has(fqdn)) {
    console.error(
      "FATAL: loading from an enrolled origin but the state does not exists.",
    );
    return { cancel: true };
  }
  /* END */

  // if we know the tab is enrolled, or it is a worker background connction then we should verify
  if (tabs.has(details.tabId) === true || details.tabId < 0) {
    await validateResponseContent(details);
  }

  // See https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/BlockingResponse
  // Returning a response here is a very powerful tool, let's think about it later
  return {};
}
