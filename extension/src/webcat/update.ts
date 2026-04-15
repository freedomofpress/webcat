import { importCommit } from "@freedomofpress/cometbft/dist/commit";
import { verifyCommit } from "@freedomofpress/cometbft/dist/lightclient";
import { CommitJson, ValidatorJson } from "@freedomofpress/cometbft/dist/types";
import { importValidators } from "@freedomofpress/cometbft/dist/validators";
import {
  verifyWebcatProof,
  WebcatLeavesFile,
} from "@freedomofpress/ics23/dist/webcat";

import {
  CHECK_INTERVAL_MS,
  FETCH_TIMEOUT_MS,
  UPDATE_INTERVAL_MS,
} from "../config";
import validator_set from "../validator_set.json";
import { WebcatDatabase } from "./db";
import { hexToUint8Array, Uint8ArrayToBase64 } from "./encoding";
import { arraysEqual } from "./utils";

let lastUpdateFailed = false;

const ALARM_NAME = "webcat-scheduled-update";

// Helper function to fetch with timeout
async function fetchWithTimeout(
  url: string,
  timeoutMs: number = FETCH_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      cache: "no-store",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`Fetch timeout after ${timeoutMs}ms: ${url}`);
    }
    throw error;
  }
}

// Check if we should do an update at startup (overdue check)
export function shouldDoScheduledUpdate(lastUpdated: number | null): boolean {
  return lastUpdated === null || Date.now() - lastUpdated >= UPDATE_INTERVAL_MS;
}

// Handle the alarm firing: check if an update is due and run it
export async function handleUpdateAlarm(
  db: WebcatDatabase,
  endpoint: string,
): Promise<void> {
  try {
    const lastUpdated = await db.getLastUpdated();
    if (
      lastUpdated === null ||
      Date.now() - lastUpdated >= UPDATE_INTERVAL_MS
    ) {
      console.log("[webcat] Running scheduled update (alarm check)");
      try {
        await update(db, endpoint);
      } catch (error) {
        console.error("[webcat] Scheduled update failed:", error);
      }
    }
  } catch (error) {
    console.error("[webcat] Error in update alarm handler:", error);
  }
}

// Create a periodic alarm for update checks (works in both MV2 and MV3).
async function ensureUpdateAlarm(): Promise<void> {
  const existing = await browser.alarms.get(ALARM_NAME);
  if (!existing) {
    browser.alarms.create(ALARM_NAME, {
      periodInMinutes: CHECK_INTERVAL_MS / 60000,
    });
    console.log("[webcat] Created update alarm");
  }
}

// Check and run update if needed
async function checkAndUpdate(
  db: WebcatDatabase,
  endpoint: string,
): Promise<void> {
  const lastUpdated = await db.getLastUpdated();

  if (shouldDoScheduledUpdate(lastUpdated)) {
    console.log("[webcat] Running overdue scheduled update");
    try {
      await update(db, endpoint);
    } catch (error) {
      console.error("[webcat] Scheduled update failed:", error);
    }
  }
}

// Main update function
export async function update(
  db: WebcatDatabase,
  endpoint: string,
  bundled = false,
): Promise<void> {
  try {
    console.log("[webcat] Running production list updater");
    await db.setLastChecked();

    let leavesUrl: string;
    let blocksUrl: string;

    if (bundled) {
      // Use bundled files at install or update time
      console.log("[webcat] Loading bundled update files");
      leavesUrl = browser.runtime.getURL("data/list.json");
      blocksUrl = browser.runtime.getURL("data/block.json");
    } else {
      // Use network endpoints for production
      console.log("[webcat] Fetching update files");
      leavesUrl = `${endpoint}list.json`;
      blocksUrl = `${endpoint}block.json`;
    }

    const leavesResponse = fetchWithTimeout(leavesUrl);
    const blockResponse = fetchWithTimeout(blocksUrl);

    // Prevent unhandled rejection if block fetch fails before leaves is awaited
    leavesResponse.catch(() => {});

    // 2 Await latest block
    const block = await (await blockResponse).json();
    console.log("[webcat] Update block fetched");

    // 3 Verify block against validatorSet
    const { proto: vset, cryptoIndex } = await importValidators(
      validator_set as ValidatorJson,
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
      throw new Error(`Block verification failed: ${out}`);
    }

    if (!out.headerTime) {
      throw new Error("Block verification did not return a time");
    }

    const lastBlockTime = await db.getLastBlockTime();
    if (lastBlockTime !== null && out.headerTime.seconds <= lastBlockTime) {
      console.log("[webcat] Block already applied, skipping");
      lastUpdateFailed = false;
      return;
    }

    // 5 Fetch leaves file (with timeout)
    const leaves = (await (await leavesResponse).json()) as WebcatLeavesFile;

    // 6 Verify leaves file app_hash matches the block one
    if (!arraysEqual(hexToUint8Array(leaves.proof.app_hash), out.appHash)) {
      throw new Error("app hash mismatch");
    }

    // 7 Verify leaves against the canonical_root_hash and app_hash
    const verifiedLeaves = await verifyWebcatProof(leaves);
    if (verifiedLeaves === false) {
      throw new Error("proof did not verify against app hash");
    }

    await db.updateList(verifiedLeaves);
    await db.setLastBlockTime(out.headerTime?.seconds);
    await db.setRootHash(leaves.proof.canonical_root_hash);
    if (!bundled) {
      await db.setLastUpdated();
    }
    console.log(`[webcat] List updated successfully`);

    // Success - clear failure flag
    lastUpdateFailed = false;
  } catch (error) {
    console.error("[webcat] Update failed:", error);
    lastUpdateFailed = true;
    throw error;
  }
}

// Public API: Initialize scheduled updates (call on extension startup)
export async function initializeScheduledUpdates(
  db: WebcatDatabase,
  endpoint: string,
): Promise<void> {
  // Check if we need to update now
  try {
    await checkAndUpdate(db, endpoint);
  } catch (error) {
    console.error("[webcat] Error during startup update check:", error);
  }

  // Ensure the periodic alarm exists for future checks
  await ensureUpdateAlarm();
}

// Public API: Try to update if last one failed (call on main_frame navigation)
export async function retryUpdateIfFailed(
  db: WebcatDatabase,
  endpoint: string,
): Promise<void> {
  if (lastUpdateFailed) {
    console.log("[webcat] Retrying failed update on main_frame navigation");
    try {
      await update(db, endpoint);
    } catch (error) {
      console.error("[webcat] Retry update failed:", error);
      // Don't re-throw, don't block navigation
    }
  }
}
