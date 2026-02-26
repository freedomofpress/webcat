import { importCommit } from "@freedomofpress/cometbft/dist/commit";
import { verifyCommit } from "@freedomofpress/cometbft/dist/lightclient";
import { CommitJson, ValidatorJson } from "@freedomofpress/cometbft/dist/types";
import { importValidators } from "@freedomofpress/cometbft/dist/validators";
import {
  verifyWebcatProof,
  WebcatLeavesFile,
} from "@freedomofpress/ics23/dist/webcat";

import validator_set from "../validator_set.json";
import { WebcatDatabase } from "./db";
import { hexToUint8Array, Uint8ArrayToBase64 } from "./encoding";
import { arraysEqual } from "./utils";

let lastUpdateFailed = false;
const FETCH_TIMEOUT_MS = 3000; // 3 second timeout for fetches

let scheduledUpdateTimer: number | null = null;

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

// Check if we should do scheduled daily update
function shouldDoScheduledUpdate(lastUpdated: number | null): boolean {
  const now = Date.now();
  const nowUTC = new Date(now);

  // Calculate today's scheduled update time (01:10 UTC)
  const todayScheduled = new Date(
    Date.UTC(
      nowUTC.getUTCFullYear(),
      nowUTC.getUTCMonth(),
      nowUTC.getUTCDate(),
      1, // hour
      10, // minute
      0, // second
      0, // millisecond
    ),
  ).getTime();

  // If we haven't passed today's scheduled time yet, check yesterday's
  const scheduledTime =
    now >= todayScheduled
      ? todayScheduled
      : todayScheduled - 24 * 60 * 60 * 1000;

  // Update if we've never updated, or if last update was before the most recent scheduled time
  return lastUpdated === null || lastUpdated < scheduledTime;
}

// Schedule the next daily update check
function scheduleNextUpdate(db: WebcatDatabase, endpoint: string): void {
  if (scheduledUpdateTimer !== null) {
    clearTimeout(scheduledUpdateTimer);
  }

  /*const now = Date.now();
  const nowUTC = new Date(now);

  // Calculate next scheduled update time (01:10 UTC)
  let nextScheduled = new Date(
    Date.UTC(
      nowUTC.getUTCFullYear(),
      nowUTC.getUTCMonth(),
      nowUTC.getUTCDate(),
      0, // hour
      15, // minute
      0, // second
      0, // millisecond
    ),
  ).getTime();

  // If we've already passed today's scheduled time, schedule for tomorrow
  if (now >= nextScheduled) {
    nextScheduled += 1 * 60 * 60 * 1000;
  }*/

  // During alpha, sechedule update an hour from now
  const now = Date.now();
  const nextScheduled = now + 60 * 60 * 1000;

  const delay = nextScheduled - now;
  console.log(
    `[webcat] Scheduling next update in ${Math.round(delay / 1000 / 60)} minutes`,
  );

  scheduledUpdateTimer = setTimeout(async () => {
    console.log("[webcat] Running scheduled daily update");
    try {
      await update(db, endpoint);
    } catch (error) {
      console.error("[webcat] Scheduled update failed:", error);
    }
    // Schedule the next one
    scheduleNextUpdate(db, endpoint);
  }, delay) as unknown as number;
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
  await checkAndUpdate(db, endpoint);

  // Schedule future updates
  scheduleNextUpdate(db, endpoint);
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
