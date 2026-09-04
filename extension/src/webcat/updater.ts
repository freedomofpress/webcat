import { importCommit } from "@freedomofpress/cometbft/dist/commit";
import { verifyCommit } from "@freedomofpress/cometbft/dist/lightclient";
import { CommitJson, ValidatorJson } from "@freedomofpress/cometbft/dist/types";
import { importValidators } from "@freedomofpress/cometbft/dist/validators";
import {
  verifyWebcatProof,
  WebcatLeavesFile,
} from "@freedomofpress/ics23/dist/webcat";

import { Mutex } from "../browser/sync";
import { hexToUint8Array, Uint8ArrayToBase64 } from "./encoding";
import { Database } from "./interfaces/database";
import { arraysEqual } from "./utils";

/**
 * An event indicating the completion of an update attempt.
 */
export class UpdateEvent extends Event {
  /**
   * Indicates whether the update was local or networked. Set to true for
   * updates loaded from local files and false for updates done over the
   * network.
   */
  readonly local: boolean;
  /**
   * Indicates whether the update was successful. Set to true if the update
   * resulted in a new block being applied. If false, the update may have
   * failed with an error, or there may not have been anything to update.
   */
  readonly success: boolean;

  constructor(success: boolean, local = false) {
    super("updated");
    this.success = success;
    this.local = local;
  }
}

/**
 * Options for an {@link EnrollmentUpdater}.
 */
export interface EnrollmentUpdaterOptions {
  /**
   * The update endpoint that serves verifiable enrollments as `list.json` and
   * `block.json`.
   */
  endpoint: string;
  /**
   * The path to bundled `list.json` and `block.json` files.
   */
  localDataPath: string;
  /**
   * The database to persist enrollments in.
   */
  database: Database;
  /**
   * The set of CometBFT validators to verify enrollments against.
   */
  validatorSet: ValidatorJson;
  /**
   * The time in seconds between enrollment update checks. Determines how often
   * the extension is activated to check whether an update is due. An update is
   * only downloaded if, at check time, {@link updateInterval} has elapsed
   * since the last update.
   *
   * @defaultValue {@link EnrollmentUpdater.DefaultCheckInterval}
   */
  checkInterval?: number;
  /**
   * The minimum time in seconds between updates. Update checks are run
   * periodically at an interval determined by this value. An update is only
   * downloaded when a {@link checkInterval | check } runs and updateInterval
   * has elapsed since the last update.
   *
   * @defaultValue {@link EnrollmentUpdater.DefaultUpdateInterval}
   */
  updateInterval?: number;
  /**
   * The timeout, in milliseconds, of update download attempts.
   *
   * @defaultValue {@link EnrollmentUpdater.DefaultFetchTimeout}
   */
  fetchTimeout?: number;
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export interface EnrollmentUpdater extends EventTarget {
  /** @group Methods */
  addEventListener: EventTarget["addEventListener"] &
    ((type: "updated", callback: (event: UpdateEvent) => void) => void);
}

/**
 * Handles loading enrollment updates periodically from the endpoint,
 * storing them to the database, and notifying event consumers.
 */
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export class EnrollmentUpdater extends EventTarget {
  /**
   * The default value for {@link EnrollmentUpdaterOptions.checkInterval},
   * 5 minutes.
   */
  static readonly DefaultCheckInterval = 5 * 60 * 1000;
  /**
   * The default value for {@link EnrollmentUpdaterOptions.updateInterval},
   * 1 hour.
   */
  static readonly DefaultUpdateInterval = 60 * 60 * 1000;
  /**
   * The default value for {@link EnrollmentUpdaterOptions.fetchTimeout},
   * 3 seconds.
   */
  static readonly DefaultFetchTimeout = 3000;

  readonly #endpoint: string;
  readonly #localDataPath: string;
  readonly #db: Database;
  readonly #validatorSet: ValidatorJson;
  readonly #checkInterval: number;
  readonly #updateInterval: number;
  readonly #fetchTimeout: number;
  readonly #alarm: string;
  readonly #mutex = new Mutex();

  #lastUpdateFailed = false;

  constructor(options: EnrollmentUpdaterOptions) {
    super();
    this.#endpoint = options.endpoint;
    this.#localDataPath = options.localDataPath;
    this.#db = options.database;
    this.#validatorSet = options.validatorSet;
    this.#checkInterval =
      options.checkInterval || EnrollmentUpdater.DefaultCheckInterval;
    this.#updateInterval =
      options.updateInterval || EnrollmentUpdater.DefaultUpdateInterval;
    this.#fetchTimeout =
      options.fetchTimeout || EnrollmentUpdater.DefaultFetchTimeout;
    this.#alarm = `webcat-scheduled-update:${options.endpoint}`;
  }

  /**
   * Loads bundled enrollments and initiates periodic updates.
   */
  start() {
    browser.alarms.onAlarm.addListener(this.#handleUpdateAlarm.bind(this));
    browser.alarms.get(this.#alarm).then((alarm) => {
      if (!alarm) {
        browser.alarms.create(this.#alarm, {
          periodInMinutes: this.#checkInterval / 60000,
        });
      }
      this.dispatchEvent(new Event("scheduled"));
    });

    console.log("[webcat] Importing bundled list");
    this.update(true)
      .finally(async () => {
        console.log("[webcat] Attempting network update");
        await this.#checkAndUpdate();
      })
      .catch((error) => {
        console.error("[webcat] Bundled list import failed:", error);
      });
  }

  /**
   * Immediately does a single update. If local is true, only the enrollment
   * files bundled with the extension are consulted without accessing the network.
   */
  async update(local = false) {
    try {
      console.log("[webcat] Running production list updater");
      await this.#db.setLastChecked();

      let leavesUrl: string;
      let blocksUrl: string;

      if (local) {
        // Use bundled files at install or update time
        console.log("[webcat] Loading bundled update files");
        leavesUrl = browser.runtime.getURL(`${this.#localDataPath}/list.json`);
        blocksUrl = browser.runtime.getURL(`${this.#localDataPath}/block.json`);
      } else {
        // Use network endpoints for production
        console.log("[webcat] Fetching update files");
        leavesUrl = `${this.#endpoint}list.json`;
        blocksUrl = `${this.#endpoint}block.json`;
      }

      const leavesResponse = this.#fetchWithTimeout(leavesUrl);
      const blockResponse = this.#fetchWithTimeout(blocksUrl);

      // Prevent unhandled rejection if block fetch fails before leaves is awaited
      leavesResponse.catch(() => {});

      // 2 Await latest block
      const block = await (await blockResponse).json();
      console.log("[webcat] Update block fetched");

      if (import.meta.env.VITE_TESTING) {
        const reschedule = block.__WEBCAT_TEST_SCHEDULE_UPDATE__;
        if (reschedule) {
          console.log(
            "[webcat] Rescheduling update for test in",
            reschedule,
            "second(s)",
          );
          browser.alarms.create(this.#alarm, {
            when: Date.now() + reschedule * 1000,
          });
        }
      }

      // 3 Verify block against validatorSet
      const { proto: vset, cryptoIndex } = await importValidators(
        this.#validatorSet,
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

      const meta = await this.#db.getBlockMeta();
      if (meta !== null && out.headerTime.seconds <= meta.blockTime) {
        console.log("[webcat] Block already applied, skipping");
        this.#lastUpdateFailed = false;
        this.dispatchEvent(new UpdateEvent(false, local));
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

      await this.#db.updateList(verifiedLeaves, {
        blockTime: Number(out.headerTime.seconds),
        rootHash: leaves.proof.canonical_root_hash,
      });
      if (!local) {
        await this.#db.setLastUpdated();
      }
      console.log(`[webcat] List updated successfully`);
      this.dispatchEvent(new UpdateEvent(true, local));

      // Success - clear failure flag
      this.#lastUpdateFailed = false;
    } catch (error) {
      console.error("[webcat] Update failed:", error);
      this.#lastUpdateFailed = true;
      this.dispatchEvent(new UpdateEvent(false, local));
      throw error;
    }
  }

  /**
   * Retries an update if the previous attempt failed. Unlike {@link update},
   * retryIfFailed never throws.
   */
  async retryIfFailed(): Promise<void> {
    if (this.#lastUpdateFailed) {
      console.log("[webcat] Retrying failed update on main_frame navigation");
      try {
        await this.#checkAndUpdate();
      } catch (error) {
        console.error("[webcat] Retry update failed:", error);
        // Don't re-throw, don't block navigation
      }
    }
  }

  async #checkAndUpdate(): Promise<void> {
    using _lock = await this.#mutex.acquire();
    if ((await this.isDue()) || import.meta.env.VITE_TESTING) {
      console.log("[webcat] Running overdue scheduled update");
      try {
        await this.update();
      } catch (error) {
        console.error("[webcat] Scheduled update failed:", error);
      }
    }
  }

  /**
   * Determines whether an update is due.
   *
   * @returns A Promise that resolves to true if an update is due.
   */
  async isDue(): Promise<boolean> {
    const lastUpdated = await this.#db.getLastUpdated();
    return (
      lastUpdated === null || Date.now() - lastUpdated >= this.#updateInterval
    );
  }

  async #handleUpdateAlarm(alarm: browser.alarms.Alarm): Promise<void> {
    if (alarm.name !== this.#alarm) {
      return;
    }
    try {
      await this.#checkAndUpdate();
    } catch (error) {
      console.error("[webcat] Error in update alarm handler:", error);
    }
  }

  async #fetchWithTimeout(
    url: string,
    timeoutMs: number = this.#fetchTimeout,
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
}
