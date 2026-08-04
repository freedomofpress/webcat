import { BeforeRequestDetails, RequestEvent } from "./browser/requests";
import {
  CHECK_INTERVAL_MS,
  endpoint,
  FETCH_TIMEOUT_MS,
  UPDATE_INTERVAL_MS,
} from "./config";
import validator_set from "./validator_set.json";
import { WebcatDatabase } from "./webcat/db";
import { WebcatRequestHandler } from "./webcat/handler";
import { EnrollmentUpdater } from "./webcat/updater";
import { clearBrowserCaches } from "./webcat/utils";

function start() {
  const db = new WebcatDatabase();
  const requestHandler = new WebcatRequestHandler(db);
  const updater = new EnrollmentUpdater({
    endpoint: endpoint,
    database: db,
    validatorSet: validator_set,
    checkInterval: CHECK_INTERVAL_MS,
    updateInterval: UPDATE_INTERVAL_MS,
    fetchTimeout: FETCH_TIMEOUT_MS,
  });

  requestHandler.bindAll();
  requestHandler.addEventListener(
    "beforeframeload",
    async (event: RequestEvent<BeforeRequestDetails>) => {
      using _blockingResponse = event.blockingResponse;
      await updater.retryIfFailed();
    },
  );

  let firstUpdate = true;
  updater.addEventListener("updated", async (event) => {
    if (!event.success && !firstUpdate) {
      return;
    }
    try {
      const fqdns = await db.listAllFQDNs();
      const newFqdns = await requestHandler.bind(fqdns);
      await clearBrowserCaches(newFqdns);
      firstUpdate = false;
    } catch (error) {
      console.error("[webcat] Bundled list import failed:", error);
    }
  });
  updater.start();

  if (import.meta.env.VITE_TESTING) {
    Object.defineProperty(globalThis, "state", {
      value: {
        origins: db.origins,
        nonOrigins: db.nonOrigins,
      },
    });
  }
}

export default { start };
