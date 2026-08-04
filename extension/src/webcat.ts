import { BeforeRequestDetails, RequestEvent } from "./browser/requests";
import { WebcatConfig } from "./config";
import { WebcatDatabase } from "./webcat/db";
import { WebcatRequestHandler } from "./webcat/handler";
import { EnrollmentUpdater } from "./webcat/updater";
import { clearBrowserCaches } from "./webcat/utils";

function start(config: WebcatConfig) {
  const db = new WebcatDatabase(config);
  const requestHandler = new WebcatRequestHandler(db, config);
  const updater = new EnrollmentUpdater(
    Object.assign(
      {
        database: db,
      },
      config,
    ),
  );

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
