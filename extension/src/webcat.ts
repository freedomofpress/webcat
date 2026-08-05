import { BeforeRequestDetails, RequestEvent } from "./browser/requests";
import config, { WebcatConfig } from "./config";
import { WebcatDatabase } from "./webcat/db";
import { WebcatRequestHandler } from "./webcat/handler";
import { setIconsPath, setPagesPath } from "./webcat/ui";
import { EnrollmentUpdater } from "./webcat/updater";
import { clearBrowserCaches } from "./webcat/utils";

function start(options?: Partial<WebcatConfig>) {
  const cfg = Object.assign(structuredClone(config.default), options);
  const db = new WebcatDatabase(cfg);
  const requestHandler = new WebcatRequestHandler(db, cfg);
  const updater = new EnrollmentUpdater(Object.assign({ database: db }, cfg));

  setIconsPath(cfg.iconsPath);
  setPagesPath(cfg.pagesPath);

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
