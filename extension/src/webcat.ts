import { BeforeRequestDetails, RequestEvent } from "./browser/requests";
import { defaults, WebcatConfig } from "./config";
import { WebcatDatabase } from "./webcat/db";
import { WebcatRequestHandler } from "./webcat/handler";
import { setStaticHookPath } from "./webcat/hookbuilder";
import { setIconsPath, setPagesPath } from "./webcat/ui";
import { EnrollmentUpdater } from "./webcat/updater";

export default {
  /**
   * Sets up the full unmodified WEBCAT experience as it is designed to operate
   * in Firefox-based browsers.
   *
   * @param options Configuration options. Defaults to {@link defaults}.
   */
  start(options?: Partial<WebcatConfig>) {
    const cfg = Object.assign(structuredClone(defaults), options);
    setStaticHookPath(cfg.staticHookPath);
    setIconsPath(cfg.iconsPath);
    setPagesPath(cfg.pagesPath);

    const db = new WebcatDatabase(cfg);
    const requestHandler = new WebcatRequestHandler(db, cfg);
    const updater = new EnrollmentUpdater(Object.assign({ database: db }, cfg));

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
        await requestHandler.bind(fqdns);
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
  },
};
