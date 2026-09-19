/**
 * This module is the main entrypoint to an uncustomized WEBCAT browser
 * extension. The module exports a single function,
 * {@link default.start | start}. For configuration options, see
 * {@link WebcatConfig}. For a more custom experience, set up
 * {@link WebcatRequestHandler} and {@link EnrollmentUpdater} objects directly
 * instead.
 *
 * @example
 * import webcat from "@freedomofpress/webcat";
 * webcat.start({
 *   localDataPath: "webcat/data",
 *   staticHookPath: "webcat/hooks/content.js",
 *   iconPaths: (p) => `webcat/icons/${p.name}-${p.colorScheme}.png`,
 *   pagePaths: (p) => `webcat/pages/${p.name}.html`,
 * });
 *
 * @module
 */
import { BeforeRequestDetails, RequestEvent } from "./browser/requests";
import { defaults, WebcatConfig } from "./config";
import { WebcatDatabase } from "./webcat/db";
import { WebcatRequestHandler } from "./webcat/handler";
import { WebcatUI } from "./webcat/ui";
import { EnrollmentUpdater } from "./webcat/updater";

export default {
  /**
   * Sets up the full unmodified WEBCAT experience as it is designed to operate
   * in Firefox-based browsers.
   *
   * @param options Configuration options. Defaults to {@link defaults}.
   */
  start(options?: Partial<WebcatConfig>) {
    const cfg = Object.assign(Object.assign({}, defaults), options);

    const db = new WebcatDatabase(cfg);
    const ui = new WebcatUI(cfg);
    const requestHandler = new WebcatRequestHandler(db, ui, cfg);
    const updater = new EnrollmentUpdater(Object.assign({ database: db }, cfg));

    requestHandler.bindAll();
    requestHandler.addEventListener(
      "beforeframeload",
      async (event: RequestEvent<BeforeRequestDetails>) => {
        using blockingResponse = event.createBlockingResponse();
        await updater.retryIfFailed();
        blockingResponse.cancel = false;
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
