import { WebcatErrorCode } from "../interfaces/errors";
import { updatableHook } from "./core";

/**
 * Enforces frame isolation by checking the originAgentCluster property.
 */
export const oacHook = updatableHook(
  "originAgentCluster",
  async function (data: Promise<{ connectionName: string }>) {
    if (!window.originAgentCluster) {
      window.stop();
      const port = browser.runtime.connect({
        name: (await data).connectionName,
      });
      port.postMessage({
        code: WebcatErrorCode.FrameIsolation.OAC_UNAVAILABLE,
      });
    }
  },
);
