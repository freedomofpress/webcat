import { WebcatErrorCode } from "../interfaces/errors";
import { updatableHook } from "./core";

/**
 * Enforces frame isolation by checking the originAgentCluster property.
 */
export const oacHook = updatableHook(
  "originAgentCluster",
  async function (data: Promise<{ connectionName: string }>) {
    if (!window.originAgentCluster) {
      // Only enforce on active content, i.e. XML and HTML documents. An
      // instanceof check doesn't work here, because ImageDocument extends
      // HTMLDocument. SVG images are XMLDocuments, not ImageDocuments.
      const type = (document as unknown as { [Symbol.toStringTag]: string })[
        Symbol.toStringTag
      ];
      if (type !== "XMLDocument" && type !== "HTMLDocument") {
        return;
      }
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
