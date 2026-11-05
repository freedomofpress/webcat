import { RequestDetails } from "../browser/requests";
import pageHooks from "./../../dist/hooks/page.js?raw";
import { WebcatError, WebcatErrorCodeAny } from "./interfaces/errors";
import { Stateful } from "./interfaces/requeststate";
import { WebcatUI } from "./ui";
import { getFQDN } from "./utils";

const hooks = {
  content_script: '"__DATA_PLACEHOLDER__"',
  page: pageHooks,
};

/** @internal @inline */
export type HookBuilderConfig = {
  /**
   * The path to the static hook content script file, relative to the
   * extension root directory.
   */
  staticHookPath: string;
  /**
   * The name of the connection that content script hooks use to communicate
   * with the rest of the extension.
   */
  connectionName: string;
};

/**
 * Builds the hooks injected into documents and worker scripts.
 */
export class HookBuilder {
  readonly #staticHookPath: string;
  readonly #connectionName: string;

  constructor(ui: WebcatUI, config: HookBuilderConfig) {
    this.#staticHookPath = config.staticHookPath;
    this.#connectionName = config.connectionName;
    browser.runtime.onConnect.addListener((port: browser.runtime.Port) => {
      if (port.name !== this.#connectionName) {
        return;
      }
      port.onMessage.addListener((message) => {
        const error = message as {
          code: WebcatErrorCodeAny;
        };
        ui.showErrorPage(
          {
            tabId: port.sender?.tab?.id,
            state: { fqdn: getFQDN(port.sender?.url as string) },
          } as Stateful<RequestDetails>,
          new WebcatError(error.code),
          true,
        );
      });
    });
  }

  /**
   * @returns The path to the static content script file.
   */
  getStaticHookPath() {
    return this.#staticHookPath;
  }

  /**
   * @param wasm An array of hashes to validate WASM modules against.
   * @returns A Promise that resolves to hook code ready to be injected
   *   directly to a script file.
   */
  async getPageHooks(wasm: string[]) {
    return this.#get("page", wasm);
  }

  /**
   * @param wasm An array of hashes to validate WASM modules against.
   * @returns A Promise that resolves to hook code ready to be included in a
   *   content script.
   */
  async getContentScriptHooks(
    wasm: string[],
  ): Promise<[func: (data: string) => void, args: [data: string]]> {
    const data = await this.#get("content_script", wasm);
    return [
      function (data: string) {
        const scope = window as unknown as {
          hooks?: { [index: string]: { data: unknown } };
        };
        for (const name in scope.hooks) {
          console.log(`[WEBCAT] Updating hook: ${name}`);
          scope.hooks[name].data = JSON.parse(data);
        }
      },
      [data],
    ];
  }

  async #get(type: "page" | "content_script", wasm: string[]) {
    return hooks[type].replace(
      '"__DATA_PLACEHOLDER__"',
      JSON.stringify({
        hashes: wasm,
        connectionName: this.#connectionName,
      }),
    );
  }
}
