import { buildUrlPatterns } from "./utils";

/**
 * Represents a single content script in a static file.
 */
export class ContentScript {
  readonly #idPrefix;
  readonly #path: string;

  /**
   * @param path Path to a script file.
   */
  constructor(path: string) {
    this.#path = path;
    this.#idPrefix = `webcat-script:${path}:`;
  }

  /**
   * Binds the content script to the given list of FQDNs. When called, the
   * content script is registered for the FQDNs in the list and unregistered
   * for all other FQDNS.
   *
   * @param fqdns A list of fully-qualified domain names to bind the script to.
   * @returns A list of the FQDNs that the script was not yet bound to.
   */
  async bind(fqdns: string[]) {
    // Look up existing content scripts and add the ones that are missing
    const registeredFqdns = (
      await browser.scripting.getRegisteredContentScripts()
    )
      .filter((script) => script.id.startsWith(this.#idPrefix))
      .map((script) => script.id.substring(this.#idPrefix.length));
    const newFqdns = fqdns.filter((fqdn) => {
      return !registeredFqdns.includes(fqdn);
    });
    await browser.scripting.registerContentScripts(
      newFqdns.map((fqdn) => {
        return {
          id: this.#idPrefix + fqdn,
          js: [this.#path],
          matches: buildUrlPatterns([fqdn]),
          matchOriginAsFallback: true,
          allFrames: true,
          runAt: "document_start",
        };
      }),
    );
    // Remove the content scripts whose fqdn is no longer enrolled
    await browser.scripting.unregisterContentScripts({
      ids: registeredFqdns
        .filter((fqdn) => !fqdns.includes(fqdn))
        .map((fqdn) => this.#idPrefix + fqdn),
    });

    return newFqdns;
  }
}
