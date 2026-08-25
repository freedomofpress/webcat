import { KVStore } from "../browser/kvstore";
import pageHooks from "./../../dist/hooks/page.js?raw";

const hooks = {
  content_script: '"__DATA_PLACEHOLDER__"',
  page: pageHooks,
};

let staticHookPath = "dist/hooks/content.js";

export function setStaticHookPath(path: string) {
  staticHookPath = path;
}

/**
 * Builds hooks using unique cryptographic keys.
 */
export class HookBuilder {
  #firstPartyKey: Promise<CryptoKey>;
  #firstPartySalt: Promise<Uint8Array<ArrayBuffer>>;

  constructor(store: KVStore) {
    this.#firstPartyKey = store
      .get("firstPartyKey", "session")
      .then(async (raw: ArrayBuffer) => {
        let key: CryptoKey;
        const algorithm = { name: "AES-GCM", length: 256 };
        const extractable = true;
        const usages = ["encrypt", "decrypt"] as KeyUsage[];
        if (!raw) {
          key = await crypto.subtle.generateKey(algorithm, extractable, usages);
          store.set(
            {
              firstPartyKey: await crypto.subtle.exportKey("raw", key),
            },
            "session",
          );
        } else {
          key = await crypto.subtle.importKey(
            "raw",
            raw,
            algorithm,
            extractable,
            usages,
          );
        }
        return key;
      });
    this.#firstPartySalt = store
      .get("firstPartySalt", "session")
      .then((salt) => {
        if (!salt) {
          salt = crypto.getRandomValues(
            new Uint8Array(256 / 8), // SHA-256 length
          );
          store.set(
            {
              firstPartySalt: salt,
            },
            "session",
          );
        }
        return salt;
      });
  }

  /**
   * @returns the path to the static content script file
   */
  getStaticHookPath() {
    return staticHookPath;
  }

  /**
   * @param wasm an array of hashes to validate WASM modules against
   * @param firstParty the first-party origin of the associated page
   * @param sameOrigin true if the target document is same-origin with the first party
   * @returns hook code ready to be injected directly to a script file
   */
  async getPageHooks(wasm: string[], firstParty: string, sameOrigin: boolean) {
    return this.#get("page", wasm, firstParty, sameOrigin);
  }

  /**
   * @param wasm an array of hashes to validate WASM modules against
   * @param firstParty the first-party origin of the associated page
   * @param sameOrigin true if the target document is same-origin with the first party
   * @returns hook code ready to be included in a content script
   */
  async getContentScriptHooks(
    wasm: string[],
    firstParty: string,
    sameOrigin: boolean,
  ): Promise<[func: (data: string) => void, args: [data: string]]> {
    const data = await this.#get(
      "content_script",
      wasm,
      firstParty,
      sameOrigin,
    );
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

  /**
   * @param url a URL where an encrypted fragment has been added via a hook
   * @returns the decrypted fragment
   */
  async decryptFragment(url: string) {
    const markerIndex = url.lastIndexOf("#");
    if (markerIndex === -1) {
      throw new Error("no fragment present when decrypting");
    }
    const efpo = Uint8Array.fromBase64(url.substring(markerIndex + 1), {
      alphabet: "base64url",
    });
    const fpo = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: efpo.slice(0, 12),
      },
      await this.#firstPartyKey,
      efpo.slice(12),
    );
    return new TextDecoder().decode(fpo);
  }

  async #get(
    type: "page" | "content_script",
    wasm: string[],
    firstParty: string,
    sameOrigin: boolean,
  ) {
    // Generate deterministic IV using HKDF and SHA-256. Using firstParty as the input
    // ensures the same IV is never used for encrypting two different plaintext. Using
    // firstPartySalt instead of the default zero salt ensures an attacker can't generate
    // collisions.
    const iv = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: await this.#firstPartySalt,
        info: new ArrayBuffer(),
      },
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(firstParty),
        { name: "HKDF" },
        false,
        ["deriveBits"],
      ),
      96,
    );
    // Encrypt firstParty
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        await this.#firstPartyKey,
        new TextEncoder().encode(firstParty),
      ),
    );
    // Construct the first party URL fragment value
    const efpo = new Uint8Array(iv.byteLength + ct.byteLength);
    efpo.set(new Uint8Array(iv));
    efpo.set(ct, iv.byteLength);
    const efpoBase64 = efpo.toBase64({ alphabet: "base64url" });
    // Return the hook script updated with data
    return hooks[type].replace(
      '"__DATA_PLACEHOLDER__"',
      JSON.stringify({
        hashes: wasm,
        firstParty: efpoBase64,
        sameOriginWithFirstParty: sameOrigin,
      }),
    );
  }
}
