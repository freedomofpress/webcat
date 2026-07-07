import { firstPartyKey } from "../globals";
import contentHooks from "./../../dist/hooks/content.js?raw";
import pageHooks from "./../../dist/hooks/page.js?raw";
import { hooksType } from "./interfaces/base";

const hooks = {
  [hooksType.content_script]: contentHooks,
  [hooksType.page]: pageHooks,
};

export async function getHooks(
  type: hooksType,
  wasm: string[],
  firstParty: string,
  sameOrigin: boolean,
) {
  // This just patches the script string dynamically,
  // adding per-origin WASM hashes and FPO hints
  const iv = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(96)));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      await firstPartyKey,
      new TextEncoder().encode(firstParty),
    ),
  );
  const efpo = new Uint8Array(iv.length + ct.byteLength);
  efpo.set(iv);
  efpo.set(ct, iv.length);
  const efpoBase64 = efpo.toBase64({ alphabet: "base64url" });
  return hooks[type].replace(
    '"__DATA_PLACEHOLDER__"',
    JSON.stringify({
      hashes: wasm,
      firstParty: efpoBase64,
      sameOriginWithFirstParty: sameOrigin,
    }),
  );
}
